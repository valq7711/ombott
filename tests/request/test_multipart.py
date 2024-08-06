from typing import Iterable, List
import pytest
from io import BytesIO, SEEK_CUR, SEEK_END, TextIOWrapper
from ombott.request_pkg.multipart import MultipartMarkup, FieldStorage, BytesIOProxy


class Field:
    def __init__(self, name: str, value: str, filename: str = None, ctype: str = None):
        self.name = name
        self.value = value
        self.filename = filename
        self.ctype = ctype

    def dump(self):
        cdisp = f'Content-Disposition: form-data; name="{self.name}"'
        if self.filename:
            cdisp += f'; filename={self.filename}'
        hbuff = [cdisp]
        if self.ctype:
            hbuff.append(f'Content-Type: {self.ctype}')
        headers = '\r\n'.join(hbuff)
        return '\r\n' + headers + ('\r\n' * 2) + self.value


def make_body(form: List[Field], boundary: str) -> str:
    hyphen_boundary = '--' + boundary
    token = '\r\n' + hyphen_boundary
    body = token.join([f.dump() for f in form])
    return hyphen_boundary + body + token + '--'
    #return token + body + token + '--'


@pytest.fixture
def form() -> List[Field]:
    fields = [
        Field(name=f, value=f'{f}-value')
        for f in 'foo bar baz'.split()
    ]
    fields.append(
        Field(name='some-file', value='file content', filename='some-file.jpg', ctype='image/jpeg')
    )
    return fields


@pytest.fixture
def boundary() -> str:
    return '--qqaassqqasas'


@pytest.fixture
def body(form, boundary) -> BytesIO:
    frm = make_body(form, boundary)
    return BytesIO(frm.encode())


@pytest.fixture
def chunks(body: BytesIO) -> List[bytes]:
    body = body.getvalue()
    print(body)
    chunked = []
    prt_len = 1000
    i = 0
    while True:
        prt = body[i: i + prt_len]
        i = i + prt_len
        prt_len += 1
        if not prt:
            break
        chunked.append(prt)
    return chunked


@pytest.fixture
def markup(chunks, boundary) -> MultipartMarkup:
    m = MultipartMarkup(boundary)
    for ch in chunks:
        m.parse(ch)
    print('chunks number:', len(chunks))
    return m


@pytest.fixture
def field_store(body: BytesIO, markup: MultipartMarkup) -> Iterable[FieldStorage]:
    return FieldStorage.iter_items(body, markup.markups, max_read=10000)


@pytest.fixture
def bytes_proxy() -> BytesIOProxy:
    proxied_bytes_1 = b'some \n'
    proxied_bytes_2 = b'bytes'
    proxied_bytes = proxied_bytes_1 + proxied_bytes_2
    start = 3
    end = start + len(proxied_bytes)
    src_body = (b' ' * start) + proxied_bytes + (b' ' * 5)
    bytes_src = BytesIO(src_body)
    bytes_proxy = BytesIOProxy(bytes_src, start, end)
    return bytes_proxy


def test_markup(markup: MultipartMarkup):
    print('error', markup.error)
    assert len(markup.markups) > 0
    print(markup.markups)


def test_read_multipart(field_store: Iterable[FieldStorage], form: List[Field]):
    fields_num = len(form)
    iter_form = iter(form)
    i = 0
    for i, f in enumerate(field_store, 1):
        src, parsed = next(iter_form), f
        assert src.name == parsed.name
        print(src.name, src.value, src.ctype)
        if src.filename:
            assert src.value == parsed.file.read().decode()
            assert src.ctype == parsed.ctype
        else:
            assert src.value == parsed.value
    assert fields_num == i


def test_bytes_io_proxy():
    proxied_bytes_1 = b'some '
    proxied_bytes_2 = b'bytes'
    proxied_bytes = proxied_bytes_1 + proxied_bytes_2
    start = 3
    end = start + len(proxied_bytes)
    src_body = (b' ' * start) + proxied_bytes + (b' ' * 5)
    bytes_src = BytesIO(src_body)
    bytes_proxy = BytesIOProxy(bytes_src, start, end)

    assert bytes_proxy.read() == proxied_bytes
    bytes_proxy.seek(0)
    assert bytes_proxy.read(100) == proxied_bytes

    bytes_proxy.seek(len(proxied_bytes_1))
    assert bytes_proxy.read(len(proxied_bytes_2)) == proxied_bytes_2

    bytes_proxy.seek(0)
    bytes_proxy.read(len(proxied_bytes_1) - 1)
    bytes_proxy.seek(1, SEEK_CUR)
    assert bytes_proxy.read() == proxied_bytes_2

    bytes_proxy.seek(100)
    assert bytes_proxy.tell() == len(proxied_bytes)
    bytes_proxy.seek(-len(proxied_bytes_2), SEEK_END)
    assert bytes_proxy.read() == proxied_bytes_2


def test_bytes_io_proxy_shutil(bytes_proxy: BytesIOProxy):
    import shutil
    import tempfile
    proxied_bytes = bytes_proxy.read()
    assert proxied_bytes
    bytes_proxy.seek(0)
    try:
        dst = tempfile.NamedTemporaryFile(delete=False)
        shutil.copyfileobj(bytes_proxy, dst)
        dst.close()
        with open(dst.name, 'rb') as dst:
            assert dst.read() == proxied_bytes
    finally:
        import os
        os.unlink(dst.name)


def test_bytes_io_proxy_text_wrapper(bytes_proxy: BytesIOProxy):
    proxied_bytes = bytes_proxy.read()
    assert proxied_bytes
    bytes_proxy.seek(0)
    with TextIOWrapper(bytes_proxy, encoding='utf8') as txt:
        assert txt.read() == proxied_bytes.decode()

    bytes_proxy.seek(0)
    with TextIOWrapper(bytes_proxy, encoding='utf8', newline='') as txt:
        ln = txt.readline()
        assert ln.rstrip('\n') == proxied_bytes.decode().split('\n', 1)[0]

    bytes_proxy.seek(0)
    with TextIOWrapper(bytes_proxy, encoding='utf8', newline='') as txt:
        lns = [it.rstrip('\n') for it in txt.readlines()]
        assert lns == proxied_bytes.decode().split('\n')
        print(proxied_bytes.decode().split('\n'))
