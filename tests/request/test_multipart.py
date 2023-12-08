from typing import Iterable
import pytest
from io import BytesIO
from ombott.request_pkg.multipart import MultipartMarkup, FieldStorage


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


def make_body(form: list[Field], boundary: str) -> str:
    hyphen_boundary = '--' + boundary
    token = '\r\n' + hyphen_boundary
    body = token.join([f.dump() for f in form])
    return hyphen_boundary + body + token + '--'
    #return token + body + token + '--'


@pytest.fixture
def form() -> list[Field]:
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
def chunks(body: BytesIO) -> list[bytes]:
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


def test_markup(markup: MultipartMarkup):
    print('error', markup.error)
    assert len(markup.markups) > 0
    print(markup.markups)


def test_read_multipart(field_store: Iterable[FieldStorage], form: list[Field]):
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
