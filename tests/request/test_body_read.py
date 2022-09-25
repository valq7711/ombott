import pytest
from io import BytesIO
from ombott.request_pkg.body_mixin import _body_read, _iter_chunked
from ombott.request_pkg.errors import BodyParsingError, BodySizeError



@pytest.fixture
def body_len():
    bs = 'some body asdfdf fdfdf fdf '.encode('utf8')
    ret = BytesIO(bs)
    return ret, len(bs)

@pytest.fixture
def chunks(body_len):
    body, clen = body_len
    bs = body.getvalue()
    chunked = []
    s = 0
    for k in [3, 5, 10, clen]:
        ch = bs[s:k]
        chunked.append(ch)
        s = k
    return chunked


@pytest.fixture
def body_chunked(chunks, request):
    extra_info = request.param
    ch = [ b'%x%b\r\n%b\r\n' % (len(ch), extra_info, ch) for ch in chunks]
    ch.append(b'0\r\n')
    ret = BytesIO(b''.join(ch))
    print(ret.getvalue())
    print(ret.getvalue().decode())
    ret.seek(0)
    return ret


def test_body_read(body_len):
    body, clen = body_len
    res = _body_read(body.read, 4, content_length=clen)
    res.seek(0)
    assert body.getvalue() == res.read()


@pytest.mark.parametrize(
    'body_chunked, buff_size',
    [
        (b'', 4),
        (b';ab\n\r;\rd\nd = fgh', 25),
    ],
    indirect = ['body_chunked']
)
def test_body_read_chunked(body_len, body_chunked, buff_size):
    body, clen = body_len
    res = _body_read(body_chunked.read, buff_size, chunked=True)
    res.seek(0)
    assert body.getvalue() == res.read()

def test_body_read_chunked_error(body_len):
    body, clen = body_len
    with pytest.raises(BodyParsingError):
        _body_read(body.read, 10, content_length=clen, chunked=True)

def test_body_read_size_error(body_len):
    body, clen = body_len
    with pytest.raises(BodySizeError):
        _body_read(body.read, 10, content_length=clen, max_body_size=5)


