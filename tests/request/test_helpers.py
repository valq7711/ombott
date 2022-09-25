import pytest
from ombott.request.helpers import FormsDict, CookieDict


def test_formsdict():
    src = dict(
        foo='foo',
        bar='бар',
        баз='баз',
    )
    fdict = FormsDict(src)
    assert fdict['foo'] == 'foo'
    assert fdict.foo == 'foo'
    assert fdict.bar == 'бар'
    assert fdict.get('баз') == 'баз'
    assert fdict.unknown_key == ''

    cpy = fdict.copy()

    assert cpy == fdict
    assert cpy.foo == 'foo'
    assert cpy.unknown_key == ''

    with pytest.raises(KeyError) as exc_info:
        fdict['blah']
    assert 'blah' in str(exc_info.value)


def test_cookiedict():
    src = dict(
        foo='foo',
        bar='бар',
        баз='баз',
    )

    src_latin1 = {k.encode().decode('latin1'): v.encode().decode('latin1') for k, v in src.items()}

    cd = CookieDict({**src_latin1})
    assert cd == src_latin1
    assert cd.foo == src['foo']
    assert cd.getunicode('bar') == src['bar']
    assert cd.getunicode('bar', 'cp1251') == 'бар'.encode('cp1251').decode('cp1251')

    cpy = cd.decode()

    assert cpy == src
    assert cpy.decode() == src
    assert cpy.decode('utf8') == src

    # trying to decode already decoded using another encoding
    with pytest.raises(TypeError) as exc_info:
        cpy.decode('cp1251')
    assert 'cp1251' in str(exc_info.value)
    assert 'utf8' in str(exc_info.value)
