from typing import Union
import pytest
from ombott.request_pkg import Request
from ombott.request_pkg.request import RequestConfig
from ombott.request_pkg.errors import JSONParsingError
import json
import io


class MappedError(Exception):
    pass


@pytest.fixture
def env(request):
    jsn: Union[str, dict, list] = request.param
    if not isinstance(jsn, str):
        jsn = json.dumps(jsn)
    jsn = jsn.encode()
    buf = io.BytesIO(jsn)
    buf.seek(0)
    e = {
        'PATH_INFO': '/t1',
        'CONTENT_TYPE': 'application/json; blah',
        'wsgi.input': buf,
        'CONTENT_LENGTH': len(jsn)
    }
    return e


@pytest.fixture
def ombott_request():
    return Request(config=RequestConfig(errors_map={JSONParsingError: MappedError()}))


@pytest.fixture
def request_obj(ombott_request: Request, env):
    ombott_request.__init__(env)
    return ombott_request


@pytest.mark.parametrize(
    'env, err',
    [
        (dict(foo='bar'), False),
        ([1, 'foo', 'bar'], False),
        ("", False),
        ("{bad-json", True),
    ],
    indirect=['env']
)
def test_body_json(request_obj: Request, err):
    if err:
        with pytest.raises(MappedError):
            request_obj.json
        with pytest.raises(MappedError):
            request_obj.forms
        with pytest.raises(MappedError):
            request_obj.POST
    else:
        jsn = request_obj.json
        print()
        print(jsn)
        print(request_obj.forms)


if __name__ == '__main__':
    pytest.main([
        '-o', 'log_cli=true', '-o', 'log_cli_level=INFO',
        '-s', '-vvv', '-k', 'body_json', __file__
    ])
