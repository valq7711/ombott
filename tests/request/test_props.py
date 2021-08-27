
import pytest
import  ombott
from  ombott.request import Request
import wsgiref.util



attr_expected = {
    'method': 'GET',
    'path': '/a/bb/ccc',
    'query_string': 'a=2&b=c&c=44',
    'script_name': '/scrt_name/',
    'fullpath': '/scrt_name/a/bb/ccc',
    'query': dict(a='2', b='c', c='44'),
    'params': dict(a='2', b='c', c='44'),
    'content_type': 'text/html',
    'content_length': 10,
    'url': 'http://exam.com/scrt_name/a/bb/ccc?a=2&b=c&c=44',
    'url_args': dict(arg='ccc')
}

header_expect = {
    'Some-Header': 'some_header',
}

@pytest.fixture
def env_fix():
    return {
        'SCRIPT_NAME': 'scrt_name',
        'REQUEST_METHOD': 'GET',
        'PATH_INFO': '/a/bb/ccc',
        'QUERY_STRING': 'a=2&b=c&c=44',
        'CONTENT_TYPE': 'text/html',
        'CONTENT_LENGTH': 10,
        'HTTP_SOME_HEADER': 'some_header',
        'HTTP_HOST': 'exam.com',
        'route.url_args': dict(arg='ccc')
    }

@pytest.fixture
def wsgi_env(env_fix):
    env_ = {}
    wsgiref.util.setup_testing_defaults(env_)
    env_.update(env_fix)
    return env_

@pytest.fixture
def wsgi_env_cpy(wsgi_env):
    return wsgi_env.copy()

@pytest.fixture
def ombott_requset(wsgi_env_cpy):
    ombott.request.__init__(wsgi_env_cpy)
    return ombott.request


@pytest.mark.parametrize(
    'req_attr, expect',
    attr_expected.items()
)
def test_props(ombott_requset: Request, wsgi_env, wsgi_env_cpy, req_attr, expect):
    print(wsgi_env.keys())
    assert getattr(ombott_requset, req_attr) == expect


@pytest.mark.parametrize(
    'req_attr, expect',
    header_expect.items()
)
def test_headers(ombott_requset: Request, wsgi_env, wsgi_env_cpy, req_attr, expect):
    print(wsgi_env.keys())
    assert ombott_requset.headers[req_attr] == expect