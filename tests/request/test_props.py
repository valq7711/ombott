
import pytest
from  ombott.request import Request
import wsgiref.util


attr_expected = {
    'method': 'GET',
    'path': '/a/bb/ccc',
    'query_string': 'a=2&b=c&c=44',
    'script_name': '/scrpt_name/',
    'fullpath': '/scrpt_name/a/bb/ccc',
    'query': dict(a='2', b='c', c='44'),
    'params': dict(a='2', b='c', c='44'),
    'content_type': 'text/html',
    'content_length': 10,
    'url': 'http://exam.com/scrpt_name/a/bb/ccc?a=2&b=c&c=44',
    'url_args': dict(arg='ccc')
}

header_expect = {
    'Some-Header': 'some_header',
}

@pytest.fixture
def env_fix(request):
    upd = getattr(request, 'param', {})
    ret = {
        'SCRIPT_NAME': 'scrpt_name',
        'REQUEST_METHOD': 'GET',
        'PATH_INFO': '/a/bb/ccc',
        'QUERY_STRING': 'a=2&b=c&c=44',
        'CONTENT_TYPE': 'text/html',
        'CONTENT_LENGTH': 10,
        'HTTP_SOME_HEADER': 'some_header',
        'HTTP_HOST': 'exam.com',
        'route.url_args': dict(arg='ccc')
    }
    ret.update(upd)
    return ret

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
def ombott_request(wsgi_env_cpy, request):
    config = getattr(request, 'param', None)
    req = Request(config=config)
    req.__init__(wsgi_env_cpy)
    return req


@pytest.mark.parametrize(
    'req_attr, expect',
    attr_expected.items()
)
def test_props(ombott_request: Request, wsgi_env, wsgi_env_cpy, req_attr, expect):
    print(wsgi_env.keys())
    assert getattr(ombott_request, req_attr) == expect


@pytest.mark.parametrize(
    'req_attr, expect',
    header_expect.items()
)
def test_headers(ombott_request: Request, wsgi_env, wsgi_env_cpy, req_attr, expect):
    print(wsgi_env.keys())
    assert ombott_request.headers[req_attr] == expect


@pytest.mark.parametrize(
    'ombott_request, env_fix, expect_fullpath',
    [(
        {'app_name_header': 'HTTP_X_APP_NAME'},
        {
            'PATH_INFO': '/some_app/a/bb/ccc',
            'HTTP_X_APP_NAME': '/some_app'
        },
        '/scrpt_name/a/bb/ccc'
    )],
    indirect=['ombott_request', 'env_fix']
)
def test_app_name_header(ombott_request: Request, expect_fullpath):
    assert ombott_request.fullpath == expect_fullpath
