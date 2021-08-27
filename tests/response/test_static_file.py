
import os
import pytest
import  ombott
from ombott import static_file, _Globals
from ombott.static_stream import get_first_range
import wsgiref.util


basename = os.path.basename(__file__)
root = os.path.dirname(__file__)

basename2 = os.path.basename(ombott.__file__)
root2 = os.path.dirname(ombott.__file__)


@pytest.fixture(scope='class')
def env_fix():
    return { }


@pytest.fixture
def wsgi_env(env_fix):
    env_ = {}
    wsgiref.util.setup_testing_defaults(env_)
    env_.update(env_fix)
    return env_


@pytest.fixture
def ombott_app(wsgi_env):
    orig_req = _Globals.request
    app = ombott.Ombott()
    app.request.__init__(wsgi_env)
    app.response.__init__()
    _Globals.request = app.request
    yield app
    _Globals.request = orig_req


class TestStaticFile:
    def test_valid(self, ombott_app):
        """ SendFile: Valid requests"""
        out = static_file(basename, root=root)
        assert open(__file__,'rb').read() == out.body.read()

    @pytest.mark.parametrize(
        'path, root, status',
        [
            ['not/a/file', root, 404],
            [os.path.join('./../', basename),'./views/', 403],
        ]
    )
    def test_invalid(self, ombott_app, path, root, status):
        """ SendFile: Invalid requests"""
        assert static_file(path, root=root).status_code == status

    @pytest.mark.parametrize(
        'mimetype, charset, expect_ctype',
        [
            (None, None, ('application/x-python-code', 'text/x-python')),
            ('some/type', None, 'some/type'),
            ('text/foo', None, 'text/foo; charset=UTF-8'),
            ('text/foo', 'latin1', 'text/foo; charset=latin1'),

        ]
    )
    def test_mime(self, mimetype, charset, expect_ctype):
        """ SendFile: Mime Guessing"""

        if not mimetype:
            f = static_file(basename, root=root)
            assert f.headers['Content-Type'].split(';')[0] in expect_ctype
            return

        kw = dict(mimetype=mimetype)
        if charset:
            kw['charset'] = charset
        f = static_file(basename, root=root, **kw)
        assert f.headers['Content-Type'] == expect_ctype

    def test_disposition(self):
        f = static_file(basename, root=root, download=True)
        assert f'attachment; filename="{basename}"' == f.headers['Content-Disposition']

    def test_range(self, ombott_app):
        ombott_app.request.environ['HTTP_RANGE'] = 'bytes=10-25,-80'
        f = static_file(basename, root)
        with open(__file__, 'rb') as c:
            c.seek(10)
            assert c.read(16) == b''.join(f.body)
            c.seek(0)
            assert (
                'bytes 10-25/%d' % len(c.read()) == f.headers['Content-Range']
            )
        assert 'bytes' == f.headers['Accept-Ranges']

    def test_range_parser(self):
        r = lambda rs: get_first_range(rs, 100)
        assert (90, 100) == r('bytes=-10')
        assert (10, 100) == r('bytes=10-')
        assert (5, 11) ==  r('bytes=5-10')
