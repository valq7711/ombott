import cgi
import json as json_mod
from urllib.parse import urljoin, SplitResult as UrlSplitResult
from urllib.parse import quote as urlquote
import base64

from .request import cache_in, _parse_qsl
from http.cookies import SimpleCookie
from .helpers import (
    touni, tob,
    cookie_decode,
    WSGIHeaderDict, FormsDict,
    FileUpload
)


# fix bug cgi.FieldStorage context manager bug https://github.com/python/cpython/pull/14815
def cgi_monkey_patch():
    def patch_exit(self, *exc):
        if self.file is not None:
            self.file.close()
    cgi.FieldStorage.__exit__ = patch_exit
cgi_monkey_patch()


def on_env_changed(request, key, v):
    todelete = ()
    if key == 'wsgi.input':
        todelete = ('forms', 'files', 'params', 'post', 'json')
    elif key == 'QUERY_STRING':
        todelete = ('query', 'params')
    elif key.startswith('HTTP_'):
        todelete = ('headers', 'cookies')
    for key in todelete:
        request.environ.pop('ombott.request.' + key, None)


def mixin():

    def __new__(self, *a, **kw):
        self.on('env_changed', on_env_changed)

    @cache_in('environ[ ombott.app ]', read_only=True)
    def app(self):
        raise RuntimeError('This request is not connected to an application.')

    @cache_in('environ[ ombott.route ]', read_only=True)
    def route(self):
        """ The ombott :class:`Route` object that matches this request. """
        raise RuntimeError('This request is not connected to a route.')

    @cache_in('environ[ route.url_args ]', read_only=True)
    def url_args(self):
        """ The arguments extracted from the URL. """
        raise RuntimeError('This request is not connected to a route.')

    @property
    def path(self):
        ''' The value of ``PATH_INFO`` with exactly one prefixed slash (to fix
            broken clients and avoid the "empty path" edge case). '''
        return '/' + self.environ.get('PATH_INFO', '').lstrip('/')

    @property
    def method(self):
        ''' The ``REQUEST_METHOD`` value as an uppercase string. '''
        return self.environ.get('REQUEST_METHOD', 'GET').upper()

    @cache_in('environ[ ombott.request.headers ]', read_only=True)
    def headers(self):
        ''' A :class:`WSGIHeaderDict` that provides case-insensitive access to
            HTTP request headers. '''
        return WSGIHeaderDict(self.environ)

    @cache_in('environ[ ombott.request.cookies ]', read_only=True)
    def cookies(self):
        """ Cookies parsed into a :class:`FormsDict`. Signed cookies are NOT
            decoded. Use :meth:`get_cookie` if you expect signed cookies. """
        cookies = SimpleCookie(self.environ.get('HTTP_COOKIE', '')).values()
        return FormsDict((c.key, c.value) for c in cookies)

    def get_cookie(self, key, default=None, secret=None):
        """ Return the content of a cookie. To read a `Signed Cookie`, the
            `secret` must match the one used to create the cookie (see
            :meth:`BaseResponse.set_cookie`). If anything goes wrong (missing
            cookie or wrong signature), return a default value. """
        value = self.cookies.get(key)
        if secret and value:
            dec = cookie_decode(value, secret)  # (key, value) tuple or None
            return dec[1] if dec and dec[0] == key else default
        return value or default

    @cache_in('environ[ ombott.request.query ]', read_only=True)
    def query(self):
        ''' The :attr:`query_string` parsed into a :class:`FormsDict`. These
            values are sometimes called "URL arguments" or "GET parameters", but
            not to be confused with "URL wildcards" as they are provided by the
            :class:`Router`. '''
        env = self.environ
        ret = FormsDict()
        if (qs := env.get('QUERY_STRING', '')):
            _parse_qsl(qs, setitem = ret.__setitem__)
        env['ombott.get'] = ret
        return ret

    @cache_in('environ[ ombott.request.forms ]', read_only=True)
    def forms(self):
        """ Form values parsed from an `url-encoded` or `multipart/form-data`
            encoded POST or PUT request body. The result is returned as a
            :class:`FormsDict`. All keys and values are strings. File uploads
            are stored separately in :attr:`files`. """
        if self.POST is None:
            return None
        forms = FormsDict()
        for name, item in self.POST.items():
            if not isinstance(item, FileUpload):
                forms[name] = item
        return forms

    @cache_in('environ[ ombott.request.params ]', read_only=True)
    def params(self):
        """ A :class:`FormsDict` with the combined values of :attr:`query` and
            :attr:`forms`. File uploads are stored in :attr:`files`. """
        params = FormsDict()
        params.update(self.query)
        params.update(self.forms)
        return params

    @cache_in('environ[ ombott.request.files ]', read_only=True)
    def files(self):
        """ File uploads parsed from `multipart/form-data` encoded POST or PUT
            request body. The values are instances of :class:`FileUpload`.

        """
        files = FormsDict()
        for name, item in self.POST.items():
            if isinstance(item, FileUpload):
                files[name] = item
        return files

    @cache_in('environ[ ombott.request.ctype ]', read_only=True)
    def ctype(self):
        ctype = self.environ.get('CONTENT_TYPE', '').lower().split(';')
        return [t.strip() for t in ctype]

    @cache_in('environ[ ombott.request.json ]', read_only=True)
    def json(self):
        ''' If the ``Content-Type`` header is ``application/json``, this
            property holds the parsed content of the request body. Only requests
            smaller than :attr:`MEMFILE_MAX` are processed to avoid memory
            exhaustion. '''
        if self.ctype[0] == 'application/json':
            b = self._get_body_string()
            if not b:
                return None
            return json_mod.loads(b)
        return None

    @property
    def body(self):
        (ret := self._body).seek(0)
        return ret

    @property
    def chunked(self):
        ''' True if Chunked transfer encoding was. '''
        return 'chunked' in self.environ.get('HTTP_TRANSFER_ENCODING', '').lower()

    #: An alias for :attr:`query`.
    GET = query

    @cache_in('environ[ ombott.request.post ]', read_only=True)
    def POST(self):
        """ The values of :attr:`forms` and :attr:`files` combined into a single
            :class:`FormsDict`. Values are either strings (form values) or
            instances of :class:`cgi.FieldStorage` (file uploads).
        """
        post = FormsDict()
        # We default to application/x-www-form-urlencoded for everything that
        # is not multipart and take the fast path
        ctype = self.content_type
        if not ctype.startswith('multipart/'):
            if ctype.startswith('application/json'):
                return self.json
            else:
                _parse_qsl(touni(self._get_body_string(), 'latin1'), setitem = post.__setitem__)
            return post

        env = self.environ

        safe_env = {'QUERY_STRING': ''}  # Build a safe environment for cgi
        for key in ('REQUEST_METHOD', 'CONTENT_TYPE', 'CONTENT_LENGTH'):
            if key in env: safe_env[key] = env[key]
        args = dict(
            fp= self.body, environ= safe_env, keep_blank_values= True,
            encoding = 'utf8'
        )
        with cgi.FieldStorage(**args) as data:
            self['_cgi.FieldStorage'] = data  # http://bugs.python.org/issue18394#msg207958
            data = data.list or []
            for item in data:
                if item.filename:
                    post[item.name] = FileUpload(
                        item.file, item.name,
                        item.filename, item.headers
                    )
                else:
                    post[item.name] = item.value
        return post

    @cache_in('environ[ ombott.request.url ]', read_only=True)
    def url(self):
        """ The full request URI including hostname and scheme. If your app
            lives behind a reverse proxy or load balancer and you get confusing
            results, make sure that the ``X-Forwarded-Host`` header is set
            correctly. """
        return self.urlparts.geturl()

    @cache_in('environ[ ombott.request.urlparts ]', read_only=True)
    def urlparts(self):
        ''' The :attr:`url` string as an :class:`urlparse.SplitResult` tuple.
            The tuple contains (scheme, host, path, query_string and fragment),
            but the fragment is always empty because it is not visible to the
            server. '''
        env = self.environ
        http = env.get('HTTP_X_FORWARDED_PROTO') or env.get('wsgi.url_scheme', 'http')
        host = env.get('HTTP_X_FORWARDED_HOST') or env.get('HTTP_HOST')
        if not host:
            # HTTP 1.1 requires a Host-header. This is for HTTP/1.0 clients.
            host = env.get('SERVER_NAME', '127.0.0.1')
            port = env.get('SERVER_PORT')
            if port and port != ('80' if http == 'http' else '443'):
                host += ':' + port
        path = urlquote(self.fullpath)
        return UrlSplitResult(http, host, path, env.get('QUERY_STRING'), '')

    @cache_in('environ[ ombott.request.fullpath ]', read_only=True)
    def fullpath(self):
        """ Request path including :attr:`script_name` (if present). """
        appname = self.environ.get('HTTP_X_PY4WEB_APPNAME', '/')
        return urljoin(self.script_name, self.path[len(appname):])

    @property
    def query_string(self):
        """ The raw :attr:`query` part of the URL (everything in between ``?``
            and ``#``) as a string. """
        return self.environ.get('QUERY_STRING', '')

    @cache_in('environ[ ombott.request.script_name ]', read_only=True)
    def script_name(self):
        ''' The initial portion of the URL's `path` that was removed by a higher
            level (server or routing middleware) before the application was
            called. This script path is returned with leading and tailing
            slashes. '''
        env_get = self.environ.get
        script_name = env_get('SCRIPT_NAME', env_get('HTTP_X_SCRIPT_NAME', '')).strip('/')
        return '/' + script_name + '/' if script_name else '/'

    @cache_in('environ[ ombott.request.content_length ]', read_only=True)
    def content_length(self):
        ''' The request body length as an integer. The client is responsible to
            set this header. Otherwise, the real length of the body is unknown
            and -1 is returned. In this case, :attr:`body` will be empty. '''
        return int(self.environ.get('CONTENT_LENGTH') or -1)

    @cache_in('environ[ ombott.request.content_type ]', read_only=True)
    def content_type(self):
        ''' The Content-Type header as a lowercase-string (default: empty). '''
        return self.environ.get('CONTENT_TYPE', '').lower()

    @property
    def is_xhr(self):
        ''' True if the request was triggered by a XMLHttpRequest. This only
            works with JavaScript libraries that support the `X-Requested-With`
            header (most of the popular libraries do). '''
        requested_with = self.environ.get('HTTP_X_REQUESTED_WITH', '')
        return requested_with.lower() == 'xmlhttprequest'

    @property
    def is_ajax(self):
        ''' Alias for :attr:`is_xhr`. "Ajax" is not the right term. '''
        return self.is_xhr

    @property
    def auth(self):
        """ HTTP authentication data as a (user, password) tuple. This
            implementation currently supports basic (not digest) authentication
            only. If the authentication happened at a higher level (e.g. in the
            front web-server or a middleware), the password field is None, but
            the user field is looked up from the ``REMOTE_USER`` environ
            variable. On any errors, None is returned. """

        def parse_auth(header):
            """ Parse rfc2617 HTTP authentication header string (basic) and return (user,pass) tuple or None"""
            try:
                method, data = header.split(None, 1)
                if method.lower() == 'basic':
                    user, pwd = touni(base64.b64decode(tob(data))).split(':', 1)
                    return user, pwd
            except (KeyError, ValueError):
                return None

        basic = parse_auth(self.environ.get('HTTP_AUTHORIZATION', ''))
        if basic: return basic
        ruser = self.environ.get('REMOTE_USER')
        if ruser: return (ruser, None)
        return None

    @cache_in('environ[ ombott.request.remote_route ]', read_only=True)
    def remote_route(self):
        """ A list of all IPs that were involved in this request, starting with
            the client IP and followed by zero or more proxies. This does only
            work if all proxies support the ```X-Forwarded-For`` header. Note
            that this information can be forged by malicious clients. """
        proxy = self.environ.get('HTTP_X_FORWARDED_FOR')
        if proxy: return [ip.strip() for ip in proxy.split(',')]
        remote = self.environ.get('REMOTE_ADDR')
        return [remote] if remote else []

    @property
    def remote_addr(self):
        """ The client IP as a string. Note that this information can be forged
            by malicious clients. """
        route = self.remote_route
        return route[0] if route else None

    return dict(locals())
