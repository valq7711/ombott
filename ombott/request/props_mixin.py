import base64
import cgi
from functools import partial
from http.cookies import SimpleCookie
from urllib.parse import (
    quote as urlquote,
    unquote as urlunquote,
    urljoin,
    SplitResult as UrlSplitResult
)

from ..common_helpers import (
    touni, tob,
    cookie_decode,
)
from .helpers import (
    cache_in,
    FormsDict,
    WSGIHeaderDict,
)


urlunquote = partial(urlunquote, encoding='latin1')


def cgi_monkey_patch():
    """Fix bug cgi.FieldStorage context manager bug https://github.com/python/cpython/pull/14815

    """
    def patch_exit(self, *exc):
        if self.file is not None:
            self.file.close()
    cgi.FieldStorage.__exit__ = patch_exit


cgi_monkey_patch()


class PropsMixin:

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
        return '/' + self._env_get('PATH_INFO', '').lstrip('/')

    @property
    def method(self):
        ''' The ``REQUEST_METHOD`` value as an uppercase string. '''
        return self._env_get('REQUEST_METHOD', 'GET').upper()

    @cache_in('environ[ ombott.request.headers ]', read_only=True)
    def headers(self):
        ''' A :class:`WSGIHeaderDict` that provides case-insensitive access to
            HTTP request headers. '''
        return WSGIHeaderDict(self.environ)

    @cache_in('environ[ ombott.request.cookies ]', read_only=True)
    def cookies(self):
        """ Cookies parsed into a :class:`FormsDict`. Signed cookies are NOT
            decoded. Use :meth:`get_cookie` if you expect signed cookies. """
        cookies = SimpleCookie(self._env_get('HTTP_COOKIE', '')).values()
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

    @cache_in('environ[ ombott.request.params ]', read_only=True)
    def params(self):
        """ A :class:`FormsDict` with the combined values of :attr:`query` and
            :attr:`forms`. File uploads are stored in :attr:`files`. """
        return self._forms_factory(self.query, **self.forms)  # FormsDict(self.query, **self.forms)

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
        env_get = self._env_get
        http = env_get('HTTP_X_FORWARDED_PROTO') or env_get('wsgi.url_scheme', 'http')
        host = env_get('HTTP_X_FORWARDED_HOST') or env_get('HTTP_HOST')
        if not host:
            # HTTP 1.1 requires a Host-header. This is for HTTP/1.0 clients.
            host = env_get('SERVER_NAME', '127.0.0.1')
            port = env_get('SERVER_PORT')
            if port and port != ('80' if http == 'http' else '443'):
                host += ':' + port
        path = urlquote(self.fullpath)
        return UrlSplitResult(http, host, path, env_get('QUERY_STRING'), '')

    @cache_in('environ[ ombott.request.fullpath ]', read_only=True)
    def fullpath(self):
        """ Request path including :attr:`script_name` (if present). """
        appname = self._env_get(self.config.app_name_header, '/')
        return urljoin(self.script_name, self.path[len(appname):].lstrip('/'))

    @property
    def query_string(self):
        """ The raw :attr:`query` part of the URL (everything in between ``?``
            and ``#``) as a string. """
        return self._env_get('QUERY_STRING', '')

    @cache_in('environ[ ombott.request.script_name ]', read_only=True)
    def script_name(self):
        ''' The initial portion of the URL's `path` that was removed by a higher
            level (server or routing middleware) before the application was
            called. This script path is returned with leading and tailing
            slashes. '''
        env_get = self._env_get
        script_name = env_get('SCRIPT_NAME')
        if not script_name and self.config.allow_x_script_name:
            script_name = env_get('HTTP_X_SCRIPT_NAME')
        return '/' + script_name.strip('/') + '/' if script_name else '/'

    @property
    def is_xhr(self):
        ''' True if the request was triggered by a XMLHttpRequest. This only
            works with JavaScript libraries that support the `X-Requested-With`
            header (most of the popular libraries do). '''
        requested_with = self._env_get('HTTP_X_REQUESTED_WITH', '')
        return requested_with.lower() == 'xmlhttprequest'

    @property
    def is_ajax(self):
        ''' Alias for :attr:`is_xhr`. "Ajax" is not the right term. '''
        return self.is_xhr

    @cache_in('environ[ ombott.request.is_json_requested ]', read_only=True)
    def is_json_requested(self):
        accept = self._env_get('HTTP_ACCEPT')
        if accept:
            return accept.startswith('application/json')

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

        basic = parse_auth(self._env_get('HTTP_AUTHORIZATION', ''))
        if basic:
            return basic
        ruser = self._env_get('REMOTE_USER')
        if ruser:
            return (ruser, None)
        return None

    @cache_in('environ[ ombott.request.remote_route ]', read_only=True)
    def remote_route(self):
        """ A list of all IPs that were involved in this request, starting with
            the client IP and followed by zero or more proxies. This does only
            work if all proxies support the ```X-Forwarded-For`` header. Note
            that this information can be forged by malicious clients. """
        proxy = self._env_get('HTTP_X_FORWARDED_FOR')
        if proxy:
            return [ip.strip() for ip in proxy.split(',')]
        remote = self._env_get('REMOTE_ADDR')
        return [remote] if remote else []

    @property
    def remote_addr(self):
        """ The client IP as a string. Note that this information can be forged
            by malicious clients. """
        route = self.remote_route
        return route[0] if route else None
