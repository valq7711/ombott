import os
import sys
import json
import functools
from traceback import format_exc
import mimetypes
import time
import itertools
from urllib.parse import urljoin

from .helpers import (
    cached_property, WSGIFileWrapper, parse_range_header,
    parse_date, html_escape, tob
)
from .radirouter import RadiRouter
from .request import Request, BaseRequest
from . import request_mixin
from .response import Response, HTTPResponse, HTTPError
from . import server_adapters

__version__ = "0.0.1"

HTTP_METHODS = 'DELETE GET HEAD OPTIONS PATCH POST PUT'.split()

Request.mixin(request_mixin.mixin())


class Config:
    __slots__ = 'domain_map'


config = Config()


class _closeiter:
    ''' This only exists to be able to attach a .close method to iterators that
        do not support attribute assignment (most of itertools). '''

    def __init__(self, iterator, close=None):
        self.iterator = iterator
        self.close_callbacks = close if isinstance(close, (list, tuple)) else [close]

    def __iter__(self):
        return iter(self.iterator)

    def close(self):
        [cb() for cb in self.close_callbacks]


def run(app=None, server='wsgiref', host='127.0.0.1', port=8080,
        quiet=False, **kargs):
    _stderr = sys.stderr.write
    try:
        app = app or default_app()
        if not callable(app):
            raise ValueError("Application is not callable: %r" % app)
        server_names = server_adapters.server_names
        if server in server_names:
            server = server_names.get(server)
        server = server(host=host, port=port, **kargs)
        server.quiet = server.quiet or quiet
        if not server.quiet:
            _stderr("Ombott v%s server starting up (using %s)...\n" % (__version__, repr(server)))
            _stderr("Listening on http://%s:%d/\n" % (server.host, server.port))
            _stderr("Hit Ctrl-C to quit.\n\n")
        server.run(app)
    except KeyboardInterrupt:
        pass
    except (SystemExit, MemoryError):
        raise
    except:
        raise


def with_method_shortcuts(methods):
    def injector(cls):
        for m in methods:
            setattr(cls, m.lower(), functools.partialmethod(cls.route, method = m))
        return cls
    return injector

###############################################################################
# Application Object ###########################################################
###############################################################################


@with_method_shortcuts(HTTP_METHODS)
class Ombott:

    def __init__(self):
        self.router = RadiRouter()
        self.request = Request()
        self.response = Response()
        self._route_hooks = {}
        self.error_handler = {}

    def run(self, **kwargs):
        ''' Calls :func:`run` with the same parameters. '''
        run(self, **kwargs)

    def to_route(self, environ):
        verb = environ['REQUEST_METHOD'].upper()
        path = environ['PATH_INFO'] or '/'

        if verb == 'HEAD':
            methods = [verb, 'GET', 'ANY']
        else:
            methods = [verb, 'ANY']
        tmp, error = self.router.get(path, methods)
        if error:
            raise HTTPError(*error)
        route, names, values, hooks = tmp
        param_values = []
        params = {n: v for n, v in zip(names, values) if n and (param_values.append(v) or True)}
        return route, params, param_values, hooks

    def add_route(self, rule, method, handler, name = None):
        self.router.add(rule, method, handler, name)

    def route(self, rule=None, method='GET', *, callback=None, name=None):
        def decorator(callback):
            self.add_route(rule, method, callback, name)
            return callback
        return decorator(callback) if callback else decorator

    @property
    def routes(self):
        return self.router.routes

    __hook_names = 'before_request', 'after_request', 'app_reset', 'config'
    __hook_reversed = 'after_request'

    @cached_property
    def _hooks(self):
        return dict((name, []) for name in self.__hook_names)

    def add_hook(self, name, func):
        ''' Attach a callback to a hook. Three hooks are currently implemented:

            before_request
                Executed once before each request. The request context is
                available, but no routing has happened yet.
            after_request
                Executed once after each request regardless of its outcome.
        '''
        if name in self.__hook_reversed:
            self._hooks[name].insert(0, func)
        else:
            self._hooks[name].append(func)

    def remove_hook(self, name, func):
        if func in self._hooks[name]:
            self._hooks[name].remove(func)
            return True

    def emit(self, name, *args, **kwargs):
        [hook(*args, **kwargs) for hook in self._hooks[name][:]]

    def on(self, name, func = None):
        if not func:  # used as decorator
            def decorator(func):
                self.add_hook(name, func)
                return func
            return decorator
        else:
            self.add_hook(name, func)

    def add_route_hook(self, route, func = None):
        self.router.add_hook(route, func)
        if not (rhooks := self._route_hooks.get(route)):
            self._route_hooks[route] = [func]
        else:
            rhooks.append(func)

    def remove_route_hook(self, route, func = None):
        self.router.remove_hook(route, func)
        if not (rhooks := self._route_hooks.get(route)):
            return
        else:
            try:
                rhooks.remove(func)
            except ValueError:
                pass

    def on_route(self, route, func = None):
        if not func:  # used as decorator
            def decorator(func):
                self.add_route_hook(route, func)
                return func
            return decorator
        else:
            self.add_route_hook(route, func)

    def error(self, code=500):
        """ Decorator: Register an output handler for a HTTP error code"""
        def wrapper(handler):
            self.error_handler[int(code)] = handler
            return handler
        return wrapper

    def default_error_handler(self, res):
        ret = json.dumps(dict(
            body = res.body,
            exception = repr(res.exception),
            traceback = res.traceback
        ))
        self.response.headers['Content-Type'] = 'application/json'
        return ret

    def _handle(self, environ):
        response = self.response
        request = self.request

        path = environ['ombott.raw_path'] = environ['PATH_INFO']
        try:
            environ['PATH_INFO'] = path.encode('latin1').decode('utf8')
        except UnicodeError:
            return HTTPError(400, 'Invalid path string. Expected UTF-8')
        try:  # init thread
            environ['ombott.app'] = self
            request.__init__(environ)
            response.__init__()
            try:  # routing
                self.emit('before_request')
                route, args, values, route_hooks = self.to_route(environ)
                environ['ombott.route'] = route
                environ['route.url_args'] = args
                environ['route.hooks'] = route_hooks
                return route(**args)
            finally:
                self.emit('after_request')
        except HTTPResponse as resp:
            return resp
        except (KeyboardInterrupt, SystemExit, MemoryError):
            raise
        except Exception as err500:
            # raise
            stacktrace = format_exc()
            environ['wsgi.errors'].write(stacktrace)
            return HTTPError(500, "Internal Server Error", err500, stacktrace)

    def _cast(self, out):
        """ Try to convert the parameter into something WSGI compatible and set
        correct HTTP headers when possible.
        Support: False, str, unicode, dict, HTTPResponse, HTTPError, file-like,
        iterable of strings and iterable of unicodes
        """

        response = self.response
        resp_headers = response.headers
        request = self.request
        loops_cnt = 0
        while True:   # <-------
            loops_cnt += 1
            if loops_cnt > 1000:
                out = HTTPError(500, 'too many iterations')
                out.apply(response)
                out = self.default_error_handler(out)

            # Empty output is done here
            if not out:
                if 'Content-Length' not in resp_headers:
                    resp_headers['Content-Length'] = 0
                return []

            if isinstance(out, str):
                out = out.encode(response.charset)
            # Byte Strings are just returned
            if isinstance(out, bytes):
                if 'Content-Length' not in resp_headers:
                    resp_headers['Content-Length'] = len(out)
                return [out]

            if isinstance(out, HTTPError):
                out.apply(response)
                out = self.error_handler.get(
                    out.status_code,
                    self.default_error_handler
                )(out); continue                         # -----------------^

            if isinstance(out, HTTPResponse):
                out.apply(response)
                out = out.body; continue                 # -----------------^

            # File-like objects.
            if hasattr(out, 'read'):
                if 'wsgi.file_wrapper' in request.environ:
                    return request.environ['wsgi.file_wrapper'](out)
                elif hasattr(out, 'close') or not hasattr(out, '__iter__'):
                    return WSGIFileWrapper(out)

            # Handle Iterables. We peek into them to detect their inner type.
            try:
                iout = iter(out)
                while not (first := next(iout)):
                    pass
            except StopIteration:
                out = ''; continue                               # -----------------^
            except HTTPResponse as rs:
                first = rs
            except (KeyboardInterrupt, SystemExit, MemoryError):
                raise
            except Exception as err500:
                # if not self.catchall: raise
                first = HTTPError(500, 'Unhandled exception', err500, format_exc())

            # These are the inner types allowed in iterator or generator objects.
            if isinstance(first, HTTPResponse):
                out = first; continue                            # -----------------^
            elif isinstance(first, bytes):
                new_iter = itertools.chain([first], iout)
            elif isinstance(first, str):
                encoder = lambda x: x.encode(response.charset)
                new_iter = map(encoder, itertools.chain([first], iout))
            else:
                out = HTTPError(500, f'Unsupported response type: {type(first)}')
                continue                                         # -----------------^
            if hasattr(out, 'close'):
                new_iter = _closeiter(new_iter, out.close)
            return new_iter

    def wsgi(self, environ, start_response):

        if (domain_map := getattr(config, 'domain_map', None)):
            if (app_name := domain_map(environ.get('HTTP_X_FORWARDED_HOST') or environ.get('HTTP_HOST'))):
                environ["HTTP_X_PY4WEB_APPNAME"] = '/' + app_name
                environ["PATH_INFO"] = '/' + app_name + environ["PATH_INFO"]

        response = self.response
        try:
            out = self._cast(self._handle(environ))
            # rfc2616 section 4.3
            if response._status_code in (100, 101, 204, 304) \
            or environ['REQUEST_METHOD'] == 'HEAD':
                if hasattr(out, 'close'):
                    out.close()
                out = []
            start_response(response._status_line, response.headerlist)
            return out
        except (KeyboardInterrupt, SystemExit, MemoryError):
            raise
        except Exception as _e:
            # if not self.catchall: raise
            err = '<h1>Critical error while processing request: %s</h1>' \
                  % html_escape(environ.get('PATH_INFO', '/'))
            if True:  # DEBUG: FIX ME
                err += '<h2>Error:</h2>\n<pre>\n%s\n</pre>\n' \
                       '<h2>Traceback:</h2>\n<pre>\n%s\n</pre>\n' \
                       % (html_escape(repr(_e)), html_escape(format_exc()))
            environ['wsgi.errors'].write(err)
            headers = [('Content-Type', 'text/html; charset=UTF-8')]
            start_response('500 INTERNAL SERVER ERROR', headers, sys.exc_info())
            return [tob(err)]

    def __call__(self, environ, start_response):
        return self.wsgi(environ, start_response)


###############################################################################
# Application Helper ###########################################################
###############################################################################


def abort(code=500, text='Unknown Error.'):
    """ Aborts execution and causes a HTTP error. """
    raise HTTPError(code, text)


def redirect(location, code=None):
    url = location
    """ Aborts execution and causes a 303 or 302 redirect, depending on
        the HTTP protocol version. """
    if not code:
        code = 303 if request.get('SERVER_PROTOCOL') == "HTTP/1.1" else 302
    res = response.copy(cls=HTTPResponse)
    res.status = code
    res.body = ""
    res.set_header('Location', urljoin(request.url, url))
    raise res


def static_file(filename, root, mimetype='auto', download=False, charset='UTF-8'):
    """ Open a file in a safe way and return :exc:`HTTPResponse` with status
        code 200, 305, 403 or 404. The ``Content-Type``, ``Content-Encoding``,
        ``Content-Length`` and ``Last-Modified`` headers are set if possible.
        Special support for ``If-Modified-Since``, ``Range`` and ``HEAD``
        requests.

        :param filename: Name or path of the file to send.
        :param root: Root path for file lookups. Should be an absolute directory
            path.
        :param mimetype: Defines the content-type header (default: guess from
            file extension)
        :param download: If True, ask the browser to open a `Save as...` dialog
            instead of opening the file with the associated program. You can
            specify a custom filename as a string. If not specified, the
            original filename is used (default: False).
        :param charset: The charset to use for files with a ``text/*``
            mime-type. (default: UTF-8)
    """

    def _file_iter_range(fp, offset, bytes, maxread = 1024 * 1024):
        ''' Yield chunks from a range in a file. No chunk is bigger than maxread.'''
        fp.seek(offset)
        while bytes > 0 and (part := fp.read(min(bytes, maxread))):
            bytes -= len(part)
            yield part

    root = os.path.abspath(root) + os.sep
    filename = os.path.abspath(os.path.join(root, filename.strip('/\\')))
    headers = dict()

    if not filename.startswith(root):
        return HTTPError(403, "Access denied.")
    if not os.path.exists(filename) or not os.path.isfile(filename):
        return HTTPError(404, "File does not exist.")
    if not os.access(filename, os.R_OK):
        return HTTPError(403, "You do not have permission to access this file.")

    if mimetype == 'auto':
        mimetype, encoding = mimetypes.guess_type(filename)
        if encoding: headers['Content-Encoding'] = encoding

    if mimetype:
        if mimetype[:5] == 'text/' and charset and 'charset' not in mimetype:
            mimetype += '; charset=%s' % charset
        headers['Content-Type'] = mimetype

    if download:
        download = os.path.basename(filename if download is True else download)
        headers['Content-Disposition'] = 'attachment; filename="%s"' % download

    stats = os.stat(filename)
    headers['Content-Length'] = clen = stats.st_size
    lm = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(stats.st_mtime))
    headers['Last-Modified'] = lm

    ims = request.environ.get('HTTP_IF_MODIFIED_SINCE')
    if ims:
        ims = parse_date(ims.split(";")[0].strip())
    if ims is not None and ims >= int(stats.st_mtime):
        headers['Date'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        return HTTPResponse(status=304, **headers)

    body = '' if request.method == 'HEAD' else open(filename, 'rb')

    headers["Accept-Ranges"] = "bytes"
    ranges = request.environ.get('HTTP_RANGE')
    if 'HTTP_RANGE' in request.environ:
        ranges = list(parse_range_header(request.environ['HTTP_RANGE'], clen))
        if not ranges:
            return HTTPError(416, "Requested Range Not Satisfiable")
        offset, end = ranges[0]
        headers["Content-Range"] = f"bytes {offset}-{end-1}/{clen}"
        headers["Content-Length"] = str(end - offset)
        if body:
            body = _file_iter_range(body, offset, end - offset)
        return HTTPResponse(body, status=206, **headers)
    return HTTPResponse(body, **headers)


app = None
route = None
on_route = None
request = None
response = None
error = None


def app_make():
    global app, route, on_route, request, response, error
    app = Ombott()
    route = app.route
    on_route = app.on_route
    request = app.request
    response = app.response
    error = app.error
    return app


def default_app():
    global app
    if not app:
        app_make()
    return app
