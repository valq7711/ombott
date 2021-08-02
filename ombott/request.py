from tempfile import TemporaryFile
from io import BytesIO
from functools import partial
from .helpers import (
    ts_props, touni, tob, cache_in
)
from .response import HTTPError


def _get_body_string(read, content_length, MEMFILE_MAX, httpErr):
    ''' read body until content-length or MEMFILE_MAX into a string. Raise
        httpErr on requests that are to large. '''
    clen = content_length
    if clen > MEMFILE_MAX:
        raise httpErr
    if clen < 0: clen = MEMFILE_MAX + 1
    data = read(clen)
    if len(data) > MEMFILE_MAX:  # Fail fast
        raise httpErr
    return data


def _iter_body(read, bufsize, content_length):
    maxread = max(0, content_length)
    while maxread:
        part = read(min(maxread, bufsize))
        if not part: break
        yield part
        maxread -= len(part)


def _iter_chunked(read, bufsize, httpErr):
    rn, sem, bs = tob('\r\n'), tob(';'), tob('')
    while True:
        header = read(1)
        while header[-2:] != rn:
            c = read(1)
            header += c
            if not c: raise httpErr
            if len(header) > bufsize: raise httpErr
        size, _, _ = header.partition(sem)
        try:
            maxread = int(touni(size.strip()), 16)
        except ValueError:
            raise httpErr
        if maxread == 0: break
        buff = bs
        while maxread > 0:
            if not buff:
                buff = read(min(maxread, bufsize))
            part, buff = buff[:maxread], buff[maxread:]
            if not part: raise httpErr
            yield part
            maxread -= len(part)
        if read(2) != rn:
            raise httpErr


def _body_read(read, MEMFILE_MAX, *, content_length = None, chunked = None, httpErr):
    body_iter = (
        partial(_iter_chunked, httpErr = httpErr)
        if chunked
        else partial(_iter_body, content_length = content_length)
    )
    body, body_size, is_temp_file = BytesIO(), 0, False
    for part in body_iter(read, MEMFILE_MAX):
        body.write(part)
        body_size += len(part)
        if not is_temp_file and body_size > MEMFILE_MAX:
            body, tmp = TemporaryFile(mode='w+b'), body
            body.write(tmp.getvalue())
            del tmp
            is_temp_file = True
    return body



# ------------------[ BaseRequest ] -------------------
class BaseRequest:
    __slots__ = ('environ', '__subscribers__')

    #: Maximum size of memory buffer for :attr:`body` in bytes.
    MEMFILE_MAX = 102400

    def __new__(cls, *a, **kw):
        self = super().__new__(cls)
        self.__subscribers__ = {}
        self.on(
            'env_changed',
            lambda request, k, v: (
                request.environ.pop('ombott.request.body', None)
                if k == 'wsgi.input' else None
            )
        )
        return self

    def __init__(self, environ = None):
        """ Wrap a WSGI environ dictionary. """
        #: The wrapped WSGI environ dictionary. This is the only real attribute.
        #: All other attributes actually are read-only properties.
        self.environ = {} if environ is None else environ
        self.environ['ombott.request'] = self

    @cache_in('environ[ ombott.request.body ]', read_only=True)
    def _body(self):
        body = _body_read(
            self.environ['wsgi.input'].read,
            self.MEMFILE_MAX,
            content_length = self.content_length,
            chunked = self.chunked,
            httpErr = HTTPError(400, 'Error while parsing chunked transfer body.')
        )
        self.environ['wsgi.input'] = body
        body.seek(0)
        return body

    def _get_body_string(self):
        self._body.seek(0)
        return _get_body_string(
            self._body.read,
            self.content_length,
            self.MEMFILE_MAX,
            HTTPError(413, 'Request to large')
        )

    def on(self, e, cb):
        if e not in self.__subscribers__:
            self.__subscribers__[e] = []
        self.__subscribers__[e].append(cb)
        return lambda: self.__subscribers__[e].remove(cb)

    def off(self, e, cb):
        self.__subscribers__[e].remove(cb)

    def emit(self, e, *a, **kw):
        if e not in self.__subscribers__:
            return
        [cb(self, *a, **kw) for cb in self.__subscribers__[e]]

    def copy(self):
        """ Return a new :class:`Request` with a shallow :attr:`environ` copy. """
        copy = Request(self.environ.copy())
        copy.__subscribers__ = self.__subscribers__
        return copy

    def get(self, value, default=None): return self.environ.get(value, default)
    def __getitem__(self, key): return self.environ[key]
    def __delitem__(self, key): self[key] = ""; del(self.environ[key])
    def __iter__(self): return iter(self.environ)
    def __len__(self): return len(self.environ)
    def keys(self): return self.environ.keys()
    def __setitem__(self, key, value):
        """ Change an environ value and clear all caches that depend on it. """

        if self.environ.get('ombott.request.readonly'):
            raise KeyError('The environ dictionary is read-only.')

        self.environ[key] = value
        self.emit('env_changed', key, value)

    def __repr__(self):
        return '<%s: %s %s>' % (self.__class__.__name__, self.method, self.url)

    def __getattr__(self, name):
        ''' Search in self.environ for additional user defined attributes. '''

        try:
            var = self.environ['ombott.request.ext.%s' % name]
            return var.__get__(self) if hasattr(var, '__get__') else var
        except KeyError:
            raise AttributeError('Attribute %r not defined.' % name)

    def __setattr__(self, name, value):
        if name in ('environ', '__subscribers__'):
            return object.__setattr__(self, name, value)
        self.environ['ombott.request.ext.%s' % name] = value
        return value


@ts_props('environ')
class Request(BaseRequest):
    __mixins__special__ = {
        '__new__': [],
        '__init__': [],
    }

    def __new__(cls, *a, **kw):
        self = super().__new__(cls, *a, **kw)
        new_mixins = cls.__mixins__special__['__new__']
        [new(self, *a, **kw) for new in new_mixins]
        return self

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        init_mixins = self.__mixins__special__['__init__']
        [init(self, *a, **kw) for init in init_mixins]

    @classmethod
    def mixin(cls, *mixins):
        special = cls.__mixins__special__
        for mixin in mixins:
            for k, v in mixin.items():
                if k in special:
                    special[k].append(v)
                else:
                    setattr(cls, k, v)
