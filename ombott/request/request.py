
from ..common_helpers import ts_props, SimpleConfig
from ..mixable import Mixable

from .props_mixin import PropsMixin
from .body_mixin import BodyMixin


class RequestConfig(SimpleConfig):
    app_name_header = ''
    errors_map = {}
    max_body_size = None
    max_memfile_size = 100 * 1024


class BaseRequest:
    __slots__ = ('environ', '_env_get', '__listeners__', 'config', '_ts_props')

    def __new__(cls, environ = None, *, config=None):
        self = super().__new__(cls)
        self.__listeners__ = {}
        self.on('env_changed', cls._on_env_changed)
        self.config = RequestConfig.get_from(config)
        return self

    def __init__(self, environ = None, *, config = None):
        # self.environ = some  - also does self._env_get = some.get
        self.environ = {} if environ is None else environ
        self.environ['ombott.request'] = self

    def setup(self, config):
        self.config = RequestConfig.get_from(config)

    def _raise(self, err, except_class = None):
        errors_map = self.config.errors_map
        for err_cls in (err.__class__, except_class):
            out_err = errors_map.get(err_cls)
            if out_err:
                err = out_err
                break
        raise err

    @staticmethod
    def _on_env_changed(request, key, v):
        todelete = ()
        if key == 'wsgi.input':
            todelete = ('forms', 'files', 'params', 'post', 'json', 'body')
        elif key == 'QUERY_STRING':
            todelete = ('query', 'params')
        elif key.startswith('HTTP_'):
            todelete = ('headers', 'cookies')
        env = request.environ
        [env.pop('ombott.request.' + key, None) for key in todelete]

    def on(self, e, cb):
        if e not in self.__listeners__:
            self.__listeners__[e] = []
        self.__listeners__[e].append(cb)
        return lambda: self.__listeners__[e].remove(cb)

    def off(self, e, cb):
        self.__listeners__[e].remove(cb)

    def emit(self, e, *a, **kw):
        if e not in self.__listeners__:
            return
        [cb(self, *a, **kw) for cb in self.__listeners__[e]]

    def copy(self):
        """ Return a new :class:`Request` with a shallow :attr:`environ` copy.

        NOTE: __listeners__ are not copied

        """
        copy = self.__class__(self.environ.copy(), config = self.config)
        return copy

    def get(self, value, default=None):
        return self._env_get(value, default)

    def keys(self):
        return self.environ.keys()

    def __iter__(self):
        return iter(self.environ)

    def __len__(self):
        return len(self.environ)

    def __getitem__(self, key):
        return self.environ[key]

    def __setitem__(self, key, value):
        """ Change an environ value and clear all caches that depend on it. """

        if self._env_get('ombott.request.readonly'):
            raise KeyError('The environ dictionary is read-only.')

        if self.environ[key] in [value]:  # `in` performs 2 OR-gluing tests (`is` OR `==`)
            return

        self.environ[key] = value
        self.emit('env_changed', key, value)

    def __delitem__(self, key):
        self[key] = ""
        del self.environ[key]

    def __getattr__(self, name):
        ''' Search in self.environ for additional user defined attributes. '''
        if name in self.__slots__:
            return
        try:
            var = self.environ['ombott.request.ext.%s' % name]
            getter = getattr(var, '__get__', None)
            return getter(self) if getter else var
        except KeyError:
            raise AttributeError('Attribute %r not defined.' % name)

    def __setattr__(self, name, value):
        if name in self.__slots__:
            ret = object.__setattr__(self, name, value)
            if name == 'environ':
                object.__setattr__(self, '_env_get', value.get)
            return ret
        self.environ['ombott.request.ext.%s' % name] = value
        return value

    def __repr__(self):
        return '<%s: %s %s>' % (self.__class__.__name__, self.method, self.url)


@ts_props('environ', '_env_get', store_name = '_ts_props')
class Request(Mixable, BaseRequest, PropsMixin, BodyMixin):
    _as_mixins = [PropsMixin, BodyMixin]
