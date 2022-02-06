from collections.abc import MutableMapping as DictMixin
import types
import threading
import base64
import pickle
import hmac
import hashlib
import email.utils
import time
from . import errors


def parse_date(ims):
    """ Parse rfc1123, rfc850 and asctime timestamps and return UTC epoch. """
    try:
        ts = email.utils.parsedate_tz(ims)
        return time.mktime(ts[:8] + (0,)) - (ts[9] or 0) - time.timezone
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


# ---------------- [ Some helpers for string/byte handling ] ---------
def tob(s, enc='utf8'):
    encode = getattr(s, 'encode', None)
    if encode:
        return encode(enc)
    return bytes(s)


def touni(s, enc='utf8', err='strict'):
    decode = getattr(s, 'decode', None)
    if decode:  # bytes
        return decode(enc, err)
    return str(s)


# ------------------[ cookie ] -------------------
def cookie_encode(data, key):
    ''' Encode and sign a pickle-able object. Return a (byte) string '''
    msg = base64.b64encode(pickle.dumps(data, -1))
    sig = base64.b64encode(hmac.new(tob(key), msg, digestmod=hashlib.md5).digest())
    return tob('!') + sig + tob('?') + msg


def cookie_decode(data, key):
    ''' Verify and decode an encoded string. Return an object or None.'''

    def cookie_is_encoded(data):
        ''' Return True if the argument looks like a encoded cookie.'''
        return bool(data.startswith(tob('!')) and tob('?') in data)

    def _lscmp(a, b):
        ''' Compares two strings in a cryptographically safe way:
            Runtime is not affected by length of common prefix. '''
        return not sum(0 if x == y else 1 for x, y in zip(a, b)) and len(a) == len(b)

    data = tob(data)
    if cookie_is_encoded(data):
        sig, msg = data.split(tob('?'), 1)
        if _lscmp(sig[1:], base64.b64encode(hmac.new(tob(key), msg, digestmod=hashlib.md5).digest())):
            return pickle.loads(base64.b64decode(msg))
    return None


# ------------------[ html escape `&<>'"`] -------------------
def html_escape(string):
    ''' Escape HTML special characters ``&<>`` and quotes ``'"``. '''
    return string.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')\
                 .replace('"', '&quot;').replace("'", '&#039;')


# ------------------[ thread safe props] -------------------
def ts_props(*props, store_name=None):
    def wrapper(cls):
        local_store = None
        cls_init = cls.__init__

        def init_wrapper(self, *a, **kw):
            nonlocal local_store
            local_store = getattr(self, store_name, None)
            if local_store is None:
                local_store = threading.local()
                setattr(self, store_name, local_store)
            [setattr(local_store, k, None) for k in props]
            cls_init(self, *a, **kw)

        def make_prop(k):
            def fget(s):
                return getattr(local_store, k)

            def fset(s, v):
                return setattr(local_store, k, v)

            def fdel(s):
                return delattr(local_store, k)
            doc = 'Local property: %s' % k
            return property(fget, fset, fdel, doc)

        cls.__init__ = init_wrapper
        [setattr(cls, p, make_prop(p)) for p in props]
        return cls
    return wrapper


# ------------------[ exposes prop callable attrubutes at instance level] -------------------
def proxy(prop, attrs, cls = None):
    def injector(cls):
        for attr in attrs:
            setattr(
                cls, attr,
                (lambda _attr = attr: lambda s, *a, **kw: getattr(getattr(s, prop), _attr)(*a, **kw))()
            )
        return cls
    return injector if not cls else injector(cls)


# ------------------[ helper classes] -------------------

class cached_property(object):
    ''' A property that is only computed once per instance and then replaces
        itself with an ordinary attribute. Deleting the attribute resets the
        property. '''

    def __init__(self, func):
        self.__doc__ = getattr(func, '__doc__')
        self.func = func

    def __get__(self, obj, cls):
        if obj is None:
            return self
        try:
            value = self.func(obj)
        except AttributeError as err:
            raise errors.PropertyGetterError(
                'AttributeError in cached_property getter of '
                f'`{self.func.__name__}`: {str(err)}'
            )
        setattr(obj, self.func.__name__, value)
        return value


class NameSpace(types.SimpleNamespace):
    ''' fast Name-Space-Dict
    nsd.some       # - fast
    nsd['some']    # - 20...30% slower
    '''
    __getitem__ = types.SimpleNamespace.__getattribute__
    __setitem__ = types.SimpleNamespace.__setattr__
    get = lambda s, k, d=None: s.__dict__.get(k, d)
    keys = lambda s: s.__dict__.keys()
    values = lambda s: s.__dict__.values()
    items = lambda s: s.__dict__.items()
    setdefault = lambda s, k, d: s.__dict__.setdefault(k, d)
    update = lambda s, d: s.__dict__.update(d)

    def __init__(self, **kw):
        super().__init__(**kw)


class _MetaSimpleConfig(type):

    def __init__(cls, name, bases, dct):
        keys = cls.__get_keys__(bases)
        if keys:
            for k in dct.keys():
                if k.startswith('_'):
                    continue
                if k not in keys:
                    raise KeyError(f'Unexpected key: {k}')

    @staticmethod
    def __get_keys__(bases):
        ret_keys = None
        for bcls in bases:
            keys = getattr(bcls, '__keys__', None)
            if not keys:
                continue
            if not ret_keys:
                ret_keys = keys
            elif keys != ret_keys:
                raise TypeError('Multiple keys holders detected')
        return ret_keys


class SimpleConfig(metaclass=_MetaSimpleConfig):

    @classmethod
    def keys_holder(cls, holder_cls):
        assert cls.__base__ is object
        keys_holder_cls = getattr(holder_cls, '__keys_holder__', None)
        if keys_holder_cls:
            raise RuntimeError(f'Keys holder is already registered: {keys_holder_cls}')

        keys = set(holder_cls.keys())
        for k in keys:
            if hasattr(cls, k):
                raise KeyError(f'Bad key `{k}`, reserved keys/attrs are {cls.keys()}')
        holder_cls.__keys__ = keys
        holder_cls.__keys_holder__ = holder_cls
        return holder_cls

    def __new__(cls, src_config=None, **kw):
        return cls.get_from(src_config, **kw)

    @classmethod
    def keys(cls):
        keys = getattr(cls, '__keys__', None)
        if keys:
            return keys.copy()
        return (k for k in cls.__dict__ if not k.startswith('__'))

    @classmethod
    def items(cls):
        return ((k, getattr(cls, k)) for k in cls.keys())

    @classmethod
    def get_from(cls, src_config=None, **kw):
        if src_config is None:
            src_config = {}
        return NameSpace(**{
            key: src_config.get(key, kw.get(key, default))
            for key, default in cls.items()
        })

    @classmethod
    def get(cls, k, default=None):
        return getattr(cls, k) if k in cls.keys() else default


# ------------------[ headers parsing] -------------------
def _hval(value):
    if not (value is None or isinstance(value, (str, int, float, bool))):
        raise TypeError(f"Header value must be type of (str, int, float, bool, None), got: {type(value)}")
    value = str(value)
    if '\n' in value or '\r' in value or '\0' in value:
        raise ValueError("Header value must not contain control characters: %r" % value)
    return value


@proxy('dict', 'keys pop popitem values items get'.split())
class HeaderDict(DictMixin):
    __slots__ = ('_ts',)

    dict = property(
        (lambda s: s._ts.dict),
        (lambda s, v: setattr(s._ts, 'dict', v)),
    )

    def __init__(self, *a, **kw):
        self._ts = threading.local()
        self._ts.dict = dict(*a, **kw)

    def __len__(self):
        return len(self._ts.dict)

    def __iter__(self):
        return self._ts.dict.__iter__()

    def __contains__(self, key):
        return key in self._ts.dict

    def __delitem__(self, key):
        del self._ts.dict[key]

    def __getitem__(self, key):
        return self._ts.dict[key]

    def __setitem__(self, key, value):
        self._ts.dict[key] = _hval(value)

    def copy(self):
        ret = self.__class__()
        ret.dict = {k: (v[:] if isinstance(v, list) else v) for k, v in self.items()}
        return ret

    def setdefault(self, key, value):
        return self._ts.dict.setdefault(key, _hval(value) if not isinstance(value, list) else value)

    def append(self, key, value):
        d = self._ts.dict
        value = _hval(value)
        v = d.get(key)
        if v is None:
            d[key] = value
        elif isinstance(v, list):
            v.append(value)
        else:
            d[key] = [v, value]

    def clear(self, *names):
        if names:
            for n in names:
                if n in self:
                    del self[n]
        else:
            self._ts.dict.clear()

    def update(self, d):
        self._ts.dict.update(d)

    def __repr__(self):
        return f'<{self.__class__.__name__}: {self.dict}>'


class HeaderProperty:

    __slots__ = ('name', 'default', 'reader', 'writer', '__doc__')

    def __init__(self, name, reader=None, writer=None, default=''):
        self.name, self.default = name, default
        self.reader, self.writer = reader, writer
        self.__doc__ = 'Current value of the %r header.' % name.title()

    def __get__(self, obj, cls):
        if obj is None:
            return self
        value = obj.headers.get(self.name, self.default)
        return self.reader(value) if self.reader else value

    def __set__(self, obj, value):
        obj.headers[self.name] = self.writer(value) if self.writer else value

    def __delete__(self, obj):
        del obj.headers[self.name]


class WSGIFileWrapper(object):

    def __init__(self, fp, buffer_size=1024 * 64):
        self.fp, self.buffer_size = fp, buffer_size
        for attr in ('fileno', 'close', 'read', 'readlines', 'tell', 'seek'):
            a = getattr(fp, attr, None)
            if a is not None:
                setattr(self, attr, a)

    def __iter__(self):
        buff, read = self.buffer_size, self.read
        part = read(buff)
        while part:
            yield part
            part = read(buff)
