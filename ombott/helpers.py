from collections.abc import MutableMapping as DictMixin
import os
import re
import types
import threading
import base64
import pickle
import hmac
import hashlib
import email.utils
import time
from unicodedata import normalize


class OmbottException(Exception):
    __slots__ = ()
    pass


###############################################################################
# Common Utilities #############################################################
###############################################################################

def parse_date(ims):
    """ Parse rfc1123, rfc850 and asctime timestamps and return UTC epoch. """
    try:
        ts = email.utils.parsedate_tz(ims)
        return time.mktime(ts[:8] + (0,)) - (ts[9] or 0) - time.timezone
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


# ---------------- [ Some helpers for string/byte handling ] ---------
def tob(s, enc='utf8'):
    return s.encode(enc) if isinstance(s, str) else bytes(s)

def touni(s, enc='utf8', err='strict'):
    return s.decode(enc, err) if isinstance(s, bytes) else str(s)


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
def ts_props(*props):
    def wrapper(cls):
        local_store = threading.local()
        for k in props:
            setattr(local_store, k, None)
            setattr(
                cls, k,
                property(
                    (lambda n = k: lambda s: getattr(local_store, n))(),
                    (lambda n = k: lambda s, v: setattr(local_store, n, v))(),
                    (lambda n = k: lambda s: delattr(local_store, n))(),
                )
            )
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


# ------------------[ exposes prop callable attrubutes at instance level] -------------------
def cache_in(attr, key=None, read_only=False):
    # attr = 'environ[ PATH_INFO ]'
    re_attr_key = re.compile(r'^(.+?)\[\s*([^\[\]]+?)\s*\]$')
    if not key and (attr_key := re_attr_key.match(attr)):
        attr, key = attr_key.groups()

    def wrapper(getter):
        def maybe_readonly():
            if read_only: raise AttributeError("Read-Only property.")

        if not key:
            def fget(self):
                try:
                    return getattr(self, attr)
                except AttributeError:
                    setattr(self, attr, getter(self))
                    return getattr(self, attr)

            def fset(self, value):
                maybe_readonly()
                setattr(self, attr, value)

            def fdel(self):
                maybe_readonly()
                delattr(self, attr)
        else:
            def fget(self):
                storage = getattr(self, attr)
                if key not in storage:
                    storage[key] = getter(self)
                return storage[key]

            def fset(self, value):
                maybe_readonly()
                getattr(self, attr)[key] = value

            def fdel(self):
                maybe_readonly()
                del getattr(self, attr)[key]

        return property(fget, fset, fdel, 'cache_in')
    return wrapper

# ------------------[ helper classes] -------------------


class cached_property(object):
    ''' A property that is only computed once per instance and then replaces
        itself with an ordinary attribute. Deleting the attribute resets the
        property. '''

    def __init__(self, func):
        self.__doc__ = getattr(func, '__doc__')
        self.func = func

    def __get__(self, obj, cls):
        if obj is None: return self
        value = obj.__dict__[self.func.__name__] = self.func(obj)
        return value


class NameSpace(types.SimpleNamespace):
    ''' fast Name-Space-Dict
    nsd.some       # - fast
    nsd['some']    # - 20...30% slower
    '''
    __getitem__ = types.SimpleNamespace.__getattribute__
    __setitem__ = types.SimpleNamespace.__setattr__
    get = lambda s, k, d: s.__dict__.get(k, d)
    keys = lambda s: s.__dict__.keys()
    values = lambda s: s.__dict__.values()
    items = lambda s: s.__dict__.items()
    setdefault = lambda s, k, d: s.__dict__.setdefault(k, d)
    update = lambda s, d: s.__dict__.update(d)
    def __init__(self, **kw):
        super().__init__(**kw)


class FormsDict(dict):
    ''' This :class:`dict` subclass is used to store request form data.
        Additionally to the normal dict-like item access methods (which return
        unmodified data as native strings), this container also supports
        attribute-like access to its values. Attributes are automatically de-
        or recoded to match :attr:`input_encoding` (default: 'utf8'). Missing
        attributes default to an empty string. '''

    #: Encoding used for attribute values.
    input_encoding = 'utf8'
    #: If true (default), unicode strings are first encoded with `latin1`
    #: and then decoded to match :attr:`input_encoding`.
    recode_unicode = True

    def _fix(self, s, encoding=None):
        if isinstance(s, str) and self.recode_unicode:  # Python 3 WSGI
            return s.encode('latin1').decode(encoding or self.input_encoding)
        else:
            return s

    def decode(self, encoding=None):
        ''' Returns a copy with all keys and values de- or recoded to match
            :attr:`input_encoding`. Some libraries (e.g. WTForms) want a
            unicode dictionary. '''
        copy = FormsDict()
        enc = copy.input_encoding = encoding or self.input_encoding
        copy.recode_unicode = False
        for key, value in self.items():
            copy[self._fix(key, enc)] = self._fix(value, enc)
        return copy

    def getunicode(self, name, default=None, encoding=None):
        ''' Return the value as a unicode string, or the default. '''
        try:
            return self._fix(self[name], encoding)
        except (UnicodeError, KeyError):
            return default

    def __getattr__(self, name, default=str()):
        # Without this guard, pickle generates a cryptic TypeError:
        if name.startswith('__') and name.endswith('__'):
            return super().__getattr__(name)
        return self.getunicode(name, default=default)


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
    def __len__(self): return len(self._ts.dict)
    def __iter__(self): return self._ts.dict.__iter__()
    def __contains__(self, key): return key in self._ts.dict
    def __delitem__(self, key): del self._ts.dict[key]
    def __getitem__(self, key): return self._ts.dict[key]
    def __setitem__(self, key, value): self._ts.dict[key] = _hval(value)
    def copy(self):
        ret = self.__class__()
        ret.dict = {k: (v[:] if isinstance(v, list) else v) for k, v in self.items()}
        return ret
    def setdefault(self, key, value):
        return self._ts.dict.setdefault(key, _hval(value) if not isinstance(value, list) else value)

    def append(self, key, value):
        d = self._ts.dict
        value = _hval(value)
        if (v := d.get(key)) is None:
            d[key] = value
        elif isinstance(v, list):
            v.append(value)
        else:
            d[key] = [v, value]

    def clear(self, *names):
        if names:
            for n in names:
                if n in self: del self[n]
        else:
            self._ts.dict.clear()

    def update(self, d):
        self._ts.dict.update(d)

    def __repr__(self):
        return f'<{self.__class__.__name__}: {self.dict}>'


class WSGIHeaderDict(DictMixin):
    ''' This dict-like class wraps a WSGI environ dict and provides convenient
        access to HTTP_* fields. Keys and values are native strings
        (2.x bytes or 3.x unicode) and keys are case-insensitive. If the WSGI
        environment contains non-native string values, these are de- or encoded
        using a lossless 'latin1' character set.
    '''
    #: List of keys that do not have a ``HTTP_`` prefix.
    cgikeys = ('CONTENT_TYPE', 'CONTENT_LENGTH')

    def __init__(self, environ):
        self.environ = environ

    def _ekey(self, key):
        ''' Translate header field name to CGI/WSGI environ key. '''
        key = key.replace('-', '_').upper()
        if key in self.cgikeys:
            return key
        return 'HTTP_' + key

    def raw(self, key, default=None):
        ''' Return the header value as is (may be bytes or unicode). '''
        return self.environ.get(self._ekey(key), default)

    def __getitem__(self, key):
        return touni(self.environ[self._ekey(key)], 'latin1')

    def __setitem__(self, key, value):
        raise TypeError("%s is read-only." % self.__class__)

    def __delitem__(self, key):
        raise TypeError("%s is read-only." % self.__class__)

    def __iter__(self):
        for key in self.environ:
            if key.startswith('HTTP_'):
                yield key[5:].replace('_', '-').title()
            elif key in self.cgikeys:
                yield key.replace('_', '-').title()

    def keys(self): return [x for x in self]
    def __len__(self): return len(self.keys())
    def __contains__(self, key): return self._ekey(key) in self.environ


class HeaderProperty:
    def __init__(self, name, reader=None, writer=None, default=''):
        self.name, self.default = name, default
        self.reader, self.writer = reader, writer
        self.__doc__ = 'Current value of the %r header.' % name.title()

    def __get__(self, obj, cls):
        if obj is None: return self
        value = obj.headers.get(self.name, self.default)
        return self.reader(value) if self.reader else value

    def __set__(self, obj, value):
        obj.headers[self.name] = self.writer(value) if self.writer else value

    def __delete__(self, obj):
        del obj.headers[self.name]


class FileUpload:

    def __init__(self, fileobj, name, filename, headers=None):
        ''' Wrapper for file uploads. '''
        #: Open file(-like) object (BytesIO buffer or temporary file)
        self.file = fileobj
        #: Name of the upload form field
        self.name = name
        #: Raw filename as sent by the client (may contain unsafe characters)
        self.raw_filename = filename
        #: A :class:`HeaderDict` with additional headers (e.g. content-type)
        self.headers = HeaderDict(headers) if headers else HeaderDict()

    content_type = HeaderProperty('Content-Type')
    content_length = HeaderProperty('Content-Length', reader=int, default=-1)

    def get_header(self, name, default=None):
        """ Return the value of a header within the mulripart part. """
        return self.headers.get(name, default)

    @cached_property
    def filename(self):
        ''' Name of the file on the client file system, but normalized to ensure
            file system compatibility. An empty filename is returned as 'empty'.

            Only ASCII letters, digits, dashes, underscores and dots are
            allowed in the final filename. Accents are removed, if possible.
            Whitespace is replaced by a single dash. Leading or tailing dots
            or dashes are removed. The filename is limited to 255 characters.
        '''
        fname = self.raw_filename
        if not isinstance(fname, str):
            fname = fname.decode('utf8', 'ignore')
        fname = normalize('NFKD', fname).encode('ASCII', 'ignore').decode('ASCII')
        fname = os.path.basename(fname.replace('\\', os.path.sep))
        fname = re.sub(r'[^a-zA-Z0-9-_.\s]', '', fname).strip()
        fname = re.sub(r'[-\s]+', '-', fname).strip('.-')
        return fname[:255] or 'empty'

    def _copy_file(self, fp, chunk_size=2**16):
        read, write, offset = self.file.read, fp.write, self.file.tell()
        while 1:
            buf = read(chunk_size)
            if not buf: break
            write(buf)
        self.file.seek(offset)

    def save(self, destination, overwrite=False, chunk_size=2**16):
        ''' Save file to disk or copy its content to an open file(-like) object.
            If *destination* is a directory, :attr:`filename` is added to the
            path. Existing files are not overwritten by default (IOError).

            :param destination: File path, directory or file(-like) object.
            :param overwrite: If True, replace existing files. (default: False)
            :param chunk_size: Bytes to read at a time. (default: 64kb)
        '''
        if isinstance(destination, str):  # Except file-likes here
            if os.path.isdir(destination):
                destination = os.path.join(destination, self.filename)
            if not overwrite and os.path.exists(destination):
                raise IOError('File exists.')
            with open(destination, 'wb') as fp:
                self._copy_file(fp, chunk_size)
        else:
            self._copy_file(destination, chunk_size)


class WSGIFileWrapper(object):

    def __init__(self, fp, buffer_size=1024 * 64):
        self.fp, self.buffer_size = fp, buffer_size
        for attr in ('fileno', 'close', 'read', 'readlines', 'tell', 'seek'):
            if (a := getattr(fp, attr, None)) is not None:
                setattr(self, attr, a)

    def __iter__(self):
        buff, read = self.buffer_size, self.read
        while (part := read(buff)):
            yield part


def parse_range_header(header, maxlen=0):
    ''' Yield (start, end) ranges parsed from a HTTP Range header. Skip
        unsatisfiable ranges. The end index is non-inclusive.'''
    if not header or header[:6] != 'bytes=': return
    ranges = [r.split('-', 1) for r in header[6:].split(',') if '-' in r]
    for start, end in ranges:
        try:
            if not start:  # bytes=-100    -> last 100 bytes
                start, end = max(0, maxlen - int(end)), maxlen
            elif not end:  # bytes=100-    -> all but the first 99 bytes
                start, end = int(start), maxlen
            else:          # bytes=100-200 -> bytes 100-200 (inclusive)
                start, end = int(start), min(int(end) + 1, maxlen)
            if 0 <= start < end <= maxlen:
                yield start, end
        except ValueError:
            pass
