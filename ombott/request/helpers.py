import os
from collections.abc import MutableMapping as DictMixin
import re
from unicodedata import normalize
from urllib.parse import unquote as _urlunquote
from functools import partial

from ..common_helpers import touni, HeaderDict, HeaderProperty, cached_property
from .. import errors


urlunquote = partial(_urlunquote, encoding='latin1')


# ------------------[ cachable property with a custom storage ] -------------------
def cache_in(attr, key=None, read_only=False):
    # attr = 'environ[ PATH_INFO ]'
    re_attr_key = re.compile(r'^(.+?)\[\s*([^\[\]]+?)\s*\]$')
    if not key:
        attr_key = re_attr_key.match(attr)
        if attr_key:
            attr, key = attr_key.groups()

    def wrapper(getter):

        if not key:
            def fget(self):
                try:
                    return getattr(self, attr)
                except AttributeError:
                    try:
                        v = getter(self)
                    except AttributeError as err:
                        raise errors.PropertyGetterError(
                            f'AttributeError in getter of cache_in property `{getter.__name__}`, '
                            f'storage={attr}: {str(err)}'
                        )
                    setattr(self, attr, v)
                    return getattr(self, attr)

            def fset(self, value):
                if read_only:
                    raise AttributeError("Read-Only property.")
                setattr(self, attr, value)

            def fdel(self):
                if read_only:
                    raise AttributeError("Read-Only property.")
                delattr(self, attr)
        else:
            def fget(self):
                storage = getattr(self, attr)
                if key not in storage:
                    try:
                        storage[key] = getter(self)
                    except AttributeError as err:
                        raise errors.PropertyGetterError(
                            f'AttributeError in getter of cache_in property `{getter.__name__}`, '
                            f'storage={attr}[{key}]: {str(err)}'
                        )
                return storage[key]

            def fset(self, value):
                if read_only:
                    raise AttributeError("Read-Only property.")
                getattr(self, attr)[key] = value

            def fdel(self):
                if read_only:
                    raise AttributeError("Read-Only property.")
                del getattr(self, attr)[key]

        return property(fget, fset, fdel, 'cache_in')
    return wrapper


def parse_qsl(qs, *, append: callable = None, setitem: callable = None):
    container = None
    if setitem:
        _seen = dict()
        _lists = dict()

        def add(k, v):
            vlist = _lists.get(k)
            if vlist:
                vlist.append(v)
            elif k in _seen:
                tmp = _lists[k] = [_seen[k], v]
                setitem(k, tmp)
            else:
                setitem(k, _seen.setdefault(k, v))
    elif append:
        add = lambda k, v: append((k, v))
    else:
        container = []
        _append = container.append
        add = lambda k, v: _append((k, v))

    L = len(qs)
    i = 0
    while i < L:
        key = None
        idx = 0; c = None
        for idx, c in enumerate(qs[i:]):
            if c == '=' or c == '&':
                break
        else:
            idx += 1
        j = i + idx
        key = qs[i:j]
        i = j + 1  # skip '=' or '&'
        if not key:
            continue
        key = urlunquote(key.replace('+', ' '))
        if c == '&':
            value = ''
        else:
            idx = 0; c = None
            for idx, c in enumerate(qs[i:]):
                if c == '&':
                    break
            else:
                idx += 1
            j = i + idx
            value = urlunquote(qs[i:j].replace('+', ' '))
            i = j + 1  # skip '&'
        add(key, value)
    return container


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


class WSGIHeaderDict(DictMixin):
    ''' This dict-like class wraps a WSGI environ dict and provides convenient
        access to HTTP_* fields. Keys and values are native strings
        (2.x bytes or 3.x unicode) and keys are case-insensitive. If the WSGI
        environment contains non-native string values, these are de- or encoded
        using a lossless 'latin1' character set.
    '''
    #: List of keys that do not have a ``HTTP_`` prefix.
    cgikeys = {'CONTENT_TYPE', 'CONTENT_LENGTH'}
    __slots__ = ('environ',)

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


class FileUpload:

    __slots__ = ('file', 'name', 'raw_filename', 'headers')

    content_type = HeaderProperty('Content-Type')
    content_length = HeaderProperty('Content-Length', reader=int, default=-1)

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

    def get_header(self, name, default=None):
        """ Return the value of a header within the multipart part. """
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
        while True:
            buf = read(chunk_size)
            if not buf:
                break
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
