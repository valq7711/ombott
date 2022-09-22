import json as json_mod
import cgi
from tempfile import TemporaryFile
from io import BytesIO
from functools import partial

from ..common_helpers import touni

from .helpers import (
    parse_qsl,
    cache_in,
    FileUpload,
    FormsDict
)
from .errors import RequestError, BodyParsingError, BodySizeError


# fix bug cgi.FieldStorage context manager bug https://github.com/python/cpython/pull/14815
def _cgi_monkey_patch():
    def patch_exit(self, *exc):
        if self.file is not None:
            self.file.close()
    cgi.FieldStorage.__exit__ = patch_exit


_cgi_monkey_patch()


def _iter_body(read, buff_size, *, content_length):
    rest_len = content_length
    while rest_len > 0:
        part_size = min(rest_len, buff_size)
        part = read(part_size)
        if not part:
            break
        yield part
        rest_len -= part_size


def _iter_chunked(read, buff_size):
    r, n, rn, sem = b'\r', b'\n', b'\r\n', b';'
    header_size_buff = []
    parsing_err = BodyParsingError()
    while True:

        # read header to get chunk size
        header_size_buff.clear()
        read_len = 0
        seen_r = False
        seen_sem = False
        while True:   # header[-2:] != rn:
            c = read(1)
            read_len += 1
            if not c or read_len > buff_size:
                raise parsing_err
            # catch `\r\n`
            if seen_r and c == n:
                break
            seen_r = c == r
            # maybe behind `;` (chunk extra info)
            if seen_sem:
                # continue reading until `\r\n`
                continue
            seen_sem = c == sem
            if seen_r or seen_sem:
                continue
            header_size_buff.append(c)

        chunk_size = b''.join(header_size_buff)
        try:
            rest_len = int(chunk_size.strip(), 16)
        except ValueError:
            raise parsing_err
        if rest_len == 0:
            break

        # read chunk body
        while rest_len > 0:
            part_size = min(rest_len, buff_size)
            part = read(part_size)
            if not part:
                raise parsing_err
            yield part
            rest_len -= part_size
        if read(2) != rn:
            raise parsing_err


def _body_read(read, buff_size, *, content_length = None, chunked = None, max_body_size = None):
    body_iter = (
        _iter_chunked if chunked
        else partial(_iter_body, content_length = content_length)
    )
    body, body_size, is_temp_file = BytesIO(), 0, False
    for part in body_iter(read, buff_size):
        body.write(part)
        body_size += len(part)
        if max_body_size is not None and body_size > max_body_size:
            raise BodySizeError()
        if not is_temp_file and body_size > buff_size:
            body, tmp = TemporaryFile(mode='w+b'), body
            body.write(tmp.getvalue())
            del tmp
            is_temp_file = True
    return body


class BodyMixin:

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

    @cache_in('environ[ ombott.request.ctype ]', read_only=True)
    def ctype(self):
        ctype = self.content_type.split(';')
        return [t.strip() for t in ctype]

    @property
    def chunked(self):
        ''' True if Chunked transfer encoding was. '''
        return 'chunked' in self.environ.get('HTTP_TRANSFER_ENCODING', '').lower()

    @property
    def body(self):
        ret = self._body
        ret.seek(0)
        return ret

    @cache_in('environ[ ombott.request.query ]', read_only=True)
    def query(self):
        ''' The :attr:`query_string` parsed into a :class:`FormsDict`. These
            values are sometimes called "URL arguments" or "GET parameters", but
            not to be confused with "URL wildcards" as they are provided by the
            :class:`Router`. '''
        ret = self._forms_factory()  # FormsDict()
        qs = self._env_get('QUERY_STRING', '')
        if qs:
            parse_qsl(qs, setitem = ret.__setitem__)
        self.environ['ombott.request.get'] = ret
        return ret

    #: An alias for :attr:`query`.
    GET = query

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

    @cache_in('environ[ ombott.request.post ]', read_only=True)
    def POST(self):
        """ The values of :attr:`forms` and :attr:`files` combined into a single
            :class:`FormsDict`. Values are either strings (form values) or
            instances of :class:`cgi.FieldStorage` (file uploads).

        """
        env = self.environ
        files = env['ombott.request.files'] = self._forms_factory()  # FormsDict()
        post = self._forms_factory()  # FormsDict()

        # We default to application/x-www-form-urlencoded for everything that
        # is not multipart and take the fast path
        ctype = self.content_type
        if not ctype.startswith('multipart/'):
            if ctype.startswith('application/json'):
                post.update(self.json)
            else:
                parse_qsl(
                    touni(self._get_body_string(), 'latin1'),
                    setitem = post.__setitem__
                )
            env['ombott.request.forms'] = post
            return post

        forms = env['ombott.request.forms'] = self._forms_factory()  # FormsDict()
        forms.recode_unicode = False  # avoid for `multipart/form-data`

        safe_env = {'QUERY_STRING': ''}  # Build a safe environment for cgi
        for key in ('REQUEST_METHOD', 'CONTENT_TYPE', 'CONTENT_LENGTH'):
            if key in env:
                safe_env[key] = env[key]
        args = dict(
            fp=self.body,
            environ=safe_env,
            keep_blank_values=True,
            encoding='utf8'
        )
        listified = set()
        with cgi.FieldStorage(**args) as data:
            self['_cgi.FieldStorage'] = data  # http://bugs.python.org/issue18394#msg207958
            data = data.list or []
            for item in data:
                if item.filename:
                    it = FileUpload(
                        item.file, item.name,
                        item.filename, item.headers
                    )
                    dct = files
                else:
                    it = item.value
                    dct = forms
                key = item.name

                if key in post:
                    el = post[key]
                    if key not in listified:
                        el = post[key] = dct[key] = [el]
                        listified.add(key)
                    el.append(it)
                else:
                    post[key] = dct[key] = it
        return post

    @cache_in('environ[ ombott.request.forms ]', read_only=True)
    def forms(self):
        """ Form values parsed from an `url-encoded` or `multipart/form-data`
            encoded POST or PUT request body. The result is returned as a
            :class:`FormsDict`. All keys and values are strings. File uploads
            are stored separately in :attr:`files`.
        """
        self.POST
        return self.environ['ombott.request.forms']

    @cache_in('environ[ ombott.request.files ]', read_only=True)
    def files(self):
        """ File uploads parsed from `multipart/form-data` encoded POST or PUT
            request body. The values are instances of :class:`FileUpload`.

        """
        self.POST
        return self.environ['ombott.request.files']

    @cache_in('environ[ ombott.request.body ]', read_only=True)
    def _body(self):
        try:
            body = _body_read(
                self.environ['wsgi.input'].read,
                self.config.max_memfile_size,
                content_length = self.content_length,
                chunked = self.chunked,
                max_body_size = self.config.max_body_size
            )
        except RequestError as err:
            self._raise(err, RequestError)
        self.environ['wsgi.input'] = body
        body.seek(0)
        return body

    def _get_body_string(self):
        ''' read body until content-length or MEMFILE_MAX into a string. Raise
            BodySizeError on requests that are to large.

        '''
        self._body.seek(0)
        read = self._body.read
        max_content_length = self.config.max_memfile_size
        content_length = self.content_length

        if content_length > max_content_length:
            raise self._raise(BodySizeError(), RequestError)
        if content_length < 0:
            content_length = max_content_length + 1
        data = read(content_length)
        if len(data) > max_content_length:  # Fail fast
            raise self._raise(BodySizeError(), RequestError)
            # raise HTTPError(413, 'Request to large')
        return data
