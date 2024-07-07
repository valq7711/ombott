from typing import Optional, Iterable, Union, Tuple, Dict
from types import SimpleNamespace
from collections import defaultdict
from io import BytesIO, SEEK_CUR, SEEK_SET, SEEK_END
import re

from ombott.request_pkg.errors import BodyParsingError, BodySizeError


class BaseMarkupException(BodyParsingError):
    pass


class InvalidBoundaryError(BaseMarkupException):
    pass


class StopMarkupException(BaseMarkupException):
    pass


class MalformedHeadersError(BaseMarkupException):
    pass


class UnexpectedBodyEndError(BaseMarkupException):
    pass


class MatchTail:
    def __init__(self, token: bytes):
        self.token = token
        self.len = len(token)
        self.idx = idx = defaultdict(list)   # 1-based indices for each token symbol
        for i, c in enumerate(token, start=1):
            idx[c].append([i, token[:i]])

    def match_tail(self, s: bytes, start: int, end: int) -> Optional[int]:
        idxs = self.idx.get(s[end - 1])
        if idxs is None:
            return
        slen = end - start
        assert slen <= self.len
        for i, thead in idxs:  # idxs is 1-based index
            search_pos = slen - i
            if search_pos < 0:
                return
            if s[start + search_pos:end] == thead:  # if s_tail == token_head
                return i


HYPHEN = b'-'
HYPHENx2 = HYPHEN * 2
CR = b'\r'
LF = b'\n'
CRLF = b'\r\n'
CRLF_LEN = len(CRLF)
LFCRLF = b'\n\r\n'
CRLFx2 = CRLF * 2
CRLFx2_LEN = len(CRLFx2)


end_headers_patt = re.compile(br'(\r\n\r\n)|(\r(\n\r?)?)$')


class HeadersEaeter:
    def __init__(self):
        self.headers_end_expected = None
        self.eat_meth = self._eat_first_crlf_or_last_hyphens
        self._meth_map = {
            CR: self._eat_lf,
            HYPHEN: self._eat_last_hyphen
        }
        self.stopped = False

    def eat(self, chunk: bytes, base: int) -> Optional[int]:
        pos = self.eat_meth(chunk, base)
        if pos is None:
            return

        if self.eat_meth != self._eat_headers:
            if self.stopped:
                raise StopMarkupException()
            base = pos
            self.eat_meth = self._eat_headers
            return self.eat(chunk, base)

        # found headers section end, reset eater
        self.eat_meth = self._eat_first_crlf_or_last_hyphens
        return pos

    def _eat_last_hyphen(self, chunk: bytes, base: int) -> Optional[int]:
        chunk_start = chunk[base: base + 2]
        if not chunk_start:
            return
        if chunk_start == HYPHEN:
            self.stopped = True
            return base + 1
        raise UnexpectedBodyEndError(f'Last hyphen was expected, got (first 2 symbols slice): {chunk_start}')

    def _eat_lf(self, chunk: bytes, base: int) -> Optional[int]:
        chunk_start = chunk[base: base + 1]
        if not chunk_start:
            return
        if chunk_start == LF:
            return base + 1
        invalid_sequence = CR + chunk_start
        raise MalformedHeadersError(f'Malformed headers, found invalid sequence: {invalid_sequence}')

    def _eat_first_crlf_or_last_hyphens(self, chunk: bytes, base: int) -> Optional[int]:
        chunk_start = chunk[base: base + 2]
        if not chunk_start:
            return

        if chunk_start == CRLF:
            return base + 2

        if len(chunk_start) == 1:
            self.eat_meth = self._meth_map.get(chunk_start)
        elif chunk_start == HYPHENx2:
            self.stopped = True
            return base + 2

        if self.eat_meth is None:
            raise MalformedHeadersError(f'Malformed headers, invalid section start: {chunk_start}')

    def _eat_headers(self, chunk: bytes, base: int):
        expected: bytes = self.headers_end_expected
        if expected is not None:
            expected_len = len(expected)
            chunk_start = chunk[base:expected_len]
            if chunk_start == expected:
                self.headers_end_expected = None
                return base + expected_len - CRLFx2_LEN
            chunk_start_len = len(chunk_start)
            if not chunk_start_len:
                return
            if chunk_start_len < expected_len:
                if expected.startswith(chunk_start):
                    self.headers_end_expected = expected[chunk_start_len:]
                    return
                self.headers_end_expected = None

            if expected == LF:  # we saw CRLFCR
                invalid_sequence = CR + chunk_start[0:1]
                # NOTE we don not catch all CRLF-malformed errors, but only obvious ones
                # to stop doing useless work
                raise MalformedHeadersError(f'Malformed headers, found invalid sequence: {invalid_sequence}')
            else:
                assert expected_len >= 2  # (CR)LFCRLF or (CRLF)CRLF
                self.headers_end_expected = None

        assert self.headers_end_expected is None

        s = end_headers_patt.search(chunk, base)
        if s is None:
            return

        end_found = s.start(1)
        if end_found >= 0:
            return end_found

        end_head = s.group(2)
        if end_head is not None:
            self.headers_end_expected = CRLFx2[len(end_head):]


class BodyMarkuper:
    def __init__(self, boundary: bytes):
        if CR in boundary:
            raise InvalidBoundaryError(f'The {CR} must not be in the boundary: {boundary}')
        boundary = HYPHENx2 + boundary

        self.boundary = boundary
        token = CRLF + boundary
        self.tlen = len(token)
        self.token = token
        self.trest = self.trest_len = None
        self.mt = MatchTail(token)
        self.abspos = 0
        self.abs_start_section = 0
        self.headers_eater = HeadersEaeter()
        self.cur_meth = self._eat_start_boundary
        self._eat_headers = self.headers_eater.eat
        self.stopped = False

    def iter_markup(self, chunk: bytes) -> Iterable[Tuple[str, Tuple[int, int]]]:
        if self.stopped:
            raise StopMarkupException()
        cur_meth = self.cur_meth
        abs_start_section = self.abs_start_section
        start_next_sec = 0
        skip_start = 0
        tlen = self.tlen
        eat_data, eat_headers = self._eat_data, self._eat_headers
        while True:
            try:
                end_section = cur_meth(chunk, start_next_sec)
            except StopMarkupException:
                self.stopped = True
                return

            if end_section is None:
                break

            if cur_meth == eat_headers:
                sec_name = 'headers'
                start_next_sec = end_section + CRLFx2_LEN
                cur_meth = eat_data
                skip_start = 0
            elif cur_meth == eat_data:
                sec_name = 'data'
                start_next_sec = end_section + tlen
                skip_start = CRLF_LEN
                cur_meth = eat_headers
            else:
                assert cur_meth == self._eat_start_boundary
                sec_name = 'data'
                start_next_sec = end_section + tlen
                skip_start = CRLF_LEN
                cur_meth = eat_headers

                # if the body starts with a hyphen,
                # we will have a negative abs_end_section equal to the length of the CRLF
                abs_end_section = self.abspos + end_section
                if abs_end_section < 0:
                    assert abs_end_section == -CRLF_LEN
                    end_section = -self.abspos

            yield sec_name, (abs_start_section, self.abspos + end_section)
            abs_start_section = self.abspos + start_next_sec + skip_start

        self.abspos += len(chunk)
        self.cur_meth = cur_meth
        self.abs_start_section = abs_start_section

    def _eat_start_boundary(self, chunk: bytes, base: int):
        if self.trest is None:
            chunk_start = chunk[base: base + 1]
            if not chunk_start:
                return

            if chunk_start == CR:
                return self._eat_data(chunk, base)

            boundary = self.boundary
            if chunk.startswith(boundary):
                return base - CRLF_LEN

            if chunk_start != boundary[:1]:
                raise InvalidBoundaryError(
                    f'Invalid multipart/formdata body start, expected hyphen or CR, got: {chunk_start}'
                )

            self.trest = boundary
            self.trest_len = len(boundary)

        end_section = self._eat_data(chunk, base)
        if end_section is not None:
            return end_section

    def _eat_data(self, chunk: bytes, base: int):
        chunk_len = len(chunk)
        token, tlen, trest, trest_len = self.token, self.tlen, self.trest, self.trest_len
        start = base
        mt = self.mt
        part = None
        while True:
            end = start + tlen
            if end > chunk_len:
                part = chunk[start:]
                break
            if trest is not None:
                if chunk[start:start + trest_len] == trest:   # part.startswith(trest):
                    data_end = start + trest_len - tlen
                    self.trest_len = self.trest = None
                    return data_end
                else:
                    trest_len = trest = None
            matched_len = mt.match_tail(chunk, start, end)
            if matched_len is not None:
                if matched_len == tlen:
                    self.trest_len = self.trest = None
                    return start
                else:
                    trest_len, trest = tlen - matched_len, token[matched_len:]

            start += tlen

        # process the tail of the chunk
        if part:
            part_len = len(part)
            if trest is not None:
                if part_len < trest_len:
                    if trest.startswith(part):
                        trest_len -= part_len
                        trest = trest[part_len:]
                        part = None
                    else:
                        trest_len = trest = None
                else:
                    if part.startswith(trest):
                        data_end = start + trest_len - tlen
                        self.trest_len = self.trest = None
                        return data_end
                    trest_len = trest = None

            if part is not None:
                assert trest is None
                matched_len = mt.match_tail(part, 0, part_len)
                if matched_len is not None:
                    trest_len, trest = tlen - matched_len, token[matched_len:]

        self.trest_len, self.trest = trest_len, trest


class MultipartMarkup:
    def __init__(self, boundary: Union[bytes, str]):
        if isinstance(boundary, str):
            boundary = boundary.encode()
        self._markuper = BodyMarkuper(boundary)
        self.markups = []
        self.error = None

    def parse(self, chunk: bytes):
        if self.error is not None:
            return
        try:
            self._parse(chunk)
        except Exception as exc:
            self.error = exc

    def _parse(self, chunk: bytes):
        for name, start_end in self._markuper.iter_markup(chunk):
            self.markups.append([name, start_end])


class BytesIOProxy:
    def __init__(self, src: BytesIO, start: int, end: int) -> None:
        self._src = src
        self._st = start
        self._end = end
        self._pos = start

    def tell(self) -> int:
        return self._pos - self._st

    def seekable(self) -> bool:
        return True

    def seek(self, pos: int, whence=SEEK_SET) -> int:
        if whence == SEEK_SET:
            if pos < 0:
                pos = 0
            self._pos = min(self._st + pos, self._end)
        elif whence == SEEK_CUR:
            self.seek(self.tell() + pos)
        elif whence == SEEK_END:
            self.seek(self._end + pos - self._st)
        else:
            raise ValueError(f'Unexpected whence: {whence}')
        return self.tell()

    def read(self, sz: int = None) -> bytes:
        max_sz = self._end - self._pos
        if max_sz <= 0:
            return b''
        if sz is not None and sz > 0:
            sz = min(sz, max_sz)
        else:
            sz = max_sz
        self._src.seek(self._pos)
        self._pos += sz
        return self._src.read(sz)

    def writable(self) -> bool:
        return False

    def fileno(self):
        raise OSError('Not supported')

    def closed(self):
        return self._src.closed()

    def close(self):
        pass


class Header(SimpleNamespace):
    name: str
    value: str
    options: Dict[str, str]


class FieldStorage:

    _patt = re.compile('(.+?)(=(.+?))?(;|$)')

    name: str
    value: Optional[str]
    filename: Optional[str]
    file: Optional['BytesIOProxy']
    ctype: Optional[str]
    headers: Dict[str, Header]

    def __init__(self):
        self.name = None
        self.value = None
        self.filename = None
        self.file = None
        self.ctype = None
        self.headers = {}

    def read(
            self, src: BytesIO, headers_section: Tuple[int, int], data_section: Tuple[int, int], *, max_read: int
    ) -> int:

        start, end = headers_section
        sz = end - start
        has_read = sz
        if has_read > max_read:
            raise BodySizeError('Max in-memory read limit exceed')
        src.seek(start)
        headers_raw = src.read(sz).decode()
        for header_raw in headers_raw.splitlines():
            header = self.parse_header(header_raw)
            self.headers[header.name] = header
            if header.name == 'Content-Disposition':
                self.name = header.options['name']
                self.filename = header.options.get('filename')
            elif header.name == 'Content-Type':
                self.ctype = header.value

        if self.name is None:
            raise BodyParsingError(f'Noname field found while parsing multipart/formdata body: {header_raw}')

        if self.filename is not None:
            self.file = BytesIOProxy(src, *data_section)
        else:
            start, end = data_section
            sz = end - start
            if sz:
                has_read += sz
                if has_read > max_read:
                    raise BodySizeError('Max in-memory read limit exceed')
                src.seek(start)
                self.value = src.read(sz).decode()
            else:
                self.value = ''
        return has_read

    @classmethod
    def parse_header(cls, s: str):
        htype, rest = s.split(':', 1)
        opt_iter = cls._patt.finditer(rest)
        hvalue = next(opt_iter).group(1).strip()
        dct = {}
        for it in opt_iter:
            k = it.group(1).strip()
            v = it.group(3)
            if v is not None:
                v = v.strip('"')
            dct[k.lower()] = v
        return Header(name=htype, value=hvalue, options=dct)

    @classmethod
    def iter_items(cls, src: BytesIO, markup: list, max_read: int):

        iter_markup = iter(markup)

        # check & skip empty data
        null_data = next(iter_markup, None)
        if null_data is None:
            return
        sec_name, [start, end] = null_data
        assert sec_name == 'data'
        if end > 0:
            raise BodyParsingError(
                f'Malformed multipart/formdata, unexpected data before the first boundary: [{start}:{end}]'
            )

        headers = next(iter_markup, None)
        data = next(iter_markup, None)

        while headers:
            sec_name, headers_slice = headers
            assert sec_name == 'headers'
            if not data:
                raise BodyParsingError(
                    f'Malformed multipart/formdata, no data for field: [{headers_slice[0]}:{headers_slice[1]}]'
                )
            sec_name, data_slice = data
            assert sec_name == 'data'

            field = cls()
            has_read = field.read(src, headers_slice, data_slice, max_read=max_read)
            max_read -= has_read
            yield field

            headers = next(iter_markup, None)
            data = next(iter_markup, None)
