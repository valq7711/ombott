import os
import mimetypes
import time

from .common_helpers import parse_date
from .response import HTTPResponse, HTTPError
from .ombott import Globals


def get_first_range(header, maxlen=0):
    ''' Return (start, end) of first range in ranges parsed from a HTTP Range header.
        Skip unsatisfiable ranges. The end index is non-inclusive.

    '''
    try:
        ranges_str = header.split('bytes=', 1)[1]
    except IndexError:
        # no-perix/unsupported-units
        return

    first_range = ranges_str.split(',', 1)[0]
    try:
        start, end = first_range.split('-')
    except ValueError:
        # too-many/not-enougth values to unpack (invalid range)
        return

    try:
        if not start:  # bytes=-100    -> last 100 bytes
            start, end = max(0, maxlen - int(end)), maxlen
        elif not end:  # bytes=100-    -> all but the first 99 bytes
            start, end = int(start), maxlen
        else:          # bytes=100-200 -> bytes 100-200 (inclusive)
            start, end = int(start), min(int(end) + 1, maxlen)
        if 0 <= start < end <= maxlen:
            return start, end
    except ValueError:
        pass

def _file_iter_range(fp, offset, bytes_len, maxread=1024 * 1024):
    ''' Yield chunks from a range in a file. No chunk is bigger than maxread.'''
    fp.seek(offset)
    while bytes_len > 0 and (part := fp.read(min(bytes_len, maxread))):
        bytes_len -= len(part)
        yield part

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
    request = Globals.request
    os_path = os.path
    root = os_path.abspath(root) + os.sep
    filename = os_path.abspath(os_path.join(root, filename.strip('/\\')))
    headers = dict()
    env_get = request.environ.get


    if not filename.startswith(root):
        return HTTPError(403, "Access denied.")
    if not os_path.exists(filename) or not os_path.isfile(filename):
        return HTTPError(404, "File does not exist.")
    if not os.access(filename, os.R_OK):
        return HTTPError(403, "You do not have permission to access this file.")

    if mimetype == 'auto':
        mimetype, encoding = mimetypes.guess_type(filename)
        if encoding:
            headers['Content-Encoding'] = encoding

    if mimetype:
        if mimetype.startswith('text/') and charset and 'charset' not in mimetype:
            mimetype += '; charset=%s' % charset
        headers['Content-Type'] = mimetype

    if download:
        download = os_path.basename(filename if download is True else download)
        headers['Content-Disposition'] = 'attachment; filename="%s"' % download

    stats = os.stat(filename)
    headers['Content-Length'] = clen = stats.st_size
    headers['Last-Modified'] = time.strftime(
        "%a, %d %b %Y %H:%M:%S GMT",
        time.gmtime(stats.st_mtime)
    )

    ims = env_get('HTTP_IF_MODIFIED_SINCE')
    if ims:
        ims = parse_date(ims.split(";")[0].strip())
    if ims is not None and ims >= int(stats.st_mtime):
        headers['Date'] = time.strftime(
            "%a, %d %b %Y %H:%M:%S GMT",
            time.gmtime()
        )
        return HTTPResponse(status=304, **headers)

    body = '' if request.method == 'HEAD' else open(filename, 'rb')

    headers["Accept-Ranges"] = "bytes"
    range_header = env_get('HTTP_RANGE')
    if range_header:
        first_range = get_first_range(range_header, clen)
        if not first_range:
            return HTTPError(416, "Requested Range Not Satisfiable")
        offset, end = first_range
        headers["Content-Range"] = f"bytes {offset}-{end-1}/{clen}"
        headers["Content-Length"] = str(end - offset)
        if body:
            body = _file_iter_range(body, offset, end - offset)
        return HTTPResponse(body, status=206, **headers)
    return HTTPResponse(body, **headers)
