from pathlib import Path

html = Path(__file__).parent / 'error.html'

_html_lns = []

def render(err_resp, url, debug):
    ex = traceback = '-] Forbidden [-'
    if debug:
        traceback = err_resp.traceback
        ex = err_resp.exception
        try:
            ex = repr(ex)
        except:
            ex = f'<unprintable {type(ex)} object>'
    ctx = dict(
        e = err_resp,
        exception = ex,
        traceback = traceback,
        url = repr(url)
    )

    if not _html_lns:
        with html.open('r') as f:
            s = f.readlines()
        _html_lns[:] = [ln.strip() for ln in s]

    out = []
    skip_until = ''
    for ln in _html_lns:
        if skip_until:
            if ln.startswith(skip_until):
                skip_until = ''
        elif ln.startswith('<style'):
            skip_until = '</style'
        else:
            ln = ln.format(**ctx)
        out.append(ln)
    return ''.join(out)


def _test():
    class e:
        status = 'status'
        body = 'body'
        traceback = 'traceback'
        exception = 'exception'

    print(render(e, 'url', False))


