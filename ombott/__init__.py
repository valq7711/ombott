from .ombott import ( # noqa
    Ombott,
    DefaultConfig,
    HTTPResponse,
    HTTPError,
    Response,
    Request,
    abort,
    default_app,
    redirect,

    Globals as _Globals,
    default_app,  # for bottle compat
    run,
    __version__
)

route = _Globals.route
on_route = _Globals.on_route
request = _Globals.request
response = _Globals.response
error = _Globals.error
app = _Globals.app

from .common_helpers import SimpleConfig    # noqa
from .static_stream import static_file        # noqa

__author__ = "Valery Kucherov <valq7711@gmail.com>"
__copyright__ = "Copyright (c) 2009-2012, Marcel Hellkamp; Copyright (C) 2021-2024 Valery Kucherov"
__license__ = "MIT"

__all__ = ('__version__', '__license__', '__copyright__', '__author__')