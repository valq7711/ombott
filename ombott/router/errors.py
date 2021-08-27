from ..errors import OmbottException


class RouteError(OmbottException):
    """ This is a base class for all routing related exceptions """
    __slots__ = ('extra',)

    def __init__(self, *args, **kw):
        super().__init__(*args)
        self.extra = kw


class RouteSyntaxError(RouteError):
    """ The route parser found something not supported by this router. """


class RouteBuildError(RouteError):
    """ The route could not be built. """


class RouteMethodError(RouteError):
    """ Method not allowed """