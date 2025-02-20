
from ..errors import OmbottException

class RequestError(OmbottException):
    pass

class BodyParsingError(RequestError):
    pass

class BodySizeError(RequestError):
    pass

class JSONParsingError(RequestError):
    pass
