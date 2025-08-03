from .base_exception import BaseAppException


class BadRequestError(BaseAppException):
    def __init__(self, code="G2P-REQ-400", message="Bad Request", http_status_code=400, **kwargs):
        super().__init__(code, message, http_status_code, **kwargs)


class UnauthorizedError(BaseAppException):
    def __init__(self, code="G2P-AUT-401", message="Unauthorized", http_status_code=401, **kwargs):
        super().__init__(code, message, http_status_code, **kwargs)


class ForbiddenError(BaseAppException):
    def __init__(self, code="G2P-AUT-403", message="Forbidden", http_status_code=403, **kwargs):
        super().__init__(code, message, http_status_code, **kwargs)


class NotFoundError(BaseAppException):
    def __init__(self, code="G2P-REQ-404", message="Not Found", http_status_code=404, **kwargs):
        super().__init__(code, message, http_status_code, **kwargs)


class MethodNotAllowedError(BaseAppException):
    def __init__(
        self,
        code="G2P-REQ-405",
        message="Method Not Allowed",
        http_status_code=405,
        **kwargs,
    ):
        super().__init__(code, message, http_status_code, **kwargs)


class InternalServerError(BaseAppException):
    def __init__(
        self,
        code="G2P-REQ-500",
        message="Internal Server Error",
        http_status_code=500,
        **kwargs,
    ):
        super().__init__(code, message, http_status_code, **kwargs)
