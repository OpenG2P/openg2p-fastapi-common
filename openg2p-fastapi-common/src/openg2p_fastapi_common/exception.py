import logging

from fastapi.exceptions import RequestValidationError, ResponseValidationError
from fastapi.responses import ORJSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .component import BaseComponent
from .config import Settings
from .context import app_registry
from .errors import BaseAppException, ErrorListResponse, ErrorResponse
from .errors.http_exceptions import (
    BadRequestError,
    ForbiddenError,
    InternalServerError,
    MethodNotAllowedError,
    NotFoundError,
    UnauthorizedError,
)

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


class BaseExceptionHandler(BaseComponent):
    def __init__(self, name="", **kwargs):
        super().__init__(name=name)

        app = app_registry.get()
        app.add_exception_handler(StarletteHTTPException, self.http_exception_handler)
        app.add_exception_handler(BaseAppException, self.base_exception_handler)
        app.add_exception_handler(
            RequestValidationError, self.request_validation_exception_handler
        )
        app.add_exception_handler(
            ResponseValidationError, self.response_validation_exception_handler
        )
        app.add_exception_handler(Exception, self.unknown_exception_handler)

    async def base_exception_handler(self, request, exc: BaseAppException):
        _logger.exception(f"Received Exception: {exc}")
        # TODO: Handle multiple exceptions
        res = ErrorListResponse(
            errors=[ErrorResponse(code=exc.code, message=exc.message)]
        )
        return ORJSONResponse(
            content=res.model_dump(), status_code=exc.status_code, headers=exc.headers
        )

    async def http_exception_handler(self, request, exc: StarletteHTTPException):
        return await self.base_exception_handler(
            request, self.map_http_to_base_exception(exc)
        )

    async def request_validation_exception_handler(
        self, request, exc: RequestValidationError
    ):
        _logger.error(
            "Received exception: %s",
            repr(exc),
            extra={"props": {"exc_info": exc.errors()}},
        )
        # _logger.exception("Received exception: %s", repr(exc))
        errors = []
        for err in exc.errors():
            err_msg = err.get("msg")
            errors.append(
                ErrorResponse(code="G2P-REQ-102", message=f"Invalid Input. {err_msg}")
            )
        res = ErrorListResponse(errors=errors)
        return ORJSONResponse(content=res.model_dump(), status_code=400)

    async def response_validation_exception_handler(
        self, request, exc: ResponseValidationError
    ):
        _logger.exception("Received exception: %s", repr(exc))
        errors = []
        for err in exc.errors():
            errors.append(
                ErrorResponse(
                    code="G2P-RES-100",
                    message=f"Internal Server Error. Invalid Response. {err}",
                )
            )
        res = ErrorListResponse(errors=errors)
        return ORJSONResponse(content=res.model_dump(), status_code=500)

    async def unknown_exception_handler(self, request, exc):
        _logger.exception("Received Unknown Exception: %s", repr(exc))
        exc_split = str(exc).split("::")
        if len(exc_split) > 1:
            code = exc_split[0]
            message = exc_split[1]
        elif _config.error_response_debug:
            code = "G2P-REQ-100"
            message = exc_split[0]
        else:
            code = "G2P-REQ-100"
            message = "Unknown Error."
        res = ErrorListResponse(errors=[ErrorResponse(code=code, message=message)])
        return ORJSONResponse(content=res.model_dump(), status_code=500)

    def map_http_to_base_exception(
        self, exc: StarletteHTTPException
    ) -> BaseAppException:
        if exc.status_code == 400:
            final_exc = BadRequestError(headers=exc.headers)
        elif exc.status_code == 401:
            final_exc = UnauthorizedError(headers=exc.headers)
        elif exc.status_code == 403:
            final_exc = ForbiddenError(headers=exc.headers)
        elif exc.status_code == 404:
            final_exc = NotFoundError(headers=exc.headers)
        elif exc.status_code == 405:
            final_exc = MethodNotAllowedError(headers=exc.headers)
        elif exc.status_code == 500:
            final_exc = InternalServerError(headers=exc.headers)
        else:
            final_exc = BaseAppException(
                code="G2P-REQ-100",
                message="Unknown HTTP Exception",
                http_status_code=exc.status_code,
                headers=exc.headers,
            )
        if exc.detail:
            final_exc.detail = exc.detail
            final_exc.message = exc.detail
        return final_exc
