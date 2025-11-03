from pydantic import BaseModel


class ErrorResponse(BaseModel):
    code: str = ""
    message: str = ""


class ErrorListResponse(BaseModel):
    errors: list[ErrorResponse]
