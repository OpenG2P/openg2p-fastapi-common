from fastapi import HTTPException


class BaseAppException(HTTPException):
    def __init__(self, code, message, http_status_code=500, headers=None, **kwargs):
        # TODO: Handle Multiple Exceptions
        super().__init__(status_code=http_status_code, detail=message, headers=headers, **kwargs)
        self.code = code
        self.message = message

    def __str__(self):
        return f'{self.__class__.__name__}(code="{self.code}", message="{self.message}", https_status_code="{self.status_code}")'

    def __repr__(self):
        return f'{self.__class__.__name__}(code="{self.code}", message="{self.message}", https_status_code="{self.status_code}")'
