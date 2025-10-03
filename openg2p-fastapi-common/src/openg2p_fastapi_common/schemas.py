from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class G2PResponseStatus(str, Enum):
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"


class G2PPaginationRequest(BaseModel):
    current_page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    sort_by: Optional[str] = None
    filter_by: Optional[Any] = None
    search_text: Optional[str] = None


class G2PRequestHeader(BaseModel):
    sender_app_mnemonic: str
    sender_app_url: str
    request_id: str
    request_timestamp: datetime
    instance_id: Optional[str] = None


class G2PRequestBody(BaseModel):
    pagination_request: Optional[G2PPaginationRequest] = None
    request_payload: Optional[Any] = None


class G2PRequest(BaseModel):
    request_header: G2PRequestHeader
    request_body: G2PRequestBody


class G2PPaginationResponse(BaseModel):
    number_of_items: int = Field(..., ge=0)
    number_of_pages: int = Field(..., ge=0)


class G2PResponseHeader(BaseModel):
    request_id: str
    response_status: G2PResponseStatus
    response_error_code: Optional[str] = None
    response_error_message: Optional[str] = None
    response_timestamp: datetime


class G2PResponseBody(BaseModel):
    pagination_response: Optional[G2PPaginationResponse] = None
    response_payload: Optional[Any] = None


class G2PResponse(BaseModel):
    response_header: G2PResponseHeader
    response_body: G2PResponseBody
