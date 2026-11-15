from __future__ import annotations

from typing import Any

import structlog
from litestar import Request, Response
from litestar.exceptions import (
    HTTPException,
    NotAuthorizedException,
    NotFoundException,
    PermissionDeniedException,
    TooManyRequestsException,
    ValidationException,
)
from litestar.status_codes import (
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
    HTTP_413_REQUEST_ENTITY_TOO_LARGE,
    HTTP_422_UNPROCESSABLE_ENTITY,
    HTTP_429_TOO_MANY_REQUESTS,
    HTTP_500_INTERNAL_SERVER_ERROR,
    HTTP_502_BAD_GATEWAY,
    HTTP_503_SERVICE_UNAVAILABLE,
    HTTP_504_GATEWAY_TIMEOUT,
)

logger = structlog.get_logger()


class AppError(Exception):
    """Base application error rendered in the unified error format."""

    status_code: int = HTTP_500_INTERNAL_SERVER_ERROR
    code: str = "internal_error"
    message: str = "Internal server error."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        details: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.message = message or self.message
        self.code = code or self.code
        self.details = details
        self.headers = headers
        super().__init__(self.message)


class NotAuthorized(AppError):
    status_code = HTTP_401_UNAUTHORIZED
    code = "auth_required"
    message = "Authentication required."


class PermissionDenied(AppError):
    status_code = HTTP_403_FORBIDDEN
    code = "forbidden"
    message = "You do not have permission to perform this action."


class NotFound(AppError):
    status_code = HTTP_404_NOT_FOUND
    code = "not_found"
    message = "Resource not found."


class Conflict(AppError):
    status_code = HTTP_409_CONFLICT
    code = "conflict"
    message = "Conflict."


class PayloadTooLarge(AppError):
    status_code = HTTP_413_REQUEST_ENTITY_TOO_LARGE
    code = "document_too_large"
    message = "Document is too large."


class RateLimited(AppError):
    status_code = HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"
    message = "Too many requests."


class Unprocessable(AppError):
    status_code = HTTP_422_UNPROCESSABLE_ENTITY
    code = "validation_error"
    message = "Invalid request."


class UpstreamError(AppError):
    status_code = HTTP_502_BAD_GATEWAY
    code = "upstream_error"
    message = "Upstream error."


class UpstreamTimeout(AppError):
    status_code = HTTP_504_GATEWAY_TIMEOUT
    code = "upstream_timeout"
    message = "Upstream timed out."


class ServiceUnavailable(AppError):
    status_code = HTTP_503_SERVICE_UNAVAILABLE
    code = "service_unavailable"
    message = "Service unavailable."


def error_body(code: str, message: str, details: Any = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details}}


def _response(
    status: int, code: str, message: str, details: Any = None, headers: dict[str, str] | None = None
) -> Response[dict[str, Any]]:
    return Response(content=error_body(code, message, details), status_code=status, headers=headers)


def app_error_handler(_: Request[Any, Any, Any], exc: AppError) -> Response[dict[str, Any]]:
    return _response(exc.status_code, exc.code, exc.message, exc.details, exc.headers)


def validation_handler(
    _: Request[Any, Any, Any], exc: ValidationException
) -> Response[dict[str, Any]]:
    return _response(
        HTTP_422_UNPROCESSABLE_ENTITY,
        "validation_error",
        "Request validation failed.",
        exc.extra,
    )


def http_exception_handler(
    _: Request[Any, Any, Any], exc: HTTPException
) -> Response[dict[str, Any]]:
    status = exc.status_code
    headers = dict(exc.headers) if exc.headers else None
    if isinstance(exc, NotAuthorizedException):
        return _response(status, "auth_required", "Authentication required.", headers=headers)
    if isinstance(exc, PermissionDeniedException):
        return _response(status, "forbidden", exc.detail or "Forbidden.", headers=headers)
    if isinstance(exc, NotFoundException):
        return _response(status, "not_found", "Resource not found.", headers=headers)
    if isinstance(exc, TooManyRequestsException):
        headers = headers or {}
        headers.setdefault("Retry-After", "60")
        return _response(status, "rate_limited", "Too many requests.", headers=headers)
    if status == HTTP_413_REQUEST_ENTITY_TOO_LARGE:
        return _response(status, "payload_too_large", "Request body too large.", headers=headers)
    if status == 405:
        return _response(status, "method_not_allowed", "Method not allowed.", headers=headers)
    if status == 400:
        return _response(status, "bad_request", exc.detail or "Bad request.", headers=headers)
    if status >= 500:
        return _response(status, "internal_error", "Internal server error.", headers=headers)
    return _response(status, "http_error", exc.detail or "Request failed.", headers=headers)


def unhandled_handler(request: Request[Any, Any, Any], exc: Exception) -> Response[dict[str, Any]]:
    logger.error("unhandled_exception", exc_info=exc, path=request.url.path)
    return _response(HTTP_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal server error.")


EXCEPTION_HANDLERS: dict[Any, Any] = {
    AppError: app_error_handler,
    ValidationException: validation_handler,
    HTTPException: http_exception_handler,
    Exception: unhandled_handler,
}
