from fastapi import Body
from fastapi.testclient import TestClient
from starlette.responses import StreamingResponse

import openg2p_fastapi_common.app as common_app_module
from openg2p_fastapi_common.app import Initializer
from openg2p_fastapi_common.context import app_registry, component_registry, config_registry, dbengine
from openg2p_fastapi_common.errors.http_exceptions import BadRequestError


SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "x-xss-protection": "1; mode=block",
}


def _reset_state():
    component_registry.clear()
    app_registry.set(None)
    dbengine.set(None)
    config_registry.set([])


def _build_client(security_headers_enabled=True):
    _reset_state()
    common_app_module._config.security_headers_enabled = security_headers_enabled
    initializer = Initializer()
    app = initializer.return_app()

    @app.get("/ok")
    async def ok():
        return {"status": "ok"}

    @app.get("/items/{item_id}")
    async def item(item_id: int):
        return {"item_id": item_id}

    @app.get("/app-exception")
    async def app_exception():
        raise BadRequestError(message="Invalid input")

    @app.get("/stream")
    async def stream():
        return StreamingResponse(iter([b"chunk-1", b"chunk-2"]), media_type="text/plain")

    @app.post("/echo")
    async def echo(payload: dict = Body(...)):
        return payload

    return TestClient(app)


def _assert_security_headers(response):
    for header, expected_value in SECURITY_HEADERS.items():
        assert response.headers[header] == expected_value


def test_initializer():
    client = _build_client()

    response = client.get("/ok")

    assert response.status_code == 200
    _assert_security_headers(response)


def test_security_headers_added_to_404_responses():
    client = _build_client()

    response = client.get("/missing")

    assert response.status_code == 404
    _assert_security_headers(response)


def test_security_headers_added_to_validation_failure_responses():
    client = _build_client()

    response = client.get("/items/not-an-int")

    assert response.status_code == 400
    _assert_security_headers(response)


def test_security_headers_added_to_exception_handler_responses():
    client = _build_client()

    response = client.get("/app-exception")

    assert response.status_code == 400
    _assert_security_headers(response)


def test_security_headers_added_to_streaming_responses():
    client = _build_client()

    response = client.get("/stream")

    assert response.status_code == 200
    assert response.text == "chunk-1chunk-2"
    _assert_security_headers(response)


def test_security_headers_can_be_disabled():
    client = _build_client(security_headers_enabled=False)

    response = client.get("/ok")

    assert response.status_code == 200
    for header in SECURITY_HEADERS:
        assert header not in response.headers
