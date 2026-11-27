"""mcpauth: the token file and the bearer check (needs Starlette + httpx)."""

import os

import pytest

pytest.importorskip("starlette")
pytest.importorskip("httpx")

from starlette.applications import Starlette  # noqa: E402
from starlette.responses import PlainTextResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

import mcpauth  # noqa: E402


def test_the_token_is_created_once_private_and_kept(tmp_path):
    path = tmp_path / "mcp_token"
    token = mcpauth.load_or_create(path)
    assert len(token) >= 40 and oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert mcpauth.load_or_create(path) == token
    path.write_text("")  # an empty file is replaced, not trusted
    assert mcpauth.load_or_create(path) not in ("", token)


def client(token="s3cret"):
    app = Starlette(routes=[Route("/mcp", lambda r: PlainTextResponse("ok"), methods=["GET", "POST"])])
    return TestClient(mcpauth.RequireToken(app, token))


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": "s3cret"},
                                     {"Authorization": "Bearer s3cret "}, {"Authorization": "bearer s3cret"}])
def test_requests_without_the_token_are_refused(headers):
    r = client().post("/mcp", headers=headers)
    assert r.status_code == 401 and "only Home Assistant" in r.json()["error"]


def test_the_token_lets_requests_through():
    assert client().post("/mcp", headers={"Authorization": "Bearer s3cret"}).text == "ok"
