"""Test server"""

from fastapi.testclient import TestClient

from dragonfly import __version__
from dragonfly.server import app

client = TestClient(app)


def test_read_main():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {
        "message": "Welcome to the API",
        "version": __version__,
    }
