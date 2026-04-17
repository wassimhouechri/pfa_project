import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from app import app as flask_app


@pytest.fixture
def app():
    flask_app.config.update({"TESTING": True, "SECRET_KEY": "test-key"})
    yield flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(client):
    """Client déjà connecté en admin — réutilisé par tous les tests protégés."""
    client.post("/login", data={"username": "admin", "password": "Admin1234!"})
    return client
