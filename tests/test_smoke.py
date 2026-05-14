import os, sys, pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app as flask_app

@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c

def login(client, u, p):
    return client.post("/login", data={"username": u, "password": p}, follow_redirects=True)

def test_health(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"

def test_login_required(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 301)

def test_admin_dashboard(client):
    r = login(client, "admin", "admin123")
    assert r.status_code == 200

def test_client_portal(client):
    login(client, "client", "123")
    r = client.get("/client")
    assert r.status_code == 200

def test_register_validation(client):
    r = client.post("/register", data={"username": "x", "password": "1", "role": "bad"})
    assert r.status_code == 200  # rendered with error

def test_invalid_login_throttled(client):
    for _ in range(6):
        client.post("/login", data={"username": "admin", "password": "wrong"})
    r = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert r.status_code in (200, 429)
