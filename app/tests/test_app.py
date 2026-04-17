"""
Tests automatiques — DevSecOps Demo App
Lancés par le job 'test' du pipeline CI : pytest app/tests/ --cov=app
"""


# ─── /health  (requis par le pipeline DAST / ZAP) ───────────────────────────

class TestHealth:

    def test_health_returns_200(self, client):
        """/health doit toujours répondre 200 — le pipeline ZAP attend cette route."""
        res = client.get("/health")
        assert res.status_code == 200

    def test_health_returns_json(self, client):
        """/health doit retourner du JSON avec status=healthy."""
        res = client.get("/health")
        data = res.get_json()
        assert data is not None
        assert data["status"] == "healthy"
        assert "version" in data

    def test_health_no_auth_required(self, client):
        """/health doit être public — pas de redirect vers login."""
        res = client.get("/health")
        assert res.status_code != 302


# ─── Page d'accueil ──────────────────────────────────────────────────────────

class TestHome:

    def test_home_returns_200(self, client):
        res = client.get("/")
        assert res.status_code == 200

    def test_home_contains_app_name(self, client):
        res = client.get("/")
        assert b"DevSecOps" in res.data

    def test_home_has_login_link(self, client):
        res = client.get("/")
        assert b"login" in res.data.lower()

    def test_home_not_500(self, client):
        res = client.get("/")
        assert res.status_code != 500


# ─── Login ───────────────────────────────────────────────────────────────────

class TestLogin:

    def test_login_page_accessible(self, client):
        res = client.get("/login")
        assert res.status_code == 200

    def test_login_page_has_form(self, client):
        res = client.get("/login")
        assert b"<form" in res.data

    def test_login_correct_credentials_redirects(self, client):
        """Login correct → redirect 302 vers /dashboard."""
        res = client.post("/login", data={
            "username": "admin", "password": "Admin1234!"
        })
        assert res.status_code == 302
        assert "/dashboard" in res.headers["Location"]

    def test_login_user_account_works(self, client):
        """Le compte 'user' doit aussi fonctionner."""
        res = client.post("/login", data={
            "username": "user", "password": "User1234!"
        })
        assert res.status_code == 302

    def test_login_wrong_password_shows_error(self, client):
        res = client.post("/login", data={
            "username": "admin", "password": "mauvais"
        })
        assert res.status_code == 200
        assert "incorrect" in res.data.decode().lower()

    def test_login_unknown_user_shows_error(self, client):
        res = client.post("/login", data={
            "username": "hacker", "password": "anypass"
        })
        assert res.status_code == 200
        assert "incorrect" in res.data.decode().lower()

    def test_login_empty_username_fails(self, client):
        res = client.post("/login", data={"username": "", "password": "Admin1234!"})
        assert res.status_code in [200, 400]

    def test_login_empty_password_fails(self, client):
        res = client.post("/login", data={"username": "admin", "password": ""})
        assert res.status_code in [200, 400]


# ─── Dashboard (protégé) ─────────────────────────────────────────────────────

class TestDashboard:

    def test_dashboard_without_login_redirects(self, client):
        """Sans login → redirect vers /login."""
        res = client.get("/dashboard")
        assert res.status_code == 302
        assert "login" in res.headers["Location"]

    def test_dashboard_with_login_returns_200(self, auth_client):
        res = auth_client.get("/dashboard")
        assert res.status_code == 200

    def test_dashboard_shows_username(self, auth_client):
        res = auth_client.get("/dashboard")
        assert b"admin" in res.data

    def test_dashboard_not_500(self, auth_client):
        res = auth_client.get("/dashboard")
        assert res.status_code != 500


# ─── Logout ──────────────────────────────────────────────────────────────────

class TestLogout:

    def test_logout_redirects(self, auth_client):
        res = auth_client.get("/logout")
        assert res.status_code == 302

    def test_logout_clears_session(self, auth_client):
        with auth_client.session_transaction() as sess:
            assert "username" in sess
        auth_client.get("/logout")
        with auth_client.session_transaction() as sess:
            assert "username" not in sess

    def test_after_logout_dashboard_blocked(self, auth_client):
        auth_client.get("/logout")
        res = auth_client.get("/dashboard")
        assert res.status_code == 302
        assert "login" in res.headers["Location"]


# ─── API REST ────────────────────────────────────────────────────────────────

class TestAPI:

    def test_api_status_public(self, client):
        """/api/status est public et retourne 200."""
        res = client.get("/api/status")
        assert res.status_code == 200

    def test_api_status_json_structure(self, client):
        res = client.get("/api/status")
        data = res.get_json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "message" in data

    def test_api_whoami_blocked_without_login(self, client):
        """/api/whoami est protégé → redirect si pas connecté."""
        res = client.get("/api/whoami")
        assert res.status_code == 302

    def test_api_whoami_returns_username(self, auth_client):
        res = auth_client.get("/api/whoami")
        assert res.status_code == 200
        data = res.get_json()
        assert data["username"] == "admin"
        assert data["logged_in"] is True


# ─── Sécurité ────────────────────────────────────────────────────────────────

class TestSecurity:

    def test_unknown_route_is_404(self, client):
        """URL inconnue → 404, jamais 500."""
        res = client.get("/cette-page-nexiste-pas-xyz123")
        assert res.status_code == 404

    def test_password_never_in_response(self, client):
        """Le mot de passe ne doit JAMAIS apparaître dans une réponse HTML."""
        res = client.post("/login", data={
            "username": "admin", "password": "Admin1234!"
        }, follow_redirects=True)
        assert b"Admin1234!" not in res.data

    def test_session_empty_after_logout(self, auth_client):
        auth_client.get("/logout")
        with auth_client.session_transaction() as sess:
            assert "username" not in sess

    def test_sql_injection_attempt_safe(self, client):
        """Une tentative d'injection SQL ne doit pas crasher le serveur."""
        res = client.post("/login", data={
            "username": "admin' OR '1'='1",
            "password": "' OR '1'='1"
        })
        assert res.status_code in [200, 400]
        assert res.status_code != 500

    def test_xss_attempt_safe(self, client):
        """Une tentative XSS dans le username ne doit pas crasher."""
        res = client.post("/login", data={
            "username": "<script>alert(1)</script>",
            "password": "anything"
        })
        assert res.status_code in [200, 400]
        assert res.status_code != 500
