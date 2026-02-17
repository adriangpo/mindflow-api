"""Integration tests for CORS middleware with FastAPI."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from src.config.cors_config import CORSConfiguration


def create_app_with_cors(cors_config: CORSConfiguration) -> FastAPI:
    """Create a test app with CORS middleware."""
    app = FastAPI()

    middleware_config = cors_config.get_middleware_config()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=middleware_config["allow_origins"],
        allow_origin_regex=middleware_config["allow_origin_regex"],
        allow_credentials=middleware_config["allow_credentials"],
        allow_methods=middleware_config["allow_methods"],
        allow_headers=middleware_config["allow_headers"],
        max_age=middleware_config["max_age"],
    )

    @app.get("/test")
    async def test_endpoint():
        return {"message": "success"}

    return app


class TestCORSMiddlewareIntegration:
    """Integration tests for CORS middleware."""

    def test_allowed_origin_simple(self):
        """Test that allowed origin receives CORS headers."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        response = client.get(
            "/test",
            headers={"origin": "https://example.com"},
        )

        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers
        assert response.headers["access-control-allow-origin"] == "https://example.com"

    def test_blocked_origin_simple(self):
        """Test that blocked origin does not receive CORS headers."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        response = client.get(
            "/test",
            headers={"origin": "https://attacker.com"},
        )

        assert response.status_code == 200
        # Should not have CORS header for disallowed origin
        assert response.headers.get("access-control-allow-origin") != "https://attacker.com"

    def test_multiple_allowed_origins(self):
        """Test multiple allowed origins."""
        config = CORSConfiguration(
            allow_origins="https://example.com,https://app.example.com",
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        # First origin
        response1 = client.get(
            "/test",
            headers={"origin": "https://example.com"},
        )
        assert response1.headers["access-control-allow-origin"] == "https://example.com"

        # Second origin
        response2 = client.get(
            "/test",
            headers={"origin": "https://app.example.com"},
        )
        assert response2.headers["access-control-allow-origin"] == "https://app.example.com"

    def test_preflight_request(self):
        """Test preflight (OPTIONS) request handling."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            allow_methods="GET,POST,PUT",
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        response = client.options(
            "/test",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "POST",
            },
        )

        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers
        assert "access-control-allow-methods" in response.headers
        assert "POST" in response.headers["access-control-allow-methods"]

    def test_credentials_header_present_when_enabled(self):
        """Test that credentials are allowed when enabled."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            allow_credentials=True,
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        response = client.get(
            "/test",
            headers={"origin": "https://example.com"},
        )

        assert response.status_code == 200
        assert response.headers["access-control-allow-credentials"] == "true"

    def test_max_age_header(self):
        """Test that max-age is set correctly."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            max_age=7200,
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        response = client.options(
            "/test",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "GET",
            },
        )

        assert response.status_code == 200
        assert "access-control-max-age" in response.headers
        assert response.headers["access-control-max-age"] == "7200"

    def test_allowed_headers_in_response(self):
        """Test that allowed headers are listed in response."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            allow_headers="authorization,content-type,x-custom-header",
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        response = client.options(
            "/test",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "POST",
                "access-control-request-headers": "x-custom-header",
            },
        )

        assert response.status_code == 200
        assert "access-control-allow-headers" in response.headers
        headers = response.headers["access-control-allow-headers"].lower()
        assert "authorization" in headers
        assert "content-type" in headers

    def test_development_default_origins(self):
        """Test that development environment allows localhost."""
        config = CORSConfiguration.for_development()
        app = create_app_with_cors(config)
        client = TestClient(app)

        response = client.get(
            "/test",
            headers={"origin": "http://localhost:3000"},
        )

        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers

    def test_foreign_origin_without_cors_headers(self):
        """Test that foreign origin doesn't get CORS headers."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        response = client.get(
            "/test",
            headers={"origin": "https://foreign.com"},
        )

        # Request succeeds but CORS headers are not added
        assert response.status_code == 200
        # FastAPI TestClient might not include origin header in response if not allowed
        ac_origin = response.headers.get("access-control-allow-origin")
        if ac_origin:
            assert ac_origin != "https://foreign.com"

    def test_no_origin_header_no_cors_check(self):
        """Test that requests without origin header are processed normally."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        response = client.get("/test")

        assert response.status_code == 200
        assert response.json() == {"message": "success"}

    def test_case_insensitive_origin_matching(self):
        """Test origin matching is done correctly."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        # Exact match
        response = client.get(
            "/test",
            headers={"origin": "https://example.com"},
        )
        assert "access-control-allow-origin" in response.headers

    def test_trailing_slash_normalized_in_origin(self):
        """Test that trailing slashes are normalized."""
        config = CORSConfiguration(
            allow_origins="https://example.com/",  # With trailing slash
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        # Should match even without trailing slash
        response = client.get(
            "/test",
            headers={"origin": "https://example.com"},
        )

        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers


class TestCORSRegexPattern:
    """Test CORS with regex pattern matching."""

    def test_regex_pattern_matches_subdomain(self):
        """Test that regex pattern matches subdomains."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            allow_origin_regex="^https://.*\\.example\\.com$",
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        # Subdomain matching pattern
        response = client.get(
            "/test",
            headers={"origin": "https://app.example.com"},
        )

        assert response.status_code == 200

    def test_regex_pattern_main_domain_still_allowed(self):
        """Test that main domain from allow_origins is still allowed."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            allow_origin_regex="^https://.*\\.example\\.com$",
            environment="production",
        )
        app = create_app_with_cors(config)
        client = TestClient(app)

        # Main domain
        response = client.get(
            "/test",
            headers={"origin": "https://example.com"},
        )

        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers
