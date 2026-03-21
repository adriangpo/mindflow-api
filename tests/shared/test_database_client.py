"""Tests for database client URL normalization."""

from src.database.client import _normalize_asyncpg_engine_configuration


class TestAsyncpgEngineConfigurationNormalization:
    """Verify provider URLs are normalized for asyncpg compatibility."""

    def test_maps_neon_sslmode_and_drops_channel_binding(self):
        """Neon libpq params should be adapted before asyncpg sees them."""
        database_url = "".join(
            (
                "postgresql+asyncpg://user:pass@example.neon.tech/db",
                "?sslmode=require&channel_binding=require",
            )
        )
        url, connect_args = _normalize_asyncpg_engine_configuration(database_url)

        assert url.query == {}
        assert connect_args["ssl"] == "require"
        assert "channel_binding" not in connect_args
        assert "prepared_statement_name_func" in connect_args

    def test_preserves_supported_query_params_and_maps_direct_tls(self):
        """Asyncpg-safe query params should survive normalization."""
        url, connect_args = _normalize_asyncpg_engine_configuration(
            "postgresql+asyncpg://user:pass@example.neon.tech/db"
            "?sslmode=require&sslnegotiation=direct&application_name=mindflow"
        )

        assert url.query == {"application_name": "mindflow"}
        assert connect_args["ssl"] == "require"
        assert connect_args["direct_tls"] is True
