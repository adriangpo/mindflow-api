"""OpenAPI documentation contract tests."""

from fastapi.routing import APIRoute

from src.main import app

MIN_DESCRIPTION_LENGTH = 60
EXCLUDED_PATHS = {
    "/docs",
    "/redoc",
    "/openapi.json",
}


def _iter_schema_routes():
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if not route.include_in_schema:
            continue
        if route.path in EXCLUDED_PATHS:
            continue
        yield route


def test_all_schema_routes_have_explicit_summary_and_rich_description():
    """Ensure every exposed route defines explicit OpenAPI summary and rich description text."""
    missing_summary: list[str] = []
    weak_descriptions: list[str] = []

    for route in _iter_schema_routes():
        methods = ",".join(sorted(route.methods or []))
        route_label = f"{methods} {route.path}"

        if route.summary is None or not route.summary.strip():
            missing_summary.append(route_label)

        description = (route.description or "").strip()
        if len(description) < MIN_DESCRIPTION_LENGTH:
            weak_descriptions.append(route_label)

    assert not missing_summary, f"Routes missing explicit summary: {missing_summary}"
    assert not weak_descriptions, f"Routes missing detailed description: {weak_descriptions}"


def test_special_routes_expose_custom_openapi_contracts():
    """Ensure special-case routes keep their custom OpenAPI content and summaries."""
    schema = app.openapi()

    export_events = schema["paths"]["/api/exports/events"]["get"]
    assert "text/event-stream" in export_events["responses"]["200"]["content"]

    export_download = schema["paths"]["/api/exports/{job_id}/download"]["get"]["responses"]
    assert "307" in export_download

    root_operation = schema["paths"]["/"]["get"]
    assert root_operation["summary"] == "Get basic API availability"

    health_operation = schema["paths"]["/health"]["get"]
    assert health_operation["summary"] == "Get health probe status"
