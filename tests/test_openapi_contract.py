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


def test_export_job_examples_match_the_queued_job_contract():
    """Ensure export-job examples stay aligned with the job creation response."""
    schema = app.openapi()

    expected_examples = {
        "/api/patients/{patient_id}/export/pdf": "patient_complete_pdf",
        "/api/medical-records/export/pdf": "medical_record_all_pdf",
        "/api/medical-records/patients/{patient_id}/export/pdf": "medical_record_patient_history_pdf",
        "/api/medical-records/{record_id}/export/pdf": "medical_record_single_pdf",
        "/api/finance/report/export/pdf": "finance_report_pdf",
    }

    for path, expected_kind in expected_examples.items():
        operation = schema["paths"][path]["post"]
        example = operation["responses"]["202"]["content"]["application/json"]["examples"]["default"]
        value = example.get("value", example)

        assert value["kind"] == expected_kind
        assert value["status"] == "queued"
        assert value["progress_current"] == 0
        assert value["progress_total"] == 3
        assert value["progress_message"] == "Queued"


def _has_tenant_header(operation: dict) -> bool:
    return any("TenantHeader" in requirement for requirement in operation.get("security", []))


def test_tenant_header_security_is_applied_only_to_tenant_routes():
    """Ensure the custom tenant header contract stays scoped to tenant routes only."""
    schema = app.openapi()

    assert schema["components"]["securitySchemes"]["TenantHeader"]["name"] == "X-Tenant-ID"

    tenant_operations = [
        schema["paths"]["/api/exports/events"]["get"],
        schema["paths"]["/api/notifications/settings"]["get"],
        schema["paths"]["/api/patients"]["get"],
        schema["paths"]["/api/schedule/appointments"]["get"],
    ]
    public_operations = [
        schema["paths"]["/api/auth/login"]["post"],
        schema["paths"]["/api/internal/qstash/exports/process"]["post"],
        schema["paths"]["/api/internal/qstash/notifications/sync"]["post"],
        schema["paths"]["/"]["get"],
        schema["paths"]["/health"]["get"],
    ]

    assert all(_has_tenant_header(operation) for operation in tenant_operations)
    assert all(not _has_tenant_header(operation) for operation in public_operations)
