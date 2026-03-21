"""OpenAPI contract tests for the schedule feature."""

from src.main import app


def test_schedule_routes_expose_rich_openapi_metadata():
    """Ensure the schedule feature exposes route-level OpenAPI metadata and examples."""
    schema = app.openapi()
    schedule_paths = {
        "/api/schedule/appointments": {"post", "get"},
        "/api/schedule/appointments/{appointment_id}": {"get", "put", "delete"},
        "/api/schedule/appointments/{appointment_id}/status": {"patch"},
        "/api/schedule/appointments/{appointment_id}/payment-status": {"patch"},
        "/api/schedule/defaults": {"get"},
        "/api/schedule/availability": {"get"},
    }

    for path, methods in schedule_paths.items():
        assert path in schema["paths"], path
        for method in methods:
            operation = schema["paths"][path][method]
            assert operation["summary"].strip()
            assert len(operation["description"].strip()) >= 60

    delete_operation = schema["paths"]["/api/schedule/appointments/{appointment_id}"]["delete"]
    assert delete_operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "ScheduleMessageResponse"
    )

    create_operation = schema["paths"]["/api/schedule/appointments"]["post"]
    assert "created" in create_operation["responses"]["200"]["content"]["application/json"]["examples"]

    availability_operation = schema["paths"]["/api/schedule/availability"]["get"]
    assert "default" in availability_operation["responses"]["200"]["content"]["application/json"]["examples"]
