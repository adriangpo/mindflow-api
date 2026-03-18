"""Tests for finance feature."""

from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from uuid import UUID

from fastapi import status

from src.features.auth.dependencies import get_current_active_user, get_current_user
from src.features.finance.schemas import FinanceReportView, FinancialEntryCreateRequest
from src.features.finance.service import FinanceService
from src.features.patient.schemas import PatientCreateRequest
from src.features.patient.service import PatientService
from src.features.schedule.schemas import AppointmentModality, PaymentStatus, ScheduleAppointmentCreateRequest
from src.features.schedule.service import ScheduleService
from src.features.schedule_config.schemas import ScheduleConfigurationCreateRequest, WeekDay
from src.features.schedule_config.service import ScheduleConfigurationService
from src.features.user.models import UserRole
from src.main import app


def _tenant_id_from_client(client) -> UUID:
    tenant_id_header = client.headers.get("X-Tenant-ID")
    assert tenant_id_header is not None
    return UUID(tenant_id_header)


async def _create_schedule_configuration(session, user_id: int):
    configuration = await ScheduleConfigurationService.create_configuration(
        session,
        user_id,
        ScheduleConfigurationCreateRequest(
            working_days=[
                WeekDay.MONDAY,
                WeekDay.TUESDAY,
                WeekDay.WEDNESDAY,
                WeekDay.THURSDAY,
                WeekDay.FRIDAY,
                WeekDay.SATURDAY,
                WeekDay.SUNDAY,
            ],
            start_time=time(8, 0),
            end_time=time(18, 0),
            appointment_duration_minutes=50,
            break_between_appointments_minutes=10,
        ),
    )
    await session.flush()
    return configuration


async def _create_patient(session, *, cpf: str = "52998224725"):
    patient = await PatientService.create_patient(
        session,
        PatientCreateRequest(
            full_name="Paciente Financeiro",
            birth_date=date(1990, 1, 1),
            cpf=cpf,
            cep="19900000",
            phone_number="14999999999",
            session_price=Decimal("200.00"),
            session_frequency="weekly",
        ),
    )
    await session.flush()
    return patient


class TestFinanceService:
    """Service-layer tests for finance reporting."""

    async def test_report_combines_automatic_and_manual_totals_using_paid_at(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        report_day = datetime.now(UTC).date()
        future_start = datetime.now(UTC) + timedelta(days=10)

        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=future_start,
                modality=AppointmentModality.IN_PERSON,
                payment_status=PaymentStatus.PAID,
            ),
        )
        appointment.paid_at = datetime.combine(report_day, time(9, 0), tzinfo=UTC)

        await FinanceService.create_entry(
            session,
            user.id,
            FinancialEntryCreateRequest(
                entry_type="income",
                classification="fixed",
                description="Subscription",
                amount=Decimal("50.00"),
                occurred_on=report_day,
                notes="Monthly plan",
            ),
        )
        await FinanceService.create_entry(
            session,
            user.id,
            FinancialEntryCreateRequest(
                entry_type="expense",
                classification="variable",
                description="Office supplies",
                amount=Decimal("30.00"),
                occurred_on=report_day,
                notes=None,
            ),
        )
        await FinanceService.create_entry(
            session,
            user.id,
            FinancialEntryCreateRequest(
                entry_type="income",
                classification="fixed",
                description="Out of range",
                amount=Decimal("999.00"),
                occurred_on=report_day - timedelta(days=10),
                notes=None,
            ),
        )
        await session.commit()

        report = await FinanceService.build_report(
            session,
            view=FinanceReportView.DAY,
            reference_date=report_day,
            start_date=None,
            end_date=None,
        )

        assert report["automatic_income_total"] == Decimal("200.00")
        assert report["manual_income_total"] == Decimal("50.00")
        assert report["manual_expense_total"] == Decimal("30.00")
        assert report["total_income"] == Decimal("250.00")
        assert report["total_expense"] == Decimal("30.00")
        assert report["net_total"] == Decimal("220.00")
        assert report["paid_appointments_count"] == 1
        assert report["manual_income_count"] == 1
        assert report["manual_expense_count"] == 1


class TestFinanceAPI:
    """API-layer tests for finance operations."""

    async def test_create_and_list_entries_with_filters(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        response_one = await client.post(
            "/api/finance/entries",
            json={
                "entry_type": "income",
                "classification": "fixed",
                "description": "Monthly package",
                "amount": "50.00",
                "occurred_on": "2026-03-17",
                "notes": "Recurring",
            },
        )
        assert response_one.status_code == status.HTTP_200_OK

        response_two = await client.post(
            "/api/finance/entries",
            json={
                "entry_type": "expense",
                "classification": "variable",
                "description": "Snacks",
                "amount": "12.50",
                "occurred_on": "2026-03-18",
                "notes": None,
            },
        )
        assert response_two.status_code == status.HTTP_200_OK

        list_response = await client.get(
            "/api/finance/entries?entry_type=income&classification=fixed&start_date=2026-03-01&end_date=2026-03-31"
        )

        assert list_response.status_code == status.HTTP_200_OK
        body = list_response.json()
        assert body["total"] == 1
        assert len(body["entries"]) == 1
        assert body["entries"][0]["description"] == "Monthly package"
        assert body["entries"][0]["entry_type"] == "income"

    async def test_reverse_entry_and_reject_double_reversal(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        create_response = await client.post(
            "/api/finance/entries",
            json={
                "entry_type": "expense",
                "classification": "fixed",
                "description": "Internet",
                "amount": "100.00",
                "occurred_on": "2026-03-17",
                "notes": "Provider invoice",
            },
        )
        assert create_response.status_code == status.HTTP_200_OK
        entry_id = create_response.json()["id"]

        reverse_response = await client.post(
            f"/api/finance/entries/{entry_id}/reverse",
            json={"reversal_reason": "Wrong amount"},
        )
        assert reverse_response.status_code == status.HTTP_200_OK
        assert reverse_response.json()["is_reversed"] is True

        second_reverse = await client.post(
            f"/api/finance/entries/{entry_id}/reverse",
            json={"reversal_reason": "Still wrong"},
        )
        assert second_reverse.status_code == status.HTTP_409_CONFLICT

    async def test_report_custom_range_requires_both_dates(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        response = await client.get("/api/finance/report?view=custom&start_date=2026-03-01")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_assistant_can_access_finance_endpoints(self, auth_client, make_user):
        client, owner = auth_client
        tenant_id = _tenant_id_from_client(client)
        owner.tenant_ids = [tenant_id]

        assistant = await make_user(
            email="assistant_finance@example.com",
            username="assistant_finance",
            roles=[UserRole.ASSISTANT],
            tenant_ids=[tenant_id],
        )

        async def override_get_current_user():
            return assistant

        app.dependency_overrides[get_current_user] = override_get_current_user
        app.dependency_overrides[get_current_active_user] = override_get_current_user
        try:
            response = await client.get("/api/finance/report")
        finally:
            app.dependency_overrides.pop(get_current_user, None)
            app.dependency_overrides.pop(get_current_active_user, None)

        assert response.status_code == status.HTTP_200_OK

    async def test_user_not_assigned_to_tenant_gets_403(self, auth_client):
        client, user = auth_client
        user.tenant_ids = []

        response = await client.get("/api/finance/report")

        assert response.status_code == status.HTTP_403_FORBIDDEN
