"""Finance service layer."""

from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.features.patient.models import Patient
from src.features.schedule.models import ScheduleAppointment
from src.features.schedule.schemas import PaymentStatus
from src.shared.pagination.pagination import PaginationParams
from src.shared.pdf import append_wrapped, build_pdf
from src.shared.storage import StoredFile

from .exceptions import (
    FinanceCustomRangeRequired,
    FinanceInvalidCustomRange,
    FinancialEntryAlreadyReversed,
    FinancialEntryNotFound,
)
from .models import FinancialEntry
from .schemas import (
    FinanceReportResponse,
    FinanceReportView,
    FinancialEntryClassification,
    FinancialEntryCreateRequest,
    FinancialEntryReverseRequest,
    FinancialEntryType,
)
from .storage import FinanceStorage

ZERO_AMOUNT = Decimal("0.00")


class FinanceService:
    """Service for finance reporting and manual entries."""

    @staticmethod
    def _require_tenant_id(session: AsyncSession):
        tenant_id = session.info.get("tenant_id")
        if tenant_id is None:
            raise RuntimeError("Tenant context is required for finance operations")
        return tenant_id

    @staticmethod
    def _resolve_range(
        view: FinanceReportView,
        reference_date: date | None,
        start_date: date | None,
        end_date: date | None,
    ) -> tuple[date | None, date | None]:
        if view == FinanceReportView.TOTAL:
            return None, None

        if view == FinanceReportView.CUSTOM:
            if start_date is None or end_date is None:
                raise FinanceCustomRangeRequired()
            if end_date < start_date:
                raise FinanceInvalidCustomRange()
            return start_date, end_date

        current = reference_date or datetime.now(UTC).date()

        if view == FinanceReportView.DAY:
            return current, current

        if view == FinanceReportView.WEEK:
            week_start = current - timedelta(days=current.weekday())
            return week_start, week_start + timedelta(days=6)

        if view == FinanceReportView.MONTH:
            month_start = current.replace(day=1)
            if month_start.month == 12:
                next_month = month_start.replace(year=month_start.year + 1, month=1, day=1)
            else:
                next_month = month_start.replace(month=month_start.month + 1, day=1)
            return month_start, next_month - timedelta(days=1)

        year_start = current.replace(month=1, day=1)
        year_end = current.replace(month=12, day=31)
        return year_start, year_end

    @staticmethod
    def _apply_entry_filters(
        stmt,
        *,
        tenant_id,
        entry_type: FinancialEntryType | None,
        classification: FinancialEntryClassification | None,
        start_date: date | None,
        end_date: date | None,
        include_reversed: bool,
    ):
        stmt = stmt.where(FinancialEntry.tenant_id == tenant_id)

        if not include_reversed:
            stmt = stmt.where(FinancialEntry.is_reversed.is_(False))

        if entry_type is not None:
            stmt = stmt.where(FinancialEntry.entry_type == entry_type.value)

        if classification is not None:
            stmt = stmt.where(FinancialEntry.classification == classification.value)

        if start_date is not None:
            stmt = stmt.where(FinancialEntry.occurred_on >= start_date)

        if end_date is not None:
            stmt = stmt.where(FinancialEntry.occurred_on <= end_date)

        return stmt

    @staticmethod
    async def create_entry(
        session: AsyncSession,
        user_id: int,
        data: FinancialEntryCreateRequest,
    ) -> FinancialEntry:
        """Create a manual financial entry."""
        entry = FinancialEntry(
            tenant_id=FinanceService._require_tenant_id(session),
            created_by_user_id=user_id,
            entry_type=data.entry_type.value,
            classification=data.classification.value,
            description=data.description,
            amount=data.amount,
            occurred_on=data.occurred_on,
            notes=data.notes,
        )
        session.add(entry)
        await session.flush()
        return entry

    @staticmethod
    async def get_entry(session: AsyncSession, entry_id: int) -> FinancialEntry | None:
        """Get one financial entry from the current tenant."""
        tenant_id = FinanceService._require_tenant_id(session)
        stmt = select(FinancialEntry).where(
            FinancialEntry.id == entry_id,
            FinancialEntry.tenant_id == tenant_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def require_entry(session: AsyncSession, entry_id: int) -> FinancialEntry:
        """Get one financial entry or raise not-found."""
        entry = await FinanceService.get_entry(session, entry_id)
        if entry is None:
            raise FinancialEntryNotFound()
        return entry

    @staticmethod
    async def list_entries(
        session: AsyncSession,
        pagination: PaginationParams,
        *,
        entry_type: FinancialEntryType | None,
        classification: FinancialEntryClassification | None,
        start_date: date | None,
        end_date: date | None,
        include_reversed: bool,
    ) -> tuple[list[FinancialEntry], int]:
        """List manual financial entries in the current tenant."""
        if start_date is not None and end_date is not None and end_date < start_date:
            raise FinanceInvalidCustomRange()

        tenant_id = FinanceService._require_tenant_id(session)

        count_stmt = select(func.count()).select_from(FinancialEntry)
        count_stmt = FinanceService._apply_entry_filters(
            count_stmt,
            tenant_id=tenant_id,
            entry_type=entry_type,
            classification=classification,
            start_date=start_date,
            end_date=end_date,
            include_reversed=include_reversed,
        )

        stmt = select(FinancialEntry).order_by(FinancialEntry.occurred_on.desc(), FinancialEntry.id.desc())
        stmt = FinanceService._apply_entry_filters(
            stmt,
            tenant_id=tenant_id,
            entry_type=entry_type,
            classification=classification,
            start_date=start_date,
            end_date=end_date,
            include_reversed=include_reversed,
        )

        total_result = await session.execute(count_stmt)
        total = total_result.scalar_one()

        if pagination.is_paginated:
            stmt = stmt.offset(pagination.skip).limit(pagination.limit)

        result = await session.execute(stmt)
        return list(result.scalars().all()), total

    @staticmethod
    async def reverse_entry(
        session: AsyncSession,
        user_id: int,
        entry: FinancialEntry,
        data: FinancialEntryReverseRequest,
    ) -> FinancialEntry:
        """Mark a manual financial entry as reversed."""
        if entry.is_reversed:
            raise FinancialEntryAlreadyReversed()

        entry.is_reversed = True
        entry.reversed_at = datetime.now(UTC)
        entry.reversed_by_user_id = user_id
        entry.reversal_reason = data.reversal_reason
        await session.flush()
        return entry

    @staticmethod
    async def _manual_totals(
        session: AsyncSession,
        *,
        start_date: date | None,
        end_date: date | None,
    ) -> tuple[Decimal, int, Decimal, int]:
        """Aggregate manual income and expense totals/counts."""
        tenant_id = FinanceService._require_tenant_id(session)
        stmt = select(
            FinancialEntry.entry_type,
            func.count(FinancialEntry.id),
            func.coalesce(func.sum(FinancialEntry.amount), ZERO_AMOUNT),
        ).where(
            FinancialEntry.tenant_id == tenant_id,
            FinancialEntry.is_reversed.is_(False),
        )

        if start_date is not None:
            stmt = stmt.where(FinancialEntry.occurred_on >= start_date)
        if end_date is not None:
            stmt = stmt.where(FinancialEntry.occurred_on <= end_date)

        stmt = stmt.group_by(FinancialEntry.entry_type)
        result = await session.execute(stmt)

        manual_income_total = ZERO_AMOUNT
        manual_income_count = 0
        manual_expense_total = ZERO_AMOUNT
        manual_expense_count = 0

        for entry_type, count, total in result.all():
            normalized_total = Decimal(str(total))
            if entry_type == FinancialEntryType.INCOME.value:
                manual_income_total = normalized_total
                manual_income_count = count
            elif entry_type == FinancialEntryType.EXPENSE.value:
                manual_expense_total = normalized_total
                manual_expense_count = count

        return manual_income_total, manual_income_count, manual_expense_total, manual_expense_count

    @staticmethod
    async def _automatic_totals(
        session: AsyncSession,
        *,
        start_date: date | None,
        end_date: date | None,
    ) -> tuple[Decimal, int]:
        """Aggregate automatic consultation revenue totals/counts."""
        tenant_id = FinanceService._require_tenant_id(session)
        stmt = select(
            func.count(ScheduleAppointment.id),
            func.coalesce(func.sum(ScheduleAppointment.charge_amount), ZERO_AMOUNT),
        ).where(
            ScheduleAppointment.tenant_id == tenant_id,
            ScheduleAppointment.is_deleted.is_(False),
            ScheduleAppointment.payment_status == PaymentStatus.PAID.value,
            ScheduleAppointment.paid_at.is_not(None),
        )

        if start_date is not None:
            start_dt = datetime.combine(start_date, time.min, tzinfo=UTC)
            stmt = stmt.where(ScheduleAppointment.paid_at >= start_dt)

        if end_date is not None:
            end_dt = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=UTC)
            stmt = stmt.where(ScheduleAppointment.paid_at < end_dt)

        result = await session.execute(stmt)
        count, total = result.one()
        return Decimal(str(total)), count

    @staticmethod
    async def build_report(
        session: AsyncSession,
        *,
        view: FinanceReportView,
        reference_date: date | None,
        start_date: date | None,
        end_date: date | None,
    ) -> dict[str, object]:
        """Build a finance report summary."""
        range_start, range_end = FinanceService._resolve_range(view, reference_date, start_date, end_date)
        automatic_income_total, paid_appointments_count = await FinanceService._automatic_totals(
            session,
            start_date=range_start,
            end_date=range_end,
        )
        manual_income_total, manual_income_count, manual_expense_total, manual_expense_count = (
            await FinanceService._manual_totals(
                session,
                start_date=range_start,
                end_date=range_end,
            )
        )

        total_income = automatic_income_total + manual_income_total
        total_expense = manual_expense_total

        return {
            "view": view,
            "range_start": range_start,
            "range_end": range_end,
            "automatic_income_total": automatic_income_total,
            "manual_income_total": manual_income_total,
            "manual_expense_total": manual_expense_total,
            "total_income": total_income,
            "total_expense": total_expense,
            "net_total": total_income - total_expense,
            "paid_appointments_count": paid_appointments_count,
            "manual_income_count": manual_income_count,
            "manual_expense_count": manual_expense_count,
        }

    @staticmethod
    def _coerce_view(value: FinanceReportView | str) -> FinanceReportView:
        """Normalize finance report view values."""
        if isinstance(value, FinanceReportView):
            return value
        return FinanceReportView(value)

    @staticmethod
    def _coerce_date(value: date | str | None) -> date | None:
        """Normalize finance export date values."""
        if value is None or isinstance(value, date):
            return value
        return date.fromisoformat(value)

    @staticmethod
    async def _list_manual_entries(
        session: AsyncSession,
        *,
        start_date: date | None,
        end_date: date | None,
    ) -> list[FinancialEntry]:
        """List manual entries for finance export detail output."""
        tenant_id = FinanceService._require_tenant_id(session)
        stmt = (
            select(FinancialEntry)
            .where(
                FinancialEntry.tenant_id == tenant_id,
                FinancialEntry.is_reversed.is_(False),
            )
            .order_by(FinancialEntry.occurred_on.desc(), FinancialEntry.id.desc())
        )

        if start_date is not None:
            stmt = stmt.where(FinancialEntry.occurred_on >= start_date)
        if end_date is not None:
            stmt = stmt.where(FinancialEntry.occurred_on <= end_date)

        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def _list_paid_appointments(
        session: AsyncSession,
        *,
        start_date: date | None,
        end_date: date | None,
    ) -> list[tuple[ScheduleAppointment, str]]:
        """List paid appointments for finance export detail output."""
        tenant_id = FinanceService._require_tenant_id(session)
        stmt = (
            select(ScheduleAppointment, Patient.full_name)
            .join(Patient, Patient.id == ScheduleAppointment.patient_id)
            .where(
                ScheduleAppointment.tenant_id == tenant_id,
                ScheduleAppointment.is_deleted.is_(False),
                ScheduleAppointment.payment_status == PaymentStatus.PAID.value,
                ScheduleAppointment.paid_at.is_not(None),
            )
            .order_by(ScheduleAppointment.paid_at.desc(), ScheduleAppointment.id.desc())
        )

        if start_date is not None:
            start_dt = datetime.combine(start_date, time.min, tzinfo=UTC)
            stmt = stmt.where(ScheduleAppointment.paid_at >= start_dt)
        if end_date is not None:
            end_dt = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=UTC)
            stmt = stmt.where(ScheduleAppointment.paid_at < end_dt)

        result = await session.execute(stmt)
        return list(result.tuples().all())

    @staticmethod
    async def export_report_pdf(
        session: AsyncSession,
        *,
        view: FinanceReportView | str,
        reference_date: date | str | None,
        start_date: date | str | None,
        end_date: date | str | None,
    ) -> StoredFile:
        """Export a finance summary report with detail sections as PDF."""
        resolved_view = FinanceService._coerce_view(view)
        resolved_reference_date = FinanceService._coerce_date(reference_date)
        resolved_start_date = FinanceService._coerce_date(start_date)
        resolved_end_date = FinanceService._coerce_date(end_date)

        report = await FinanceService.build_report(
            session,
            view=resolved_view,
            reference_date=resolved_reference_date,
            start_date=resolved_start_date,
            end_date=resolved_end_date,
        )
        report_data = FinanceReportResponse.model_validate(report)
        manual_entries = await FinanceService._list_manual_entries(
            session,
            start_date=report_data.range_start,
            end_date=report_data.range_end,
        )
        paid_appointments = await FinanceService._list_paid_appointments(
            session,
            start_date=report_data.range_start,
            end_date=report_data.range_end,
        )

        lines: list[str] = [
            "Summary",
            f"View: {report_data.view}",
            f"Range Start: {report_data.range_start}",
            f"Range End: {report_data.range_end}",
            f"Automatic Income Total: {report_data.automatic_income_total}",
            f"Manual Income Total: {report_data.manual_income_total}",
            f"Manual Expense Total: {report_data.manual_expense_total}",
            f"Total Income: {report_data.total_income}",
            f"Total Expense: {report_data.total_expense}",
            f"Net Total: {report_data.net_total}",
            f"Paid Appointments Count: {report_data.paid_appointments_count}",
            f"Manual Income Count: {report_data.manual_income_count}",
            f"Manual Expense Count: {report_data.manual_expense_count}",
            "",
            "Manual Entries",
        ]

        if not manual_entries:
            lines.append("No manual entries available")
        for entry in manual_entries:
            lines.append(f"Entry ID: {entry.id}")
            append_wrapped(lines, "Occurred On", str(entry.occurred_on))
            append_wrapped(lines, "Type", entry.entry_type)
            append_wrapped(lines, "Classification", entry.classification)
            append_wrapped(lines, "Description", entry.description)
            append_wrapped(lines, "Amount", f"{entry.amount:.2f}")
            append_wrapped(lines, "Notes", entry.notes or "None")
            lines.append("")

        lines.append("Paid Appointments")
        if not paid_appointments:
            lines.append("No paid appointments available")
        for appointment, patient_name in paid_appointments:
            lines.append(f"Appointment ID: {appointment.id}")
            append_wrapped(lines, "Patient", patient_name)
            append_wrapped(lines, "Starts At", appointment.starts_at.astimezone(UTC).isoformat())
            append_wrapped(
                lines, "Paid At", appointment.paid_at.astimezone(UTC).isoformat() if appointment.paid_at else "None"
            )
            append_wrapped(lines, "Charge Amount", f"{appointment.charge_amount:.2f}")
            append_wrapped(lines, "Status", appointment.status)
            append_wrapped(lines, "Payment Status", appointment.payment_status)
            lines.append("")

        tenant_id = FinanceService._require_tenant_id(session)
        pdf_bytes = build_pdf("Finance Report Export", lines)
        filename = f"finance-report-{resolved_view.value}.pdf"
        return FinanceStorage().store_report_export(tenant_id, filename, pdf_bytes)
