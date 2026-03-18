"""Finance service layer."""

from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.features.schedule.models import ScheduleAppointment
from src.features.schedule.schemas import PaymentStatus
from src.shared.pagination.pagination import PaginationParams

from .exceptions import (
    FinanceCustomRangeRequired,
    FinanceInvalidCustomRange,
    FinancialEntryAlreadyReversed,
    FinancialEntryNotFound,
)
from .models import FinancialEntry
from .schemas import (
    FinanceReportView,
    FinancialEntryClassification,
    FinancialEntryCreateRequest,
    FinancialEntryReverseRequest,
    FinancialEntryType,
)

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
