"""Finance router (API endpoints)."""

from datetime import date

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_tenant_db_session
from src.features.auth.dependencies import require_tenant_membership
from src.features.export.schemas import ExportJobKind, ExportJobResponse, FinanceReportExportRequest
from src.features.export.service import ExportService
from src.features.user.models import User
from src.shared.pagination.pagination import PaginationParams

from .schemas import (
    FinanceReportResponse,
    FinanceReportView,
    FinancialEntryClassification,
    FinancialEntryCreateRequest,
    FinancialEntryListResponse,
    FinancialEntryResponse,
    FinancialEntryReverseRequest,
    FinancialEntryType,
)
from .service import FinanceService

router = APIRouter(
    prefix="/finance",
    tags=["Finance Management"],
)


@router.post("/entries", response_model=FinancialEntryResponse)
async def create_financial_entry(
    data: FinancialEntryCreateRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Create a manual financial entry."""
    entry = await FinanceService.create_entry(session, current_user.id, data)
    await session.commit()
    await session.refresh(entry)
    return FinancialEntryResponse.model_validate(entry)


@router.get("/entries", response_model=FinancialEntryListResponse)
async def list_financial_entries(
    pagination: PaginationParams = Depends(),
    entry_type: FinancialEntryType | None = Query(default=None),
    classification: FinancialEntryClassification | None = Query(default=None),
    start_date: date | None = Query(default=None),
    end_date: date | None = Query(default=None),
    include_reversed: bool = Query(default=False),
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """List manual financial entries with filters."""
    entries, total = await FinanceService.list_entries(
        session=session,
        pagination=pagination,
        entry_type=entry_type,
        classification=classification,
        start_date=start_date,
        end_date=end_date,
        include_reversed=include_reversed,
    )
    return FinancialEntryListResponse(
        entries=[FinancialEntryResponse.model_validate(entry) for entry in entries],
        total=total,
        page=pagination.page or 1,
        page_size=pagination.page_size or 50,
    )


@router.get("/entries/{entry_id}", response_model=FinancialEntryResponse)
async def get_financial_entry(
    entry_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get one manual financial entry."""
    entry = await FinanceService.require_entry(session, entry_id)
    return FinancialEntryResponse.model_validate(entry)


@router.post("/entries/{entry_id}/reverse", response_model=FinancialEntryResponse)
async def reverse_financial_entry(
    entry_id: int,
    data: FinancialEntryReverseRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Reverse a manual financial entry."""
    entry = await FinanceService.require_entry(session, entry_id)
    updated = await FinanceService.reverse_entry(session, current_user.id, entry, data)
    await session.commit()
    await session.refresh(updated)
    return FinancialEntryResponse.model_validate(updated)


@router.get("/report", response_model=FinanceReportResponse)
async def get_finance_report(
    view: FinanceReportView = Query(default=FinanceReportView.DAY),
    reference_date: date | None = Query(default=None),
    start_date: date | None = Query(default=None),
    end_date: date | None = Query(default=None),
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get finance summary report."""
    report = await FinanceService.build_report(
        session,
        view=view,
        reference_date=reference_date,
        start_date=start_date,
        end_date=end_date,
    )
    return FinanceReportResponse.model_validate(report)


@router.post("/report/export/pdf", response_model=ExportJobResponse, status_code=status.HTTP_202_ACCEPTED)
async def export_finance_report_pdf(
    data: FinanceReportExportRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Queue a finance report PDF export."""
    await FinanceService.build_report(
        session,
        view=data.view,
        reference_date=data.reference_date,
        start_date=data.start_date,
        end_date=data.end_date,
    )
    return await ExportService.create_job(
        kind=ExportJobKind.FINANCE_REPORT_PDF,
        tenant_id=session.info["tenant_id"],
        user_id=current_user.id,
        payload=data.model_dump(mode="json"),
    )
