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

from .openapi import (
    CREATE_FINANCIAL_ENTRY_RESPONSES,
    EXPORT_FINANCE_REPORT_RESPONSES,
    FINANCE_EXPORT_DESCRIPTION,
    FINANCE_REPORT_DESCRIPTION,
    FINANCE_REPORT_RESPONSES,
    FINANCIAL_ENTRY_CREATE_DESCRIPTION,
    FINANCIAL_ENTRY_DETAIL_DESCRIPTION,
    FINANCIAL_ENTRY_LIST_DESCRIPTION,
    FINANCIAL_ENTRY_REVERSE_DESCRIPTION,
    GET_FINANCIAL_ENTRY_RESPONSES,
    LIST_FINANCIAL_ENTRIES_RESPONSES,
    REVERSE_FINANCIAL_ENTRY_RESPONSES,
)
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


@router.post(
    "/entries",
    response_model=FinancialEntryResponse,
    summary="Create a manual financial entry",
    description=FINANCIAL_ENTRY_CREATE_DESCRIPTION,
    response_description="The created manual financial entry for the current tenant.",
    responses=CREATE_FINANCIAL_ENTRY_RESPONSES,
)
async def create_financial_entry(
    data: FinancialEntryCreateRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Create a manual financial entry for the active tenant."""
    entry = await FinanceService.create_entry(session, current_user.id, data)
    await session.commit()
    await session.refresh(entry)
    return FinancialEntryResponse.model_validate(entry)


@router.get(
    "/entries",
    response_model=FinancialEntryListResponse,
    summary="List manual financial entries",
    description=FINANCIAL_ENTRY_LIST_DESCRIPTION,
    response_description="A paginated list of manual entries for the current tenant.",
    responses=LIST_FINANCIAL_ENTRIES_RESPONSES,
)
async def list_financial_entries(
    pagination: PaginationParams = Depends(),
    entry_type: FinancialEntryType | None = Query(
        default=None,
        description="Filter by manual entry type (`income` or `expense`).",
    ),
    classification: FinancialEntryClassification | None = Query(
        default=None,
        description="Filter by entry classification (`fixed` or `variable`).",
    ),
    start_date: date | None = Query(
        default=None,
        description="Return entries with `occurred_on` on or after this date.",
    ),
    end_date: date | None = Query(
        default=None,
        description="Return entries with `occurred_on` on or before this date.",
    ),
    include_reversed: bool = Query(
        default=False,
        description="Set to `true` to include reversed entries in the list.",
    ),
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """List manual financial entries with filters and optional pagination."""
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


@router.get(
    "/entries/{entry_id}",
    response_model=FinancialEntryResponse,
    summary="Get one manual financial entry",
    description=FINANCIAL_ENTRY_DETAIL_DESCRIPTION,
    response_description="The requested manual financial entry.",
    responses=GET_FINANCIAL_ENTRY_RESPONSES,
)
async def get_financial_entry(
    entry_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get one manual financial entry from the current tenant."""
    entry = await FinanceService.require_entry(session, entry_id)
    return FinancialEntryResponse.model_validate(entry)


@router.post(
    "/entries/{entry_id}/reverse",
    response_model=FinancialEntryResponse,
    summary="Reverse one manual financial entry",
    description=FINANCIAL_ENTRY_REVERSE_DESCRIPTION,
    response_description="The reversed manual financial entry with reversal metadata.",
    responses=REVERSE_FINANCIAL_ENTRY_RESPONSES,
)
async def reverse_financial_entry(
    entry_id: int,
    data: FinancialEntryReverseRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Reverse a manual financial entry and persist the reversal reason."""
    entry = await FinanceService.require_entry(session, entry_id)
    updated = await FinanceService.reverse_entry(session, current_user.id, entry, data)
    await session.commit()
    await session.refresh(updated)
    return FinancialEntryResponse.model_validate(updated)


@router.get(
    "/report",
    response_model=FinanceReportResponse,
    summary="Build the finance summary report",
    description=FINANCE_REPORT_DESCRIPTION,
    response_description="The aggregated finance summary for the requested report window.",
    responses=FINANCE_REPORT_RESPONSES,
)
async def get_finance_report(
    view: FinanceReportView = Query(
        default=FinanceReportView.DAY,
        description="Select the report window: `day`, `week`, `month`, `year`, `total`, or `custom`.",
    ),
    reference_date: date | None = Query(
        default=None,
        description="Reference date used for `day`, `week`, `month`, and `year` windows. Defaults to current UTC date.",
    ),
    start_date: date | None = Query(
        default=None,
        description="Inclusive start date used only when `view=custom`.",
    ),
    end_date: date | None = Query(
        default=None,
        description="Inclusive end date used only when `view=custom`.",
    ),
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Build a tenant finance summary for the requested time window."""
    report = await FinanceService.build_report(
        session,
        view=view,
        reference_date=reference_date,
        start_date=start_date,
        end_date=end_date,
    )
    return FinanceReportResponse.model_validate(report)


@router.post(
    "/report/export/pdf",
    response_model=ExportJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a finance report PDF export",
    description=FINANCE_EXPORT_DESCRIPTION,
    response_description="The async export job envelope for the queued finance report PDF.",
    responses=EXPORT_FINANCE_REPORT_RESPONSES,
)
async def export_finance_report_pdf(
    data: FinanceReportExportRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Queue a finance report PDF export for the active tenant."""
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
