"""Finance feature exceptions."""

from fastapi import HTTPException, status


class FinanceException(HTTPException):
    """Base finance exception."""

    def __init__(
        self,
        detail: str = "Finance operation failed",
        status_code: int = status.HTTP_400_BAD_REQUEST,
    ):
        super().__init__(status_code=status_code, detail=detail)


class FinancialEntryNotFound(FinanceException):
    """Raised when a financial entry does not exist in the tenant."""

    def __init__(self):
        super().__init__(detail="Financial entry not found", status_code=status.HTTP_404_NOT_FOUND)


class FinancialEntryAlreadyReversed(FinanceException):
    """Raised when a financial entry was already reversed."""

    def __init__(self):
        super().__init__(detail="Financial entry is already reversed", status_code=status.HTTP_409_CONFLICT)


class FinanceCustomRangeRequired(FinanceException):
    """Raised when custom report/list range is incomplete."""

    def __init__(self):
        super().__init__(
            detail="custom view requires both start_date and end_date",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class FinanceInvalidCustomRange(FinanceException):
    """Raised when custom report/list range is invalid."""

    def __init__(self):
        super().__init__(
            detail="end_date must be greater than or equal to start_date",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
