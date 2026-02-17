"""Pagination utilities and models for API responses."""

from typing import TypeVar

from pydantic import BaseModel, Field

# Type variables for generic pagination
T = TypeVar("T")


class PaginationParams(BaseModel):
    """Query parameters for pagination.

    Can be used as dependency in FastAPI routes:
    ```python
    @router.get("/items")
    async def list_items(pagination: PaginationParams = Depends()):
        skip = (pagination.page - 1) * pagination.page_size
        # ... query with skip and limit
    ```

    Frontend can disable pagination by using page=None.
    """

    page: int | None = Field(default=1, ge=1, description="Page number (1-indexed). Set to None to disable pagination")

    page_size: int | None = Field(
        default=50, ge=1, le=1000, description="Items per page. Set to None to disable pagination"
    )

    @property
    def skip(self) -> int:
        """Calculate skip/offset for database query."""
        if self.page is None or self.page_size is None:
            return 0
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int | None:
        """Calculate limit for database query (None = no limit)."""
        return self.page_size

    @property
    def is_paginated(self) -> bool:
        """Check if pagination is enabled."""
        return self.page is not None and self.page_size is not None


class PaginatedResponse[T](BaseModel):
    """Generic paginated response model.

    Use with TypeAdapter for JSON serialization:
    ```python
    from pydantic import TypeAdapter

    ta = TypeAdapter(PaginatedResponse[UserResponse])
    json_str = ta.dump_json(paginated_response)
    ```
    """

    items: list[T]
    total: int
    page: int | None = None
    page_size: int | None = None

    @property
    def total_pages(self) -> int | None:
        """Calculate total pages. Returns None if not paginated."""
        if self.page is None or self.page_size is None or self.page_size == 0:
            return None
        return (self.total + self.page_size - 1) // self.page_size

    @property
    def has_next(self) -> bool:
        """Check if there's a next page."""
        if not self.is_paginated or self.total_pages is None:
            return False
        # At this point, page is guaranteed to be not None due to is_paginated check
        assert self.page is not None
        return self.page < self.total_pages

    @property
    def has_previous(self) -> bool:
        """Check if there's a previous page."""
        if not self.is_paginated:
            return False
        # At this point, page is guaranteed to be not None due to is_paginated check
        assert self.page is not None
        return self.page > 1

    @property
    def is_paginated(self) -> bool:
        """Check if response is paginated."""
        return self.page is not None and self.page_size is not None


__all__ = ["PaginatedResponse", "PaginationParams"]
