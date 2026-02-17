"""SQLAlchemy query helpers for pagination."""

from typing import TypeVar

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.base import Base

from .pagination import PaginationParams

ModelType = TypeVar("ModelType", bound=Base)


class SQLAlchemyPagination:
    """Helper class for paginating SQLAlchemy queries."""

    @staticmethod
    async def paginate(
        session: AsyncSession,
        model: type[ModelType],
        pagination: PaginationParams,
        filters: list | None = None,
    ) -> tuple[list[ModelType], int]:
        """Paginate a SQLAlchemy model query.

        Args:
            session: Database session
            model: SQLAlchemy model class
            pagination: PaginationParams with page and page_size
            filters: Optional list of SQLAlchemy filter conditions

        Returns:
            Tuple of (items, total_count)

        Example:
            ```python
            items, total = await SQLAlchemyPagination.paginate(
                session,
                User,
                pagination,
                filters=[User.status == "active"]
            )
            ```

        """
        # Build base query
        stmt = select(model)
        if filters:
            for filter_condition in filters:
                stmt = stmt.where(filter_condition)

        # Get total count
        count_stmt = select(func.count()).select_from(model)
        if filters:
            for filter_condition in filters:
                count_stmt = count_stmt.where(filter_condition)

        total_result = await session.execute(count_stmt)
        total = total_result.scalar_one()

        # Apply pagination
        if pagination.is_paginated:
            stmt = stmt.offset(pagination.skip).limit(pagination.limit)

        result = await session.execute(stmt)
        items = list(result.scalars().all())

        return items, total

    @staticmethod
    async def paginate_with_response(
        session: AsyncSession,
        model: type[ModelType],
        pagination: PaginationParams,
        filters: list | None = None,
        response_model: type | None = None,
    ) -> dict:
        """Paginate and return formatted response dict.

        Args:
            session: Database session
            model: SQLAlchemy model class
            pagination: PaginationParams
            filters: Optional list of SQLAlchemy filter conditions
            response_model: Optional Pydantic model for serialization

        Returns:
            Dict with items, total, page, page_size

        Example:
            ```python
            response = await SQLAlchemyPagination.paginate_with_response(
                session,
                User,
                pagination,
                response_model=UserResponse
            )
            return response
            ```

        """
        items, total = await SQLAlchemyPagination.paginate(
            session,
            model,
            pagination,
            filters,
        )

        # Serialize items if response model provided
        if response_model:
            serialized_items = [response_model.model_validate(item) for item in items]  # type: ignore[attr-defined]
        else:
            serialized_items = items

        return {
            "items": serialized_items,
            "total": total,
            "page": pagination.page,
            "page_size": pagination.page_size,
        }


__all__ = ["SQLAlchemyPagination"]
