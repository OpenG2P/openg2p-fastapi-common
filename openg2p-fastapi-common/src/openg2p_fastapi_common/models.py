"""Module containing base models"""

import sys
from datetime import datetime, timezone

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from sqlalchemy import DateTime, inspect, select
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .context import dbengine


class BaseORMModel(DeclarativeBase):
    __enabled__ = True
    __abstract__ = True
    __allow_unmapped__ = True
    __table_exists: bool | None = None

    @classmethod
    async def create_migrate(cls):
        if cls.__enabled__:
            async with dbengine.get().begin() as conn:
                await conn.run_sync(lambda sconn: cls.metadata.create_all(sconn, tables=[cls.__table__]))

    @classmethod
    async def table_exists_cached(cls) -> bool:
        if cls.__abstract__:
            return False
        if cls.__table_exists is not None:
            return cls.__table_exists
        async with dbengine.get().begin() as conn:
            inspector = inspect(conn)
            cls.__table_exists = await inspector.has_table(cls.__tablename__)
            return cls.__table_exists

    async def update_to_db(self):
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            await session.merge(self)
            await session.commit()


class BaseORMModelWithId(BaseORMModel):
    __abstract__ = True

    id: Mapped[int] = mapped_column(primary_key=True)
    active: Mapped[bool] = mapped_column()

    @classmethod
    async def get_by_id(cls, id: int, active=True) -> Self:
        result = None
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            result = await session.get(cls, id)
            if (not result) or (result.active != active):
                result = None

        return result

    @classmethod
    async def get_all(cls, active=True) -> list[Self]:
        response = []
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            stmt = select(cls).where(cls.active == active).order_by(cls.id.asc())

            result = await session.execute(stmt)

            response = list(result.scalars())
        return response


class BaseORMModelWithTimes(BaseORMModelWithId):
    __abstract__ = True

    created_at: Mapped[datetime] = mapped_column(
        DateTime(), default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None)
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(), default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None)
    )
