"""Module containing base models"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import DateTime, select
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .context import dbengine


class BaseORMModel(DeclarativeBase):
    __enabled__ = True

    @classmethod
    async def create_migrate(cls):
        if cls.__enabled__:
            async with dbengine.get().begin() as conn:
                await conn.run_sync(cls.metadata.create_all)


class BaseORMModelWithId(BaseORMModel):
    __abstract__ = True

    id: Mapped[int] = mapped_column(primary_key=True)
    active: Mapped[bool] = mapped_column()

    @classmethod
    async def get_by_id(cls, id: int, active=True) -> "BaseORMModelWithId":
        result = None
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            result = await session.get(cls, id)
            if (not result) or (result.active != active):
                result = None

        return result

    @classmethod
    async def get_all(cls, active=True) -> List["BaseORMModelWithId"]:
        response = []
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            stmt = select(cls).where(cls.active == active).order_by(cls.id.asc())

            result = await session.execute(stmt)

            response = list(result.scalars())
        return response


class BaseORMModelWithTimes(BaseORMModelWithId):
    __abstract__ = True

    created_at: Mapped[datetime] = mapped_column(DateTime(), default=datetime.utcnow)
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(), default=datetime.utcnow
    )
