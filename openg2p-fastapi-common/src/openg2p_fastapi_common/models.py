"""Module containing base models"""

import sys
from datetime import datetime, timezone
from typing import Optional

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from sqlalchemy import Boolean, DateTime, String, inspect, select
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


class PartnerKey(BaseORMModelWithTimes):
    """Partner public-key registry for the "local" JWS verify backend.

    Each row holds one partner's X.509 certificate (PEM), keyed by ``reference_id``
    (``PARTNER_<MNEMONIC>`` — the value ``JWTValidationHelper`` derives from
    ``sender_app_mnemonic``). Public certs are not secret, so they live in this
    table rather than a Secret. Multiple ``active`` rows per partner make rotation
    an overlap operation. Onboarding is seed-based (``crypto_partner_certs``); a
    runtime admin API is a planned follow-up (TODO).

    Only used when ``crypto_backend`` is ``pyjwt`` or ``local``; the keymanager backend never creates
    or reads this table (the service calls ``create_migrate`` only when local).
    """

    __tablename__ = "partner_keys"

    # The base declares a NOT NULL ``active`` with no default; give it one so
    # seed-inserted rows need not set it explicitly.
    active: Mapped[bool] = mapped_column(Boolean(), default=True)
    # PARTNER_<MNEMONIC>, e.g. PARTNER_G2P_BRIDGE. Looked up on every inbound verify.
    reference_id: Mapped[str] = mapped_column(String, index=True)
    # X.509 certificate in PEM (preferred) or a bare public-key PEM.
    public_key: Mapped[str] = mapped_column(String)
    # Optional JWS 'kid' the partner stamps in the protected header (informational;
    # verification keys off reference_id, kid only narrows candidates).
    kid: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    algorithm: Mapped[str] = mapped_column(String, default="RS256")
    # 'active' | 'revoked'. Only 'active' rows are considered at verify time.
    status: Mapped[str] = mapped_column(String, default="active")
    valid_from: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True)
    valid_to: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True)
