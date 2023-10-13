import asyncio
import logging
import uuid
from datetime import datetime
from typing import Callable, Coroutine, Dict, List

import httpx
from openg2p_fastapi_common.errors.base_exception import BaseAppException
from openg2p_fastapi_common.service import BaseService

from ..config import Settings
from ..models.common import (
    Ack,
    CommonResponseMessage,
    MapperValue,
    RequestStatusEnum,
    SingleTxnRefStatus,
    TxnStatus,
)
from ..models.message import MsgHeader
from ..models.resolve import ResolveHttpRequest, ResolveRequest, SingleResolveRequest

_logger = logging.getLogger(__name__)
_config = Settings.get_config(strict=False)


class MapperResolveService(BaseService):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # TODO: Do garbage collection for this
        self.transaction_queue: Dict[str, TxnStatus] = {}

    async def resolve_request(
        self,
        mappings: List[MapperValue],
        callback_func: Callable[[TxnStatus], Coroutine] = None,
    ) -> TxnStatus:
        current_timestamp = datetime.utcnow()

        resolve_request = []
        txn_statuses = {}
        total_count = len(mappings)

        txn_id = str(uuid.uuid4())
        for mapping in mappings:
            reference_id = str(uuid.uuid4())
            txn_statuses[reference_id] = SingleTxnRefStatus(
                status=RequestStatusEnum.rcvd,
                reference_id=reference_id,
                **mapping.model_dump(),
            )
            single_resolve_request = SingleResolveRequest(
                reference_id=reference_id,
                timestamp=current_timestamp,
            )
            if mapping.id:
                single_resolve_request.id = mapping.id
            elif mapping.fa:
                single_resolve_request.fa = mapping.fa
            else:
                # TODO: raise error
                pass
            resolve_request.append(single_resolve_request)

        txn_status = TxnStatus(
            txn_id=txn_id,
            status=RequestStatusEnum.rcvd,
            refs=txn_statuses,
            callable_on_complete=callback_func,
        )

        if not mappings:
            txn_status.status = RequestStatusEnum.succ
            return txn_status

        self.transaction_queue[txn_id] = txn_status
        resolve_http_request = ResolveHttpRequest(
            signature='Signature:  namespace="g2p", '
            'kidId="{sender_id}|{unique_key_id}|{algorithm}", '
            'algorithm="ed25519", created="1606970629", '
            'expires="1607030629", '
            'headers="(created) '
            '(expires) digest", '
            'signature="Base64(signing content)',
            header=MsgHeader(
                message_id=str(uuid.uuid4()),
                message_ts=current_timestamp,
                action="resolve",
                sender_id=_config.mapper_common_sender_id,
                sender_uri=_config.mapper_resolve_sender_url,
                total_count=total_count,
            ),
            message=ResolveRequest(
                transaction_id=txn_id, resolve_request=resolve_request
            ),
        )

        async def start_resolve_process():
            try:
                res = httpx.post(
                    _config.mapper_resolve_url,
                    json=resolve_http_request.model_dump(),
                    timeout=_config.mapper_api_timeout_secs,
                )
                res.raise_for_status()
                res = CommonResponseMessage.model_validate(res.json())
                if res.message.ack_status != Ack.ACK:
                    _logger.error(
                        "Encountered negative ACK from ID Mapper during resolve request"
                    )
                    txn_status.change_all_status(RequestStatusEnum.rjct)
                else:
                    txn_status.change_all_status(RequestStatusEnum.pdng)
            except Exception:
                _logger.exception("Encountered error during ID Mapper resolve request")
                txn_status.change_all_status(RequestStatusEnum.rjct)

        asyncio.create_task(start_resolve_process())
        return txn_status

    async def resolve_request_sync(
        self, mappings: List[MapperValue], loop_sleep=1, max_retries=10
    ) -> TxnStatus:
        txn_status = TxnStatus(
            txn_id="",
            status=RequestStatusEnum.rcvd,
            ref={},
        )

        async def wait_for_callback(rec_txn_status: TxnStatus):
            txn_status.status = rec_txn_status.status
            txn_status.txn_id = rec_txn_status.txn_id
            txn_status.refs = txn_status.refs
            txn_status.callable_on_complete = rec_txn_status.callable_on_complete

        await self.resolve_request(mappings, wait_for_callback)

        retry_count = 0
        while (not txn_status.txn_id) and retry_count < max_retries:
            retry_count += 1
            await asyncio.sleep(loop_sleep)

        if not txn_status.txn_id:
            raise BaseAppException(
                "G2P-MAP-101", "Max retries exhausted while resolving."
            )