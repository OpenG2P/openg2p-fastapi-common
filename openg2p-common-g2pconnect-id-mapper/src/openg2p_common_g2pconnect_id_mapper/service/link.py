import asyncio
import logging
import time
import uuid
from datetime import datetime
from typing import List

import httpx
import orjson
import redis
import redis.asyncio as redis_asyncio
from openg2p_fastapi_common.errors.base_exception import BaseAppException
from openg2p_fastapi_common.service import BaseService

from ..config import Settings
from ..context import queue_redis_async_pool, queue_redis_conn_pool
from ..models.common import (
    Ack,
    CommonResponseMessage,
    MapperValue,
    RequestStatusEnum,
    SingleTxnRefStatus,
    TxnStatus,
)
from ..models.link import LinkHttpRequest, LinkRequest, SingleLinkRequest
from ..models.message import MsgHeader

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class MapperLinkService(BaseService):
    async def link_request(
        self,
        mappings: List[MapperValue],
        txn_id: str = None,
        wait_for_response: bool = True,
        loop_sleep=1,
        max_retries=10,
    ) -> TxnStatus:
        link_http_request, txn_status = self.get_new_link_request(mappings, txn_id)

        queue = redis_asyncio.Redis(connection_pool=queue_redis_async_pool.get())
        await queue.set(
            f"{_config.queue_link_name}{txn_status.txn_id}",
            orjson.dumps(txn_status.model_dump()).decode(),
        )

        if not mappings:
            txn_status.status = RequestStatusEnum.succ
            return txn_status

        if not wait_for_response:
            asyncio.create_task(self.start_link_process(link_http_request, txn_status))
            await queue.aclose()
            return txn_status

        await self.start_link_process(link_http_request, txn_status)

        retry_count = 0
        while retry_count < max_retries:
            res_txn_status = TxnStatus.model_validate(
                orjson.loads(
                    await queue.get(f"{_config.queue_link_name}{txn_status.txn_id}")
                )
            )
            if res_txn_status.status in (
                RequestStatusEnum.succ,
                RequestStatusEnum.rjct,
            ):
                await queue.aclose()
                return res_txn_status
            retry_count += 1
            if loop_sleep:
                await asyncio.sleep(loop_sleep)
        await queue.aclose()
        raise BaseAppException("G2P-MAP-100", "Max retries exhausted while linking.")

    def link_request_sync(
        self,
        mappings: List[MapperValue],
        txn_id: str = None,
        wait_for_response: bool = True,
        loop_sleep=1,
        max_retries=10,
    ) -> TxnStatus:
        link_http_request, txn_status = self.get_new_link_request(mappings, txn_id)

        queue = redis.Redis(connection_pool=queue_redis_conn_pool.get())
        queue.set(
            f"{_config.queue_link_name}{txn_status.txn_id}",
            orjson.dumps(txn_status.model_dump()).decode(),
        )

        if not mappings:
            txn_status.status = RequestStatusEnum.succ
            queue.close()
            return txn_status

        self.start_link_process_sync(link_http_request, txn_status)

        if not wait_for_response:
            return txn_status

        retry_count = 0
        while retry_count < max_retries:
            res_txn_status = TxnStatus.model_validate(
                orjson.loads(queue.get(f"{_config.queue_link_name}{txn_status.txn_id}"))
            )
            if res_txn_status.status in (
                RequestStatusEnum.succ,
                RequestStatusEnum.rjct,
            ):
                queue.close()
                return res_txn_status
            retry_count += 1
            if loop_sleep:
                time.sleep(loop_sleep)

        queue.close()
        raise BaseAppException("G2P-MAP-100", "Max retries exhausted while linking.")

    async def start_link_process(
        self, link_http_request: LinkHttpRequest, txn_status: TxnStatus
    ):
        try:
            client = httpx.AsyncClient()
            res = await client.post(
                _config.mapper_link_url,
                content=link_http_request.model_dump_json(),
                headers={"content-type": "application/json"},
                timeout=_config.mapper_api_timeout_secs,
            )
            await client.aclose()
            res.raise_for_status()
            res = CommonResponseMessage.model_validate(res.json())
            if res.message.ack_status != Ack.ACK:
                _logger.error(
                    "Encountered negative ACK from ID Mapper during link request"
                )
                txn_status.change_all_status(RequestStatusEnum.rjct)
            else:
                txn_status.change_all_status(RequestStatusEnum.pdng)
        except httpx.ReadTimeout:
            # TODO: There is a timeout problem with sunbird
            _logger.exception("Encountered timeout during ID Mapper link request")
        except Exception:
            _logger.exception("Encountered error during ID Mapper link request")
            txn_status.change_all_status(RequestStatusEnum.rjct)

    def start_link_process_sync(
        self, link_http_request: LinkHttpRequest, txn_status: TxnStatus
    ):
        try:
            res = httpx.post(
                _config.mapper_link_url,
                content=link_http_request.model_dump_json(),
                headers={"content-type": "application/json"},
                timeout=_config.mapper_api_timeout_secs,
            )
            res.raise_for_status()
            res = CommonResponseMessage.model_validate(res.json())
            if res.message.ack_status != Ack.ACK:
                _logger.error(
                    "Encountered negative ACK from ID Mapper during link request"
                )
                txn_status.change_all_status(RequestStatusEnum.rjct)
            else:
                txn_status.change_all_status(RequestStatusEnum.pdng)
        except httpx.ReadTimeout:
            # TODO: There is a timeout problem with sunbird
            _logger.exception("Encountered timeout during ID Mapper link request")
        except Exception:
            _logger.exception("Encountered error during ID Mapper link request")
            txn_status.change_all_status(RequestStatusEnum.rjct)

    def get_new_link_request(
        self,
        mappings: List[MapperValue],
        txn_id: str = None,
    ):
        current_timestamp = datetime.utcnow()

        link_request = []
        txn_statuses = {}
        total_count = len(mappings)

        if not txn_id:
            txn_id = str(uuid.uuid4())
        for mapping in mappings:
            reference_id = str(uuid.uuid4())
            txn_statuses[reference_id] = SingleTxnRefStatus(
                status=RequestStatusEnum.rcvd,
                reference_id=reference_id,
                **mapping.model_dump(),
            )
            link_request.append(
                SingleLinkRequest(
                    reference_id=reference_id,
                    timestamp=current_timestamp,
                    id=mapping.id,
                    fa=mapping.fa,
                )
            )
        txn_status = TxnStatus(
            txn_id=txn_id,
            status=RequestStatusEnum.rcvd,
            refs=txn_statuses,
        )

        link_http_request = (
            LinkHttpRequest(
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
                    action="link",
                    sender_id=_config.mapper_common_sender_id,
                    sender_uri=_config.mapper_link_sender_url,
                    total_count=total_count,
                ),
                message=LinkRequest(transaction_id=txn_id, link_request=link_request),
            )
            if mappings
            else None
        )

        return link_http_request, txn_status
