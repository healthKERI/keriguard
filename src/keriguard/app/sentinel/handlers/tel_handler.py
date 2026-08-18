# -*- encoding: utf-8 -*-
"""
keriguard.app.sentinel.handlers.tel_handler

TEL (Transaction Event Log) event handler.
"""

from keri.kering import Ilks
from sentinel.framework import TELEvent
from keri import help

from ..config import SentinelHandlerConfig
from ..services.tel_service import TELService

logger = help.ogler.getLogger()


class TELHandler:
    """Handler for TEL events - manages transaction-based peer authorizations."""

    def __init__(self, config: SentinelHandlerConfig):
        self.config = config
        self.rgy = config.rgy
        self.service = TELService(config, config.config_dir)

    async def process(self, event: TELEvent):
        """
        Process TEL event for transaction-based peer management.

        TEL events could track:
        - Bandwidth allocations
        - Time-based access grants
        - Usage transactions
        """
        logger.info(f"Processing TEL event for credential SAID: {event.aid}")

        creder, *_ = self.rgy.reger.cloneCred(said=event.aid)

        regk = creder.regi
        status = self.rgy.tevers[regk].vcState(creder.said)
        if status.et not in [Ilks.rev, Ilks.brv]:
            logger.debug(
                f"TEL handling ignoring non-revocation event for credential SAID: {event.aid}"
            )
            return

        await self.service.process_revocation_event(creder=creder)

        logger.info(f"TEL event processed for {event.aid}")
