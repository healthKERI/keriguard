# -*- encoding: utf-8 -*-
"""
keriguard.app.sentinel.services.tel_service

Business logic for TEL event processing.
"""

from pathlib import Path

from keri import help
from keri.core.serdering import SerderACDC

from keriguard.core.systeming import restart_wireguard
from keriguard.core.wireguarding import Schema, WireguardConfigManager
from ..config import SentinelHandlerConfig

logger = help.ogler.getLogger()


class TELService:
    """Service for managing transaction-based peer authorizations."""

    def __init__(self, config: SentinelHandlerConfig, config_dir):
        self.config = config
        self.hby = config.hby
        self.rgy = config.rgy
        self.kgb = config.kgb
        self.config_dir = config_dir

    async def process_revocation_event(self, creder: SerderACDC):
        """
        Process TEL transaction for peer authorization.

        Future implementation:
        - Parse transaction data
        - Update peer configs based on transaction state
        - Implement bandwidth limits, time restrictions, etc.
        """

        try:
            match creder.schema:
                case Schema.INTERFACE_SCHEMA:
                    await self.process_interface_credential_revocation(
                        creder.said, creder
                    )
                case Schema.CONNECTION_SCHEMA:
                    await self.process_connection_credential_revocation(
                        creder.said, creder
                    )
                case _:
                    print(f"Unknown credential schema: {creder.schema}")
                    return -1

        except Exception as e:
            print(f"Error processing revocation event: {e}")
            return -1

        return 0

    async def process_interface_credential_revocation(self, said, creder):
        pass

    async def process_connection_credential_revocation(self, said, creder):
        edges = creder.edge

        # Extract peer1 and peer2 from edges
        peer1 = edges.get("peer1")
        peer2 = edges.get("peer2")

        if not peer1 or not peer2:
            logger.error(f"Connection credential {said} missing peer1 or peer2")
            return

        # Clone both interface credentials
        peer1_interface_creder, *_ = self.rgy.reger.cloneCred(said=peer1.get("n"))
        peer2_interface_creder, *_ = self.rgy.reger.cloneCred(said=peer2.get("n"))

        if not peer1_interface_creder or not peer2_interface_creder:
            logger.error(f"Failed to load interface credentials for connection {said}")
            return

        # Determine which peer is local by checking interface credential recipients
        peer1_recipient = peer1_interface_creder.attrib.get("i")
        peer2_recipient = peer2_interface_creder.attrib.get("i")

        # Check if peer1's interface belongs to this host
        if (hab := self.hby.habs.get(peer1_recipient)) is not None:
            # peer1 is local, peer2 is remote
            local_interface_creder = peer1_interface_creder
            remote_interface_creder = peer2_interface_creder

            logger.debug(f"Matched peer1 interface to local host: {peer1_recipient}")
        # Check if peer2's interface belongs to this host
        elif (hab := self.hby.habs.get(peer2_recipient)) is not None:
            # peer2 is local, peer1 is remote
            local_interface_creder = peer2_interface_creder
            remote_interface_creder = peer1_interface_creder

            logger.debug(f"Matched peer2 interface to local host: {peer2_recipient}")
        else:
            # Neither peer is local, ignore this credential
            logger.debug(
                f"Neither peer interface belongs to this host, ignoring credential {said}"
            )
            return

        # Extract interface name from local interface credential
        local_payload = local_interface_creder.attrib
        metadata = local_payload.get("interfaceMetadata")
        interface_name = metadata.get("interfaceName")

        config_path = Path(self.config_dir) / f"{interface_name}.conf"
        if not config_path.exists() or not config_path.is_file():
            logger.error(f"Interface configuration file not found for {interface_name}")
            return

        manager = WireguardConfigManager(hab=hab)
        config = manager.load_config(config_path)

        remote_aid = remote_interface_creder.attrib.get("i")
        if remote_aid not in hab.kevers:
            logger.info(f"Remove peer to remove {remote_aid} not known locally.")
            return

        if not manager.remove_peer_from_config_by_aid(config, aid=remote_aid):
            logger.info(
                f"Failed to remove peer {remote_aid} from config {interface_name}."
            )
            return

        # Save updated configuration
        manager.save_config(config, config_path, backup=True)

        conn_config_path = str(Path(self.config_dir) / f"{interface_name}.conf")
        await restart_wireguard(interface_name, conn_config_path)

        logger.info(f"Removed peer {remote_aid} from config {interface_name}.")
