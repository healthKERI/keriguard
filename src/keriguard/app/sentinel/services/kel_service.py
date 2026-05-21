# -*- encoding: utf-8 -*-
"""
keriguard.app.sentinel.services.kel_service

Business logic for KEL event processing.
"""

import base64
from pathlib import Path

import pysodium
from keri import help
from keri.core.coring import Verfer
from keri.core.eventing import Kever

from keriguard.core import (
    WireguardConfigParser,
    WireguardConfigWriter,
    WireguardPeer,
)
from ..config import SentinelConfig

logger = help.ogler.getLogger()


class KELService:
    """Service for managing Wireguard configs based on KEL events."""

    def __init__(self, config: SentinelConfig):
        self.config = config

    async def update_peer_for_aid(
        self,
        aid: str,
        verfer: Verfer,
        kever: Kever,
    ):
        """
        Update or create Wireguard peer configuration for an AID.

        Converts the KERI verfer to a Wireguard public key and
        updates the peer configuration.
        """
        # Convert KERI verfer to Wireguard public key
        public_key = self._verfer_to_wg_pubkey(verfer)

        logger.info(f"Updating peer for AID {aid}")
        logger.debug(f"  Public key: {public_key[:16]}...")

        # Find config file for this AID (or create if auto-create enabled)
        config_path = self._get_config_path(aid)

        if not config_path.exists():
            if self.config.auto_create_configs:
                logger.info(f"Creating new config for AID {aid}")
                await self._create_config_for_aid(aid, public_key, kever)
            else:
                logger.warning(f"Config not found for {aid} and auto-create disabled")
            return

        # Load existing config
        config = WireguardConfigParser.parse_file(config_path)

        # Check if peer already exists
        existing_peer = config.get_peer_by_aid(aid)

        if existing_peer:
            # Update existing peer's key if changed
            if existing_peer.public_key != public_key:
                logger.info(f"Updating public key for peer {aid}")
                config.remove_peer_by_aid(aid)
                new_peer = WireguardPeer(
                    public_key=public_key,
                    allowed_ips=existing_peer.allowed_ips,
                    endpoint=existing_peer.endpoint,
                    persistent_keepalive=existing_peer.persistent_keepalive,
                    preshared_key=existing_peer.preshared_key,
                    peer_name=existing_peer.peer_name,
                    keri_aid_qb64=aid,
                )
                config.add_peer(new_peer)
            else:
                logger.debug(f"Public key unchanged for {aid}")
                return
        elif self.config.auto_add_peers:
            # Add new peer
            logger.info(f"Adding new peer for AID {aid}")
            new_peer = WireguardPeer(
                public_key=public_key,
                allowed_ips=self._generate_allowed_ips(aid),
                keri_aid_qb64=aid,
                peer_name=f"peer-{aid[:8]}",
            )
            config.add_peer(new_peer)
        else:
            logger.warning(f"Peer not found for {aid} and auto-add disabled")
            return

        # Save updated config
        if self.config.backup_configs:
            backup_path = config_path.with_suffix(config_path.suffix + ".bak")
            backup_path.write_bytes(config_path.read_bytes())

        WireguardConfigWriter.write_file(config, config_path)
        logger.info(f"Updated config file: {config_path}")

    def _verfer_to_wg_pubkey(self, verfer: Verfer) -> str:
        """Convert KERI verfer to Wireguard public key."""
        # Convert signing key to encryption key
        public_key_bytes = pysodium.crypto_sign_pk_to_box_pk(verfer.raw)
        return base64.b64encode(public_key_bytes).decode("ascii")

    def _get_config_path(self, aid: str) -> Path:
        """Get config file path for an AID."""
        config_dir = Path(self.config.config_dir)
        # Use first 8 chars of AID for filename
        return config_dir / f"wg-{aid[:8]}.conf"

    async def _create_config_for_aid(
        self,
        aid: str,
        public_key: str,
        kever: Kever,
    ):
        """Create new Wireguard config for an AID."""
        # This would require access to a Hab to generate interface keys
        # For now, just log that we would create it
        logger.info(f"Would create config for {aid} (not implemented)")

    def _generate_allowed_ips(self, aid: str) -> list[str]:
        """Generate allowed IPs for a peer based on AID."""
        # Simple implementation: use hash of AID to generate IP
        # In production, you'd want a more sophisticated allocation
        return ["10.0.0.0/32"]  # Placeholder
