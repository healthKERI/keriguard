# -*- encoding: utf-8 -*-
"""
keriguard.app.sentinel.config

Configuration for Keriguard Sentinel handler.
"""

from dataclasses import dataclass

from keri.app.habbing import Habery, Hab
from keri.vdr.credentialing import Regery


@dataclass
class SentinelConfig:
    """Configuration for Sentinel event handler."""

    # Sentinel framework settings
    export_dir: str  # Directory containing kel/, tel/, cred/
    poll_interval: float = 2.0  # Polling interval in seconds

    # Wireguard configuration
    config_dir: str = "/etc/wireguard"  # Directory for .conf files

    # KERI settings
    hby: Habery = None
    hab: Hab = None
    rgy: Regery = None
    # Handler behavior
    auto_create_configs: bool = True  # Auto-create configs for new AIDs
    auto_add_peers: bool = True  # Auto-add peers on KEL updates
    backup_configs: bool = True  # Create .bak files on updates
