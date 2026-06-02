# -*- encoding: utf-8 -*-
"""
keriguard.app.cli.commands.peer.add module

Issue a KERI credential for Wireguard peer connection configuration.
"""

import argparse
import asyncio
import sys

from keri import help
from keri import kering
from keri.app.cli.common import existing
from keri.help import helping
from keri.vdr import credentialing

from keriguard.core.kering import Issuer

parser = argparse.ArgumentParser(
    description="Issue a KERI credential for Wireguard peer connection configuration."
)
parser.set_defaults(handler=lambda args: asyncio.run(issue_credential(args)))

# KERI identity arguments
parser.add_argument(
    "--name",
    "-n",
    help="keystore name and file location of KERI keystore",
    required=False,
    default="keriguard",
)
parser.add_argument("--alias", action="store", required=False, default="keriguard")
parser.add_argument(
    "--base",
    "-b",
    help="additional optional prefix to file location of KERI keystore",
    required=False,
    default="",
)
parser.add_argument(
    "--passcode",
    "-p",
    help="21 character encryption passcode for keystore (is not saved)",
    dest="bran",
    default=None,
)

# Interface credential references (edges)
parser.add_argument(
    "--local-interface-said",
    required=True,
    help="SAID of the local interface credential",
)
parser.add_argument(
    "--remote-interface-said",
    required=True,
    help="SAID of the remote interface credential",
)

# Connection metadata arguments
parser.add_argument(
    "--connection-name",
    required=True,
    help="Human-readable name for this connection",
)
parser.add_argument(
    "--purpose",
    help="Purpose or description of this connection",
    default=None,
)
parser.add_argument(
    "--environment",
    help="Deployment environment tag",
    choices=["production", "staging", "development", "test"],
    default=None,
)
parser.add_argument(
    "--bandwidth-class",
    help="Expected bandwidth class",
    choices=["low", "medium", "high", "ultra"],
    default=None,
)

# Required peer arguments
parser.add_argument(
    "--allowed-ips",
    "-i",
    required=True,
    action="append",
    help="IP address or CIDR block the peer can route (can be specified multiple times)",
)

# Optional peer parameters
parser.add_argument(
    "--endpoint",
    "-e",
    type=str,
    default=None,
    help="Peer endpoint in format host:port or [IPv6]:port",
)
parser.add_argument(
    "--keepalive",
    type=int,
    default=None,
    help="Persistent keepalive interval in seconds (1-300)",
)
parser.add_argument(
    "--preshared-key",
    "--psk",
    type=str,
    default=None,
    help="Base64-encoded preshared key (32 bytes)",
)
parser.add_argument(
    "--peer-name",
    type=str,
    default=None,
    help="Human-readable name for this peer",
)

parser.add_argument(
    "--output",
    "-o",
    type=str,
    default=None,
    help="Output file for credential",
)
parser.add_argument(
    "--authenticate",
    "-z",
    help="Prompt the controller for authentication codes for each witness",
    action="store_true",
)

logger = help.ogler.getLogger()


async def issue_credential(args):
    """Issue a KERI credential for Wireguard peer connection configuration."""
    name = args.name
    alias = args.alias
    bran = args.bran

    # Load existing Hab
    with existing.existingHab(name=name, alias=alias, base=args.base, bran=bran) as (
        hby,
        hab,
    ):
        # Create Regery
        rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base, temp=hby.temp)

        issuer = Issuer(hby=hby, hab=hab, rgy=rgy)

        # Validate keepalive range if provided (schema requirement)
        if args.keepalive is not None and (args.keepalive < 1 or args.keepalive > 300):
            raise kering.ConfigurationError(
                f"Keepalive must be between 1 and 300 seconds, got {args.keepalive}"
            )

        # Validate connection name length (schema requirement)
        if len(args.connection_name) < 1 or len(args.connection_name) > 128:
            raise kering.ConfigurationError(
                f"Connection name must be between 1 and 128 characters, got {len(args.connection_name)}"
            )

        # Validate purpose length if provided (schema requirement)
        if args.purpose and len(args.purpose) > 512:
            raise kering.ConfigurationError(
                f"Purpose must be 512 characters or less, got {len(args.purpose)}"
            )

        # Build credential data
        print(
            f"Issuing connection credential using KERI identity: {hab.pre}",
            file=sys.stderr,
        )

        # Build peer configuration
        peer_config = {
            "allowedIps": args.allowed_ips,
        }

        # Add optional peer fields
        if args.endpoint:
            peer_config["endpoint"] = args.endpoint
        if args.keepalive is not None:
            peer_config["persistentKeepalive"] = args.keepalive
        if args.preshared_key:
            peer_config["presharedKey"] = args.preshared_key
        if args.peer_name:
            peer_config["peerName"] = args.peer_name

        # Build connection metadata
        connection_metadata = {
            "connectionName": args.connection_name,
        }

        if args.purpose:
            connection_metadata["purpose"] = args.purpose
        if args.environment:
            connection_metadata["environment"] = args.environment
        if args.bandwidth_class:
            connection_metadata["bandwidthClass"] = args.bandwidth_class

        auths = {}
        if args.authenticate:
            for wit in hab.kever.wits:
                if wit in auths:
                    continue
                code = input(f"Entire code for {wit}: ")
                auths[wit] = f"{code}#{helping.nowIso8601()}"

        try:
            creder = await issuer.issue_connection_credential(
                peer=peer_config,
                connection_metadata=connection_metadata,
                local_interface_said=args.local_interface_said,
                remote_interface_said=args.remote_interface_said,
                auths=auths,
            )

            # Output credential grant
            if args.output:
                grant = issuer.grant(creder.said, creder.attrib.get("i"))
                with open(args.output, "wb") as f:
                    f.write(grant)

            # Success message
            print("\n✓ Connection credential issued successfully", file=sys.stderr)
            print(f"  Credential SAID: {creder.said}", file=sys.stderr)
            print(f"  Recipient: {creder.attrib.get("i")}", file=sys.stderr)
            print(f"  Connection: {args.connection_name}", file=sys.stderr)
            print(
                f"  Local Interface SAID: {args.local_interface_said}", file=sys.stderr
            )
            print(
                f"  Remote Interface SAID: {args.remote_interface_said}",
                file=sys.stderr,
            )
            print(f"  Registry: {creder.sad.get("ri")}", file=sys.stderr)
            if args.output:
                print(f"  Output: {args.output}", file=sys.stderr)

            return 0

        except kering.ValidationError as e:
            print(f"Credential validation failed: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            import traceback

            traceback.print_exc()
            print(f"Failed to issue credential: {e}", file=sys.stderr)
            return 1
