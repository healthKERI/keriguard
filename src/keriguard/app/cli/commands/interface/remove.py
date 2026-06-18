# -*- encoding: utf-8 -*-
"""
keriguard.app.cli.commands.interface.remove module

Revoke KERI credentials for Wireguard interface configuration.
"""

import argparse
import asyncio
import sys

import httpx
from keri import help
from keri.app.httping import CESR_CONTENT_TYPE
from keri import kering
from keri.app import connecting
from keri.app.cli.common import existing
from keri.help import helping
from keri.vdr import credentialing

from keriguard.core.kering import Issuer
from keriguard.core.wireguarding import Schema

parser = argparse.ArgumentParser(
    description="Revoke a previously issued KERI credential for Wireguard interface configuration."
)
parser.set_defaults(handler=lambda args: asyncio.run(revoke_credential(args)))

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

# Credential revocation arguments
parser.add_argument(
    "--recipient",
    "-r",
    required=True,
    help="AID or alias of the credential recipient",
)
parser.add_argument(
    "--registrar-url",
    type=str,
    required=True,
    help="URL to send revocation data via PUT request",
)
parser.add_argument(
    "--authenticate",
    "-z",
    help="Prompt the controller for authentication codes for each witness",
    action="store_true",
)

logger = help.ogler.getLogger()


async def revoke_credential(args):
    """Revoke a KERI credential for Wireguard interface configuration."""
    name = args.name
    alias = args.alias
    bran = args.bran

    # Load existing Hab
    with existing.existingHab(name=name, alias=alias, base=args.base, bran=bran) as (
        hby,
        hab,
    ):
        # Validate recipient exists - use same 3-tier lookup as publish.py
        recipient = ""
        recipient_name = ""
        if args.recipient not in hby.kevers:
            if (recipient_hab := hby.habByName(args.recipient)) is not None:
                recipient = recipient_hab.pre
                recipient_name = recipient_hab.alias
            else:
                org = connecting.Organizer(hby=hby)
                results = org.find("alias", args.recipient)
                if not results:
                    raise kering.ConfigurationError(
                        f"Recipient '{args.recipient}' not found. "
                        f"Resolve recipient OOBI first with: kli oobi resolve --name {name} --oobi-alias <alias> --oobi <url>"
                    )
                recipient = results[0].get("id")
                recipient_name = args.recipient
        else:
            recipient = args.recipient

        # Create Regery
        rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base, temp=hby.temp)

        issuer = Issuer(hby=hby, hab=hab, rgy=rgy)

        try:
            # Find credentials by recipient and schema
            creders = []
            for saider in rgy.reger.subjs.get(keys=recipient):
                said = saider.qb64
                creder, *_ = rgy.reger.cloneCred(said=said)
                if creder.sad.get("s") == Schema.INTERFACE_SCHEMA:
                    creders.append(creder)

            # Handle credential selection based on count
            if len(creders) == 0:
                print(f"No interface credentials found for recipient {args.recipient}")
                return 1

            elif len(creders) > 1:
                # Multiple credentials - show interactive menu
                print(
                    f"\nMultiple interface credentials found for recipient {args.recipient}"
                )
                print("Please select the credential to revoke:\n")

                while True:
                    output_choices(creders)
                    num = input("\nEnter the number of the credential to revoke: ")
                    try:
                        num = int(num)
                        if num < 1 or num > len(creders):
                            print("Invalid number, please try again.")
                            continue
                        creder = creders[num - 1]
                        break
                    except ValueError:
                        print("Invalid input, please enter a number.")
                        continue
            else:
                # Single credential - show details and require confirmation
                creder = creders[0]

            # Display credential information and ask for confirmation
            display_credential_info(creder, recipient, recipient_name)

            # Confirmation prompt
            print("\n" + "=" * 80)
            confirmation = input(
                "Are you sure you want to REVOKE this credential? (yes/no): "
            )
            print("=" * 80 + "\n")

            if confirmation.lower() not in ["yes", "y"]:
                print("Revocation cancelled.")
                return 0

            # Collect witness auth codes if needed
            auths = {}
            if args.authenticate:
                for wit in hab.kever.wits:
                    if wit in auths:
                        continue
                    code = input(f"Enter code for {wit}: ")
                    auths[wit] = f"{code}#{helping.nowIso8601()}"

            # Revoke the credential
            print(f"\nRevoking credential {creder.said}...", file=sys.stderr)
            creder, revocation_msg = await issuer.revoke_interface_credential(
                credential_said=creder.said,
                auths=auths,
            )

            # Publish revocation message to registrar
            try:
                response = httpx.put(
                    args.registrar_url,
                    content=revocation_msg,
                    headers={"Content-Type": CESR_CONTENT_TYPE},
                    timeout=30.0,
                )
                response.raise_for_status()

                print(
                    f"  Registrar: Revocation sent to {args.registrar_url} (HTTP {response.status_code})",
                    file=sys.stderr,
                )

            except httpx.HTTPError as e:
                print(f"Failed to send revocation to registrar: {e}", file=sys.stderr)
                return 1

            # Success message
            print("\n✓ Interface credential revoked successfully")
            print(f"  Credential SAID: {creder.said}")
            print(f"  Recipient: {recipient}")
            print(f"  Registrar URL: {args.registrar_url}")

            return 0

        except kering.ValidationError as e:
            print(f"Credential revocation validation failed: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            import traceback

            traceback.print_exc()
            print(f"Failed to revoke credential: {e}", file=sys.stderr)
            return 1


def output_choices(creders):
    """Display numbered list of credentials for selection."""
    print(f"{'Number':<10} {'Name':<20}  {'Address':<20}  Port")
    print("-" * 95)

    # Print rows
    for idx, creder in enumerate(creders):
        payload = creder.attrib
        interface_data = payload.get("interface", {})
        metadata = payload.get("interfaceMetadata", {})

        name = metadata.get("interfaceName", "N/A")[:19]
        addr = (
            ", ".join(interface_data.get("address", []))
            if interface_data.get("address")
            else "N/A"
        )
        port = str(interface_data.get("listenPort", "auto"))

        print(f"{str(idx+1)+".":<10} {name:<20}  {addr:<20}  {port}")

    print()


def display_credential_info(creder, recipient, recipient_name):
    """Display detailed credential information for confirmation."""
    payload = creder.attrib
    interface_data = payload.get("interface", {})
    metadata = payload.get("interfaceMetadata", {})

    print("\n" + "=" * 80)
    print("CREDENTIAL TO REVOKE:")
    print("=" * 80)
    print(f"  Credential SAID: {creder.said}")

    if recipient_name:
        print(f"  Recipient: {recipient_name} ({recipient})")
    else:
        print(f"  Recipient: {recipient}")

    print(f"  Recipient AID: {recipient}")
    print(f"  Issuer: {creder.issuer}")

    print("\n  Interface Configuration:")
    print(f"    Name: {metadata.get('interfaceName', 'N/A')}")

    if metadata.get("interfaceDescription"):
        print(f"    Description: {metadata.get('interfaceDescription')}")

    if metadata.get("environment"):
        print(f"    Environment: {metadata.get('environment')}")

    addr = (
        ", ".join(interface_data.get("address", []))
        if interface_data.get("address")
        else "N/A"
    )
    print(f"    Address: {addr}")

    port = interface_data.get("listenPort", "auto")
    print(f"    Listen Port: {port}")

    print("=" * 80)
