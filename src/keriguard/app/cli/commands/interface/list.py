# -*- encoding: utf-8 -*-
"""
keriguard.app.cli.commands.interface.list module

List Wireguard interface credentials from KERI registry.
"""

import argparse
import asyncio

from keri import help
from keri.app import connecting
from keri.app.cli.common import existing
from keri.vdr import credentialing

from keriguard.core.wireguarding import Schema

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(
    description="List Wireguard interface credentials from the KERI registry"
)
parser.set_defaults(handler=lambda args: asyncio.run(list_interfaces(args)))
parser.add_argument(
    "--name",
    "-n",
    help="keystore name and file location of KERI keystore",
    required=False,
    default="keriguard",
)
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
parser.add_argument(
    "--verbose",
    "-v",
    help="Show all credential fields",
    action="store_true",
)


def get_recipient_name(hby, recipient):
    if recipient is None:
        return "Unknown"

    if recipient in hby.habs:
        hab = hby.habs[recipient]
        return hab.name
    else:
        org = connecting.Organizer(hby=hby)
        contact = org.get(pre=recipient)
        return contact.get("alias") if contact else None


async def list_interfaces(args):
    """List Wireguard interface credentials from the KERI registry."""
    name = args.name
    bran = args.bran

    try:
        # Load KERI Habery
        with existing.existingHby(name=name, base=args.base, bran=bran) as hby:
            # Create registry for credential access
            rgy = credentialing.Regery(
                hby=hby, name=hby.name, base=hby.base, temp=hby.temp
            )

            # Iterate all credentials and filter by schema
            interfaces = []

            try:
                for saider in rgy.reger.schms.get(keys=Schema.INTERFACE_SCHEMA):
                    try:
                        said = saider.qb64
                        creder, *_ = rgy.reger.cloneCred(said=said)

                        # Extract credential data
                        payload = creder.attrib
                        interface_data = payload.get("interface", {})
                        metadata = payload.get("interfaceMetadata", {})
                        recipient = payload.get("i")
                        recipient_name = get_recipient_name(hby, recipient)

                        interface_info = {
                            "said": creder.said,
                            "recipient": recipient,
                            "recipient_name": recipient_name,
                            "issuer": creder.issuer,
                            "name": metadata.get("interfaceName", "N/A"),
                            "description": metadata.get("interfaceDescription", ""),
                            "environment": metadata.get("environment", ""),
                            "address": interface_data.get("address", []),
                            "listenPort": interface_data.get("listenPort"),
                            # Verbose-only fields
                            "dns": interface_data.get("dns"),
                            "mtu": interface_data.get("mtu"),
                            "table": interface_data.get("table"),
                            "preUp": interface_data.get("preUp"),
                            "postUp": interface_data.get("postUp"),
                            "preDown": interface_data.get("preDown"),
                            "postDown": interface_data.get("postDown"),
                        }
                        interfaces.append(interface_info)

                    except Exception as e:
                        # Log warning and skip credential if parse fails
                        logger.warning(f"Failed to parse credential {said}: {e}")
                        continue

            except Exception as e:
                print(f"Error querying credentials: {e}")
                return 1

            # Display results
            if not interfaces:
                print("No interface credentials found.")
                return 0

            output_table(interfaces, verbose=args.verbose)
            return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


def output_table(interfaces, verbose=False):
    """Output interfaces as a formatted table."""
    if verbose:
        output_table_verbose(interfaces)
        return

    print(f"\nFound {len(interfaces)} interface credential(s):\n")

    # Print header
    print(f"{'Name':<20}  {'Identity':<45}  {'Address':<20}  Port")
    print("-" * 95)

    # Print rows
    for iface in interfaces:
        name = iface["name"][:19]
        recipient_name = iface["recipient_name"]

        if recipient_name:
            ident = f"{recipient_name} ({iface['recipient'][:6]}...{iface['recipient'][-6:]})"
        else:
            ident = iface["recipient"] if iface["recipient"] else ""

        addr = ", ".join(iface["address"]) if iface["address"] else "N/A"
        port = str(iface["listenPort"]) if iface["listenPort"] else "auto"

        print(f"{name:<20}  {ident:<45}  {addr:<20}  {port}")

    print()


def output_table_verbose(interfaces):
    """Output interfaces with all fields."""
    print(f"\nFound {len(interfaces)} interface credential(s):\n")

    for i, iface in enumerate(interfaces, 1):
        recipient_name = iface["recipient_name"]

        if recipient_name:
            ident = f"{recipient_name} ({iface['recipient'][:6]}...{iface['recipient'][-6:]})"
        else:
            ident = iface["recipient"] if iface["recipient"] else ""

        print(f"Interface {i}:")
        print(f"  Name: {iface['name']}")
        print(f"  Identity: {ident}")
        print(f"  Credential SAID: {iface['said']}")
        print(f"  Description: {iface['description']}")
        print(f"  Environment: {iface['environment']}")
        print(f"  Recipient AID: {iface['recipient']}")
        print(f"  Issuer AID: {iface['issuer']}")

        print("\n  Interface Configuration:")
        print(
            f"    Address: {', '.join(iface['address']) if iface['address'] else 'N/A'}"
        )
        print(
            f"    Listen Port: {iface['listenPort'] if iface['listenPort'] else 'auto'}"
        )

        if iface["dns"]:
            print(f"    DNS: {', '.join(iface['dns'])}")
        if iface["mtu"]:
            print(f"    MTU: {iface['mtu']}")
        if iface["table"]:
            print(f"    Table: {iface['table']}")
        if iface["preUp"]:
            print(f"    PreUp: {iface['preUp']}")
        if iface["postUp"]:
            print(f"    PostUp: {iface['postUp']}")
        if iface["preDown"]:
            print(f"    PreDown: {iface['preDown']}")
        if iface["postDown"]:
            print(f"    PostDown: {iface['postDown']}")

        print()
