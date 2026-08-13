# -*- encoding: utf-8 -*-
"""
KERI
kerugard.app.cli.commands module

Initialize the KERIGuard server
"""

import argparse
import asyncio
import sys
from pathlib import Path

import pyotp
from keri import help
from keri.app import habbing
from keri.help import helping
from keri.vdr import credentialing

from keriguard.core.initializing import (
    KERIGuardConfig,
)
from keriguard.core.querying import Receiptor
from keriguard.core.systeming import restart_guardian, restart_wireguard
from keriguard.core.wireguarding import (
    Schema,
    WireguardConfigParser,
    WireguardConfigWriter,
    KERIKeyGenerator,
)

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description="Initialize a new KERIGuard instance.")
parser.set_defaults(handler=lambda args: asyncio.run(rotate(args)))
parser.add_argument(
    "--config",
    "-c",
    help="Path to the configuration file",
    required=True,
    default=None,
)


def codes(hab):
    cdes = dict()

    try:
        with open(Path.home() / ".keriguard" / hab.pre, "r") as f:
            lines = f.readlines()
            for line in lines:
                splits = line.split(":")
                if len(splits) != 2:
                    continue
                aid, code = splits
                cdes[aid] = code.rstrip()
    except OSError:
        pass

    return cdes


async def rotate(args):
    try:
        config = KERIGuardConfig.load(args.config)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error loading config file: {e}", file=sys.stderr)
        return 1

    hby = habbing.Habery(name=config.name, base=config.base, bran=config.passcode)
    hab = hby.habByName(config.alias)
    rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base, temp=hby.temp)

    c = codes(hab=hab)
    auths = dict()
    time = helping.nowIso8601()
    for wit, code in c.items():
        otp = pyotp.TOTP(s=c[wit])
        auths[wit] = f"{otp.at(helping.fromIso8601(time))}#{time}"

    hab.rotate(isith="1", ncount=1, nsith="1", toad=1, adds=[])
    receiptor = Receiptor(hby=hby)
    await receiptor.receipt(hab.pre, sn=hab.kever.sn, auths=auths)

    key_gen = KERIKeyGenerator(hab)
    private_key, public_key, keri_signer = key_gen.generate_keypair()

    my_saids = [saider.qb64 for saider in rgy.reger.subjs.get(keys=hab.pre)]
    interface_saids = [
        saider.qb64 for saider in rgy.reger.schms.get(keys=Schema.INTERFACE_SCHEMA)
    ]
    saids = list(set(my_saids) & set(interface_saids))
    if not saids:
        print(f"No local interface credential saids found for AID {hab.pre}")
        return -1

    for said in saids:
        interface_creder, *_ = rgy.reger.cloneCred(said=said)
        payload = interface_creder.attrib
        metadata = payload.get("interfaceMetadata")
        interface_name = metadata.get("interfaceName")

        config_path = Path(config.config_dir) / f"{interface_name}.conf"
        if not config_path.exists():
            print(f"Config not found for {hab.pre}")
            return -1

        # Load existing config
        wg_config = WireguardConfigParser.parse_file(config_path)
        wg_config.interface.private_key = private_key

        WireguardConfigWriter.write_file(wg_config, config_path)
        print(f"Wireguard configuration {config_path} updated, restarting services")

        await restart_guardian()
        await restart_wireguard(interface_name, str(config_path))

    return 0
