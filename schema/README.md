# ACDC Wireguard Credential Schemas

This directory contains JSON Schema definitions for ACDC (Authentic Chained Data Containers) credentials used to configure Wireguard VPN connections between KERI-identified hosts.

## Overview

The credential architecture uses **two separate schemas** to avoid circular SAID dependencies while maintaining composability:

1. **Interface Credential** (`wireguard-interface-v1.0.0.json`) - Defines a host's Wireguard interface configuration
2. **Connection Credential** (`wireguard-connection-v1.0.0.json`) - Defines peer connections, references interface credentials via edges

## Why Two Schemas?

### The Problem with Single Schema
If credentials cross-reference each other's SAIDs in edge blocks, you can't compute the SAID until the credential is complete - creating an impossible chicken-and-egg situation.

### The Solution: Layered Architecture

**Layer 1 - Interface Credentials:**
- Issued to each host's AID
- Contains: address, listenPort, dns, mtu, etc.
- Self-contained, no outbound edge references
- Long-lived, only changes when interface config changes

**Layer 2 - Connection Credentials:**
- Issued after interface credentials exist
- Contains: peer-specific settings (allowedIps, endpoint, keepalive)
- References TWO interface credentials via edges (no circular dependency!)
- Can be created/revoked independently per connection

## Schema Files

### wireguard-interface-v1.0.0.json

Defines interface configuration for a Wireguard host.

**Schema SAID:** `EWireguardInterfaceCredentialSchemaV1_0_0`

**Key Fields:**
- `a.interface.publicKey` - Wireguard public key (derived from KERI AID)
- `a.interface.address` - VPN IP addresses in CIDR notation
- `a.interface.listenPort` - UDP port for Wireguard
- `a.interface.dns` - DNS servers (optional)
- `a.interface.mtu` - Maximum transmission unit (optional)
- `a.interfaceMetadata.interfaceName` - Human-readable name

**Example:** See `/tests/fixtures/example_interface_credential.json`

### wireguard-connection-v1.0.0.json

Defines peer connection configuration referencing two interface credentials.

**Schema SAID:** `EWireguardConnectionCredentialSchemaV1_0_0`

**Key Fields:**
- `a.peer.allowedIps` - IP ranges allowed from remote peer
- `a.peer.endpoint` - Remote peer's endpoint (host:port)
- `a.peer.persistentKeepalive` - Keepalive interval (optional)
- `e.localInterface` - Edge reference to local interface credential
- `e.remoteInterface` - Edge reference to remote interface credential

**Example:** See `/tests/fixtures/example_connection_credential.json`

## Credential Issuance Flow

```
1. Issue Interface Credential to Host A
   └─> Contains Host A's interface config (address, port, keys)
   └─> SAID: EHostAInterfaceCredSAID...

2. Issue Interface Credential to Host B
   └─> Contains Host B's interface config
   └─> SAID: EHostBInterfaceCredSAID...

3. Issue Connection Credential to Host A
   └─> Contains peer config pointing to Host B
   └─> Edges reference both interface credentials
   └─> localInterface.o = EHostAInterfaceCredSAID...
   └─> remoteInterface.o = EHostBInterfaceCredSAID...

4. Issue Connection Credential to Host B
   └─> Contains peer config pointing to Host A
   └─> Edges reference both interface credentials (reversed)
   └─> localInterface.o = EHostBInterfaceCredSAID...
   └─> remoteInterface.o = EHostAInterfaceCredSAID...
```

## Credential Processing Flow

When a host processes credentials:

1. **Interface Credential:**
   - Extract interface config from attributes
   - Create/update Wireguard config for this AID
   - Save interface settings (no peers yet)

2. **Connection Credential:**
   - Extract peer config from attributes
   - Resolve edge blocks to fetch interface credentials
   - Extract remote peer's public key from their interface credential
   - Add/update peer in existing Wireguard config
   - Save updated config

## Security Model

**Private Keys:**
- NEVER included in credentials
- Generated locally using `KERIKeyGenerator.generate_keypair()`
- Stored in local keystore only

**Public Keys:**
- Included in interface credentials
- Derived from KERI verification keys via Curve25519
- Resolved from interface credentials when processing connections

**Key Rotation:**
- When KERI keys rotate, new interface credential issued
- Old credential revoked in TEL registry
- Connection credentials automatically reference new interface credential
- CredHandler updates Wireguard config automatically

## Validation Patterns

The schemas include strict validation patterns for:

- **KERI AIDs:** `^E[A-Za-z0-9_-]{43}$`
- **Wireguard Keys:** `^[A-Za-z0-9+/]{43}=$` (base64, 32 bytes)
- **IP Addresses:** CIDR notation, IPv4 and IPv6
- **Endpoints:** `host:port` format
- **Port Ranges:** 1-65535
- **ACDC Version:** `^ACDC10JSON[0-9a-f]{6}_$`

## Integration Points

### Existing Data Models
- Maps to `WireguardInterface` (src/keriguard/core/wireguarding.py:438-466)
- Maps to `WireguardPeer` (src/keriguard/core/wireguarding.py:469-492)

### Credential Processing
- `CredService.process_credential()` - Parse and apply credentials
- `CredHandler` - Handle credential events from Sentinel
- TEL registry checks for revocation status

## Future Implementation

The following components will use these schemas:

- `src/keriguard/core/schema_validator.py` - Validate credentials against schemas
- `src/keriguard/core/acdc_parser.py` - Parse CESR-encoded credentials
- `src/keriguard/app/sentinel/services/cred_service.py` - Process credentials
- `src/keriguard/app/cli/commands/credential/` - CLI commands for issuance

## References

- ACDC Specification: [IETF ACDC Draft](https://trustoverip.github.io/tswg-acdc-specification/)
- KERI Specification: [IETF KERI Draft](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html)
- Wireguard Protocol: [wireguard.com](https://www.wireguard.com/)
- JSON Schema: [json-schema.org](https://json-schema.org/)
