# keriguard

KERI-Managed Wireguard - Dynamic Wireguard configuration management based on KERI identity events.

## Overview

Keriguard provides tools for managing Wireguard VPN configurations with KERI (Key Event Receipt Infrastructure) identity tracking. It enables automatic key rotation and peer management based on KERI key events, ensuring that Wireguard configurations stay synchronized with KERI identity state.

## Features

- **KERI Integration**: Generate Wireguard keys from KERI identifiers
- **Event-Driven Updates**: Automatically update configurations based on KERI events
- **CLI Tools**: Command-line utilities for configuration generation
- **Sentinel Handler**: Event monitoring service for automatic peer management
- **Configuration Parser**: Read and write Wireguard configuration files
- **Validation**: Comprehensive validation of Wireguard configurations

## Installation

### Core Library + CLI (Default)

Install the core library with CLI tools only:

```bash
pip install keriguard
```

This provides:
- Core Wireguard configuration management library
- CLI tools (`kg` command)
- No Sentinel framework dependencies

### With Sentinel Event Handler

Install with Sentinel framework support for event-driven configuration management:

```bash
pip install keriguard[sentinel-handler]
```

This adds:
- Sentinel framework integration
- Event monitoring capabilities
- `kg-sentinel` command for event handler

### Full Application Stack

Install with database support for advanced features:

```bash
pip install keriguard[app]
```

This includes:
- Everything from `sentinel-handler`
- SQLAlchemy for database support
- Alembic for migrations

### Development

Install with development tools:

```bash
pip install keriguard[dev]
```

This includes:
- Everything from `app`
- Ruff, mypy, black for code quality
- All development dependencies

## Quick Start

### CLI Usage

Generate a new Wireguard configuration:

```bash
# Initialize KERI keystore
kli init --name mykeriguard --alias server1 --passcode "your-21-char-passcode!"

# Generate Wireguard configuration
kg generate --address 10.0.0.1/24 --output wg0.conf
```

Add a peer to existing configuration:

```bash
kg peer add --config wg0.conf \
            --public-key "base64-encoded-key" \
            --allowed-ips 10.0.0.2/32
```

### Python API

```python
from keri.app import habbing
from keriguard.core import WireguardConfigManager

# Initialize KERI Hab
with habbing.openHab(name="mykeriguard", salt="abcdefg") as hab:
    # Create configuration manager
    manager = WireguardConfigManager(hab)

    # Generate configuration
    config = manager.generate_config(
        address=["10.0.0.1/24"],
        listen_port=51820,
        config_name="wg0"
    )

    # Add peer with KERI AID
    manager.add_peer_to_config(
        config,
        keri_aid="EHzPq4mQWbLQrMgfGH2xQ5Z7KmZAaF7cW9rBmLQrMgfG",
        allowed_ips=["10.0.0.2/32"],
        endpoint="peer.example.com:51820",
        persistent_keepalive=25
    )

    # Save configuration
    manager.save_config(config, Path("wg0.conf"))
```

## Sentinel Event Handler

The Sentinel event handler provides automatic, event-driven Wireguard configuration management based on KERI identity changes.

### What is Sentinel?

Sentinel is a KERI-native event monitoring framework that watches for changes in KERI identifiers and dispatches events to registered handlers. It monitors three types of events:

- **KEL (Key Event Log)**: Key state changes (creation, rotation)
- **TEL (Transaction Event Log)**: Transaction-based state changes
- **Credential Events**: Credential issuance, revocation, updates

### How It Works

1. **Export KERI Events**: Use KERI tools to export events to a directory:
   ```bash
   # Events are exported as .cesr files to subdirectories:
   /path/to/export/
   ├── kel/     # Key Event Logs
   ├── tel/     # Transaction Event Logs
   └── cred/    # Credentials
   ```

2. **Start Sentinel Handler**: The handler monitors the export directory:
   ```bash
   kg-sentinel --export-dir /path/to/export \
               --config-dir /etc/wireguard \
               --poll-interval 2.0
   ```

3. **Automatic Updates**: When events are detected:
   - **KEL events**: Update peer public keys when KERI keys rotate
   - **TEL events**: Manage transaction-based authorizations (future)
   - **Credential events**: Handle credential-based access control (future)

### Sentinel Handler Usage

Start the Sentinel event handler:

```bash
# Basic usage
kg-sentinel --export-dir /tmp/sentinel-export \
            --config-dir /etc/wireguard

# With KERI keystore configuration
kg-sentinel --export-dir /tmp/sentinel-export \
            --config-dir /etc/wireguard \
            --name mykeriguard \
            --alias server1 \
            --passcode "your-21-char-passcode!"

# Custom poll interval
kg-sentinel --export-dir /tmp/sentinel-export \
            --config-dir /etc/wireguard \
            --poll-interval 5.0
```

### Configuration Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--export-dir` | `-e` | Required | Directory containing kel/, tel/, cred/ subdirs |
| `--config-dir` | `-c` | `/etc/wireguard` | Directory for Wireguard .conf files |
| `--poll-interval` | `-p` | `2.0` | Polling interval in seconds |
| `--name` | `-n` | `keriguard` | KERI keystore name |
| `--alias` | `-a` | `owl` | KERI identifier alias |
| `--base` | `-b` | `""` | KERI keystore base directory |
| `--passcode` | - | None | 21-character encryption passcode |

### Event Processing

#### KEL Events (Implemented)

When a KERI identifier's keys are rotated:

1. Sentinel detects the KEL event
2. Handler extracts the new verification key
3. Converts KERI key to Wireguard public key
4. Updates the peer configuration
5. Saves the updated .conf file

Example KEL event flow:
```
KERI Key Rotation
    ↓
KEL Event Exported
    ↓
Sentinel Detects Change
    ↓
Handler Processes Event
    ↓
Wireguard Config Updated
    ↓
New Public Key Applied
```

#### TEL Events (Planned)

Transaction-based peer management:
- Bandwidth allocations
- Time-based access grants
- Usage tracking

#### Credential Events (Planned)

Credential-based access control:
- Peer authorization via credentials
- Role-based access control
- Automatic peer removal on revocation

### Integration Example

Complete workflow for KERI-managed Wireguard:

```bash
# 1. Initialize KERI identities
kli init --name keriguard --alias owl
kli incept --name keriguard --alias owl

# 2. Generate Wireguard configuration
kg generate --address 10.0.0.1/24 --output /etc/wireguard/wg0.conf

# 3. Set up Sentinel export directory
mkdir -p /tmp/sentinel-export/{kel,tel,cred}

# 4. Configure KERI to export events
# (This depends on your KERI tooling - kli, healthKERI, etc.)

# 5. Start Sentinel handler
kg-sentinel --export-dir /tmp/sentinel-export \
            --config-dir /etc/wireguard \
            --name keriguard \
            --alias owl

# 6. Handler now monitors for events and updates configs automatically
# When peers rotate keys, Wireguard configs are updated in real-time
```

## Architecture

### Core Library (`keriguard.core`)

Framework-agnostic Wireguard configuration management:

- `WireguardConfig` - Configuration data model
- `WireguardInterface` - Interface configuration
- `WireguardPeer` - Peer configuration
- `WireguardConfigParser` - Parse .conf files
- `WireguardConfigWriter` - Write .conf files
- `KERIKeyGenerator` - Generate keys from KERI identifiers

**No external framework dependencies** - can be used standalone.

### CLI Application (`keriguard.app.cli`)

Command-line tools for manual configuration management:

- `kg generate` - Generate new configurations
- `kg peer add` - Add peers to configurations
- `kg validate` - Validate configuration files

### Sentinel Handler (`keriguard.app.sentinel`)

Event-driven application for automatic configuration management:

- `KeriguardEventHandler` - Main event handler
- `KELHandler` - Key event processing
- `TELHandler` - Transaction event processing (future)
- `CredHandler` - Credential event processing (future)

**Requires `sentinel-handler` extra** - optional dependency.

## Development

### Running Tests

```bash
# Core tests (no Sentinel dependencies)
pytest tests/keriguard/core/

# Sentinel handler tests (requires sentinel-handler extra)
pip install -e .[sentinel-handler]
pytest tests/keriguard/app/sentinel/

# All tests
pytest tests/
```

### Code Quality

```bash
# Install dev dependencies
pip install -e .[dev]

# Format code
black src/ tests/

# Lint
ruff check src/ tests/

# Type checking
mypy src/
```

## Use Cases

### 1. Static Configuration Generation

Generate Wireguard configurations manually with KERI key tracking:

```bash
kg generate --address 10.0.0.1/24 --output server.conf
```

### 2. Dynamic Peer Management

Monitor KERI events and automatically update peer configurations:

```bash
kg-sentinel --export-dir /keri/events --config-dir /etc/wireguard
```

### 3. Key Rotation Automation

When KERI identifiers rotate keys, Wireguard configurations update automatically without manual intervention.

### 4. Multi-Peer Networks

Manage multiple Wireguard peers with different KERI identities, each with independent key rotation.

## Security Considerations

- **Private keys are never exported** - Only public keys are derived from KERI identifiers
- **Backup files** - Original configurations are backed up before updates (configurable)
- **Validation** - All configurations are validated before writing
- **Atomic updates** - Configuration files are updated atomically to prevent corruption
- **KERI keystore encryption** - Use strong passphrases (21+ characters) for keystore protection

## Troubleshooting

### Import Error: Sentinel Not Installed

```
ImportError: Sentinel framework not installed.
Install with: pip install keriguard[sentinel-handler]
```

**Solution**: Install the `sentinel-handler` extra:
```bash
pip install keriguard[sentinel-handler]
```

### Handler Not Processing Events

1. Check export directory exists and has correct structure:
   ```bash
   ls /path/to/export/{kel,tel,cred}
   ```

2. Verify poll interval isn't too long:
   ```bash
   kg-sentinel --export-dir /path/to/export --poll-interval 1.0
   ```

3. Check handler logs for errors

### Configuration File Not Updated

1. Verify config directory is writable:
   ```bash
   ls -la /etc/wireguard/
   ```

2. Check that auto-add-peers is enabled (it is by default)

3. Verify the KERI AID is tracked in the handler's Habery

## License

See LICENSE file for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Links

- [KERI](https://keri.one/) - Key Event Receipt Infrastructure
- [Wireguard](https://www.wireguard.com/) - Fast, modern VPN protocol
- [healthKERI](https://github.com/healthKERI) - KERI ecosystem tools
- [Sentinel](https://github.com/healthKERI/sentinel) - KERI event monitoring framework

## Support

For issues and questions:
- GitHub Issues: https://github.com/healthKERI/keriguard/issues
- KERI Community: https://keri.one/community/
