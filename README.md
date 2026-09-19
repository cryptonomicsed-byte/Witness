# Witness — Physical World Attestation

Signs and publishes observations from physical hardware (sensors, cameras, robots, drones) into the sovereign ecosystem as verifiable attestations.

**Port:** 7794 | **Security:** high | **ARP:** witness receipts (Nostr kind 31020 / twin anchor 31030)

## Architecture

```
Witness workspace
├── crates/witness-types/    # WitnessAttestation, ObservationBundle, FirmwareManifest
├── crates/witness-core/     # signing, Nostr publish, ARP wrapping
└── MANIFEST.toml
```

## Hardware Tiers

| Class | Examples |
|-------|---------|
| `companion` | M5Stack, phone sensor node |
| `agent-tag` | BLE beacon, RFID |
| `gateway` | Raspberry Pi, Omarchy node |
| `robot-controller` | ROS2 arm, mobile base |
| `drone-autopilot` | ArduPilot, PX4 |

## Attestation Flow

```
Sensor reading
  → ObservationBundle (raw data + timestamp + hardware ID)
  → WitnessAttestation (Ed25519 signed)
  → Nostr kind 31020 (published to relay)
  → ARP witness receipt (linked to VCP session)
  → Spatial Twin anchor kind 31030 (if spatial data)
```

## Environment

| Variable | Description |
|----------|-------------|
| `WITNESS_PORT` | HTTP server port (default: 7794) |
| `WITNESS_SIGNING_KEY` | Ed25519 private key (hex) |
| `NOSTR_RELAY_URL` | Relay for publishing attestations |

## Quick Start

```bash
cd Witness
cargo build --release
WITNESS_PORT=7794 WITNESS_SIGNING_KEY=... ./target/release/witness-server
```

## Dependencies

Requires: VCP (active device session before attestation accepted)
Optional: ScarabSwarm (sim comparison), Vantage (reputation update), DIP (routing)
