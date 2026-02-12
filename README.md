# MicroLink

**Tailscale-Compatible VPN Client for ESP32**

MicroLink is a complete, production-ready implementation of the Tailscale protocol for ESP32 microcontrollers. It enables your ESP32 devices to join a Tailscale network and communicate securely with any other device on your tailnet.

## Features

- **Full Tailscale Protocol Support**
  - ts2021 coordination protocol
  - WireGuard encryption (ChaCha20-Poly1305)
  - DISCO path discovery (PING/PONG/CALL_ME_MAYBE)
  - DERP relay for NAT traversal
  - STUN for public IP discovery
  - **Bidirectional UDP data transfer** (NEW in v1.2.0)

- **Production Ready**
  - Memory optimized (~100KB SRAM)
  - Tested with ESP32-S3
  - Works with `tailscale ping`
  - **Bidirectional VPN data transfer** (ESP32 ↔ PC)

- **Easy Integration**
  - Simple C API
  - ESP-IDF component format
  - Kconfig configuration
  - **Callback-based UDP reception** for low-latency handling

## Requirements

- ESP-IDF v5.0 or later (tested with v5.3)
- ESP32-S3 with PSRAM (recommended) or ESP32 with sufficient RAM
- WiFi connectivity
- Tailscale account with auth key

## Hardware Requirements

### Recommended: ESP32-S3 with PSRAM

For production deployments, **ESP32-S3 with PSRAM is recommended**. The 8MB external PSRAM provides ample headroom for MicroLink's buffers plus your application logic.

Tested hardware:
- ESP32-S3 with 8MB PSRAM (recommended)
- Waveshare ESP32-S3-Touch-AMOLED-2.06
- Seeed Studio XIAO ESP32S3 Sense

### Supported: Standard ESP32 (No PSRAM)

MicroLink also runs on standard ESP32 boards without PSRAM, with reduced buffer sizes. This is suitable for simple IoT applications where memory headroom is less critical.

Tested hardware:
- HiLetgo ESP-32S
- ESP32-WROOM-32D
- ESP32-DevKitC

**Memory profile on ESP32 (no PSRAM):**

| Stage | Free Heap | Notes |
|-------|-----------|-------|
| Boot | ~267KB | Total available SRAM |
| After WiFi | ~225KB | WiFi stack overhead |
| After MicroLink | ~193KB | Core initialization |
| Running (connected) | ~140KB | DERP + coordination active |
| **Minimum observed** | **~9KB** | Low-water mark during operation |

To use MicroLink on ESP32 without PSRAM, configure reduced buffer sizes:

```ini
# sdkconfig.defaults for ESP32 without PSRAM
CONFIG_MICROLINK_COORD_BUFFER_SIZE_KB=24
CONFIG_MICROLINK_MAX_PEERS=8
```

See `examples/ping_pong_esp32/` for a complete working example.

## Quick Start

### 1. Add to your project

Copy the `microlink` folder to your project's `components/` directory, or add it as a git submodule:

```bash
cd your_project/components
git clone https://github.com/CamM2325/microlink.git
```

### 2. Configure sdkconfig

Add these settings to your `sdkconfig.defaults` file:

```ini
# PSRAM Configuration (required for ESP32-S3 with PSRAM)
CONFIG_SPIRAM=y
CONFIG_SPIRAM_MODE_OCT=y
CONFIG_SPIRAM_TYPE_AUTO=y
CONFIG_SPIRAM_SPEED_80M=y
CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY=y
CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=4096
CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL=32768

# Partition table (app needs ~1MB+)
CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y

# TLS/HTTPS (required for DERP)
CONFIG_ESP_TLS_USING_MBEDTLS=y
CONFIG_MBEDTLS_SSL_PROTO_TLS1_2=y
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_CMN=y

# Networking
CONFIG_LWIP_IPV4=y
CONFIG_LWIP_IP4_FRAG=y
CONFIG_LWIP_IP4_REASSEMBLY=y

# Stack size
CONFIG_ESP_MAIN_TASK_STACK_SIZE=8192
```

Then run `idf.py menuconfig` to customize MicroLink options:

```
Component config → MicroLink Configuration
├── Enable MicroLink Tailscale VPN     [*]
├── Maximum number of peers            (16)
├── Maximum endpoints per peer         (8)
├── Enable DERP relay support          [*]
├── Enable DISCO path discovery        [*]
├── Enable STUN NAT discovery          [*]
├── Heartbeat interval (ms)            (25000)
├── Default DERP region ID             (9)      ← Change this for different regions
├── Enable dynamic DERP region discovery [ ]    ← Enable for custom derpMap setups
└── Enable debug logging               [ ]
```

**Important:** If your tailnet uses a custom `derpMap` configuration, see [DERP Server Configuration](#derp-server-configuration) below.

### 3. Use in your code

```c
#include "microlink.h"

void app_main(void) {
    // Initialize WiFi first...

    // Configure MicroLink
    microlink_config_t config;
    microlink_get_default_config(&config);
    config.auth_key = "tskey-auth-xxxxx";  // Your Tailscale auth key
    config.device_name = "esp32-device";
    config.enable_derp = true;
    config.enable_disco = true;

    // Initialize
    microlink_t *ml = microlink_init(&config);
    if (!ml) {
        ESP_LOGE(TAG, "Failed to initialize MicroLink");
        return;
    }

    // Connect to Tailscale
    microlink_connect(ml);

    // Main loop
    while (1) {
        microlink_update(ml);

        if (microlink_is_connected(ml)) {
            char ip_str[16];
            ESP_LOGI(TAG, "Connected! VPN IP: %s",
                     microlink_vpn_ip_to_str(microlink_get_vpn_ip(ml), ip_str));
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
```

## API Reference

### Initialization

```c
// Get default configuration
void microlink_get_default_config(microlink_config_t *config);

// Initialize MicroLink
microlink_t *microlink_init(const microlink_config_t *config);

// Deinitialize
void microlink_deinit(microlink_t *ml);
```

### Connection

```c
// Connect to Tailscale network
esp_err_t microlink_connect(microlink_t *ml);

// Disconnect
esp_err_t microlink_disconnect(microlink_t *ml);

// Update state machine (call regularly)
esp_err_t microlink_update(microlink_t *ml);

// Check connection status
bool microlink_is_connected(const microlink_t *ml);
microlink_state_t microlink_get_state(const microlink_t *ml);
```

### UDP Data Transfer (NEW in v1.2.0)

```c
// Create UDP socket (port 0 = ephemeral, or specify port to listen)
microlink_udp_socket_t *sock = microlink_udp_create(ml, port);

// Send UDP data to peer
esp_err_t err = microlink_udp_send(sock, dest_vpn_ip, dest_port, data, len);

// Receive UDP data (with timeout in ms, 0 = non-blocking)
esp_err_t err = microlink_udp_recv(sock, &src_ip, &src_port, buffer, &len, timeout_ms);

// Register callback for incoming packets (low-latency option)
void my_callback(microlink_udp_socket_t *sock, uint32_t src_ip, uint16_t src_port,
                 const uint8_t *data, size_t len, void *user_data);
microlink_udp_set_rx_callback(sock, my_callback, user_data);

// Close socket
microlink_udp_close(sock);

// Parse IP string to uint32_t
uint32_t ip = microlink_parse_ip("100.64.0.1");
```

### Raw Data Transfer (Legacy)

```c
// Send data to peer
esp_err_t microlink_send(microlink_t *ml, uint32_t dest_vpn_ip,
                         const uint8_t *data, size_t len);

// Receive data from peer
esp_err_t microlink_receive(microlink_t *ml, uint32_t *src_vpn_ip,
                            uint8_t *buffer, size_t *len);
```

### Information

```c
// Get our VPN IP
uint32_t microlink_get_vpn_ip(const microlink_t *ml);

// Get peer list
esp_err_t microlink_get_peers(const microlink_t *ml,
                              const microlink_peer_t **peers,
                              uint8_t *count);

// Get statistics
esp_err_t microlink_get_stats(const microlink_t *ml, microlink_stats_t *stats);

// Get peer latency
uint32_t microlink_get_peer_latency(const microlink_t *ml, uint32_t peer_vpn_ip);
```

## Configuration Options

### Runtime Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `auth_key` | Required | Tailscale auth key |
| `device_name` | Required | Device hostname |
| `enable_derp` | `true` | Enable DERP relay |
| `enable_disco` | `true` | Enable path discovery |
| `enable_stun` | `true` | Enable STUN NAT discovery |
| `max_peers` | `16` | Maximum peer count |

### Kconfig Options (idf.py menuconfig)

| Option | Default | Description |
|--------|---------|-------------|
| `MICROLINK_MAX_PEERS` | `16` | Maximum peers to track (reduce to 8 for non-PSRAM) |
| `MICROLINK_COORD_BUFFER_SIZE_KB` | `64` | Coordination buffer size (use 24 for non-PSRAM) |
| `MICROLINK_DERP_REGION` | `9` (Dallas) | Default DERP region ID |
| `MICROLINK_DERP_DYNAMIC_DISCOVERY` | `n` | Enable dynamic DERP region discovery |
| `MICROLINK_HEARTBEAT_INTERVAL_MS` | `25000` | Heartbeat interval |

### DERP Server Configuration

By default, MicroLink uses hardcoded DERP servers (Dallas primary, NYC fallback). This is ideal for:
- **Self-hosted DERP**: Point to your own DERP server
- **Deterministic selection**: Always use a specific region
- **Standard Tailscale setups**: Works out of the box

#### Dynamic DERP Discovery (Optional)

If your tailnet has a custom `derpMap` configuration that disables certain regions, enable dynamic discovery:

```bash
idf.py menuconfig
# Navigate to: Component config → MicroLink Configuration
# Enable: "Enable dynamic DERP region discovery"
```

When enabled, MicroLink will:
1. Parse the `DERPMap` from the Tailscale MapResponse (supports up to 32 regions)
2. Prioritize connecting to the preferred region configured in Kconfig (`MICROLINK_DERP_REGION`)
3. Automatically fall back to other discovered regions if the preferred region is unavailable
4. Ensure the ESP32 connects to the same DERP region it advertises as `PreferredDERP`

This solves issues where users have custom derpMap configurations that null out certain region IDs.

**Important:** The ESP32 must connect to the same DERP region it advertises. Tailscale's DERP mesh does support cross-region routing, but peers send packets to whichever DERP region you advertise as your `PreferredDERP`. If there's a mismatch, DISCO PING/PONG packets won't reach your device.

## Memory Usage

### ESP32-S3 with PSRAM (Recommended)

| Component | SRAM | PSRAM |
|-----------|------|-------|
| Core | ~50KB | - |
| Per Peer | ~200B | - |
| Coord Buffer | - | 64KB |
| **Total** | ~50KB | 64KB |

Leaves ~400KB+ SRAM free for your application.

### ESP32 without PSRAM

| Component | SRAM |
|-----------|------|
| WiFi Stack | ~42KB |
| MicroLink Core | ~50KB |
| Coord Buffer | 24KB |
| DERP/TLS | ~20KB |
| Per Peer (×8) | ~1.6KB |
| **Total** | ~138KB |

Leaves ~9-15KB headroom. Suitable for:
- Simple sensor reporting (temperature, humidity, GPIO states)
- Remote relay/switch control
- Status monitoring and heartbeats
- Small data payloads (<1KB per message)

**Not recommended for:**
- Display drivers (require significant RAM)
- Audio/video processing
- Large data buffers or file transfers
- Running alongside other memory-heavy components

## Examples

See the `examples/` directory:

- `basic_connect/` - Minimal connection example
- `ping_pong/` - Respond to `tailscale ping` with latency monitoring (ESP32-S3)
- `ping_pong_esp32/` - Memory-optimized version for ESP32 without PSRAM
- `sensor_node/` - Practical IoT example: send sensor data over VPN
- **`udp_netcat_example/`** - Bidirectional UDP communication (NEW in v1.2.0)
  - Send/receive UDP over Tailscale VPN
  - Equivalent to Linux `netcat -u`
  - Echo mode for latency testing
  - See [examples/udp_netcat_example/README.md](examples/udp_netcat_example/README.md)

## Testing

After flashing, test with:

```bash
# From any device on your tailnet
tailscale ping esp32-device
```

You should see responses like:
```
pong from esp32-device (100.x.x.x) via DERP(dfw) in 150ms
```

## Troubleshooting

### Device not appearing in tailnet
- Check auth key is valid and not expired
- Ensure WiFi is connected
- Check coordination server connection in logs

### `tailscale ping` times out
- Verify DISCO is enabled
- Check DERP connection in logs
- Look for "PONG sent" in logs
- **If using custom derpMap:** Run `tailscale netcheck --verbose` to verify the configured DERP region is available. Change `MICROLINK_DERP_REGION` in menuconfig or enable dynamic discovery.

### High latency
- This is normal for DERP relay (100-300ms)
- Direct connections are faster but require UDP hole-punching

### "PSRAM allocation failed" or peer fetch timeout
- Ensure PSRAM is enabled in sdkconfig (see Configuration section)
- Check that `CONFIG_SPIRAM=y` is set
- Verify your board has PSRAM (most ESP32-S3 dev boards do)

### `tailscale ping` works but shows "via DERP" with different region than expected
- This can happen when dynamic discovery is enabled but the ESP32 connects to a different region than it advertises
- Check logs for "DERP: Connecting to region X" and ensure it matches your configured `MICROLINK_DERP_REGION`
- The ESP32 must physically connect to the DERP region it advertises as `PreferredDERP`, otherwise peers will send packets to the wrong relay

### App partition too small
- Add `CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y` to sdkconfig.defaults
- Clean build: `rm -rf build sdkconfig && idf.py build`

### Device online but can't reach peers (custom derpMap)
If your tailnet has a custom `derpMap` configuration that disables certain DERP regions:
1. Run `tailscale netcheck --verbose` to see available regions
2. Either change `MICROLINK_DERP_REGION` in menuconfig to an available region, OR
3. Enable `MICROLINK_DERP_DYNAMIC_DISCOVERY` in menuconfig to auto-detect available regions

## License

MIT License - see [LICENSE](LICENSE)

## Acknowledgments

- [Tailscale](https://tailscale.com/) for the protocol specification
- [Headscale](https://github.com/juanfont/headscale) for open-source coordination server insights
- [WireGuard](https://www.wireguard.com/) for the cryptographic foundation
- [lwIP](https://savannah.nongnu.org/projects/lwip/) for the TCP/IP stack
- [wireguard-lwip](https://github.com/smartalock/wireguard-lwip) for WireGuard-lwIP integration

## Disclaimer

This is an independent implementation created for educational and interoperability purposes.
It is not affiliated with or endorsed by Tailscale Inc. Use at your own risk.
