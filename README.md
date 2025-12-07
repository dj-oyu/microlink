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

- **Production Ready**
  - Memory optimized (~100KB SRAM)
  - Tested with ESP32-S3
  - Works with `tailscale ping`

- **Easy Integration**
  - Simple C API
  - ESP-IDF component format
  - Kconfig configuration

## Requirements

- ESP-IDF v5.0 or later (tested with v5.3)
- ESP32-S3 with PSRAM (recommended) or ESP32 with sufficient RAM
- WiFi connectivity
- Tailscale account with auth key

## Hardware Requirements

**PSRAM is strongly recommended.** MicroLink uses ~64KB buffers for Tailscale MapResponse parsing. Without PSRAM, you may experience memory issues.

Tested hardware:
- ESP32-S3 with 8MB PSRAM (recommended)
- Waveshare ESP32-S3 Touch LCD 1.28
- Seeed Studio XIAO ESP32S3 Sense

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

Then run `idf.py menuconfig` to customize MicroLink options if needed.

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

### Data Transfer

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

| Option | Default | Description |
|--------|---------|-------------|
| `auth_key` | Required | Tailscale auth key |
| `device_name` | Required | Device hostname |
| `enable_derp` | `true` | Enable DERP relay |
| `enable_disco` | `true` | Enable path discovery |
| `enable_stun` | `true` | Enable STUN NAT discovery |
| `max_peers` | `16` | Maximum peer count |

## Memory Usage

| Component | SRAM | PSRAM |
|-----------|------|-------|
| Core | ~50KB | - |
| Per Peer | ~200B | - |
| Buffers | ~24KB | Optional |
| **Total** | ~100KB | 24KB |

## Examples

See the `examples/` directory:

- `basic_connect/` - Minimal connection example
- `ping_pong/` - Respond to `tailscale ping` with latency monitoring
- `sensor_node/` - Practical IoT example: send sensor data over VPN

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
- Check DERP connection
- Look for "PONG sent" in logs

### High latency
- This is normal for DERP relay (100-300ms)
- Direct connections are faster but require UDP hole-punching

### "PSRAM allocation failed" or peer fetch timeout
- Ensure PSRAM is enabled in sdkconfig (see Configuration section)
- Check that `CONFIG_SPIRAM=y` is set
- Verify your board has PSRAM (most ESP32-S3 dev boards do)

### App partition too small
- Add `CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y` to sdkconfig.defaults
- Clean build: `rm -rf build sdkconfig && idf.py build`

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
