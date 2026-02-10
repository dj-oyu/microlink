/**
 * @file microlink_stun.c
 * @brief STUN client for NAT discovery (RFC 5389/8489)
 *
 * Discovers public IP and port mapping using STUN protocol.
 * Used by Tailscale for NAT traversal and direct peer connections.
 *
 * STUN requests are sent through the DISCO PCB (microlink_disco_sendto)
 * so that the discovered public mapping matches the port used for
 * both DISCO probes and WireGuard direct packets.
 *
 * STUN responses are delivered asynchronously by the DISCO PCB recv
 * callback into ml->disco.stun_resp_data/stun_resp_ready.  The probe
 * function polls this flag with vTaskDelay().
 *
 * STUN message format:
 *   [2B type][2B length][4B magic cookie 0x2112A442][12B transaction ID]
 *   [attributes...]
 *
 * Binding Request: type 0x0001, no attributes needed
 * Binding Response: type 0x0101, contains XOR-MAPPED-ADDRESS (0x0020)
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include <string.h>
#include <netdb.h>
#include <lwip/inet.h>

static const char *TAG = "ml_stun";

/* STUN protocol constants (RFC 5389) */
#define STUN_MAGIC_COOKIE       0x2112A442
#define STUN_HEADER_SIZE        20
#define STUN_TRANSACTION_ID_LEN 12

/* STUN message types */
#define STUN_BINDING_REQUEST    0x0001
#define STUN_BINDING_RESPONSE   0x0101
#define STUN_BINDING_ERROR      0x0111

/* STUN attribute types */
#define STUN_ATTR_MAPPED_ADDRESS        0x0001  // RFC 3489 (deprecated)
#define STUN_ATTR_XOR_MAPPED_ADDRESS    0x0020  // RFC 5389

/* Address family */
#define STUN_ADDR_FAMILY_IPV4   0x01
#define STUN_ADDR_FAMILY_IPV6   0x02

/* Timeouts */
#define STUN_TIMEOUT_MS         3000
#define STUN_POLL_INTERVAL_MS   10

/* Static transaction ID storage */
static uint8_t stun_transaction_id[STUN_TRANSACTION_ID_LEN];

/**
 * @brief Build a STUN Binding Request
 */
static size_t stun_build_binding_request(uint8_t *buf, size_t buf_size) {
    if (buf_size < STUN_HEADER_SIZE) {
        return 0;
    }

    // Message Type: Binding Request (0x0001)
    buf[0] = 0x00;
    buf[1] = 0x01;

    // Message Length: 0 (no attributes)
    buf[2] = 0x00;
    buf[3] = 0x00;

    // Magic Cookie: 0x2112A442 (big-endian)
    buf[4] = 0x21;
    buf[5] = 0x12;
    buf[6] = 0xA4;
    buf[7] = 0x42;

    // Transaction ID: 12 random bytes
    uint32_t r = esp_random();
    for (int i = 0; i < STUN_TRANSACTION_ID_LEN; i++) {
        if (i % 4 == 0 && i > 0) {
            r = esp_random();
        }
        stun_transaction_id[i] = (r >> ((i % 4) * 8)) & 0xFF;
        buf[8 + i] = stun_transaction_id[i];
    }

    return STUN_HEADER_SIZE;
}

/**
 * @brief Parse STUN Binding Response
 * @return 0 on success, -1 on error
 */
static int stun_parse_binding_response(const uint8_t *buf, size_t len,
                                        uint32_t *mapped_ip, uint16_t *mapped_port) {
    if (len < STUN_HEADER_SIZE) {
        ESP_LOGE(TAG, "Response too short: %zu bytes", len);
        return -1;
    }

    // Check message type (Binding Response: 0x0101)
    uint16_t msg_type = ((uint16_t)buf[0] << 8) | buf[1];
    if (msg_type != STUN_BINDING_RESPONSE) {
        ESP_LOGE(TAG, "Unexpected message type: 0x%04x", msg_type);
        return -1;
    }

    // Get message length
    uint16_t msg_len = ((uint16_t)buf[2] << 8) | buf[3];
    if (STUN_HEADER_SIZE + msg_len > len) {
        ESP_LOGE(TAG, "Message truncated: claimed %u, have %zu", msg_len, len - STUN_HEADER_SIZE);
        return -1;
    }

    // Verify magic cookie
    uint32_t cookie = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                      ((uint32_t)buf[6] << 8) | buf[7];
    if (cookie != STUN_MAGIC_COOKIE) {
        ESP_LOGE(TAG, "Invalid magic cookie: 0x%08lx", (unsigned long)cookie);
        return -1;
    }

    // Verify transaction ID
    if (memcmp(buf + 8, stun_transaction_id, STUN_TRANSACTION_ID_LEN) != 0) {
        ESP_LOGE(TAG, "Transaction ID mismatch");
        return -1;
    }

    // Parse attributes
    const uint8_t *ptr = buf + STUN_HEADER_SIZE;
    const uint8_t *end = buf + STUN_HEADER_SIZE + msg_len;

    while (ptr + 4 <= end) {
        uint16_t attr_type = ((uint16_t)ptr[0] << 8) | ptr[1];
        uint16_t attr_len = ((uint16_t)ptr[2] << 8) | ptr[3];
        ptr += 4;

        if (ptr + attr_len > end) {
            ESP_LOGE(TAG, "Attribute truncated");
            return -1;
        }

        ESP_LOGD(TAG, "Attribute: type=0x%04x len=%u", attr_type, attr_len);

        if (attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8) {
            uint8_t family = ptr[1];

            if (family == STUN_ADDR_FAMILY_IPV4) {
                // X-Port = port XOR (magic cookie >> 16)
                uint16_t x_port = ((uint16_t)ptr[2] << 8) | ptr[3];
                *mapped_port = x_port ^ (STUN_MAGIC_COOKIE >> 16);

                // X-Address = address XOR magic cookie
                uint32_t x_addr = ((uint32_t)ptr[4] << 24) | ((uint32_t)ptr[5] << 16) |
                                  ((uint32_t)ptr[6] << 8) | ptr[7];
                *mapped_ip = x_addr ^ STUN_MAGIC_COOKIE;

                ESP_LOGI(TAG, "XOR-MAPPED-ADDRESS: %lu.%lu.%lu.%lu:%u",
                         (*mapped_ip >> 24) & 0xFF,
                         (*mapped_ip >> 16) & 0xFF,
                         (*mapped_ip >> 8) & 0xFF,
                         *mapped_ip & 0xFF,
                         *mapped_port);
                return 0;
            } else {
                ESP_LOGW(TAG, "IPv6 not supported, family=%u", family);
            }
        } else if (attr_type == STUN_ATTR_MAPPED_ADDRESS && attr_len >= 8) {
            // Fallback: MAPPED-ADDRESS (RFC 3489, not XORed)
            uint8_t family = ptr[1];

            if (family == STUN_ADDR_FAMILY_IPV4) {
                *mapped_port = ((uint16_t)ptr[2] << 8) | ptr[3];
                *mapped_ip = ((uint32_t)ptr[4] << 24) | ((uint32_t)ptr[5] << 16) |
                             ((uint32_t)ptr[6] << 8) | ptr[7];

                ESP_LOGI(TAG, "MAPPED-ADDRESS: %lu.%lu.%lu.%lu:%u",
                         (*mapped_ip >> 24) & 0xFF,
                         (*mapped_ip >> 16) & 0xFF,
                         (*mapped_ip >> 8) & 0xFF,
                         *mapped_ip & 0xFF,
                         *mapped_port);
                return 0;
            }
        }

        // Move to next attribute (aligned to 4 bytes)
        size_t padded_len = (attr_len + 3) & ~3;
        ptr += padded_len;
    }

    ESP_LOGE(TAG, "No MAPPED-ADDRESS attribute found");
    return -1;
}

esp_err_t microlink_stun_init(microlink_t *ml) {
    ESP_LOGI(TAG, "Initializing STUN client (async via DISCO PCB)");

    memset(&ml->stun, 0, sizeof(microlink_stun_t));

    // STUN now uses the DISCO PCB for sending (microlink_disco_sendto)
    // and the DISCO PCB recv callback delivers responses to
    // ml->disco.stun_resp_data/stun_resp_ready.
    // No socket or PCB of our own needed.

    if (!ml->disco.pcb) {
        ESP_LOGW(TAG, "DISCO PCB not ready — STUN will fail until DISCO is initialized");
    } else {
        ESP_LOGI(TAG, "STUN client ready (sharing DISCO PCB port %u)", ml->disco.port);
    }

    return ESP_OK;
}

esp_err_t microlink_stun_deinit(microlink_t *ml) {
    ESP_LOGI(TAG, "Deinitializing STUN client");
    memset(&ml->stun, 0, sizeof(microlink_stun_t));
    return ESP_OK;
}

/**
 * @brief Try STUN probe to a specific server (async via DISCO PCB)
 *
 * Sends the STUN binding request via microlink_disco_sendto() and then
 * polls ml->disco.stun_resp_ready with vTaskDelay() until a response
 * arrives or the timeout expires.
 */
static esp_err_t stun_probe_server(microlink_t *ml, const char *server, uint16_t port) {
    if (!ml->disco.pcb) {
        ESP_LOGE(TAG, "DISCO PCB not available for STUN");
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Trying STUN server %s:%d (via DISCO PCB)", server, port);

    // Resolve STUN server hostname
    uint32_t server_ip_nbo = 0;
    struct hostent *he = gethostbyname(server);
    if (he != NULL) {
        memcpy(&server_ip_nbo, he->h_addr_list[0], sizeof(server_ip_nbo));
        ESP_LOGI(TAG, "STUN server resolved: %s -> %s",
                 server, inet_ntoa(*(struct in_addr *)he->h_addr_list[0]));
    } else {
        // DNS failed - try hardcoded fallback IP
        const char *fallback_ip = NULL;
        if (strcmp(server, MICROLINK_STUN_SERVER) == 0) {
            fallback_ip = MICROLINK_STUN_SERVER_IP;
        } else if (strcmp(server, MICROLINK_STUN_SERVER_FALLBACK) == 0) {
            fallback_ip = MICROLINK_STUN_SERVER_FALLBACK_IP;
        }
        if (fallback_ip) {
            ESP_LOGW(TAG, "DNS failed for %s, using fallback IP %s", server, fallback_ip);
            server_ip_nbo = inet_addr(fallback_ip);
        } else {
            ESP_LOGW(TAG, "Failed to resolve %s (no fallback)", server);
            return ESP_FAIL;
        }
    }

    // Build STUN Binding Request
    uint8_t request[STUN_HEADER_SIZE];
    size_t req_len = stun_build_binding_request(request, sizeof(request));
    if (req_len == 0) {
        ESP_LOGE(TAG, "Failed to build STUN request");
        return ESP_FAIL;
    }

    // Clear any stale response
    __atomic_store_n(&ml->disco.stun_resp_ready, false, __ATOMIC_RELEASE);

    // Send via DISCO PCB (dispatched to tcpip_thread)
    esp_err_t send_ret = microlink_disco_sendto(ml, server_ip_nbo, port, request, req_len);
    if (send_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to send STUN request via DISCO PCB: %d", send_ret);
        return ESP_FAIL;
    }

    ESP_LOGD(TAG, "Sent STUN Binding Request (%zu bytes) via DISCO PCB", req_len);

    // Poll for response (async — DISCO PCB callback sets stun_resp_ready)
    uint64_t start = microlink_get_time_ms();
    while (microlink_get_time_ms() - start < STUN_TIMEOUT_MS) {
        if (__atomic_load_n(&ml->disco.stun_resp_ready, __ATOMIC_ACQUIRE)) {
            // Response arrived
            uint32_t mapped_ip = 0;
            uint16_t mapped_port = 0;

            if (stun_parse_binding_response(ml->disco.stun_resp_data,
                                             ml->disco.stun_resp_len,
                                             &mapped_ip, &mapped_port) == 0) {
                ml->stun.public_ip = mapped_ip;
                ml->stun.public_port = mapped_port;
                ml->stun.nat_detected = true;
                ml->stun.last_probe_ms = microlink_get_time_ms();

                ESP_LOGI(TAG, "STUN probe successful: public endpoint %lu.%lu.%lu.%lu:%u",
                         (mapped_ip >> 24) & 0xFF,
                         (mapped_ip >> 16) & 0xFF,
                         (mapped_ip >> 8) & 0xFF,
                         mapped_ip & 0xFF,
                         mapped_port);

                return ESP_OK;
            }

            // Parse failed — don't keep polling
            ESP_LOGW(TAG, "STUN response parse failed");
            return ESP_FAIL;
        }

        vTaskDelay(pdMS_TO_TICKS(STUN_POLL_INTERVAL_MS));
    }

    ESP_LOGW(TAG, "STUN timeout (no response within %d ms)", STUN_TIMEOUT_MS);
    return ESP_FAIL;
}

esp_err_t microlink_stun_probe(microlink_t *ml) {
    if (!ml->disco.pcb) {
        ESP_LOGE(TAG, "DISCO PCB not initialized — cannot send STUN");
        return ESP_ERR_INVALID_STATE;
    }

    // Try Google STUN first (reliable, fast response)
    if (stun_probe_server(ml, MICROLINK_STUN_SERVER_FALLBACK, MICROLINK_STUN_PORT_GOOGLE) == ESP_OK) {
        return ESP_OK;
    }

    // Try DERP server STUN as fallback
    ESP_LOGW(TAG, "Google STUN failed, trying DERP server...");
    if (stun_probe_server(ml, MICROLINK_STUN_SERVER, MICROLINK_STUN_PORT) == ESP_OK) {
        return ESP_OK;
    }

    ESP_LOGE(TAG, "All STUN servers failed");
    return ESP_FAIL;
}

esp_err_t microlink_stun_detect_nat_type(microlink_t *ml) {
    if (!ml->disco.pcb) {
        ESP_LOGE(TAG, "DISCO PCB not initialized — cannot detect NAT type");
        return ESP_ERR_INVALID_STATE;
    }

    // Probe two different STUN servers and compare external ports
    uint32_t ip1 = 0, ip2 = 0;
    uint16_t port1 = 0, port2 = 0;

    // Save/restore stun state so normal probe result is preserved
    uint32_t saved_ip = ml->stun.public_ip;
    uint16_t saved_port = ml->stun.public_port;

    ESP_LOGI(TAG, "NAT type detection: probing two STUN servers...");

    // Probe 1: Google STUN
    if (stun_probe_server(ml, MICROLINK_STUN_SERVER_FALLBACK, MICROLINK_STUN_PORT_GOOGLE) == ESP_OK) {
        ip1 = ml->stun.public_ip;
        port1 = ml->stun.public_port;
    } else {
        ESP_LOGW(TAG, "NAT detect: first STUN probe failed");
        ml->stun.public_ip = saved_ip;
        ml->stun.public_port = saved_port;
        ml->stun.nat_type = MICROLINK_NAT_UNKNOWN;
        return ESP_FAIL;
    }

    // Probe 2: DERP STUN (different server, same local port)
    if (stun_probe_server(ml, MICROLINK_STUN_SERVER, MICROLINK_STUN_PORT) == ESP_OK) {
        ip2 = ml->stun.public_ip;
        port2 = ml->stun.public_port;
    } else {
        ESP_LOGW(TAG, "NAT detect: second STUN probe failed");
        // Restore first probe result
        ml->stun.public_ip = ip1;
        ml->stun.public_port = port1;
        ml->stun.nat_type = MICROLINK_NAT_UNKNOWN;
        return ESP_FAIL;
    }

    // Restore first probe as canonical result
    ml->stun.public_ip = ip1;
    ml->stun.public_port = port1;
    ml->stun.public_port_alt = port2;
    ml->stun.port_delta = (int16_t)((int32_t)port2 - (int32_t)port1);

    if (ip1 == 0) {
        ml->stun.nat_type = MICROLINK_NAT_UNKNOWN;
        ESP_LOGW(TAG, "NAT detect: no public IP discovered");
    } else if (port1 == port2) {
        ml->stun.nat_type = MICROLINK_NAT_CONE;
        ESP_LOGI(TAG, "NAT type: CONE (EIM) - port %u same for both servers", port1);
    } else {
        ml->stun.nat_type = MICROLINK_NAT_SYMMETRIC;
        ESP_LOGW(TAG, "NAT type: SYMMETRIC (EDM) - port %u vs %u (delta=%d)",
                 port1, port2, ml->stun.port_delta);
    }

    return ESP_OK;
}
