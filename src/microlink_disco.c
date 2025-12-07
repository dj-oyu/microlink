/**
 * @file microlink_disco.c
 * @brief DISCO protocol for path discovery and optimization
 *
 * Tests multiple network paths and selects the best one based on latency.
 *
 * DISCO packets are sent via WireGuard tunnel or DERP relay and contain:
 * - 6-byte magic: "TS💬" (DISCO magic)
 * - 32-byte sender disco public key
 * - 24-byte nonce
 * - Encrypted payload (NaCl box):
 *   - 1-byte message type (ping=0x01, pong=0x02, call_me_maybe=0x03)
 *   - 12-byte TxID (for ping/pong matching)
 *   - Additional data depending on type
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_random.h"
#include "nacl_box.h"
#include <string.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <lwip/err.h>
#include <lwip/netif.h>

static const char *TAG = "ml_disco";

/* DISCO protocol constants */
#define DISCO_MAGIC             "TS\xf0\x9f\x92\xac"  // "TS💬" (6 bytes)
#define DISCO_MAGIC_LEN         6
#define DISCO_KEY_LEN           32
#define DISCO_NONCE_LEN         24
#define DISCO_TXID_LEN          12
#define DISCO_MAC_LEN           16

/* Message types (encrypted payload) */
#define DISCO_MSG_PING          0x01
#define DISCO_MSG_PONG          0x02
#define DISCO_MSG_CALL_ME_MAYBE 0x03

/* Timing */
#define DISCO_PROBE_INTERVAL_MS     5000   // 5 seconds between probes
#define DISCO_PROBE_TIMEOUT_MS      3000   // 3 second timeout for response
#define DISCO_STALE_THRESHOLD_MS    30000  // Consider path stale after 30s

/* Maximum DISCO packet size */
#define DISCO_MAX_PACKET_SIZE   256

/* Per-endpoint probe state */
typedef struct {
    uint8_t txid[DISCO_TXID_LEN];   // Transaction ID
    uint64_t send_time_ms;           // When probe was sent
    bool pending;                    // Waiting for response
} disco_probe_state_t;

/* Pending probes for each peer/endpoint combination */
static disco_probe_state_t pending_probes[MICROLINK_MAX_PEERS][MICROLINK_MAX_ENDPOINTS];

/* UDP socket for direct DISCO probes */
static int disco_socket = -1;

/* Forward declarations */
static esp_err_t disco_probe_via_derp(microlink_t *ml, uint8_t peer_idx);
static esp_err_t disco_process_packet(microlink_t *ml, const uint8_t *packet, size_t len,
                                      uint32_t src_ip, uint16_t src_port);

/**
 * @brief Generate random bytes
 */
static void disco_random_bytes(uint8_t *buf, size_t len) {
    esp_fill_random(buf, len);
}

/**
 * @brief Build DISCO ping packet
 *
 * @param ml MicroLink context
 * @param peer Target peer
 * @param txid Transaction ID (output, 12 bytes)
 * @param packet Output buffer (min DISCO_MAX_PACKET_SIZE)
 * @return Packet length, or -1 on error
 */
static int disco_build_ping(microlink_t *ml, const microlink_peer_t *peer,
                            uint8_t *txid, uint8_t *packet) {
    // Generate random transaction ID
    disco_random_bytes(txid, DISCO_TXID_LEN);

    // Generate random nonce
    uint8_t nonce[DISCO_NONCE_LEN];
    disco_random_bytes(nonce, DISCO_NONCE_LEN);

    // Build plaintext: [type (1)][version (1)][txid (12)][nodekey (32)]
    // Per Tailscale DISCO spec: Ping = type(1) + version(1) + TxID(12) + NodeKey(32) + Padding
    // NodeKey is our WireGuard public key - lets peers validate the ping source
    uint8_t plaintext[1 + 1 + DISCO_TXID_LEN + 32];
    int pt_offset = 0;
    plaintext[pt_offset++] = DISCO_MSG_PING;
    plaintext[pt_offset++] = 0;  // version = 0
    memcpy(plaintext + pt_offset, txid, DISCO_TXID_LEN);
    pt_offset += DISCO_TXID_LEN;
    memcpy(plaintext + pt_offset, ml->wireguard.public_key, 32);

    // Encrypt with NaCl box (our disco key -> peer's disco key)
    uint8_t ciphertext[sizeof(plaintext) + DISCO_MAC_LEN];

    // Use peer's DISCO key for encryption (NOT their WireGuard key)
    if (nacl_box(ciphertext, plaintext, sizeof(plaintext), nonce,
                 peer->disco_key, ml->wireguard.disco_private_key) != 0) {
        ESP_LOGE(TAG, "nacl_box encryption failed");
        return -1;
    }

    // Build packet: [magic][our_disco_pubkey][nonce][ciphertext]
    int offset = 0;
    memcpy(packet + offset, DISCO_MAGIC, DISCO_MAGIC_LEN);
    offset += DISCO_MAGIC_LEN;

    memcpy(packet + offset, ml->wireguard.disco_public_key, DISCO_KEY_LEN);
    offset += DISCO_KEY_LEN;

    memcpy(packet + offset, nonce, DISCO_NONCE_LEN);
    offset += DISCO_NONCE_LEN;

    memcpy(packet + offset, ciphertext, sizeof(ciphertext));
    offset += sizeof(ciphertext);

    return offset;
}

/**
 * @brief Build DISCO pong packet (response to ping)
 *
 * Tailscale DISCO PONG format:
 * Encrypted payload: [type (1)][version (1)][TxID (12)][Src (18)]
 * Src format: IPv6-mapped IPv4 address (16 bytes) + port (2 bytes big-endian)
 *
 * For DERP-relayed pongs, Src is the DERP server address (not meaningful for direct path).
 */
static int disco_build_pong(microlink_t *ml, const microlink_peer_t *peer,
                            const uint8_t *txid, uint32_t src_ip, uint16_t src_port,
                            uint8_t *packet) {
    ESP_LOGD(TAG, "Building PONG: src=%u.%u.%u.%u:%u",
             (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
             (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port);

    // Generate random nonce
    uint8_t nonce[DISCO_NONCE_LEN];
    disco_random_bytes(nonce, DISCO_NONCE_LEN);

    // Build plaintext: [type (1)][version (1)][txid (12)][src_addr (18)]
    // src_addr format: IPv6-mapped IPv4 (16 bytes) + port (2 bytes big-endian)
    // IPv6-mapped IPv4 format: ::ffff:A.B.C.D -> 10 zeros, 2x 0xff, then 4-byte IPv4
    uint8_t plaintext[1 + 1 + DISCO_TXID_LEN + 18];
    int pt_offset = 0;

    plaintext[pt_offset++] = DISCO_MSG_PONG;  // type
    plaintext[pt_offset++] = 0;                // version = 0

    memcpy(plaintext + pt_offset, txid, DISCO_TXID_LEN);
    pt_offset += DISCO_TXID_LEN;

    // IPv6-mapped IPv4: 10 bytes of zeros, 2 bytes of 0xff, then 4-byte IPv4
    memset(plaintext + pt_offset, 0, 10);
    pt_offset += 10;
    plaintext[pt_offset++] = 0xff;
    plaintext[pt_offset++] = 0xff;
    // IPv4 address in network byte order (big-endian)
    plaintext[pt_offset++] = (src_ip >> 24) & 0xFF;
    plaintext[pt_offset++] = (src_ip >> 16) & 0xFF;
    plaintext[pt_offset++] = (src_ip >> 8) & 0xFF;
    plaintext[pt_offset++] = src_ip & 0xFF;
    // Port in big-endian
    plaintext[pt_offset++] = (src_port >> 8) & 0xFF;
    plaintext[pt_offset++] = src_port & 0xFF;

    // Encrypt using peer's DISCO key
    uint8_t ciphertext[sizeof(plaintext) + DISCO_MAC_LEN];
    if (nacl_box(ciphertext, plaintext, sizeof(plaintext), nonce,
                 peer->disco_key, ml->wireguard.disco_private_key) != 0) {
        ESP_LOGE(TAG, "nacl_box encryption failed");
        return -1;
    }

    // Build packet
    int offset = 0;
    memcpy(packet + offset, DISCO_MAGIC, DISCO_MAGIC_LEN);
    offset += DISCO_MAGIC_LEN;

    memcpy(packet + offset, ml->wireguard.disco_public_key, DISCO_KEY_LEN);
    offset += DISCO_KEY_LEN;

    memcpy(packet + offset, nonce, DISCO_NONCE_LEN);
    offset += DISCO_NONCE_LEN;

    memcpy(packet + offset, ciphertext, sizeof(ciphertext));
    offset += sizeof(ciphertext);

    return offset;
}

/**
 * @brief Send UDP packet to endpoint
 */
static esp_err_t disco_send_udp(uint32_t ip, uint16_t port, const uint8_t *data, size_t len) {
    if (disco_socket < 0) {
        return ESP_ERR_INVALID_STATE;
    }

    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(ip)
    };

    int sent = sendto(disco_socket, data, len, 0,
                      (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sent < 0) {
        ESP_LOGD(TAG, "sendto failed: errno=%d", errno);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/**
 * @brief Send DISCO probe to a specific endpoint
 */
static esp_err_t disco_probe_endpoint(microlink_t *ml, uint8_t peer_idx, uint8_t ep_idx) {
    microlink_peer_t *peer = &ml->peers[peer_idx];
    microlink_endpoint_t *ep = &peer->endpoints[ep_idx];
    disco_probe_state_t *probe = &pending_probes[peer_idx][ep_idx];

    // Skip DERP endpoints for direct UDP probes
    if (ep->is_derp) {
        return ESP_OK;
    }

    // Build ping packet
    uint8_t packet[DISCO_MAX_PACKET_SIZE];
    uint8_t txid[DISCO_TXID_LEN];
    int pkt_len = disco_build_ping(ml, peer, txid, packet);
    if (pkt_len < 0) {
        return ESP_FAIL;
    }

    // Send UDP packet
    esp_err_t err = disco_send_udp(ep->ip, ep->port, packet, pkt_len);
    if (err != ESP_OK) {
        return err;
    }

    // Record pending probe
    memcpy(probe->txid, txid, DISCO_TXID_LEN);
    probe->send_time_ms = microlink_get_time_ms();
    probe->pending = true;

    ESP_LOGD(TAG, "Sent DISCO ping to %08lx:%d", (unsigned long)ep->ip, ep->port);
    return ESP_OK;
}

/**
 * @brief Process incoming DISCO packet
 */
static esp_err_t disco_process_packet(microlink_t *ml, const uint8_t *packet, size_t len,
                                      uint32_t src_ip, uint16_t src_port) {
    // Minimum packet size: magic + key + nonce + encrypted(type + txid) + mac
    size_t min_len = DISCO_MAGIC_LEN + DISCO_KEY_LEN + DISCO_NONCE_LEN + DISCO_MAC_LEN + 1 + DISCO_TXID_LEN;
    if (len < min_len) {
        ESP_LOGD(TAG, "DISCO packet too short: %zu", len);
        return ESP_ERR_INVALID_SIZE;
    }

    // Verify magic
    if (memcmp(packet, DISCO_MAGIC, DISCO_MAGIC_LEN) != 0) {
        return ESP_ERR_INVALID_ARG;  // Not a DISCO packet
    }

    const uint8_t *sender_key = packet + DISCO_MAGIC_LEN;
    const uint8_t *nonce = packet + DISCO_MAGIC_LEN + DISCO_KEY_LEN;
    const uint8_t *ciphertext = nonce + DISCO_NONCE_LEN;
    size_t ciphertext_len = len - DISCO_MAGIC_LEN - DISCO_KEY_LEN - DISCO_NONCE_LEN;

    // Find peer by disco public key
    int peer_idx = -1;
    for (int i = 0; i < ml->peer_count; i++) {
        if (memcmp(ml->peers[i].disco_key, sender_key, 32) == 0) {
            peer_idx = i;
            break;
        }
    }

    if (peer_idx < 0) {
        ESP_LOGW(TAG, "DISCO from unknown peer");
        return ESP_ERR_NOT_FOUND;
    }

    microlink_peer_t *peer = &ml->peers[peer_idx];

    // Decrypt payload using nacl_box_open
    // Plaintext: [1-byte type][12-byte txid][optional extra data]
    // Note: Tailscale DISCO can include call-me-maybe with endpoint lists (can be 100+ bytes)
    uint8_t plaintext[256];  // Increased for call-me-maybe endpoint data
    size_t plaintext_len = ciphertext_len - DISCO_MAC_LEN;

    if (plaintext_len > sizeof(plaintext)) {
        ESP_LOGW(TAG, "DISCO payload too large: %zu", plaintext_len);
        return ESP_ERR_NO_MEM;
    }

    // Decrypt: sender_pk is peer's key, recipient_sk is our disco key
    int ret = nacl_box_open(plaintext, ciphertext, ciphertext_len,
                            nonce, sender_key, ml->wireguard.disco_private_key);
    if (ret != 0) {
        ESP_LOGE(TAG, "DISCO decryption failed");
        return ESP_ERR_INVALID_ARG;
    }

    // Validate decrypted payload: [type (1)][version (1)][txid (12)][...]
    if (plaintext_len < 1 + 1 + DISCO_TXID_LEN) {
        ESP_LOGD(TAG, "DISCO payload too short after decrypt: %zu", plaintext_len);
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t msg_type = plaintext[0];
    uint8_t msg_version = plaintext[1];
    const uint8_t *txid = plaintext + 2;  // TxID starts after type + version
    (void)msg_version;  // Suppress unused warning

    ESP_LOGD(TAG, "DISCO %s from peer %d",
             msg_type == DISCO_MSG_PING ? "PING" :
             msg_type == DISCO_MSG_PONG ? "PONG" :
             msg_type == DISCO_MSG_CALL_ME_MAYBE ? "CALL_ME_MAYBE" : "UNKNOWN",
             peer_idx);

    switch (msg_type) {
        case DISCO_MSG_PING: {
            // Respond with pong
            ESP_LOGI(TAG, "PING from peer %d (%s)", peer_idx, peer->hostname);
            uint8_t pong[DISCO_MAX_PACKET_SIZE];
            // For PONG, include the source address where we received the PING from
            // For DERP-relayed pings (src_ip=0), use our VPN IP as the source
            uint32_t pong_src_ip = src_ip;
            uint16_t pong_src_port = src_port;
            if (pong_src_ip == 0) {
                // DERP relay - use our VPN IP (DERP doesn't provide the original source)
                pong_src_ip = ml->vpn_ip;
                pong_src_port = 0;  // No meaningful port for DERP
            }
            int pong_len = disco_build_pong(ml, peer, txid, pong_src_ip, pong_src_port, pong);
            if (pong_len > 0) {
                // If src_ip is 0, this came via DERP - respond via DERP
                if (src_ip == 0) {
                    esp_err_t err = microlink_derp_send(ml, peer->vpn_ip, pong, pong_len);
                    if (err == ESP_OK) {
                        ESP_LOGI(TAG, "PONG sent via DERP to peer %d", peer_idx);
                    } else {
                        ESP_LOGE(TAG, "Failed to send PONG via DERP: %s", esp_err_to_name(err));
                    }
                } else {
                    disco_send_udp(src_ip, src_port, pong, pong_len);
                    ESP_LOGI(TAG, "PONG sent to peer %d", peer_idx);
                }
            } else {
                ESP_LOGE(TAG, "Failed to build PONG");
            }
            break;
        }

        case DISCO_MSG_PONG: {
            // Find matching probe and calculate RTT
            uint64_t now = microlink_get_time_ms();
            bool found = false;
            bool via_derp = (src_ip == 0);  // src_ip=0 means came via DERP

            // Check all probe slots including the DERP slot (last index)
            // NOTE: Tailscale zeroes the first byte of TxID in PONG responses,
            // so we compare bytes 1-11 only (skip first byte)
            for (int ep = 0; ep < MICROLINK_MAX_ENDPOINTS; ep++) {
                disco_probe_state_t *probe = &pending_probes[peer_idx][ep];
                if (probe->pending && memcmp(probe->txid + 1, txid + 1, DISCO_TXID_LEN - 1) == 0) {
                    uint32_t rtt = (uint32_t)(now - probe->send_time_ms);
                    probe->pending = false;
                    found = true;

                    bool is_derp_slot = (ep == MICROLINK_MAX_ENDPOINTS - 1);

                    // Update peer latency (track best path)
                    if (peer->latency_ms == 0 || rtt < peer->latency_ms) {
                        peer->latency_ms = rtt;
                        peer->best_endpoint_idx = ep;

                        if (is_derp_slot || via_derp) {
                            ESP_LOGI(TAG, "PONG peer %d via DERP: %lums", peer_idx, (unsigned long)rtt);
                            peer->using_derp = true;
                        } else {
                            ESP_LOGI(TAG, "PONG peer %d direct: %lums", peer_idx, (unsigned long)rtt);
                            // Update WireGuard with direct endpoint
                            if (ep < peer->endpoint_count && !peer->endpoints[ep].is_derp) {
                                microlink_wireguard_update_endpoint(ml, peer->vpn_ip,
                                                                    src_ip, src_port);
                            }
                            peer->using_derp = false;
                        }
                    }

                    // Initiate WireGuard handshake via DERP if path is via DERP
                    if ((is_derp_slot || via_derp) && ml->wireguard.netif) {
                        extern err_t wireguardif_peer_is_up(struct netif *netif, u8_t peer_index, ip_addr_t *current_ip, u16_t *current_port);
                        extern err_t wireguardif_connect_derp(struct netif *netif, u8_t peer_index);

                        ip_addr_t dummy_ip;
                        u16_t dummy_port;
                        err_t up_err = wireguardif_peer_is_up((struct netif *)ml->wireguard.netif, peer_idx, &dummy_ip, &dummy_port);

                        if (up_err != ERR_OK) {
                            peer->using_derp = true;
                            err_t wg_err = wireguardif_connect_derp((struct netif *)ml->wireguard.netif, peer_idx);
                            if (wg_err == ERR_OK) {
                                ESP_LOGD(TAG, "WG handshake initiated for peer %d", peer_idx);
                            } else {
                                ESP_LOGW(TAG, "WG handshake failed: %d", wg_err);
                            }
                        }
                    }

                    peer->last_seen_ms = now;
                    break;
                }
            }

            if (!found) {
                ESP_LOGD(TAG, "PONG from peer %d - no matching probe", peer_idx);

                if (!via_derp) {
                    // Pong from unexpected source - might be hole-punching success
                    for (int ep = 0; ep < MICROLINK_MAX_ENDPOINTS; ep++) {
                        disco_probe_state_t *probe = &pending_probes[peer_idx][ep];
                        if (probe->pending && memcmp(probe->txid, txid, DISCO_TXID_LEN) == 0) {
                            uint32_t rtt = (uint32_t)(now - probe->send_time_ms);
                            probe->pending = false;

                            ESP_LOGI(TAG, "Hole-punch success! Peer %d RTT=%lums", peer_idx, (unsigned long)rtt);
                            microlink_wireguard_update_endpoint(ml, peer->vpn_ip, src_ip, src_port);

                            peer->latency_ms = rtt;
                            peer->last_seen_ms = now;
                            peer->using_derp = false;
                            break;
                        }
                    }
                } else {
                    // PONG via DERP but no matching probe - still try to connect
                    peer->using_derp = true;
                    peer->last_seen_ms = now;

                    if (ml->wireguard.netif) {
                        extern err_t wireguardif_peer_is_up(struct netif *netif, u8_t peer_index, ip_addr_t *current_ip, u16_t *current_port);
                        extern err_t wireguardif_connect_derp(struct netif *netif, u8_t peer_index);

                        ip_addr_t dummy_ip;
                        u16_t dummy_port;
                        err_t up_err = wireguardif_peer_is_up((struct netif *)ml->wireguard.netif, peer_idx, &dummy_ip, &dummy_port);

                        if (up_err != ERR_OK) {
                            wireguardif_connect_derp((struct netif *)ml->wireguard.netif, peer_idx);
                        }
                    }
                }
            }
            break;
        }

        case DISCO_MSG_CALL_ME_MAYBE: {
            // Peer is asking us to try connecting to their endpoints
            ESP_LOGI(TAG, "CallMeMaybe from peer %d", peer_idx);
            // Trigger probing of this peer
            ml->disco.peer_disco[peer_idx].active = true;
            break;
        }

        default:
            ESP_LOGD(TAG, "Unknown DISCO message type: 0x%02x", msg_type);
            break;
    }

    return ESP_OK;
}

esp_err_t microlink_disco_init(microlink_t *ml) {
    ESP_LOGI(TAG, "Initializing DISCO protocol");

    memset(&ml->disco, 0, sizeof(microlink_disco_t));
    memset(pending_probes, 0, sizeof(pending_probes));

    // Create UDP socket for direct DISCO probes
    disco_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (disco_socket < 0) {
        ESP_LOGE(TAG, "Failed to create DISCO socket: errno=%d", errno);
        return ESP_FAIL;
    }

    // Bind to any port
    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_port = 0,  // Let system assign port
        .sin_addr.s_addr = INADDR_ANY
    };
    if (bind(disco_socket, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind DISCO socket: errno=%d", errno);
        close(disco_socket);
        disco_socket = -1;
        return ESP_FAIL;
    }

    // Set non-blocking
    int flags = fcntl(disco_socket, F_GETFL, 0);
    fcntl(disco_socket, F_SETFL, flags | O_NONBLOCK);

    // Get assigned port
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    getsockname(disco_socket, (struct sockaddr *)&local_addr, &addr_len);
    ESP_LOGI(TAG, "DISCO socket bound to port %d", ntohs(local_addr.sin_port));

    ESP_LOGI(TAG, "DISCO initialized");
    return ESP_OK;
}

esp_err_t microlink_disco_deinit(microlink_t *ml) {
    ESP_LOGI(TAG, "Deinitializing DISCO protocol");

    if (disco_socket >= 0) {
        close(disco_socket);
        disco_socket = -1;
    }

    memset(&ml->disco, 0, sizeof(microlink_disco_t));
    memset(pending_probes, 0, sizeof(pending_probes));

    ESP_LOGI(TAG, "DISCO deinitialized");
    return ESP_OK;
}

esp_err_t microlink_disco_probe_peers(microlink_t *ml) {
    uint64_t now = microlink_get_time_ms();

    // Check if it's time for global DISCO
    if (now - ml->disco.last_global_disco_ms < DISCO_PROBE_INTERVAL_MS) {
        return ESP_OK;
    }
    ml->disco.last_global_disco_ms = now;

    ESP_LOGD(TAG, "Probing %d peers with DISCO", ml->peer_count);

    for (uint8_t i = 0; i < ml->peer_count; i++) {
        microlink_peer_t *peer = &ml->peers[i];

        // Skip if recently probed
        if (now - ml->disco.peer_disco[i].last_probe_ms < DISCO_PROBE_INTERVAL_MS) {
            continue;
        }

        // Probe each direct endpoint (UDP)
        for (uint8_t ep = 0; ep < peer->endpoint_count; ep++) {
            disco_probe_endpoint(ml, i, ep);
        }

        // Also probe via DERP relay - this is critical for NAT traversal!
        // Peers behind NAT can't receive direct UDP, so DERP is the fallback
        disco_probe_via_derp(ml, i);

        ml->disco.peer_disco[i].last_probe_ms = now;
        ml->disco.peer_disco[i].probe_sequence++;
        ml->disco.peer_disco[i].active = true;

        // NOTE: Dual-Core Fix - Coordination polling is now handled by a dedicated
        // high-priority task on Core 1. This allows DISCO probes to run on Core 0
        // without worrying about blocking the coordination socket.
        // The old poll_updates call here was the cause of ECONNRESET issues.
    }

    return ESP_OK;
}

esp_err_t microlink_disco_update_paths(microlink_t *ml) {
    if (disco_socket < 0) {
        return ESP_ERR_INVALID_STATE;
    }

    uint64_t now = microlink_get_time_ms();

    // Receive incoming DISCO packets
    uint8_t rx_buf[DISCO_MAX_PACKET_SIZE];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    while (1) {
        int len = recvfrom(disco_socket, rx_buf, sizeof(rx_buf), 0,
                          (struct sockaddr *)&src_addr, &addr_len);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  // No more packets
            }
            ESP_LOGD(TAG, "recvfrom error: errno=%d", errno);
            break;
        }

        uint32_t src_ip = ntohl(src_addr.sin_addr.s_addr);
        uint16_t src_port = ntohs(src_addr.sin_port);

        disco_process_packet(ml, rx_buf, len, src_ip, src_port);
    }

    // Check for probe timeouts and update path state
    for (uint8_t i = 0; i < ml->peer_count; i++) {
        microlink_peer_t *peer = &ml->peers[i];

        for (uint8_t ep = 0; ep < peer->endpoint_count; ep++) {
            disco_probe_state_t *probe = &pending_probes[i][ep];

            // Check for timeout
            if (probe->pending && (now - probe->send_time_ms) > DISCO_PROBE_TIMEOUT_MS) {
                probe->pending = false;
                ESP_LOGD(TAG, "DISCO probe timeout: peer %d endpoint %d", i, ep);
            }
        }

        // Mark peer as stale if not seen recently
        if (peer->last_seen_ms > 0 && (now - peer->last_seen_ms) > DISCO_STALE_THRESHOLD_MS) {
            ESP_LOGW(TAG, "Peer %d path stale (no response in %lums)",
                     i, (unsigned long)(now - peer->last_seen_ms));
            // Consider switching to DERP fallback
        }
    }

    return ESP_OK;
}

/**
 * @brief Send DISCO probe to peer via DERP relay
 *
 * This is essential for NAT traversal - peers behind NAT can't receive
 * direct UDP probes, so we must also probe via DERP.
 */
static esp_err_t disco_probe_via_derp(microlink_t *ml, uint8_t peer_idx) {
    microlink_peer_t *peer = &ml->peers[peer_idx];

    if (!ml->derp.connected) {
        ESP_LOGD(TAG, "DERP not connected, skipping DERP probe");
        return ESP_ERR_INVALID_STATE;
    }

    // Build ping packet
    uint8_t packet[DISCO_MAX_PACKET_SIZE];
    uint8_t txid[DISCO_TXID_LEN];
    int pkt_len = disco_build_ping(ml, peer, txid, packet);
    if (pkt_len < 0) {
        return ESP_FAIL;
    }

    // Send via DERP relay
    esp_err_t err = microlink_derp_send(ml, peer->vpn_ip, packet, pkt_len);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Failed to send DISCO via DERP: %d", err);
        return err;
    }

    // Use a special slot for DERP probes (last endpoint slot)
    disco_probe_state_t *probe = &pending_probes[peer_idx][MICROLINK_MAX_ENDPOINTS - 1];
    memcpy(probe->txid, txid, DISCO_TXID_LEN);
    probe->send_time_ms = microlink_get_time_ms();
    probe->pending = true;

    ESP_LOGD(TAG, "DISCO ping via DERP to peer %d", peer_idx);
    return ESP_OK;
}

esp_err_t microlink_disco_handle_derp_packet(microlink_t *ml, const uint8_t *src_key,
                                              const uint8_t *data, size_t len) {
    // Check for DISCO magic
    if (len < DISCO_MAGIC_LEN || memcmp(data, DISCO_MAGIC, DISCO_MAGIC_LEN) != 0) {
        return ESP_ERR_INVALID_ARG;  // Not a DISCO packet
    }

    // Find peer by WireGuard public key (src_key from DERP frame is WG pubkey)
    int peer_idx = -1;
    for (int i = 0; i < ml->peer_count; i++) {
        if (memcmp(ml->peers[i].public_key, src_key, 32) == 0) {
            peer_idx = i;
            break;
        }
    }

    if (peer_idx < 0) {
        ESP_LOGW(TAG, "DISCO from unknown DERP peer");
        return ESP_ERR_NOT_FOUND;
    }

    // Update disco key if it differs from packet header (handles key rotation)
    if (len >= DISCO_MAGIC_LEN + DISCO_KEY_LEN) {
        const uint8_t *disco_sender_key = data + DISCO_MAGIC_LEN;
        microlink_peer_t *peer = &ml->peers[peer_idx];

        if (memcmp(peer->disco_key, disco_sender_key, 32) != 0) {
            ESP_LOGI(TAG, "Peer %d disco_key updated", peer_idx);
            memcpy(peer->disco_key, disco_sender_key, 32);
        }
    }

    // Process the DISCO packet - use 0 for IP/port since it came via DERP
    return disco_process_packet(ml, data, len, 0, 0);
}

bool microlink_disco_is_disco_packet(const uint8_t *data, size_t len) {
    return (len >= DISCO_MAGIC_LEN && memcmp(data, DISCO_MAGIC, DISCO_MAGIC_LEN) == 0);
}
