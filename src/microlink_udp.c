/**
 * @file microlink_udp.c
 * @brief MicroLink UDP Socket API - PSTOP Transport Layer (Task 1.3)
 *
 * Provides simple UDP send/receive over Tailscale VPN, equivalent to:
 *   echo "data" | nc -u <tailscale_ip> <port>
 *
 * This implementation routes UDP through the existing MicroLink infrastructure:
 * - Uses WireGuard tunnel for encrypted transport (standard Tailscale path)
 * - Automatically sends DISCO CallMeMaybe to trigger peer handshake initiation
 *
 * Handshake Strategy:
 * ESP32-initiated WireGuard handshakes may not complete due to NAT/firewall
 * asymmetry. To work around this, we send DISCO CallMeMaybe messages which
 * tell the peer "please initiate a connection to me". When the peer (e.g., PC)
 * initiates the handshake, it completes successfully, enabling bidirectional
 * UDP communication.
 */

#include "microlink.h"
#include "microlink_internal.h"
#include "esp_log.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include <string.h>

static const char *TAG = "ml_udp";

/* ============================================================================
 * UDP Socket Structure
 * ========================================================================== */

#define UDP_RX_QUEUE_SIZE 4
#define UDP_MAX_PACKET_SIZE 1400

typedef struct {
    uint32_t src_ip;
    uint16_t src_port;
    uint8_t data[UDP_MAX_PACKET_SIZE];
    size_t len;
    bool valid;
} udp_rx_packet_t;

struct microlink_udp_socket {
    microlink_t *ml;                    ///< Parent MicroLink context
    struct udp_pcb *pcb;                ///< lwIP UDP PCB (for receiving)
    uint16_t local_port;                ///< Local bound port

    // RX queue for received packets
    udp_rx_packet_t rx_queue[UDP_RX_QUEUE_SIZE];
    uint8_t rx_head;
    uint8_t rx_tail;
};

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

/**
 * @brief Convert MicroLink IP (host byte order) to lwIP ip_addr_t
 */
static void microlink_ip_to_lwip(uint32_t ml_ip, ip_addr_t *lwip_ip) {
    IP4_ADDR(&lwip_ip->u_addr.ip4,
             (ml_ip >> 24) & 0xFF,
             (ml_ip >> 16) & 0xFF,
             (ml_ip >> 8) & 0xFF,
             ml_ip & 0xFF);
    lwip_ip->type = IPADDR_TYPE_V4;
}

/**
 * @brief Convert lwIP ip_addr_t to MicroLink IP (host byte order)
 */
static uint32_t lwip_ip_to_microlink(const ip_addr_t *lwip_ip) {
    if (lwip_ip->type != IPADDR_TYPE_V4) {
        return 0;
    }

    uint32_t ip = ip4_addr_get_u32(&lwip_ip->u_addr.ip4);
    return ((ip & 0xFF) << 24) |
           (((ip >> 8) & 0xFF) << 16) |
           (((ip >> 16) & 0xFF) << 8) |
           ((ip >> 24) & 0xFF);
}

/**
 * @brief lwIP UDP receive callback
 */
static void udp_recv_callback(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                               const ip_addr_t *addr, u16_t port) {
    microlink_udp_socket_t *sock = (microlink_udp_socket_t *)arg;

    if (!sock || !p) {
        if (p) pbuf_free(p);
        return;
    }

    // Check if queue is full
    uint8_t next_head = (sock->rx_head + 1) % UDP_RX_QUEUE_SIZE;
    if (next_head == sock->rx_tail) {
        ESP_LOGW(TAG, "RX queue full, dropping packet");
        pbuf_free(p);
        return;
    }

    // Copy packet to queue
    udp_rx_packet_t *pkt = &sock->rx_queue[sock->rx_head];
    pkt->src_ip = lwip_ip_to_microlink(addr);
    pkt->src_port = port;
    pkt->len = (p->tot_len > UDP_MAX_PACKET_SIZE) ? UDP_MAX_PACKET_SIZE : p->tot_len;
    pbuf_copy_partial(p, pkt->data, pkt->len, 0);
    pkt->valid = true;

    sock->rx_head = next_head;

    char ip_buf[16];
    ESP_LOGI(TAG, "Received %u bytes from %s:%u",
             (unsigned int)pkt->len, microlink_vpn_ip_to_str(pkt->src_ip, ip_buf), port);

    pbuf_free(p);
}

/* ============================================================================
 * Public API Implementation
 * ========================================================================== */

uint32_t microlink_parse_ip(const char *ip_str) {
    if (!ip_str) return 0;

    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        ESP_LOGE(TAG, "Invalid IP format: %s", ip_str);
        return 0;
    }

    if (a > 255 || b > 255 || c > 255 || d > 255) {
        ESP_LOGE(TAG, "IP octet out of range: %s", ip_str);
        return 0;
    }

    return (a << 24) | (b << 16) | (c << 8) | d;
}

microlink_udp_socket_t *microlink_udp_create(microlink_t *ml, uint16_t local_port) {
    if (!ml) {
        ESP_LOGE(TAG, "NULL MicroLink handle");
        return NULL;
    }

    if (!microlink_is_connected(ml)) {
        ESP_LOGE(TAG, "MicroLink not connected");
        return NULL;
    }

    // Allocate socket structure
    microlink_udp_socket_t *sock = calloc(1, sizeof(microlink_udp_socket_t));
    if (!sock) {
        ESP_LOGE(TAG, "Failed to allocate UDP socket");
        return NULL;
    }

    sock->ml = ml;
    sock->rx_head = 0;
    sock->rx_tail = 0;

    // Create lwIP UDP PCB for receiving
    sock->pcb = udp_new();
    if (!sock->pcb) {
        ESP_LOGE(TAG, "Failed to create UDP PCB");
        free(sock);
        return NULL;
    }

    // Bind to WireGuard netif if available
    if (ml->wireguard.netif) {
        udp_bind_netif(sock->pcb, (struct netif *)ml->wireguard.netif);
    }

    // Bind to local IP and port
    ip_addr_t local_ip;
    microlink_ip_to_lwip(ml->vpn_ip, &local_ip);

    err_t err = udp_bind(sock->pcb, &local_ip, local_port);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "udp_bind() failed: %d", err);
        udp_remove(sock->pcb);
        free(sock);
        return NULL;
    }

    sock->local_port = sock->pcb->local_port;

    // Set receive callback
    udp_recv(sock->pcb, udp_recv_callback, sock);

    char ip_buf[16];
    ESP_LOGI(TAG, "UDP socket created: %s:%u",
             microlink_vpn_ip_to_str(ml->vpn_ip, ip_buf), sock->local_port);

    // Send CallMeMaybe to all peers to trigger them to initiate WireGuard handshakes
    // This works around the issue where ESP32-initiated handshakes don't complete
    ESP_LOGI(TAG, "Sending CallMeMaybe to %d peers to trigger handshake initiation...",
             ml->peer_count);
    for (int i = 0; i < ml->peer_count; i++) {
        esp_err_t cmm_err = microlink_disco_send_call_me_maybe(ml, ml->peers[i].vpn_ip);
        if (cmm_err == ESP_OK) {
            ESP_LOGI(TAG, "  -> Sent CallMeMaybe to peer %d (%s)",
                     i, microlink_vpn_ip_to_str(ml->peers[i].vpn_ip, ip_buf));
        }
    }

    return sock;
}

void microlink_udp_close(microlink_udp_socket_t *sock) {
    if (!sock) return;

    if (sock->pcb) {
        udp_recv(sock->pcb, NULL, NULL);
        udp_remove(sock->pcb);
        ESP_LOGI(TAG, "UDP socket closed (port=%u)", sock->local_port);
    }

    free(sock);
}

esp_err_t microlink_udp_send(microlink_udp_socket_t *sock, uint32_t dest_ip,
                              uint16_t dest_port, const void *data, size_t len) {
    if (!sock || !sock->pcb || !data || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!sock->ml) {
        return ESP_ERR_INVALID_STATE;
    }

    microlink_t *ml = sock->ml;

    if (len > UDP_MAX_PACKET_SIZE) {
        ESP_LOGE(TAG, "Packet too large: %u", (unsigned int)len);
        return ESP_ERR_INVALID_SIZE;
    }

    char ip_buf[16];

    // Convert destination IP to lwIP format
    ip_addr_t dest_addr;
    microlink_ip_to_lwip(dest_ip, &dest_addr);

    // Allocate pbuf for the data
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (!p) {
        ESP_LOGE(TAG, "Failed to allocate pbuf");
        return ESP_ERR_NO_MEM;
    }

    // Copy data to pbuf
    memcpy(p->payload, data, len);

    // Send via lwIP UDP - routes through WireGuard netif for encryption
    err_t err = udp_sendto(sock->pcb, p, &dest_addr, dest_port);
    pbuf_free(p);

    if (err != ERR_OK) {
        // WireGuard send failed - likely no handshake yet
        // Send CallMeMaybe to request peer initiate handshake, then retry
        ESP_LOGW(TAG, "udp_sendto() failed: %d, sending CallMeMaybe to trigger handshake", err);

        esp_err_t cmm_err = microlink_disco_send_call_me_maybe(ml, dest_ip);
        if (cmm_err == ESP_OK) {
            ESP_LOGI(TAG, "CallMeMaybe sent - peer should initiate handshake soon");
            ESP_LOGI(TAG, "Tip: Run 'tailscale ping %s' from the peer to speed up handshake",
                     microlink_vpn_ip_to_str(dest_ip, ip_buf));
        }

        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "UDP sent %u bytes to %s:%u via WireGuard",
             (unsigned int)len, microlink_vpn_ip_to_str(dest_ip, ip_buf), dest_port);

    return ESP_OK;
}

esp_err_t microlink_udp_sendto(microlink_t *ml, uint32_t dest_ip,
                                uint16_t dest_port, const void *data, size_t len) {
    if (!ml || !data || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    // Create temporary socket
    microlink_udp_socket_t *sock = microlink_udp_create(ml, 0);
    if (!sock) {
        return ESP_ERR_NO_MEM;
    }

    // Send data
    esp_err_t ret = microlink_udp_send(sock, dest_ip, dest_port, data, len);

    // Close socket
    microlink_udp_close(sock);

    return ret;
}

esp_err_t microlink_udp_recv(microlink_udp_socket_t *sock, uint32_t *src_ip,
                              uint16_t *src_port, void *buffer, size_t *len,
                              uint32_t timeout_ms) {
    if (!sock || !buffer || !len || *len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    // Wait for packet with timeout
    uint32_t start_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;

    while (1) {
        // Check if packet available in queue
        if (sock->rx_tail != sock->rx_head) {
            udp_rx_packet_t *pkt = &sock->rx_queue[sock->rx_tail];

            if (pkt->valid) {
                size_t copy_len = (pkt->len < *len) ? pkt->len : *len;
                memcpy(buffer, pkt->data, copy_len);
                *len = copy_len;

                if (src_ip) *src_ip = pkt->src_ip;
                if (src_port) *src_port = pkt->src_port;

                pkt->valid = false;
                sock->rx_tail = (sock->rx_tail + 1) % UDP_RX_QUEUE_SIZE;

                return ESP_OK;
            }
        }

        // Check timeout
        uint32_t elapsed = (xTaskGetTickCount() * portTICK_PERIOD_MS) - start_ms;
        if (timeout_ms > 0 && elapsed >= timeout_ms) {
            return ESP_ERR_TIMEOUT;
        }

        // Process MicroLink state machine while waiting (essential for DERP/WG)
        if (sock->ml) {
            microlink_update(sock->ml);
        }

        // Brief delay
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

uint16_t microlink_udp_get_local_port(const microlink_udp_socket_t *sock) {
    return sock ? sock->local_port : 0;
}
