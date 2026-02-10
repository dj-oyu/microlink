/**
 * @file microlink_wireguard.c
 * @brief WireGuard wrapper using wireguard-lwip
 *
 * Integrates wireguard-lwip (smartalock/wireguard-lwip) for ESP32.
 * Provides manual peer management for Tailscale multi-peer support.
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_netif.h"
#include "mbedtls/base64.h"
#include "nvs_flash.h"
#include "nvs.h"
#include <string.h>

// WireGuard-lwIP headers
#include "wireguardif.h"
#include "wireguard.h"
#include "x25519.h"  // For public key derivation

// lwIP headers
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/err.h"
#include "lwip/mem.h"      // For mem_free()
#include "lwip/udp.h"      // For udp_remove()
#include "lwip/pbuf.h"     // For pbuf_alloc()
#include "lwip/timeouts.h" // For sys_untimeout()
#include "lwip/tcpip.h"    // For tcpip_try_callback()
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

// External lwIP global
extern struct netif *netif_list;

static const char *TAG = "ml_wg";

/* Forward declaration for DERP output callback */
static err_t wg_derp_output_callback(const uint8_t *peer_public_key, const uint8_t *data, size_t len, void *ctx);

/**
 * @brief Direct output callback: sends WG packets through the DISCO PCB
 *        (critical for NAT traversal — same source port as DISCO probes).
 *
 * This runs inside the tcpip_thread context (called from wireguardif_peer_output),
 * so we use raw lwIP udp_sendto() directly.  The DISCO PCB is shared for
 * receiving (demux callback) and sending (WG output + DISCO probes + STUN).
 */
static err_t wg_direct_output_callback(const uint8_t *data, size_t len,
                                        const ip_addr_t *dest_ip, u16_t dest_port, void *ctx) {
    microlink_t *ml = (microlink_t *)ctx;
    if (!ml || !ml->disco.pcb) return ERR_IF;

    struct udp_pcb *pcb = (struct udp_pcb *)ml->disco.pcb;
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (!p) return ERR_MEM;

    memcpy(p->payload, data, len);
    err_t err = udp_sendto(pcb, p, dest_ip, dest_port);
    pbuf_free(p);
    return err;
}

/* ============================================================================
 * Thread-safe DERP Packet Injection via tcpip_callback
 *
 * LOCK_TCPIP_CORE() is a no-op without CONFIG_LWIP_TCPIP_CORE_LOCKING.
 * Enabling that option causes SDIO contention (tcpip thread blocked on lock).
 * Instead, we use tcpip_try_callback() to run wireguardif_network_rx()
 * inside the tcpip thread, which already has exclusive lwIP access.
 * ========================================================================== */

typedef struct {
    struct wireguard_device *device;
    struct udp_pcb *pcb;
    struct pbuf *p;
    ip_addr_t addr;
    u16_t port;
} wg_inject_ctx_t;

/* Synchronous injection for DERP packets (low volume, needs ordering guarantees) */
static wg_inject_ctx_t s_inject_ctx;
static SemaphoreHandle_t s_inject_done = NULL;

extern void wireguardif_network_rx(void *arg, struct udp_pcb *pcb,
                                    struct pbuf *p, const ip_addr_t *addr, u16_t port);

static void wg_inject_in_tcpip_thread(void *arg) {
    wg_inject_ctx_t *ctx = (wg_inject_ctx_t *)arg;
    wireguardif_network_rx(ctx->device, ctx->pcb, ctx->p, &ctx->addr, ctx->port);
    xSemaphoreGive(s_inject_done);
}

/* ============================================================================
 * Deferred DERP Packet Queue
 *
 * When WireGuard's timer callback triggers a retransmission, it runs from
 * the lwIP tcpip thread which has insufficient stack for mbedtls TLS ops.
 * We queue these packets and send them from the main MicroLink task.
 * ========================================================================== */

#define DERP_QUEUE_SIZE 16
#define DERP_PACKET_MAX_SIZE 256

typedef struct {
    uint8_t peer_pubkey[32];
    uint8_t data[DERP_PACKET_MAX_SIZE];
    size_t len;
    bool pending;
} derp_queued_packet_t;

static derp_queued_packet_t derp_packet_queue[DERP_QUEUE_SIZE];
static microlink_t *queued_ml_ctx = NULL;

/* NVS keys for persistent storage */
#define NVS_NAMESPACE       "microlink"
#define NVS_KEY_WG_PRIVATE  "wg_private"
#define NVS_KEY_WG_PUBLIC   "wg_public"
#define NVS_KEY_DISCO_PRI   "disco_pri"
#define NVS_KEY_DISCO_PUB   "disco_pub"

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

/**
 * @brief Generate WireGuard private/public key pair
 */
static void generate_wireguard_keys(uint8_t *private_key, uint8_t *public_key) {
    // Generate random private key
    esp_fill_random(private_key, 32);

    // Clamp private key (Curve25519 requirement)
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;

    // Derive public key from private key using Curve25519 base point multiplication
    x25519_base(public_key, private_key, 1);
}

/**
 * @brief Load or generate WireGuard and Disco keys from NVS
 *
 * Keys are persisted so the device identity remains stable across reboots.
 * This is critical for Tailscale - if keys change, peers see a "new" device.
 */
static esp_err_t load_or_generate_keys(microlink_t *ml) {
    nvs_handle_t nvs;
    esp_err_t ret;
    bool need_save = false;

    ret = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to open NVS, generating ephemeral keys: %d", ret);
        generate_wireguard_keys(ml->wireguard.private_key, ml->wireguard.public_key);
        generate_wireguard_keys(ml->wireguard.disco_private_key, ml->wireguard.disco_public_key);
        return ESP_OK;  // Still works, just not persistent
    }

    // Try to load WireGuard keys
    size_t key_len = 32;
    ret = nvs_get_blob(nvs, NVS_KEY_WG_PRIVATE, ml->wireguard.private_key, &key_len);
    if (ret == ESP_OK && key_len == 32) {
        key_len = 32;
        ret = nvs_get_blob(nvs, NVS_KEY_WG_PUBLIC, ml->wireguard.public_key, &key_len);
        if (ret == ESP_OK && key_len == 32) {
            ESP_LOGI(TAG, "Loaded existing WireGuard keys from NVS");
        } else {
            // Regenerate public key from private
            x25519_base(ml->wireguard.public_key, ml->wireguard.private_key, 1);
            need_save = true;
        }
    } else {
        ESP_LOGI(TAG, "No WireGuard keys in NVS, generating new ones");
        generate_wireguard_keys(ml->wireguard.private_key, ml->wireguard.public_key);
        need_save = true;
    }

    // Try to load Disco keys
    key_len = 32;
    ret = nvs_get_blob(nvs, NVS_KEY_DISCO_PRI, ml->wireguard.disco_private_key, &key_len);
    if (ret == ESP_OK && key_len == 32) {
        key_len = 32;
        ret = nvs_get_blob(nvs, NVS_KEY_DISCO_PUB, ml->wireguard.disco_public_key, &key_len);
        if (ret == ESP_OK && key_len == 32) {
            ESP_LOGI(TAG, "Loaded existing Disco keys from NVS");
        } else {
            x25519_base(ml->wireguard.disco_public_key, ml->wireguard.disco_private_key, 1);
            need_save = true;
        }
    } else {
        ESP_LOGI(TAG, "No Disco keys in NVS, generating new ones");
        generate_wireguard_keys(ml->wireguard.disco_private_key, ml->wireguard.disco_public_key);
        need_save = true;
    }

    // Save newly generated keys
    if (need_save) {
        ret = nvs_set_blob(nvs, NVS_KEY_WG_PRIVATE, ml->wireguard.private_key, 32);
        if (ret == ESP_OK) {
            ret = nvs_set_blob(nvs, NVS_KEY_WG_PUBLIC, ml->wireguard.public_key, 32);
        }
        if (ret == ESP_OK) {
            ret = nvs_set_blob(nvs, NVS_KEY_DISCO_PRI, ml->wireguard.disco_private_key, 32);
        }
        if (ret == ESP_OK) {
            ret = nvs_set_blob(nvs, NVS_KEY_DISCO_PUB, ml->wireguard.disco_public_key, 32);
        }
        if (ret == ESP_OK) {
            ret = nvs_commit(nvs);
        }

        if (ret == ESP_OK) {
            ESP_LOGI(TAG, "Saved new WireGuard/Disco keys to NVS");
        } else {
            ESP_LOGW(TAG, "Failed to save keys to NVS: %d", ret);
        }
    }

    nvs_close(nvs);
    return ESP_OK;
}

/**
 * @brief Convert binary key to base64 string using mbedtls
 */
static esp_err_t key_to_base64(const uint8_t *key, char *base64_out, size_t out_len) {
    // Use mbedtls for standard-compliant base64 encoding
    size_t olen = 0;
    int ret = mbedtls_base64_encode((unsigned char *)base64_out, out_len, &olen, key, 32);

    if (ret != 0) {
        ESP_LOGE("ml_wg", "Base64 encode failed: %d", ret);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/**
 * @brief Convert MicroLink IP format to lwIP ip_addr_t
 */
static void microlink_ip_to_lwip(uint32_t ml_ip, ip_addr_t *lwip_ip) {
    // MicroLink uses host byte order (0x6440000A = 100.64.0.10)
    // lwIP uses network byte order
    IP4_ADDR(&lwip_ip->u_addr.ip4,
             (ml_ip >> 24) & 0xFF,
             (ml_ip >> 16) & 0xFF,
             (ml_ip >> 8) & 0xFF,
             ml_ip & 0xFF);
    lwip_ip->type = IPADDR_TYPE_V4;
}

/**
 * @brief Convert lwIP ip_addr_t to MicroLink IP format
 */
static uint32_t lwip_ip_to_microlink(const ip_addr_t *lwip_ip) {
    if (lwip_ip->type != IPADDR_TYPE_V4) {
        return 0;
    }

    uint32_t ip = ip4_addr_get_u32(&lwip_ip->u_addr.ip4);
    // Convert from network byte order to host byte order
    return ((ip & 0xFF) << 24) |
           (((ip >> 8) & 0xFF) << 16) |
           (((ip >> 16) & 0xFF) << 8) |
           ((ip >> 24) & 0xFF);
}

/* ============================================================================
 * Initialization
 * ========================================================================== */

esp_err_t microlink_wireguard_init(microlink_t *ml) {
    ESP_LOGI(TAG, "Initializing WireGuard with wireguard-lwip");

    memset(&ml->wireguard, 0, sizeof(microlink_wireguard_t));

    // Load or generate WireGuard and Disco keys (persisted in NVS)
    esp_err_t key_ret = load_or_generate_keys(ml);
    if (key_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to load/generate keys: %d", key_ret);
        return key_ret;
    }

    // Convert private key to base64 for wireguard-lwip (store in persistent struct)
    esp_err_t b64_ret = key_to_base64(ml->wireguard.private_key, ml->wireguard.private_key_b64,
                                       sizeof(ml->wireguard.private_key_b64));
    if (b64_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to encode private key to base64");
        return b64_ret;
    }

    ESP_LOGI(TAG, "WireGuard and Disco keys ready");
    ESP_LOGD(TAG, "Private key (first 8 chars): %.8s...", ml->wireguard.private_key_b64);

    // Allocate lwIP netif structure
    // IMPORTANT: Use calloc() to zero-initialize all fields, including:
    // - netif->client_data[] array (ensures lwip_get_esp_netif() returns NULL)
    // - All callback function pointers (status_callback, link_callback, etc.)
    // This prevents ESP-IDF's callbacks from being triggered during manual netif setup
    ml->wireguard.netif = (struct netif *)calloc(1, sizeof(struct netif));
    if (!ml->wireguard.netif) {
        ESP_LOGE(TAG, "Failed to allocate netif");
        return ESP_ERR_NO_MEM;
    }

    // Prepare WireGuard initialization data (use persistent base64 key!)
    struct wireguardif_init_data wg_init = {0};
    wg_init.private_key = ml->wireguard.private_key_b64;
    wg_init.listen_port = 51820;  // Standard WireGuard port
    wg_init.bind_netif = NULL;    // Use default routing

    // WORKAROUND for ESP-IDF netif callback crash:
    // Call wireguardif_init() FIRST to initialize netif->state with wireguard_device,
    // THEN call netif_add() with NULL init function to just register the netif.
    // This prevents ESP-IDF's callback from seeing wireguardif_init_data in netif->state
    // and interpreting it as an esp_netif structure.

    ESP_LOGI(TAG, "Pre-initializing WireGuard netif...");
    ESP_LOGD(TAG, "WireGuard private key (base64): %s", ml->wireguard.private_key_b64);
    ESP_LOGD(TAG, "WireGuard listen port: %d", wg_init.listen_port);

    ((struct netif *)ml->wireguard.netif)->state = &wg_init;
    err_t init_result = wireguardif_init((struct netif *)ml->wireguard.netif);

    if (init_result != ERR_OK) {
        ESP_LOGE(TAG, "wireguardif_init() failed with error %d", init_result);
        free(ml->wireguard.netif);
        ml->wireguard.netif = NULL;
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "WireGuard netif initialized successfully!");
    ESP_LOGI(TAG, "Manually registering netif with lwIP...");

    // Since wireguardif_init() succeeded, we now need to manually add the netif to lwIP's global list
    // and set its IP address. We can't use netif_add() because the netif is already initialized.

    // IMPORTANT: Set IP addresses directly on netif structure fields to avoid triggering ESP-IDF callbacks
    // Do NOT use netif_set_addr() - it triggers esp_netif_internal_dhcpc_cb() which crashes
    struct netif *netif = (struct netif *)ml->wireguard.netif;

    // Set IP address directly
    IP4_ADDR(&netif->ip_addr.u_addr.ip4, 100, 64, 0, 1);  // Temporary IP
    netif->ip_addr.type = IPADDR_TYPE_V4;

    // Set netmask directly
    IP4_ADDR(&netif->netmask.u_addr.ip4, 255, 192, 0, 0);  // /10 subnet
    netif->netmask.type = IPADDR_TYPE_V4;

    // Set gateway directly
    IP4_ADDR(&netif->gw.u_addr.ip4, 0, 0, 0, 0);  // No gateway for VPN
    netif->gw.type = IPADDR_TYPE_V4;

    ESP_LOGI(TAG, "IP addresses set: 100.64.0.1/10");

    // Manually add to global netif list
    struct netif *netif_list_head = netif_list;
    netif->next = netif_list_head;
    netif_list = netif;

    ESP_LOGI(TAG, "WireGuard netif added to global list");

    // Bring interface up
    netif_set_up((struct netif *)ml->wireguard.netif);
    netif_set_link_up((struct netif *)ml->wireguard.netif);

    ml->wireguard.listen_port = 51820;
    ml->wireguard.initialized = true;

    // Register DERP output callback for DERP-only peers
    // This allows WireGuard to send packets via DERP when peer has no direct endpoint
    ESP_LOGI(TAG, "Registering DERP output callback for WireGuard");
    wireguardif_set_derp_output((struct netif *)ml->wireguard.netif, wg_derp_output_callback, ml);

    // NOTE: direct_output callback is registered later by microlink_wireguard_enable_direct_output()
    // after DISCO init creates the raw PCB we need to send through.

    ESP_LOGI(TAG, "WireGuard interface initialized on port %d", ml->wireguard.listen_port);

    return ESP_OK;
}

esp_err_t microlink_wireguard_enable_direct_output(microlink_t *ml) {
    if (!ml || !ml->wireguard.initialized || !ml->wireguard.netif) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!ml->disco.pcb) {
        ESP_LOGW(TAG, "DISCO PCB not ready, cannot enable direct output");
        return ESP_ERR_INVALID_STATE;
    }

    // The DISCO PCB is shared for both receiving (zero-copy demux) and sending.
    // WG direct output uses the same PCB so the source port matches the
    // STUN-discovered NAT mapping and DISCO probe port.
    ESP_LOGI(TAG, "Enabling WG direct output via DISCO PCB port %u", ml->disco.port);
    wireguardif_set_direct_output((struct netif *)ml->wireguard.netif,
                                  wg_direct_output_callback, ml);
    return ESP_OK;
}

esp_err_t microlink_wireguard_deinit(microlink_t *ml) {
    ESP_LOGI(TAG, "Deinitializing WireGuard");

    if (!ml->wireguard.initialized) {
        return ESP_OK;  // Already deinitialized
    }

    if (ml->wireguard.netif) {
        struct netif *netif = (struct netif *)ml->wireguard.netif;

        // Bring interface down first
        netif_set_link_down(netif);
        netif_set_down(netif);

        // WORKAROUND: Brief delay to allow any pending wireguardif_tmr() callback
        // to complete before we free the device structure. The timer runs every 400ms,
        // so 500ms ensures any in-flight callback finishes.
        vTaskDelay(pdMS_TO_TICKS(500));

        // Clean up wireguard_device resources
        if (netif->state) {
            struct wireguard_device *device = (struct wireguard_device *)netif->state;

            // Remove UDP PCB to free port 51820 for next init
            if (device->udp_pcb) {
                udp_remove(device->udp_pcb);
                device->udp_pcb = NULL;
            }

            // Free wireguard_device allocated by wireguardif_init()
            mem_free(netif->state);
            netif->state = NULL;
        }

        // Remove from global netif list
        netif_remove(netif);

        // Free netif structure itself (we allocated this with calloc())
        free(netif);
        ml->wireguard.netif = NULL;
    }

    ml->wireguard.initialized = false;

    // Clear keys from memory
    memset(&ml->wireguard, 0, sizeof(microlink_wireguard_t));

    return ESP_OK;
}

/* ============================================================================
 * Peer Management
 * ========================================================================== */

esp_err_t microlink_wireguard_add_peer(microlink_t *ml, const microlink_peer_t *peer) {
    if (!ml->wireguard.initialized || !ml->wireguard.netif) {
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Adding WireGuard peer: %s", peer->hostname);

    // Convert peer public key to base64
    char peer_pubkey_b64[64];
    esp_err_t peer_b64_ret = key_to_base64(peer->public_key, peer_pubkey_b64, sizeof(peer_pubkey_b64));
    if (peer_b64_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to encode peer public key to base64");
        return peer_b64_ret;
    }

    // Initialize peer structure
    struct wireguardif_peer wg_peer;
    wireguardif_peer_init(&wg_peer);

    wg_peer.public_key = peer_pubkey_b64;
    wg_peer.preshared_key = NULL;  // No PSK for now

    // Set allowed IP (peer's VPN IP)
    microlink_ip_to_lwip(peer->vpn_ip, &wg_peer.allowed_ip);
    IP4_ADDR(&wg_peer.allowed_mask.u_addr.ip4, 255, 255, 255, 255);  // /32 single host
    wg_peer.allowed_mask.type = IPADDR_TYPE_V4;

    // No direct endpoint - always start via DERP relay.
    // wireguardif_connect_derp will clear peer->ip/port to route through DERP.
    memset(&wg_peer.endpoint_ip, 0, sizeof(ip_addr_t));
    wg_peer.endport_port = 0;

    // Set keepalive (25 seconds for NAT traversal)
    wg_peer.keep_alive = 25;

    // Add peer to WireGuard interface
    u8_t peer_index = WIREGUARDIF_INVALID_INDEX;
    err_t err = wireguardif_add_peer((struct netif *)ml->wireguard.netif, &wg_peer, &peer_index);

    if (err != ERR_OK) {
        ESP_LOGE(TAG, "Failed to add peer: lwIP error %d", err);
        return ESP_FAIL;
    }

    // Store peer index for later reference
    uint8_t last_byte = peer->vpn_ip & 0xFF;
    if (last_byte < MICROLINK_PEER_MAP_SIZE) {
        ml->peer_map[last_byte] = peer_index;
    }

    ESP_LOGI(TAG, "Peer added successfully (index %d)", peer_index);

    // Always initiate handshake via DERP relay.
    // Direct UDP handshakes fail when the ESP32 has no STUN-discovered public
    // endpoint, because peers cannot route responses back through NAT.
    // DISCO will switch to direct paths once a reachable endpoint is discovered.
    ESP_LOGI(TAG, "Initiating handshake via DERP for peer %s", peer->hostname);
    err = wireguardif_connect_derp((struct netif *)ml->wireguard.netif, peer_index);
    if (err != ERR_OK) {
        ESP_LOGW(TAG, "Failed to initiate DERP handshake: lwIP error %d", err);
    }

    return ESP_OK;
}

/**
 * @brief Update peer endpoint and initiate handshake
 *
 * Called when DISCO discovers a direct path to a peer.
 * Updates the WireGuard peer's endpoint and initiates handshake.
 */
esp_err_t microlink_wireguard_update_endpoint(microlink_t *ml, uint32_t vpn_ip,
                                               uint32_t endpoint_ip, uint16_t endpoint_port) {
    if (!ml->wireguard.initialized || !ml->wireguard.netif) {
        return ESP_ERR_INVALID_STATE;
    }

    struct netif *netif = (struct netif *)ml->wireguard.netif;

    // Find peer index by VPN IP
    uint8_t last_byte = vpn_ip & 0xFF;
    if (last_byte >= MICROLINK_PEER_MAP_SIZE) {
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t peer_index = ml->peer_map[last_byte];
    if (peer_index == 0xFF) {
        return ESP_ERR_NOT_FOUND;
    }

    // Skip if endpoint is unchanged (avoid redundant handshake initiation)
    ip_addr_t current_ip;
    u16_t current_port;
    if (wireguardif_peer_is_up(netif, peer_index, &current_ip, &current_port) == ERR_OK) {
        uint32_t current_ml_ip = lwip_ip_to_microlink(&current_ip);
        if (current_ml_ip == endpoint_ip && current_port == endpoint_port) {
            ESP_LOGD(TAG, "Endpoint unchanged (%u.%u.%u.%u:%u), skipping",
                     (endpoint_ip >> 24) & 0xFF, (endpoint_ip >> 16) & 0xFF,
                     (endpoint_ip >> 8) & 0xFF, endpoint_ip & 0xFF, endpoint_port);
            return ESP_OK;
        }
    }

    // Convert endpoint IP to lwIP format
    ip_addr_t lwip_endpoint;
    microlink_ip_to_lwip(endpoint_ip, &lwip_endpoint);

    // Update peer endpoint
    err_t err = wireguardif_update_endpoint(netif, peer_index, &lwip_endpoint, endpoint_port);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "Failed to update endpoint: lwIP error %d", err);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Updated peer endpoint to %u.%u.%u.%u:%u",
             (endpoint_ip >> 24) & 0xFF,
             (endpoint_ip >> 16) & 0xFF,
             (endpoint_ip >> 8) & 0xFF,
             endpoint_ip & 0xFF,
             endpoint_port);

    // Initiate handshake with the NEW endpoint
    err = wireguardif_connect(netif, peer_index);
    if (err != ERR_OK) {
        ESP_LOGW(TAG, "Failed to initiate handshake after endpoint update: %d", err);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Handshake initiated with updated endpoint");
    return ESP_OK;
}

/* ============================================================================
 * Data Transfer
 * ========================================================================== */

esp_err_t microlink_wireguard_send(microlink_t *ml, uint32_t dest_vpn_ip,
                                   const uint8_t *data, size_t len) {
    if (!ml->wireguard.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    // Find peer index
    uint8_t last_byte = dest_vpn_ip & 0xFF;
    if (last_byte >= MICROLINK_PEER_MAP_SIZE) {
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t peer_index = ml->peer_map[last_byte];
    if (peer_index == 0xFF) {
        return ESP_ERR_NOT_FOUND;
    }

    // Check if peer is up
    ip_addr_t peer_ip;
    u16_t peer_port;
    err_t err = wireguardif_peer_is_up((struct netif *)ml->wireguard.netif, peer_index, &peer_ip, &peer_port);

    if (err != ERR_OK) {
        ESP_LOGD(TAG, "Peer not ready, handshake may be in progress");
        return ESP_ERR_INVALID_STATE;
    }

    // TODO: Actually send data through WireGuard interface
    // For now, wireguard-lwip handles this at the lwIP layer automatically
    // We would need to create IP packets and pass them to the netif

    ESP_LOGD(TAG, "WireGuard send: %zu bytes to peer %d", len, peer_index);
    ml->stats.direct_packets_sent++;

    // Return success - actual sending happens via lwIP routing
    return ESP_OK;
}

esp_err_t microlink_wireguard_receive(microlink_t *ml) {
    if (!ml->wireguard.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    // Direct UDP reception is handled automatically by wireguard-lwip via udp_recv callback
    // This function processes DERP-relayed packets from the rx_queue
    while (ml->rx_head != ml->rx_tail) {
        microlink_packet_t *pkt = &ml->rx_queue[ml->rx_tail];

        // Inject DERP-relayed packet into WireGuard
        esp_err_t ret = microlink_wireguard_inject_derp_packet(ml, pkt->src_vpn_ip,
                                                                pkt->data, pkt->len);
        if (ret != ESP_OK) {
            ESP_LOGD(TAG, "Failed to inject DERP packet: %d", ret);
        }

        ml->rx_tail = (ml->rx_tail + 1) % MICROLINK_RX_QUEUE_SIZE;
    }

    return ESP_OK;
}

/**
 * @brief Inject a DERP-relayed WireGuard packet for processing
 *
 * When a WireGuard packet arrives via DERP relay, we need to pass it
 * to the WireGuard stack for decryption and routing.
 *
 * Thread safety: wireguardif_network_rx() calls ip_input() which modifies
 * TCP PCB state. The FetchTask concurrently uses TCP via sockets.
 * LOCK_TCPIP_CORE() is a no-op without CONFIG_LWIP_TCPIP_CORE_LOCKING,
 * and enabling that causes SDIO contention. Instead, we use
 * tcpip_try_callback() to run inside the tcpip thread itself.
 */
esp_err_t microlink_wireguard_inject_derp_packet(microlink_t *ml, uint32_t src_vpn_ip,
                                                  const uint8_t *data, size_t len) {
    if (!ml->wireguard.initialized || !ml->wireguard.netif) {
        return ESP_ERR_INVALID_STATE;
    }

    if (len < 4) {
        return ESP_ERR_INVALID_SIZE;
    }

    struct netif *netif = (struct netif *)ml->wireguard.netif;
    struct wireguard_device *device = (struct wireguard_device *)netif->state;

    if (!device) {
        return ESP_ERR_INVALID_STATE;
    }

    // Lazy-init the semaphore (called from single TailscaleTask, no race)
    if (!s_inject_done) {
        s_inject_done = xSemaphoreCreateBinary();
        if (!s_inject_done) {
            ESP_LOGE(TAG, "Failed to create inject semaphore");
            return ESP_ERR_NO_MEM;
        }
    }

    // Create a pbuf to hold the packet
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (!p) {
        ESP_LOGW(TAG, "Failed to allocate pbuf for DERP packet");
        return ESP_ERR_NO_MEM;
    }

    memcpy(p->payload, data, len);

    // Set up callback context (static — only one inject at a time from TailscaleTask)
    s_inject_ctx.device = device;
    s_inject_ctx.pcb = device->udp_pcb;
    s_inject_ctx.p = p;
    IP_ADDR4(&s_inject_ctx.addr, 0, 0, 0, 0);

    // Run wireguardif_network_rx() inside the tcpip thread for thread safety.
    // This avoids races with FetchTask's TCP operations without global locking.
    err_t cb_err = tcpip_try_callback(wg_inject_in_tcpip_thread, &s_inject_ctx);
    if (cb_err != ERR_OK) {
        ESP_LOGW(TAG, "tcpip_try_callback failed: %d (mbox full?)", cb_err);
        pbuf_free(p);
        return ESP_ERR_NO_MEM;
    }

    // Block until the tcpip thread processes the packet
    if (xSemaphoreTake(s_inject_done, pdMS_TO_TICKS(2000)) != pdTRUE) {
        ESP_LOGW(TAG, "DERP inject timed out (tcpip thread stuck?)");
        // pbuf ownership transferred to callback — wireguardif_network_rx will free it
        return ESP_ERR_TIMEOUT;
    }

    ESP_LOGD(TAG, "Injected %zu byte DERP packet via tcpip thread", len);
    return ESP_OK;
}

/* ============================================================================
 * DERP Output Callback for WireGuard
 * ========================================================================== */

/**
 * @brief Callback invoked by WireGuard when it needs to send a packet to a peer
 *        that has no direct IP endpoint (DERP-only peer).
 *
 * This is called from wireguardif_peer_output() when peer->ip is 0.0.0.0.
 * We relay the WireGuard packet through DERP using the peer's public key.
 */
static err_t wg_derp_output_callback(const uint8_t *peer_public_key, const uint8_t *data, size_t len, void *ctx) {
    microlink_t *ml = (microlink_t *)ctx;

    if (!ml) {
        ESP_LOGE(TAG, "DERP output callback: NULL context");
        return ERR_ARG;
    }

    // Check available stack - mbedtls TLS operations need at least 4KB
    // The WireGuard timer callback runs with very limited stack (~1KB remaining)
    // which is not enough for mbedtls_ssl_write operations
    UBaseType_t stack_remaining = uxTaskGetStackHighWaterMark(NULL);
    if (stack_remaining < 4096) {
        // Queue the packet for later sending from main task
        if (len > DERP_PACKET_MAX_SIZE) {
            ESP_LOGW(TAG, "DERP packet too large to queue: %zu", len);
            return ERR_MEM;
        }

        // Find a free slot in the queue
        for (int i = 0; i < DERP_QUEUE_SIZE; i++) {
            if (!derp_packet_queue[i].pending) {
                memcpy(derp_packet_queue[i].peer_pubkey, peer_public_key, 32);
                memcpy(derp_packet_queue[i].data, data, len);
                derp_packet_queue[i].len = len;
                derp_packet_queue[i].pending = true;
                queued_ml_ctx = ml;
                ESP_LOGD(TAG, "DERP output queued (slot %d): %zu bytes, stack=%lu",
                         i, len, (unsigned long)stack_remaining);
                return ERR_OK;
            }
        }

        ESP_LOGW(TAG, "DERP queue full, dropping packet (stack=%lu)",
                 (unsigned long)stack_remaining);
        return ERR_OK;  // Don't return error, WireGuard will retry
    }

    ESP_LOGD(TAG, "DERP output callback: sending %zu byte WG packet to peer %02x%02x%02x%02x... (stack=%lu)",
             len, peer_public_key[0], peer_public_key[1], peer_public_key[2], peer_public_key[3],
             (unsigned long)stack_remaining);

    // Send via DERP using the peer's public key
    esp_err_t err = microlink_derp_send_raw(ml, peer_public_key, data, len);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "DERP send failed: %d", err);
        return ERR_IF;  // Interface error
    }

    return ERR_OK;
}

/**
 * @brief Process queued DERP packets from main task context
 *
 * Call this periodically from the main MicroLink task which has sufficient stack.
 */
void microlink_wireguard_process_derp_queue(void) {
    if (!queued_ml_ctx) {
        return;
    }

    for (int i = 0; i < DERP_QUEUE_SIZE; i++) {
        if (derp_packet_queue[i].pending) {
            ESP_LOGD(TAG, "Processing queued DERP packet (slot %d): %zu bytes",
                     i, derp_packet_queue[i].len);

            esp_err_t err = microlink_derp_send_raw(
                queued_ml_ctx,
                derp_packet_queue[i].peer_pubkey,
                derp_packet_queue[i].data,
                derp_packet_queue[i].len
            );

            if (err != ESP_OK) {
                ESP_LOGW(TAG, "Queued DERP send failed: %d", err);
            }

            derp_packet_queue[i].pending = false;
        }
    }
}

/* ============================================================================
 * Status & Utilities
 * ========================================================================== */

void microlink_wireguard_get_public_key(const microlink_t *ml, uint8_t *public_key) {
    // TODO: Extract actual public key from wireguard-lwip
    // For now, return the stored key
    memcpy(public_key, ml->wireguard.public_key, 32);
}

esp_err_t microlink_wireguard_set_vpn_ip(microlink_t *ml, uint32_t vpn_ip) {
    if (!ml->wireguard.initialized || !ml->wireguard.netif) {
        return ESP_ERR_INVALID_STATE;
    }

    // Skip if VPN IP is 0 (not assigned yet)
    if (vpn_ip == 0) {
        ESP_LOGW(TAG, "VPN IP not assigned yet, skipping netif update");
        return ESP_OK;
    }

    struct netif *netif = (struct netif *)ml->wireguard.netif;

    // Convert to lwIP format
    ip4_addr_t ip4addr;
    IP4_ADDR(&ip4addr,
             (vpn_ip >> 24) & 0xFF,
             (vpn_ip >> 16) & 0xFF,
             (vpn_ip >> 8) & 0xFF,
             vpn_ip & 0xFF);

    // Directly set the IP without triggering callbacks
    // This avoids the ESP-IDF esp_netif callback crash
    ip4_addr_set(&netif->ip_addr.u_addr.ip4, &ip4addr);

    ml->vpn_ip = vpn_ip;

    char ip_buf[16];
    ESP_LOGI(TAG, "WireGuard VPN IP set to: %s",
             microlink_vpn_ip_to_str(vpn_ip, ip_buf));

    return ESP_OK;
}
