# MicroLink - Tailscale-Compatible VPN for ESP32
# ESP-IDF Component CMakeLists.txt

idf_component_register(
    SRCS
        "src/microlink.c"
        "src/microlink_connection.c"
        "src/microlink_coordination.c"
        "src/microlink_derp.c"
        "src/microlink_disco.c"
        "src/microlink_stun.c"
        "src/microlink_udp.c"
        "src/microlink_peer_registry.c"
        "src/microlink_wireguard.c"
        "src/nacl_box.c"
        "src/x25519.c"
    INCLUDE_DIRS
        "include"
        "src"
    REQUIRES
        esp_wifi
        esp_netif
        esp_http_client
        mbedtls
        nvs_flash
        esp_timer
        lwip
        wireguard_lwip
        json
)

# Enable optimizations for crypto code
# Disable format warnings for uint32_t format specifiers (ESP-IDF 5.3 uses long unsigned int)
# Disable stringop-overread for x25519.c mul() function (false positive - nb param limits read size)
target_compile_options(${COMPONENT_LIB} PRIVATE -O2 -Wno-format -Wno-stringop-overread)
