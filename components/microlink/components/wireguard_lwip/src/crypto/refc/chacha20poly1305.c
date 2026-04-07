/*
 * ChaCha20-Poly1305 AEAD using mbedTLS backend for ESP32 performance.
 *
 * Original refc implementation by Daniel Hope (www.floorsense.nz).
 * Replaced with mbedTLS calls for significantly better throughput on ESP32-P4.
 * XChaCha20-Poly1305 still uses refc HChaCha20 + mbedTLS ChaCha20-Poly1305.
 *
 * Nonce construction per WireGuard spec §5.4.6: the 64-bit counter is placed
 * into a 96-bit RFC 7539 nonce as [4 zero bytes][8-byte LE counter].
 */

#include "chacha20poly1305.h"
#include "chacha20.h"  /* hchacha20() for XChaCha20 */
#include "../../crypto.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/chachapoly.h"

#define POLY1305_MAC_SIZE 16

/* Build 96-bit RFC 7539 nonce from WireGuard 64-bit counter (§5.4.6):
 * [4 bytes zero] [8 bytes little-endian counter] */
static void build_nonce(uint8_t nonce12[12], uint64_t counter) {
	memset(nonce12, 0, 4);
	nonce12[4]  = (uint8_t)(counter);
	nonce12[5]  = (uint8_t)(counter >> 8);
	nonce12[6]  = (uint8_t)(counter >> 16);
	nonce12[7]  = (uint8_t)(counter >> 24);
	nonce12[8]  = (uint8_t)(counter >> 32);
	nonce12[9]  = (uint8_t)(counter >> 40);
	nonce12[10] = (uint8_t)(counter >> 48);
	nonce12[11] = (uint8_t)(counter >> 56);
}

void chacha20poly1305_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
                              const uint8_t *ad, size_t ad_len,
                              uint64_t nonce, const uint8_t *key) {
	mbedtls_chachapoly_context ctx;
	uint8_t nonce12[12];

	build_nonce(nonce12, nonce);

	mbedtls_chachapoly_init(&ctx);
	if (mbedtls_chachapoly_setkey(&ctx, key) != 0 ||
	    mbedtls_chachapoly_encrypt_and_tag(&ctx, src_len, nonce12,
	                                        ad, ad_len,
	                                        src, dst, dst + src_len) != 0) {
		/* Crypto failure — zero output to avoid sending garbage */
		memset(dst, 0, src_len + POLY1305_MAC_SIZE);
	}
	mbedtls_chachapoly_free(&ctx);
}

bool chacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
                              const uint8_t *ad, size_t ad_len,
                              uint64_t nonce, const uint8_t *key) {
	mbedtls_chachapoly_context ctx;
	uint8_t nonce12[12];

	if (src_len < POLY1305_MAC_SIZE) {
		return false;
	}

	size_t ct_len = src_len - POLY1305_MAC_SIZE;
	const uint8_t *tag = src + ct_len;

	build_nonce(nonce12, nonce);

	mbedtls_chachapoly_init(&ctx);
	if (mbedtls_chachapoly_setkey(&ctx, key) != 0) {
		mbedtls_chachapoly_free(&ctx);
		return false;
	}
	int ret = mbedtls_chachapoly_auth_decrypt(&ctx, ct_len, nonce12,
	                                           ad, ad_len,
	                                           tag, src, dst);
	mbedtls_chachapoly_free(&ctx);

	return (ret == 0);
}

/* XChaCha20-Poly1305: derive subkey via HChaCha20 (refc), then use mbedTLS AEAD */
void xchacha20poly1305_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
                               const uint8_t *ad, size_t ad_len,
                               const uint8_t *nonce, const uint8_t *key) {
	uint8_t subkey[32];
	uint64_t new_nonce;

	new_nonce = U8TO64_LITTLE(nonce + 16);
	hchacha20(subkey, nonce, key);
	chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, new_nonce, subkey);
	crypto_zero(subkey, sizeof(subkey));
}

bool xchacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
                               const uint8_t *ad, size_t ad_len,
                               const uint8_t *nonce, const uint8_t *key) {
	uint8_t subkey[32];
	uint64_t new_nonce;
	bool result;

	new_nonce = U8TO64_LITTLE(nonce + 16);
	hchacha20(subkey, nonce, key);
	result = chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len, new_nonce, subkey);
	crypto_zero(subkey, sizeof(subkey));
	return result;
}
