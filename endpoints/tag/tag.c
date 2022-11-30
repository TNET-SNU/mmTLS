#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/cmac.h>
#include <openssl/modes.h>

#include "openssl/include/crypto/modes.h"

typedef union {
    u64 u[2];
    u8 c[16];
} CRYPTO_DATA;

#define GHASH_CHUNK       (3*1024)

#define AES_256_GCM_KEY_SIZE 32
#define AES_256_GCM_TAG_SIZE 16
#define AES_256_GCM_IV_SIZE 12
#define TLS_1_3_AAD_SIZE 5
#define FILE_SIZE 131072

/*-----------------------------------------------------------------------------*/
/* standard encryption with cipher: AES_256_GCM */
void
encrypt_text(uint8_t* key, uint8_t* iv, uint8_t* aad, uint8_t* plain, uint64_t plain_len, uint8_t* cipher, uint8_t* tag)
{
    int len = 0;
    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_SIZE, NULL);
    EVP_EncryptInit_ex(evp_ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(evp_ctx, NULL, &len, aad, TLS_1_3_AAD_SIZE);
    EVP_EncryptUpdate(evp_ctx, cipher, &len, plain, plain_len);
    EVP_EncryptFinal_ex(evp_ctx, cipher, &len);
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_SIZE, cipher);
}
/*-----------------------------------------------------------------------------*/
/* Encrypt and generates additional tag with key2 */
/* Encryption is done by C implementation */
void
generate_tag_sw(uint8_t* key1, uint8_t* key2, uint8_t* iv, uint8_t* aad, 
                uint8_t* plain, uint64_t plain_len, uint8_t* cipher, 
                uint8_t* tag1, uint8_t* tag2)
{
    GCM128_CONTEXT ctx;
    u128 Htable[16];
    AES_KEY aes_key1, aes_key2;
    CRYPTO_DATA H, EK0, Xi;     // follow names in GCM specification
    u8* cipher_text;
    size_t clen, i, len = 16;
    size_t enclen = 0;

    memset(&EK0, 0, sizeof(EK0));
    memset(&Xi, 0, sizeof(Xi));
    memset(&H, 0, sizeof(H));

    /* Warning: deprecated function: AES_set_encrypt_key() since OpenSSL 3.0 */
    AES_set_encrypt_key(key1, AES_256_GCM_KEY_SIZE * 8, &aes_key1);
    AES_set_encrypt_key(key2, AES_256_GCM_KEY_SIZE * 8, &aes_key2);
    
    CRYPTO_gcm128_init(&ctx, &aes_key1, (block128_f)AES_encrypt);
    /* H value with key2 */
    (*ctx.block)(H.c, H.c, &aes_key2);

    /* BSWAP for little endians */
    H.u[0] = BSWAP8(H.u[0]);
    H.u[1] = BSWAP8(H.u[1]);
    gcm_init_avx(Htable, H.u);

    memcpy(ctx.Yi.c, iv, AES_256_GCM_IV_SIZE);
    ctx.Yi.c[12] = 0;
    ctx.Yi.c[13] = 0;
    ctx.Yi.c[14] = 0;
    ctx.Yi.c[15] = 1;

    /* E(K1, Y) */
    (*ctx.block)(ctx.Yi.c, ctx.EK0.c, ctx.key);
    /* E(K2, Y) */
    (*ctx.block)(ctx.Yi.c, EK0.c, &aes_key2);
    ctx.Yi.d[3] = BSWAP4(2);

    CRYPTO_gcm128_aad(&ctx, aad, TLS_1_3_AAD_SIZE);
    gcm_ghash_avx(Xi.u, Htable, ctx.Xi.c, sizeof(Xi));
    CRYPTO_gcm128_encrypt(&ctx, plain, cipher, plain_len);

    clen = plain_len;
    cipher_text = cipher;
    while (clen >= GHASH_CHUNK) {
        /* clen >= 3*1024 */
        gcm_ghash_avx(Xi.u, Htable, cipher_text, GHASH_CHUNK);
        clen -= GHASH_CHUNK;
        cipher_text += GHASH_CHUNK;
    }
    if ((i = (clen & (size_t)-16))) {
        /* 3*1024 > clen >= 16 */
        gcm_ghash_avx(Xi.u, Htable, cipher_text, i);
        clen = clen % 16;
    }
    /* tag 1 */
    CRYPTO_gcm128_tag(&ctx, tag1, AES_256_GCM_TAG_SIZE);
    /* tag 2 */
    if (clen)
        len += 16;
    gcm_ghash_avx(Xi.u, Htable, ctx.Xn, len);
    Xi.u[0] ^= EK0.u[0];
    Xi.u[1] ^= EK0.u[1];

    memcpy(tag2, Xi.c, AES_256_GCM_TAG_SIZE);
}
/*-----------------------------------------------------------------------------*/
/* Encrypt and generates additional tag with key2 */
/* Encryption is done by AES-NI instructions */
void
generate_tag_asm(uint8_t* key1, uint8_t* key2, uint8_t* iv, uint8_t* aad, 
                 uint8_t* plain, uint64_t plain_len, uint8_t* cipher, 
                 uint8_t* tag1, uint8_t* tag2)
{
    CRYPTO_DATA H, EK0, Xi, Yi, AAD;     // follow names in GCM specification
    AES_KEY aes_key;
    u128 Htable[16], bitlen;
    u8* cipher_text;
    size_t clen, i;
    unsigned char Xn[48];
    GCM128_CONTEXT ctx;
    unsigned int mres = 0;
    int len = 0;
    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();

    memset(&EK0, 0, sizeof(EK0));
    memset(&Xi, 0, sizeof(Xi));
    memset(&Yi, 0, sizeof(Yi));
    memset(&H, 0, sizeof(H));
    memset(&AAD, 0, sizeof(AAD));
    memset(Xn, 0, sizeof(Xn));

    AES_set_encrypt_key(key2, AES_256_GCM_KEY_SIZE * 8, &aes_key);
    CRYPTO_gcm128_init(&ctx, &aes_key, (block128_f)AES_encrypt);
    (*ctx.block)(H.c, H.c, &aes_key);
    H.u[0] = BSWAP8(H.u[0]);
    H.u[1] = BSWAP8(H.u[1]);
    gcm_init_avx(Htable, H.u);

    memcpy(Yi.c, iv, AES_256_GCM_IV_SIZE);
    Yi.c[15] = 1;
    (*ctx.block)(Yi.c, EK0.c, &aes_key);

    memcpy(AAD.c, aad, TLS_1_3_AAD_SIZE);

    gcm_ghash_avx(Xi.u, Htable, AAD.c, sizeof(Xi));

    EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_SIZE, NULL);
    EVP_EncryptInit_ex(evp_ctx, NULL, NULL, key1, iv);
    EVP_EncryptUpdate(evp_ctx, NULL, &len, aad, TLS_1_3_AAD_SIZE);
    EVP_EncryptUpdate(evp_ctx, cipher, &len, plain, plain_len);
    EVP_EncryptFinal_ex(evp_ctx, cipher, &len);

    clen = plain_len;
    cipher_text = cipher;
    while (clen >= GHASH_CHUNK) {
        /* clen >= 3*1024 */
        gcm_ghash_avx(Xi.u, Htable, cipher_text, GHASH_CHUNK);
        clen -= GHASH_CHUNK;
        cipher_text += GHASH_CHUNK;
    }
    if ((i = (clen & (size_t)-16))) {
        /* 3*1024 > clen >= 16 */
        gcm_ghash_avx(Xi.u, Htable, cipher_text, i);
        cipher_text += i;
        clen = clen % 16;
    }
    if (clen) {
        /* plain len & 16 != 0 */
        memcpy(Xn, cipher_text, clen);
        mres = (clen + 15) & -16;
    }

    bitlen.hi = BSWAP8(TLS_1_3_AAD_SIZE << 3);
    bitlen.lo = BSWAP8(plain_len << 3);
    memcpy(Xn + mres, &bitlen, sizeof(bitlen));
    mres += sizeof(bitlen);

    gcm_ghash_avx(Xi.u, Htable, Xn, mres);
    Xi.u[0] ^= EK0.u[0];
    Xi.u[1] ^= EK0.u[1];
    memcpy(tag2, Xi.c, AES_256_GCM_TAG_SIZE);

    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_SIZE, cipher);
    memcpy(tag1, cipher, AES_256_GCM_TAG_SIZE);
}