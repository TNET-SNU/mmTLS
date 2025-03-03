#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/cmac.h>
#include <openssl/modes.h>

#include "../include/crypto/modes.h"
#include "../include/crypto/aes_platform.h"

typedef union {
    u64 u[2];
    u8 c[16];
} CRYPTO_DATA;

#define K 1024
#define M (K*K)
#define MAX_RECORD_SIZE (16*K + 64)
#define GHASH_CHUNK (3*K)

#define AES_256_GCM_KEY_SIZE 32
#define AES_256_GCM_TAG_SIZE 16
#define AES_256_GCM_IV_SIZE 12
#define TLS_1_3_AAD_SIZE 5

void gcm_init_avx(u128 Htable[16], const u64 Xi[2]);
/*-----------------------------------------------------------------------------*/
static void
read_hex(const char *hex, uint8_t *out, size_t outmax, size_t *outlen)
{
	size_t i;

	*outlen = 0;
	if (strlen(hex) > 2 * outmax)
	{
		fprintf(stderr, "Error: hex length exceeds outmax (%lu > %lu*2)\n", strlen(hex), outmax * 2);
		exit(-1);
	}

	for (i = 0; hex[i] && hex[i + 1]; i += 2)
	{
		unsigned int value = 0;

		if (!sscanf(hex + i, "%02x", &value))
		{
			fprintf(stderr, "Error: [%s] sscanf fail\n", __FUNCTION__);
			exit(-1);
		}
		out[(*outlen)++] = value;
	}
}
/*----------------------------------------------------------------------------*/
/* Dump bytestream in hexademical form */
static inline void
hexdump(char *title, uint8_t *buf, size_t len)
{
	fprintf(stdout, "%s\n", title);
	for (size_t i = 0; i < len; i++)
		fprintf(stdout, "%02X%c", buf[i], ((i + 1) % 16 ? ' ' : '\n'));
	fprintf(stdout, "\n");
}
/*-----------------------------------------------------------------------------*/
/* standard encryption with cipher: AES_256_GCM */
static inline void
encrypt_text0(EVP_CIPHER_CTX *evp_ctx1, EVP_CIPHER_CTX *evp_ctx2,
             uint8_t* key1, uint8_t *key2,
             uint8_t* iv, uint8_t* aad,
             uint8_t* plain, uint64_t plain_len,
             uint8_t* cipher,
             uint8_t* tag1)
{
    int len = 0;

    EVP_EncryptInit_ex(evp_ctx1, NULL, NULL, key1, iv);
    EVP_EncryptUpdate(evp_ctx1, NULL, &len, aad, TLS_1_3_AAD_SIZE);
    EVP_EncryptUpdate(evp_ctx1, cipher, &len, plain, plain_len);
    EVP_EncryptFinal_ex(evp_ctx1, cipher, &len);
    EVP_CIPHER_CTX_ctrl(evp_ctx1, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_SIZE, tag1);
}
/*-----------------------------------------------------------------------------*/
/* standard encryption with cipher: AES_256_GCM */
static inline void
encrypt_text1(EVP_CIPHER_CTX *evp_ctx1, EVP_CIPHER_CTX *evp_ctx2,
             uint8_t* key1, uint8_t *key2,
             uint8_t* iv, uint8_t* aad,
             uint8_t* plain, uint64_t plain_len,
             uint8_t* cipher1, uint8_t* cipher2,
             uint8_t* tag1, uint8_t *tag2)
{
    int len = 0;

    EVP_EncryptInit_ex(evp_ctx1, NULL, NULL, key1, iv);
    EVP_EncryptUpdate(evp_ctx1, NULL, &len, aad, TLS_1_3_AAD_SIZE);
    EVP_EncryptUpdate(evp_ctx1, cipher1, &len, plain, plain_len);
    EVP_EncryptFinal_ex(evp_ctx1, cipher1, &len);
    EVP_CIPHER_CTX_ctrl(evp_ctx1, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_SIZE, tag1);

    EVP_EncryptInit_ex(evp_ctx2, NULL, NULL, key2, iv);
    EVP_EncryptUpdate(evp_ctx2, NULL, &len, aad, TLS_1_3_AAD_SIZE);
    EVP_EncryptUpdate(evp_ctx2, cipher2, &len, plain, plain_len);
    EVP_EncryptFinal_ex(evp_ctx2, cipher2, &len);
    EVP_CIPHER_CTX_ctrl(evp_ctx2, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_SIZE, tag2);
}
/*-----------------------------------------------------------------------------*/
static inline void
encrypt_text2(uint8_t* key, uint8_t* iv, uint8_t* aad, uint8_t* plain, uint64_t plain_len, uint8_t* cipher, uint8_t* tag)
{
    GCM128_CONTEXT ctx;
    AES_KEY aes_key;

    aesni_set_encrypt_key(key, 32*8, &aes_key);
    CRYPTO_gcm128_init(&ctx, &aes_key, (block128_f)aesni_encrypt);
    CRYPTO_gcm128_setiv(&ctx, iv, 12);
    CRYPTO_gcm128_aad(&ctx, aad, 5);
    CRYPTO_gcm128_encrypt(&ctx, plain, cipher, plain_len);
    CRYPTO_gcm128_tag(&ctx, tag, 16);
}
/*-----------------------------------------------------------------------------*/
/* Encrypt and generates additional tag with key2 */
/* Encryption is done by AES-NI instructions */
static inline void
generate_tag_asm2(EVP_CIPHER_CTX *evp_ctx, u128 *Htable, CRYPTO_DATA *EK0,
                 uint8_t* key1,
                 uint8_t* iv, uint8_t* aad, 
                 uint8_t* plain, uint64_t plain_len, uint8_t* cipher, 
                 uint8_t* tag1, uint8_t* tag2)
{
    CRYPTO_DATA *Xi = (CRYPTO_DATA *)tag2; // follow names in GCM specification
    u128 *bitlen;
    u8* cipher_text;
    size_t clen, i;
    unsigned char Xn[48];
    unsigned int mres = 0;
    int len = 0;

    /* make first tag */
    EVP_EncryptInit_ex(evp_ctx, NULL, NULL, key1, iv);
    EVP_EncryptUpdate(evp_ctx, NULL, &len, aad, TLS_1_3_AAD_SIZE);
    EVP_EncryptUpdate(evp_ctx, cipher, &len, plain, plain_len);
    EVP_EncryptFinal_ex(evp_ctx, cipher, &len);
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_SIZE, tag1);

    /* make second tag */
    gcm_ghash_avx(Xi->u, Htable, ((CRYPTO_DATA *)aad)->c, sizeof(CRYPTO_DATA));
    clen = plain_len;
    cipher_text = cipher;
    while (clen >= GHASH_CHUNK) {
        /* clen >= 3*1024 */
        gcm_ghash_avx(Xi->u, Htable, cipher_text, GHASH_CHUNK);
        clen -= GHASH_CHUNK;
        cipher_text += GHASH_CHUNK;
    }
    if ((i = (clen & (size_t)-16))) {
        /* 3*1024 > clen >= 16 */
        gcm_ghash_avx(Xi->u, Htable, cipher_text, i);
        cipher_text += i;
        clen = clen % 16;
    }
    if (clen) {
        /* plain len & 16 != 0 */
        memcpy(Xn, cipher_text, clen);
        mres = (clen + 15) & -16;
    }

    bitlen = (u128 *)(Xn + mres);
    bitlen->hi = BSWAP8(TLS_1_3_AAD_SIZE << 3);
    bitlen->lo = BSWAP8(plain_len << 3);
    mres += sizeof(u128);

    gcm_ghash_avx(Xi->u, Htable, Xn, mres);
    Xi->u[0] ^= EK0->u[0];
    Xi->u[1] ^= EK0->u[1];
}
/*-----------------------------------------------------------------------------*/
/* Encrypt and generates additional tag with key2 */
/* Encryption is done by AES-NI instructions */
static inline void
generate_tag_asm2_only_tag1(EVP_CIPHER_CTX *evp_ctx, u128 *Htable, CRYPTO_DATA *EK0,
                 uint8_t* key1,
                 uint8_t* iv, uint8_t* aad, 
                 uint8_t* plain, uint64_t plain_len, uint8_t* cipher, 
                 uint8_t* tag1, uint8_t* tag2)
{
    CRYPTO_DATA *Xi = (CRYPTO_DATA *)tag2; // follow names in GCM specification
    u128 *bitlen;
    u8* cipher_text;
    size_t clen, i;
    unsigned char Xn[48];
    unsigned int mres = 0;
    int len = 0;

    /* make first tag */
    EVP_EncryptInit_ex(evp_ctx, NULL, NULL, key1, iv);
    EVP_EncryptUpdate(evp_ctx, NULL, &len, aad, TLS_1_3_AAD_SIZE);
    EVP_EncryptUpdate(evp_ctx, cipher, &len, plain, plain_len);
    EVP_EncryptFinal_ex(evp_ctx, cipher, &len);
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_SIZE, tag1);

    /* make second tag */
    gcm_ghash_avx(Xi->u, Htable, ((CRYPTO_DATA *)aad)->c, sizeof(CRYPTO_DATA));
    clen = AES_256_GCM_TAG_SIZE;
    cipher_text = tag1;
    while (clen >= GHASH_CHUNK) {
        /* clen >= 3*1024 */
        gcm_ghash_avx(Xi->u, Htable, cipher_text, GHASH_CHUNK);
        clen -= GHASH_CHUNK;
        cipher_text += GHASH_CHUNK;
    }
    if ((i = (clen & (size_t)-16))) {
        /* 3*1024 > clen >= 16 */
        gcm_ghash_avx(Xi->u, Htable, cipher_text, i);
        cipher_text += i;
        clen = clen % 16;
    }
    if (clen) {
        /* plain len & 16 != 0 */
        memcpy(Xn, cipher_text, clen);
        mres = (clen + 15) & -16;
    }

    bitlen = (u128 *)(Xn + mres);
    bitlen->hi = BSWAP8(TLS_1_3_AAD_SIZE << 3);
    bitlen->lo = BSWAP8(plain_len << 3);
    mres += sizeof(u128);

    gcm_ghash_avx(Xi->u, Htable, Xn, mres);
    Xi->u[0] ^= EK0->u[0];
    Xi->u[1] ^= EK0->u[1];
}
/*-----------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
    int i;
    uint8_t key1[AES_256_GCM_KEY_SIZE],
            key2[AES_256_GCM_KEY_SIZE],
            iv[AES_256_GCM_IV_SIZE],
            *tag1, *tag2;
    uint8_t aad[TLS_1_3_AAD_SIZE];
    uint8_t plain[MAX_RECORD_SIZE] = {0},
            cipher1[MAX_RECORD_SIZE + AES_256_GCM_TAG_SIZE + AES_256_GCM_TAG_SIZE],
            cipher2[MAX_RECORD_SIZE + AES_256_GCM_TAG_SIZE + AES_256_GCM_TAG_SIZE];
    size_t len;
    clock_t t1, t2;
    int record_len[5] = {K, 2 * K, 4 * K, 8 * K, 16 * K};
    int test_cnt[5] = {M * 16, M * 8, M * 4, M * 2, M};
    double original_time[5];

    read_hex("1111111111111111111111111111111111111111111111111111111111111111", key1, 32, &len);
    read_hex("1111111111111111111111111111111111111111111111111111111111111111", key2, 32, &len);
    read_hex("111111111111111111111111", iv, 12, &len);
    read_hex("1111111111", aad, 5, &len);

    tag1 = cipher1 + AES_256_GCM_TAG_SIZE;
    tag2 = tag1 + AES_256_GCM_TAG_SIZE;
    EVP_CIPHER_CTX *evp_ctx1 = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(evp_ctx1, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(evp_ctx1, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_SIZE, NULL);

    printf("\t\t\t1K\t2K\t4K\t8K\t16K\n");

    {
        // original TLS
        printf("Original\t");
        for (int j = 0; j < 5; j++)
        {
            EVP_CIPHER_CTX *evp_ctx2 = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(evp_ctx2, EVP_aes_256_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(evp_ctx2, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_SIZE, NULL);
            t1 = clock();
            for (i = 0; i < test_cnt[j]; i++) {
                encrypt_text0(evp_ctx1, evp_ctx2,
                            key1, key2,
                            iv, aad,
                            plain, record_len[j],
                            cipher1,
                            tag1);
            }
            t2 = clock();
            original_time[j] = (double)(t2-t1);
            printf("\t%d", 1);
        }
        printf("\n");
    }
    {
        // mmTLS
        // follow names in GCM specification
        printf("mmTLS\t\t");
        for (int j = 0; j < 5; j++)
        {
            CRYPTO_DATA H, EK0, Yi;
            AES_KEY aes_key;
            u128 Htable[16];

            /* make H, EK once, note that they do not change until session end */
            memset(&H, 0, sizeof(H));
            aesni_set_encrypt_key(key2, AES_256_GCM_KEY_SIZE * 8, &aes_key);
            (*(block128_f)aesni_encrypt)(H.c, H.c, &aes_key);
            H.u[0] = BSWAP8(H.u[0]);
            H.u[1] = BSWAP8(H.u[1]);
            gcm_init_avx(Htable, H.u);
            memcpy(Yi.c, iv, AES_256_GCM_IV_SIZE);
            Yi.c[15] = 1;
            (*(block128_f)aesni_encrypt)(Yi.c, EK0.c, &aes_key);

            t1 = clock();
            for (i = 0; i < test_cnt[j]; i++) {
                memset(tag2, 0, 16);
                generate_tag_asm2_only_tag1(evp_ctx1, Htable, &EK0,
                                            key1,
                                            iv, aad,
                                            plain, record_len[j],
                                            cipher1,
                                            tag1, tag2);
            }
            t2 = clock();
            printf("\t%.3lf", (double)(t2-t1) / original_time[j]);
        }
        printf("\n");
    }
    {
        // reusing ciphertext
        // follow names in GCM specification
        printf("Reusing ciphertext");
        for (int j = 0; j < 5; j++)
        {
            CRYPTO_DATA H, EK0, Yi;
            AES_KEY aes_key;
            u128 Htable[16];

            /* make H, EK once, note that they do not change until session end */
            memset(&H, 0, sizeof(H));
            aesni_set_encrypt_key(key2, AES_256_GCM_KEY_SIZE * 8, &aes_key);
            (*(block128_f)aesni_encrypt)(H.c, H.c, &aes_key);
            H.u[0] = BSWAP8(H.u[0]);
            H.u[1] = BSWAP8(H.u[1]);
            gcm_init_avx(Htable, H.u);
            memcpy(Yi.c, iv, AES_256_GCM_IV_SIZE);
            Yi.c[15] = 1;
            (*(block128_f)aesni_encrypt)(Yi.c, EK0.c, &aes_key);

            t1 = clock();
            for (i = 0; i < test_cnt[j]; i++) {
                memset(tag2, 0, 16);
                generate_tag_asm2(evp_ctx1, Htable, &EK0,
                                key1,
                                iv, aad,
                                plain, record_len[j],
                                cipher1,
                                tag1, tag2);
            }
            t2 = clock();
            printf("\t%.3lf", (double)(t2-t1) / original_time[j]);
        }
        printf("\n");
    }
    {
        // double tags
        printf("Double tags\t");
        for (int j = 0; j < 5; j++)
        {
            EVP_CIPHER_CTX *evp_ctx2 = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(evp_ctx2, EVP_aes_256_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(evp_ctx2, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_SIZE, NULL);
            t1 = clock();
            for (i = 0; i < test_cnt[j]; i++) {
                encrypt_text1(evp_ctx1, evp_ctx2,
                            key1, key2,
                            iv, aad,
                            plain, record_len[j],
                            cipher1, cipher2,
                            tag1, tag2);
            }
            t2 = clock();
            printf("\t%.3lf", (double)(t2-t1) / original_time[j]);
        }
        printf("\n");
    }

    return 1;
}
