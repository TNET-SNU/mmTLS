#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <stdint.h>

typedef unsigned char uchar;

static void die(const char *msg);
static void read_hex(const char *hex, uchar *out, size_t outmax, size_t *outlen);
static void build_iv(uchar *iv, uint64_t seq);

const int gcm_ivlen = 12;
const int gcm_taglen = 16;
const int aes_keylen = 32; // aes-256

int main(int argc, char **argv)
{
	if (argc != 6) {
		fprintf(stderr, "Usage: %s hexiv seq hexkey hexaad plaintext\n", argv[0]);
		fprintf(stderr, "\n");
		fprintf(stderr, "prints ciphertext and tag on stdout\n");
		exit(1);
	}

	uchar iv[1024], key[1024], aad[1024];
	size_t ivlen, keylen, aadlen;
	read_hex(argv[1], iv, sizeof(iv), &ivlen);
	uint64_t seq = atoi(argv[2]);
	read_hex(argv[3], key, sizeof(key), &keylen);
	read_hex(argv[4], aad, sizeof(aad), &aadlen);
	uchar bufin[8192], bufout[8192];
	size_t bufin_len;
	int z;
	memset(bufin, 0, sizeof(bufin));
	memset(bufin, 0, sizeof(bufout));
	read_hex(argv[5], bufin, sizeof(bufin), &bufin_len);

	/* /\* debug *\/ */
	/* bufin_len += 0x1000; */

	/* print arguments */
	fprintf(stderr, "iv:\n");
    for (z = 0; z < ivlen; z++)
        fprintf(stderr, "%02X%c", iv[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");
	fprintf(stderr, "key:\n");
    for (z = 0; z < 32; z++)
        fprintf(stderr, "%02X%c", key[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");
	fprintf(stderr, "aad:\n");
    for (z = 0; z < aadlen; z++)
        fprintf(stderr, "%02X%c", aad[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");
	fprintf(stderr, "plaintext (%u B):\n", bufin_len);
    for (z = 0; z < bufin_len; z++)
        fprintf(stderr, "%02X%c", bufin[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");

	if (keylen != aes_keylen)
		die("Incorrect key length, expected 16 bytes");
	if (ivlen != gcm_ivlen)
		die("Incorrect IV length, expected 12 bytes");
	/* build_iv(iv, seq); */

	/* encryption start */
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		die("cipher ctx create failed");

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		die("init algorithm failed");

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL))
		die("set ivlen failed");

	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
		die("set key/iv failed");

	int len = 0;
	if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen))
		die("set aad failed");

	if (!EVP_EncryptUpdate(ctx, bufout, &len, bufin, bufin_len))
		die("decrypt failed");

	EVP_EncryptFinal_ex(ctx, bufout, &len);

	/* print result */
	fprintf(stderr, "ciphertext:\n");
    for (z = 0; z < bufin_len; z++)
        fprintf(stderr, "%02X%c", bufout[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, gcm_taglen, bufout))
		die("generate tag failed");

	/* print result2 */
	fprintf(stderr, "tag:\n");
    for (z = 0; z < gcm_taglen; z++)
        fprintf(stderr, "%02X%c", bufout[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");


	EVP_CIPHER_CTX_free(ctx);
}

static void die(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

static void read_hex(const char *hex, uchar *out, size_t outmax, size_t *outlen)
{
	*outlen = 0;
	if (strlen(hex) > 2*outmax)
		die("read_hex overflow");
	size_t i;
	for (i = 0; hex[i] && hex[i+1]; i += 2) {
		unsigned int value = 0;
		if (!sscanf(hex + i, "%02x", &value))
			die("sscanf failure");
		out[(*outlen)++] = value;
	}
}

static void build_iv(uchar *iv, uint64_t seq)
{
	size_t i;
	for (i = 0; i < 8; i++) {
		iv[gcm_ivlen-1-i] ^= ((seq>>(i*8))&0xFF);
	}
}
