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
	if (argc != 7) {
		fprintf(stderr, "Usage: %s hexiv seq hexkey hexaad hextag plaintext\n", argv[0]);
		fprintf(stderr, "\n");
		fprintf(stderr, "prints plaintext on stdout\n");
		exit(1);
	}

	uchar iv[1024], key[1024], aad[1024], tag[1024];
	size_t ivlen, keylen, aadlen, taglen;
	read_hex(argv[1], iv, sizeof(iv), &ivlen);
	read_hex(argv[3], key, sizeof(key), &keylen);
	read_hex(argv[4], aad, sizeof(aad), &aadlen);
	read_hex(argv[5], tag, sizeof(tag), &taglen);
	uint64_t seq = atoi(argv[2]);
	uchar bufin[1024], bufout[1024];
	size_t bufin_len;
	char *out = NULL;
	int outlen = 0;
	int z;
	read_hex(argv[6], bufin, sizeof(bufin), &bufin_len);

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
    fprintf(stderr, "tag:\n");
    for (z = 0; z < taglen; z++)
        fprintf(stderr, "%02X%c", tag[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");
    fprintf(stderr, "ciphertext:\n");
    for (z = 0; z < bufin_len; z++)
        fprintf(stderr, "%02X%c", bufin[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");


	if (keylen != aes_keylen)
		die("Incorrect key length, expected 16 bytes");
	if (ivlen != gcm_ivlen)
		die("Incorrect IV length, expected 12 bytes");
	if (taglen != gcm_taglen)
		die("Incorrect tag length, expected 16 bytes");
	/* build_iv(iv, seq); */

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		die("cipher ctx create failed");

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		die("init algorithm failed");

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL))
		die("set ivlen failed");

	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		die("set key/iv failed");

	int len = 0;
	if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen))
		die("set aad failed");

	if (!EVP_DecryptUpdate(ctx, bufout, &len, bufin, bufin_len))
		die("decrypt failed");
	out = realloc(out, outlen + len);
	memcpy(out + outlen, bufout, len);
	outlen += len;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, taglen, tag))
		die("set expected tag failed");

	// positive is success
	int final = EVP_DecryptFinal_ex(ctx, bufout+len, &len);
	out = realloc(out, outlen + len);
	memcpy(out + outlen, bufout, len);
	outlen += len;

	EVP_CIPHER_CTX_free(ctx);

	/* print result */
	fprintf(stderr, "plaintext_len: 0x%x, plaintext: \n", outlen);
	for (z = 0; z < bufin_len; z++)
		fprintf(stderr, "%02hhX%c", out[z],
				((z + 1) % 16)? ' ' : '\n');
	fprintf(stderr, "\n");

	if (final > 0) {
		fprintf(stderr, "success!\n");
		free(out);
	} else {
		free(out);
		die("decrypt failed; tag value didn't match");
	}
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
