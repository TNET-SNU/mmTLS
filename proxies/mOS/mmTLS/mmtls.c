#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <endian.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <asm/byteorder.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/tls1.h>
#include <mos_api.h>
#include "cpu.h"
#include "include/mmtls.h"
#include "rss.h"

/* Default path to mOS configuration file */
#define MOS_CONFIG_FILE "config/mos.conf"

#define IP_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define TCP_HEADER_LEN 20
#define TLS_HEADER_LEN 5

#define VERBOSE_TCP 0
#define VERBOSE_TLS 0
#define VERBOSE_KEY 0
#define VERBOSE_CRYPTO_DEBUG 0
/*---------------------------------------------------------------------------*/
/* mmTLS context manager */
struct mtcp_conf g_mcfg;
struct mmtls_manager *g_mmtls;
/*---------------------------------------------------------------------------*/
/* Signal handler */
static void
sigint_handler(int signum)
{
	struct mtcp_conf mcfg;
	/* get the core limit */
	if (mtcp_getconf(&mcfg) == -1)
		EXIT_WITH_ERROR("mtcp_getconf() failed\n");
	/* Terminate the program if any interrupt happens */
	for (int i = 0; i < mcfg.num_cores; i++)
		if (mtcp_destroy_context(g_mmtls[i].mctx) == -1)
			EXIT_WITH_ERROR("mtcp_destroy_context() failed\n");
		
	if (mmtls_destroy() == -1)
		EXIT_WITH_ERROR("mmtls_destroy() failed\n");
	
	exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
/* Dump bytestream in hexademical form */
static inline void
hexdump(char *title, uint8_t *buf, size_t len)
{
	if (title)
		fprintf(stdout, "%s\n", title);
	for (size_t i = 0; i < len; i++)
		fprintf(stdout, "%02X%c", buf[i], ((i + 1) % 16 ? ' ' : '\n'));
		// fprintf(stdout, "%02X", buf[i]);
	if (len % 16)
		fprintf(stdout, "\n");
	fprintf(stdout, "\n");
}
/*---------------------------------------------------------------------------*/
/* Print key, iv, and mac key */
static inline void
print_key(uint8_t *key, int key_len,
		   uint8_t *iv, int iv_len,
		   uint8_t *mackey, int mackey_len)
{
#if VERBOSE_CRYPTO_DEBUG
	if (key)
		hexdump("[key]", key, key_len);
	if (iv)
		hexdump("[iv]", iv, iv_len);
	if (mackey)
		hexdump("[mackey]", mackey, mackey_len);
#endif /* !VERBOSE_CRYPTO_DEBUG */
}
/*---------------------------------------------------------------------------*/
/* Print AAD, TAG, and decrypted plain text */
static inline void
print_text(uint8_t *aad, int aad_len,
		   uint8_t *tag, int tag_len,
		   uint8_t *cipher, int cipher_len,
		   uint8_t *plain, int plain_len)
{
#if VERBOSE_CRYPTO_DEBUG
	if (aad)
		hexdump("[aad]", aad, aad_len);
	if (tag)
		hexdump("[tag]", tag, tag_len);
	fprintf(stdout, "[len]\n0x%x\n\n", plain_len);
	if (cipher)
		hexdump("[cipher]", cipher, cipher_len);
	if (plain)
		hexdump("[plain]", plain, plain_len);
#endif /* !VERBOSE_CRYPTO_DEBUG */
}
/*---------------------------------------------------------------------------*/
/* Create connection structure for new connection */
static inline session *
create_conn_info(mctx_t mctx, int sock)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	session *c;
	/* already created */
	if ((c = mtcp_get_uctx(mctx, sock)))
		return c;
	if (!(c = MPAllocateChunk(mmtls->ci_pool)))
		EXIT_WITH_ERROR("conn info pool alloc failed");
	/* MPAlloc needs memset */
	memset(c, 0, sizeof(session));
#ifndef ZERO_COPY
	if (!(c->sess_ctx[MOS_SIDE_CLI].buf = 
		MPAllocateChunk(mmtls->cli_buffer_pool)))
		EXIT_WITH_ERROR("record pool alloc failed");
	if (!(c->sess_ctx[MOS_SIDE_SVR].buf = 
		MPAllocateChunk(mmtls->svr_buffer_pool)))
		EXIT_WITH_ERROR("record pool alloc failed");
#endif
	/* Insert the structure to the queue */
	mtcp_set_uctx(mctx, sock, c);

	return c;
}
/*---------------------------------------------------------------------------*/
/* remove connection structure */
static inline void
remove_conn_info(mctx_t mctx, int sock)
{
	session *c;
	/* already removed */
	if (!(c = mtcp_get_uctx(mctx, sock)))
		return;
	/* remove the structure from the queue */
	mtcp_set_uctx(mctx, sock, NULL);
#ifndef ZERO_COPY
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	if (c->sess_ctx[MOS_SIDE_CLI].buf)
		MPFreeChunk(mmtls->cli_buffer_pool,
					c->sess_ctx[MOS_SIDE_CLI].buf);
	if (c->sess_ctx[MOS_SIDE_SVR].buf)
		MPFreeChunk(mmtls->svr_buffer_pool,
					c->sess_ctx[MOS_SIDE_SVR].buf);
#endif
	MPFreeChunk(g_mmtls->ci_pool, c);
}
/*---------------------------------------------------------------------------*/
static inline void
handle_malicious(mctx_t mctx, int sock, int side, int code)
{
	if (mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP) == -1)
		EXIT_WITH_ERROR("mtcp_setlastpkt failed");
	if (mtcp_reset_conn(mctx, sock) < 0)
		EXIT_WITH_ERROR("mtcp_reset_conn failed");
	remove_conn_info(mctx, sock);
}
/*---------------------------------------------------------------------------*/
static int
hs_done(session *c, int side)
{
	/* Note that GCM, CCM, ChaChaPoly have 16B tag */
	int done_len = TLS_HANDSHAKE_HEADER_LEN + 
				   EVP_MD_size(c->evp_md) + 
				   EVP_GCM_TLS_TAG_LEN + 
				   TLS_RECORD_TYPE_LEN;
	return (c->sess_ctx[side].record_len == done_len);
}
/*---------------------------------------------------------------------------*/
/* Decrypt single TLS record with given key_info */
/* Return length of decrypted data, -1 of error */
static int
decrypt_tls_cbc(EVP_CIPHER_CTX *evp_ctx,
				const EVP_CIPHER *evp_cipher,
				const EVP_MD *evp_md,
				uint8_t *data,
				uint8_t *plain,
				uint8_t *key_info,
				uint64_t tls_seq,
				uint16_t cipher_len)
{
	// uint8_t buf[2048] = {0,};
	uint8_t *buf = plain;
	uint8_t *tlsh, *cipher, *updated_iv, *tag;
	int len = 0;
	int key_len = EVP_CIPHER_key_length(evp_cipher);
	int iv_len = EVP_CIPHER_iv_length(evp_cipher);
	int md_len = EVP_MD_size(evp_md);
	int tag_len = md_len;
	uint8_t padding_len;
	/* key_info = key (32B) | iv (16B) | mac key (48B) */
	uint8_t *key = key_info, *iv = key + key_len, *mac_key = iv + iv_len;

	// printf("key_len: %d, iv_len: %d, tag_len: %d\n", key_len, iv_len, tag_len);
	// hexdump("key", key, key_len);
	// hexdump("iv", iv, iv_len);
	// hexdump("mac_key", mac_key, tag_len);

	/* update cipher len */
	cipher_len -= iv_len;

	/* TLS header */
	tlsh = data;
	data += TLS_HEADER_LEN;

	/* update iv */
	updated_iv = data;
	data += iv_len;

	/* cipher text */
	cipher = data;
	data += cipher_len;

    /* tag */
	tag = plain + cipher_len - tag_len;
    // hexdump("tag", tag, tag_len);

	// fprintf(stderr, "cipher_len:%d\n", cipher_len);
	// hexdump("cipher", cipher, cipher_len);

	/* decrypt */
	if (!EVP_DecryptInit(evp_ctx, evp_cipher, key, updated_iv))
		return DECRYPT_ERR;
	if ((len = EVP_Cipher(evp_ctx, plain, cipher, cipher_len)) <= 0)
		return DECRYPT_ERR;
	// hexdump("plain", plain, cipher_len);

    /* remove padding */
	padding_len = (*(tag - 1) == *(tag - 2))?*(tag - 1) + 1:0;
	len -= (tag_len + padding_len);
	// printf("paddinglen: %d\n", padding_len);

	/* check tag */
#if 0
	int flen = 0;
	if (EVP_DecryptFinal(evp_ctx, tag, &flen) <= 0)
		return DECRYPT_FINAL_ERR;
#else
	/* make pseudo header */
	*(uint64_t *)buf = htobe64(tls_seq + 1);
	memcpy(buf + sizeof(uint64_t), tlsh, TLS_HEADER_LEN);
	*(uint16_t *)(buf + sizeof(uint64_t) + 3) = htobe16(len);

	size_t hmac_len = sizeof(uint64_t) + TLS_HEADER_LEN + len;
	// hexdump("plain", buf, hmac_len);
    // hexdump("tag", tag, tag_len);
	uint8_t gen_tag[EVP_MAX_MD_SIZE] = {0,};
	unsigned int gen_len;
	HMAC(evp_md, mac_key, tag_len, buf, hmac_len, gen_tag, &gen_len);
	if (gen_len != tag_len)
		return INTEGRITY_ERR;

	// if (memcmp(gen_tag, tag, tag_len) == 0)
	// 	printf("tag checked!\n");
	// else
	// 	printf("TAG UNMATCHED!!!\n");
	// hexdump("original tag", tag, tag_len);
	// hexdump("generated tag", gen_tag, gen_len);
#endif
	(void)tlsh;
	(void)buf;
	(void)mac_key;

	/* print value and results */
	print_text(NULL, 0, tag, tag_len, cipher, cipher_len, plain, len);

	// printf("success to decrypt one record!\n");
	return len;
}
/*---------------------------------------------------------------------------*/
static int
decrypt_tls_12_aead(EVP_CIPHER_CTX *evp_ctx,
					const EVP_CIPHER *evp_cipher,
					const EVP_MD *evp_md,
					uint8_t *data,
					uint8_t *plain,
					uint8_t *key_info,
					uint64_t tls_seq,
					uint16_t cipher_len)
{
	uint8_t aad[EVP_AEAD_TLS1_AAD_LEN];
	uint8_t *tag, *cipher, *ptr = aad;
	int len = 0, flen = 0;
	int key_len = EVP_CIPHER_key_length(evp_cipher);
	// int iv_len = EVP_CIPHER_iv_length(evp_cipher);
	int tag_len = EVP_GCM_TLS_TAG_LEN;
	/* key_info = [key (16B or 32B) | iv (12B) | mac key (16B)] */
	uint8_t *key = key_info, *iv = key + key_len;

	/* update cipher len */
	cipher_len -= (tag_len + EVP_GCM_TLS_EXPLICIT_IV_LEN);

	/* aad: [seq num (8B) | tls header (5B)] in TLS1.2 */
	*(uint64_t *)ptr = htobe64(tls_seq + 1);
	ptr += sizeof(uint64_t);
	memcpy(ptr, data, sizeof(uint8_t) + sizeof(uint16_t));
	ptr += sizeof(uint8_t) + sizeof(uint16_t);
	*(uint16_t *)ptr = htobe16(cipher_len);

	/* TLS header */
	data += TLS_HEADER_LEN;

	/* update iv */
	memcpy(iv + EVP_GCM_TLS_FIXED_IV_LEN, data, EVP_GCM_TLS_EXPLICIT_IV_LEN);
	data += EVP_GCM_TLS_EXPLICIT_IV_LEN;

	/* cipher text */
	cipher = data;
	data += cipher_len;

	/* tag */
	tag = data;

	/* decrypt */
	if (!EVP_DecryptInit(evp_ctx, evp_cipher, key, iv))
		return DECRYPT_ERR;
    /*
     * For CCM we must explicitly set the total plaintext length before we add
     * any AAD.
     */
	if (EVP_CIPHER_get_mode(evp_cipher) == EVP_CIPH_CCM_MODE) {
		if (!EVP_DecryptUpdate(evp_ctx, NULL, &len, NULL, cipher_len))
			return DECRYPT_ERR;
	}
	if (!EVP_DecryptUpdate(evp_ctx, NULL, &len, aad, EVP_AEAD_TLS1_AAD_LEN))
		return DECRYPT_ERR;
	if ((len = EVP_Cipher(evp_ctx, plain, cipher, cipher_len)) <= 0)
		return DECRYPT_ERR;
	
	/* check tag */
	// if (!EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
	// 	return INTEGRITY_ERR;
	// if (EVP_DecryptFinal(evp_ctx, tag, &flen) <= 0)
	// 	return INTEGRITY_ERR;
	len += flen;

	/* print value and results */
	assert(cipher_len == len);
	print_text(aad, EVP_AEAD_TLS1_AAD_LEN, tag, tag_len, cipher, cipher_len, plain, len);

	return len;
}
/*---------------------------------------------------------------------------*/
/* Decrypt single TLS record with given key_info */
/* Return length of decrypted data, -1 of error */
static int
decrypt_tls_13_aead(EVP_CIPHER_CTX *evp_ctx,
					const EVP_CIPHER *evp_cipher,
					const EVP_MD *evp_md,
					uint8_t *data,
					uint8_t *plain,
					uint8_t *key_info,
					uint64_t tls_seq,
					uint16_t cipher_len)
{
	uint8_t updated_iv[EVP_MAX_IV_LENGTH];
	uint8_t *aad, *tag, *cipher;
	int len = 0, flen = 0;
	int key_len = EVP_CIPHER_key_length(evp_cipher);
	int iv_len = EVP_CIPHER_iv_length(evp_cipher);
	int tag_len = EVP_GCM_TLS_TAG_LEN;
	/* key_info = [key (16B or 32B) | iv (12B) | mac key (16B)] */
	uint8_t *key = key_info, *iv = key + key_len;
	// printf("key_len: %d, iv_len: %d, tag_len: %d, tls_seq: %ld\n", key_len, iv_len, tag_len, tls_seq);

	/* update cipher len */
	cipher_len -= tag_len;

	/* aad: [tls header (5B)] in TLS1.3 */
	aad = data;
	data += TLS_HEADER_LEN;

	/* update iv */
	for (int i = 0; i < EVP_GCM_TLS_EXPLICIT_IV_LEN; i++)
		updated_iv[iv_len - i - 1] = iv[iv_len - i - 1] ^
			((tls_seq >> (i * 8)) & LOWER_8BITS);
	memcpy(updated_iv, iv, EVP_GCM_TLS_FIXED_IV_LEN);

	/* cipher text */
	cipher = data;
	data += cipher_len;

	/* tag */
	tag = data;

	/* decrypt */
	if (!EVP_DecryptInit(evp_ctx, evp_cipher, key, updated_iv))
		return DECRYPT_ERR;
    /*
     * For CCM we must explicitly set the total plaintext length before we add
     * any AAD.
     */
	if (EVP_CIPHER_get_mode(evp_cipher) == EVP_CIPH_CCM_MODE) {
		if (!EVP_DecryptUpdate(evp_ctx, NULL, &len, NULL, cipher_len))
			return DECRYPT_ERR;
	}
	if (!EVP_DecryptUpdate(evp_ctx, NULL, &len, aad, TLS_HEADER_LEN))
		return DECRYPT_ERR;
	if ((len = EVP_Cipher(evp_ctx, plain, cipher, cipher_len)) <= 0)
		return DECRYPT_ERR;
	
	/* print key and iv */
	print_key(key, key_len, updated_iv, iv_len, NULL, 0);
	/* print value and results */
	print_text(aad, TLS_HEADER_LEN, tag, tag_len, cipher, cipher_len, plain, len);

	/* check tag */
	if (!EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
		return INTEGRITY_ERR;
	if (EVP_DecryptFinal(evp_ctx, tag, &flen) <= 0)
		return INTEGRITY_ERR;
	len += flen;
	assert(cipher_len == len);

	/*
	 * TLS1.3 has diguised record type at the end of plaintext of app record
	 * Update record type if not application data
	 */
	if (*(plain + len - 1) != APPLICATION_DATA)
		*aad = *(plain + len - 1);

	return len - 1;
}
/*---------------------------------------------------------------------------*/
/* Decrypt single TLS record with given key_info */
/* Return length of decrypted data, -1 on error */
static inline int
get_plaintext(mmctx_t mmctx, session_ctx *tls_ctx,
			  uint16_t version,
			  const EVP_CIPHER *evp_cipher,
			  const EVP_MD *evp_md,
			  uint8_t *data, uint8_t *plain)
{
	struct mmtls_manager *mmtls = g_mmtls + mmctx->cpu;
	crypto_cb decrypt;

	/* AEAD: AES-GCM or ChaCha20-poly1305 or CCM */
	if (EVP_CIPHER_get_flags(evp_cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
		if (version == TLS_1_3_VERSION) {
			/* TLSv1.3 allows only AEAD */
			decrypt = decrypt_tls_13_aead;
			goto Decrypt;
		}
		decrypt = decrypt_tls_12_aead;
		goto Decrypt;
	}
	/* CBC: Note that this should be deprecated due to security issue */
	decrypt = decrypt_tls_cbc;

Decrypt:
	return decrypt(mmtls->evp_ctx,
				   evp_cipher, evp_md,
				   data, plain,
				   tls_ctx->key_info, tls_ctx->tls_seq,
				   tls_ctx->record_len);
}
/*---------------------------------------------------------------------------*/
/* Return length of plaintext data, -1 on error */
/* Note: This function does not decrypt the record */
static inline int
plaintext_len(session_ctx *tls_ctx,
			  const EVP_CIPHER *evp_cipher,
			  const EVP_MD *evp_md)
{	
	/* AEAD */
	if (EVP_CIPHER_get_flags(evp_cipher) & EVP_CIPH_FLAG_AEAD_CIPHER)
		return tls_ctx->record_len - EVP_GCM_TLS_TAG_LEN;
	/* CBC */
	return tls_ctx->record_len - EVP_MD_size(evp_md);
}
/*---------------------------------------------------------------------------*/
/* Parse payload to get TLS session key data into key_info */
/* Return length of parsed data, -1 of error */
static inline int
parse_tls_key(uint8_t *data, uint16_t *version, uint16_t *cipher_suite,
			  uint8_t *client, uint8_t *server)
{
	uint8_t *ptr = data;
	uint16_t info_size;
	*version = ntohs(*(uint16_t *)ptr);
	ptr += sizeof(uint16_t);
	*cipher_suite = ntohs(*(uint16_t *)ptr);
	ptr += sizeof(uint16_t);
	info_size = ntohs(*(uint16_t *)ptr);
	ptr += sizeof(uint16_t);
	memcpy(client, ptr, info_size);
	ptr += info_size;
	memcpy(server, ptr, info_size);
	ptr += info_size;

	return ptr - data;
}
/*---------------------------------------------------------------------------*/
/* Parse TCP payload to assemble single TLS record sending to server
 * Return byte of parsed record, 0 if no complete record
 */
#ifndef ZERO_COPY
static inline int
parse_tls_record(session_ctx *tls_ctx)
{
	/* Parse header of new record */
	if (tls_ctx->head + TLS_HEADER_LEN > tls_ctx->tail)
		return 0; // TLS header is incomplete
	tls_ctx->record_len = 
		ntohs(*(uint16_t *)(tls_ctx->buf + tls_ctx->head + 3));
	if (tls_ctx->head + tls_ctx->record_len + TLS_HEADER_LEN > tls_ctx->tail)
		return 0; // TLS record is incomplete

#if VERBOSE_TLS
	fprintf(stdout,
			"\n--------------------------------------------------\n"
			"[%s] Parse new record to follow session\n"
			"Record type %x\n"
			"length %u (TCP %u ~ %u)\n"
			"cipher len %u\n",
			__FUNCTION__, 
			tls_ctx->record_type, tls_ctx->record_len + TLS_HEADER_LEN,
			tls_ctx->head, tls_ctx->tc_head + tls_ctx->record_len + TLS_HEADER_LEN,
			tls_ctx->record_len);
	hexdump("Dump of ciphertext of the record:", tls_ctx->buf + tls_ctx->head + 5,
			tls_ctx->record_len + TLS_HEADER_LEN);
#endif /* VERBOSE_TLS */

	return 1;
}
#endif
/*---------------------------------------------------------------------------*/
/* Select evp cipher and evp md functions for given cipher_suite */
static inline void
select_cipher(mctx_t mctx, session *c, uint8_t *cipher_suite)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	const SSL_CIPHER *ssl_cipher;
	const char *IANA_cipher_name;

	/* ToDo: identify cipher suite by 2B ID, not IANA name one day */
	if (!(ssl_cipher = SSL_CIPHER_find(mmtls->ssl, cipher_suite)) ||
		!(IANA_cipher_name = SSL_CIPHER_standard_name(ssl_cipher)))
		WARNING_PRINT("SSL_CIPHER_standard_name failed\n"
					  "Unknown cipher suite?\n"
					  "version: %d, ciphersuite: %d",
					  c->sess_info.version, c->sess_info.cipher_suite);
	if (strstr(IANA_cipher_name, "_GCM_")) {
		/*
		 * select symmetric crypto algorithm
		 * note that GCM has fixed MAC alrogithm for key size
		 */
		if (strstr(IANA_cipher_name, "AES_256")) {
			c->evp_cipher = EVP_aes_256_gcm();
			c->evp_md = EVP_sha384();
		}
		else if (strstr(IANA_cipher_name, "AES_128")) {
			c->evp_cipher = EVP_aes_128_gcm();
			c->evp_md = EVP_sha256();
		}
		else
			WARNING_PRINT("Not supported cipher suite, %s", IANA_cipher_name);
	}
	else if (strstr(IANA_cipher_name, "_CHACHA20_")) {
		c->evp_cipher = EVP_chacha20_poly1305();
		c->evp_md = EVP_sha256();
	}
	else if (strstr(IANA_cipher_name, "_CCM_")) {
		/* select symmetric crypto algorithm */
		if (strstr(IANA_cipher_name, "AES_256"))
			c->evp_cipher = EVP_aes_256_ccm();
		else if (strstr(IANA_cipher_name, "AES_128"))
			c->evp_cipher = EVP_aes_128_ccm();
		else
			WARNING_PRINT("Not supported cipher suite, %s", IANA_cipher_name);
		/* select MAC algorithm */
		if (strstr(IANA_cipher_name, "SHA256"))
			c->evp_md = EVP_sha256();
		else if (strstr(IANA_cipher_name, "SHA384"))
			c->evp_md = EVP_sha384();
		else if (strstr(IANA_cipher_name, "SHA512"))
			c->evp_md = EVP_sha512();
		else if (strstr(IANA_cipher_name, "SHA"))
			c->evp_md = EVP_sha1();
		else
			WARNING_PRINT("Not supported cipher suite, %s", IANA_cipher_name);
	}
	else if (strstr(IANA_cipher_name, "_CBC_")) {
		/* select symmetric crypto algorithm */
		if (strstr(IANA_cipher_name, "AES_256"))
			c->evp_cipher = EVP_aes_256_cbc();
		else if (strstr(IANA_cipher_name, "AES_128"))
			c->evp_cipher = EVP_aes_128_cbc();
		else
			WARNING_PRINT("Not supported cipher suite, %s", IANA_cipher_name);
		/* select MAC algorithm */
		if (strstr(IANA_cipher_name, "SHA256"))
			c->evp_md = EVP_sha256();
		else if (strstr(IANA_cipher_name, "SHA384"))
			c->evp_md = EVP_sha384();
		else if (strstr(IANA_cipher_name, "SHA512"))
			c->evp_md = EVP_sha512();
		else if (strstr(IANA_cipher_name, "SHA"))
			c->evp_md = EVP_sha1();
		else
			WARNING_PRINT("Not supported cipher suite, %s", IANA_cipher_name);
	}
	else
		WARNING_PRINT("Not supported mode, %s", IANA_cipher_name);
}
/*---------------------------------------------------------------------------*/
static int
parse_client_hello(mctx_t mctx, session *c, uint8_t *record)
{
	uint16_t total_ex_len, ex_type, ex_len;
	/* ToDo: check header len */

	/* client hello means key reset */
	c->has_key = 0;
	/* TLS HS header */
	record += TLS_HANDSHAKE_HEADER_LEN;
	/* client protocol version */
	record += sizeof(uint16_t);
	/* TLS1.3 client random */
	memcpy(c->sess_info.client_random, record, TLS_CLIENT_RANDOM_LEN);
	record += TLS_CLIENT_RANDOM_LEN;
	/* pass session id (one byte len field) */
	record += 1 + *record;
	/* cipher suite list (two byte len field) */
	record += 2 + ntohs(*(uint16_t *)record);
	/* compression method */
	record += 1 + *record;
	/* total extension length */
	total_ex_len = ntohs(*(uint16_t *)record);
	record += sizeof(uint16_t);
	/* find protocol extension */
	while (total_ex_len > 0) {
		ex_type = ntohs(*(uint16_t *)record);
		record += sizeof(uint16_t);
		ex_len = ntohs(*((uint16_t *)record));
		record += sizeof(uint16_t);
		/* SNI */
		if (ex_type == TLSEXT_TYPE_server_name) {
			record += sizeof(uint16_t);
			c->sess_info.sni_type = *record;
			record++;
			c->sess_info.sni_len = ntohs(*((uint16_t *)record));
			record += sizeof(uint16_t);
			memcpy(c->sess_info.sni, record, c->sess_info.sni_len);
			c->sess_info.sni[c->sess_info.sni_len] = 0;
			break;
		}
		else {
			record += ex_len;
			total_ex_len -= 2 * sizeof(uint16_t) + ex_len;
		}
	}

	return NO_DECRYPT;
}
/*---------------------------------------------------------------------------*/
static int
parse_server_hello(mctx_t mctx, session *c, uint8_t *record)
{
	uint16_t total_ex_len, ex_type, ex_len;
	uint8_t *cipher_suite;
	/* ToDo: check header len */

	/* TLS HS header */
	record += TLS_HANDSHAKE_HEADER_LEN;
	/* server protocol version */
	c->sess_info.version = ntohs(*(uint16_t *)record);
	record += sizeof(uint16_t);
	/* TLS1.3 server random */
	// memcpy(c->tls_info.server_random, record, TLS_SERVER_RANDOM_LEN);
	record += TLS_SERVER_RANDOM_LEN;
	/* pass session id (one byte len field) */
	record += 1 + *record;
	/* cipher suite */
	cipher_suite = record;
	c->sess_info.cipher_suite = ntohs(*(uint16_t *)record);
	record += sizeof(uint16_t);
	/* compression method */
	record++;
	/* total extension length */
	total_ex_len = ntohs(*(uint16_t *)record);
	record += sizeof(uint16_t);
	/* find protocol extension */
	while (total_ex_len > 0) {
		ex_type = ntohs(*(uint16_t *)record);
		record += sizeof(uint16_t);
		ex_len = ntohs(*((uint16_t *)record));
		record += sizeof(uint16_t);
		/* TLS1.3 */
		if ((ex_type == TLSEXT_TYPE_supported_versions) &&
			(ex_len == sizeof(uint16_t))) {
			/* supported version */
			c->sess_info.version = ntohs(*(uint16_t *)record);
			break;
		}
		else if ((ex_type == TLSEXT_TYPE_key_share) &&
				 (ex_len == sizeof(uint16_t))) {
			/* key share group (e.g. X25519) */
			c->sess_info.group = ntohs(*(uint16_t *)record);
		}
		else {
			record += ex_len;
			total_ex_len -= 2 * sizeof(uint16_t) + ex_len;
		}
	}
	select_cipher(mctx, c, cipher_suite);

	return NO_DECRYPT;
}
/*---------------------------------------------------------------------------*/
// static int
// parse_server_changecipherspec(mctx_t mctx, session *c, uint8_t *record)
// {
// 	uint16_t total_ex_len, ex_type, ex_len;
// 	uint8_t *cipher_suite;
// 	/* ToDo: check header len */

// 	/* TLS HS header */
// 	record += TLS_HANDSHAKE_HEADER_LEN;
// 	/* server protocol version */
// 	c->sess_info.version = ntohs(*(uint16_t *)record);
// 	record += sizeof(uint16_t);
// 	/* TLS1.3 server random */
// 	// memcpy(c->ci_server_random, record, TLS_SERVER_RANDOM_LEN);
// 	record += TLS_SERVER_RANDOM_LEN;
// 	/* pass session id (one byte len field) */
// 	record += 1 + *record;
// 	/* cipher suite */
// 	cipher_suite = record;
// 	c->sess_info.cipher_suite = ntohs(*(uint16_t *)record);
// 	record += sizeof(uint16_t);
// 	/* compression method */
// 	record++;
// 	/* total extension length */
// 	total_ex_len = ntohs(*(uint16_t *)record);
// 	record += sizeof(uint16_t);
// 	/* find protocol extension */
// 	while (total_ex_len > 0) {
// 		ex_type = ntohs(*(uint16_t *)record);
// 		record += sizeof(uint16_t);
// 		ex_len = ntohs(*((uint16_t *)record));
// 		record += sizeof(uint16_t);
// 		/* TLS1.3 */
// 		if ((ex_type == TLSEXT_TYPE_supported_versions) &&
// 			(ex_len == sizeof(uint16_t))) {
// 			/* supported version */
// 			c->sess_info.version = ntohs(*(uint16_t *)record);
// 		}
// 		else if ((ex_type == TLSEXT_TYPE_key_share) &&
// 				 (ex_len == sizeof(uint16_t))) {
// 			/* key share group (e.g. X25519) */
// 			c->sess_info.group = ntohs(*(uint16_t *)record);
// 		}
// 		else {
// 			record += ex_len;
// 			total_ex_len -= 2 * sizeof(uint16_t) + ex_len;
// 		}
// 	}
// 	select_cipher(mctx, c, cipher_suite);

// 	return NO_DECRYPT;
// }
/*---------------------------------------------------------------------------*/
static inline int
update_conn_info_13(mctx_t mctx, int sock, int side, session *c, uint8_t *record)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	mmctx_t mmctx = mmtls->mmctx;

	/* ToDo: make it more strict, subject to TLS v1.3 protocol */
	if (*record != APPLICATION_DATA)
		return NO_DECRYPT;
	if (c->tls_state == RECV_SH) {
		if (side == MOS_SIDE_CLI) {
			/*
			 * handshake related record disguised in app data
			 * e.g. server handshake finished done, new session ticket
			 */
			if (!c->svr_done) {
				/* handshake done from server */
				if (hs_done(c, side))
					c->svr_done = 1;	
				return NO_DECRYPT;
			}
			/* 
			 * If server done detected, the record after server done 
			 * shoulde be decrypted with traffic key,
			 * So we increase TLS seq here
			 * 
			 * Currently,
			 * we do not decrypt those above received during HS.
			 * If needed, decrypt w/o NEW_RECORD event handler call.
			 */
			c->sess_ctx[side].tls_seq++;
			return NO_DECRYPT;
		}
		if (side == MOS_SIDE_SVR) {
			/* handshake done from client */
			if (hs_done(c, side)) {
				c->tls_state = TLS_ESTABLISHED;
				/* client handshake done means handshake end */
				if (mmtls->cb[ON_TLS_HANDSHAKE_END])
					mmtls->cb[ON_TLS_HANDSHAKE_END](mmctx, sock, side);
			}
			return NO_DECRYPT;
		}
		return NO_DECRYPT;
	}

	return DO_DECRYPT;
}
/*---------------------------------------------------------------------------*/
static inline int
update_conn_info_12(mctx_t mctx, int sock, int side, session *c, uint8_t *record)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	mmctx_t mmctx = mmtls->mmctx;

	/* ToDo: make it more strict, subject to TLS v1.2 protocol */
	if (*record != APPLICATION_DATA)
		return NO_DECRYPT;
	c->tls_state = TLS_ESTABLISHED;

	/* handshake end */
	if (mmtls->cb[ON_TLS_HANDSHAKE_END])
		mmtls->cb[ON_TLS_HANDSHAKE_END](mmctx, sock, side);

	return DO_DECRYPT;
}
/*---------------------------------------------------------------------------*/
/* Update version and state in connection information
 * Return
 * 0 if no need decrypt,
 * 1 if need decrypt,
 * 
 * Someone might want to receive event noti for TLS inner event
 * such as SNI callback, keylog callback, msg callback, etc.
 * 
 *
 * !Notice!
 *
 * side == MOS_SIDE_CLI means
 * client side recv buffer, whose contents are from server
 * side == MOS_SIDE_SVR means
 * server side recv buffer, whose contents are from client
 *
 */
static inline int
update_conn_info(mctx_t mctx, int sock, int side, session *c)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	mmctx_t mmctx = mmtls->mmctx;
	session_ctx *tls_ctx = &c->sess_ctx[side];
	uint8_t *record;
	int ret;
#ifndef ZERO_COPY
	record = tls_ctx->buf + tls_ctx->head;
#else
	record = tls_ctx->buf;
#endif
	if (c->tls_state == INITIAL_STATE) {
		if (*record != HANDSHAKE)
			return NO_DECRYPT;
		record += TLS_HEADER_LEN;
		if (*record != CLIENT_HS)
			return NO_DECRYPT;
		ret = parse_client_hello(mctx, c, record);
		if (ret < 0)
			return ret;
		/* client hello means handshake start */
		if (mmtls->cb[ON_TLS_HANDSHAKE_START])
			mmtls->cb[ON_TLS_HANDSHAKE_START](mmctx, sock, side);
		c->tls_state = RECV_CH;
		return NO_DECRYPT;
	}
	if (c->tls_state == RECV_CH) {
		if (*record != HANDSHAKE)
			return NO_DECRYPT;
		record += TLS_HEADER_LEN;
		if (*record != SERVER_HS)
			return NO_DECRYPT;
		ret = parse_server_hello(mctx, c, record);
		if (ret < 0)
			return ret;
		c->tls_state = RECV_SH;
		return NO_DECRYPT;
	}
	if (c->sess_info.version == TLS_1_3_VERSION)
		return update_conn_info_13(mctx, sock, side, c, record);
	if (c->sess_info.version == TLS_1_2_VERSION)
		return update_conn_info_12(mctx, sock, side, c, record);

	return INVALID_VERSION;
}
/*---------------------------------------------------------------------------*/
/* 1. Check whether peeked record is complete
 * 2. Parse the complete record
 * 3. Update connection info (e.g., state, client random)
 * 4. Decrypt if needed
 * 5. Move buffer head right by parsed bytes
 * 6. Return 1 on success, or -1 if error
 */
static inline int
process_data(mctx_t mctx, int sock, int side, session *c)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	session_ctx *tls_ctx = &c->sess_ctx[side];
	uint16_t plain_len;
	int ret;

	/* decrypt complete records */
#ifndef ZERO_COPY
	while (parse_tls_record(tls_ctx) > 0) {
#endif
		ret = update_conn_info(mctx, sock, side, c);
		if (ret < 0) {
			c->err_code = ret;
			return c->err_code;
		}
		if (ret == DO_DECRYPT) {
			if (!c->has_key)
				return NO_KEY;
			/* handle callback */
Callback:
			if (!c->stop_len[side]) {
				if (mmtls->cb[ON_TLS_NEW_RECORD])
					mmtls->cb[ON_TLS_NEW_RECORD](mmtls->mmctx, sock, side);
			}
			else {
				plain_len = plaintext_len(tls_ctx, c->evp_cipher, c->evp_md);
				if (c->stop_len[side] >= plain_len)
					c->stop_len[side] -= plain_len;
				else {
					if (c->stop_len[side] != -1) {
						/*
						* when skipped plaintext length range is out of stop range,
						* call handler for the edge of range to be conservative
						* note that it can be changed
						*/
						c->stop_len[side] = 0;
						goto Callback;
					}
				}
			}

			/*
			 * TLS sequence number always increases for
			 * every record, but upon changing key,
			 * it should be zero. (refer to RFC 8446)
			 * 
			 * Handshake data is encrypted using HANDSHAKE KEY
			 * and application data is encrypted using TRAFFIC KEY,
			 * so we have two TLS sequence number spaces for TLS 1.3
			 * 
			 * In mmTLS, we only use TLS sequence number space for
			 * application data, since we do not need to decrypt
			 * TLS handshake record.
			 * 
			 * Thus, we increase TLS sequence only for
			 * application data which should be decrypted
			 * with TRAFFIC KEY, here
			 */

			tls_ctx->tls_seq++;

			if (c->err_code < 0)
				return c->err_code;
		}
#ifndef ZERO_COPY
		/* move to next record */
		tls_ctx->head += TLS_HEADER_LEN + tls_ctx->record_len;
	}
#endif

	return 1;
}
/*---------------------------------------------------------------------------*/
/* Allocate new chunk from raw packet mempool for raw packet buffer
 * Copy the last raw packet to raw packet buffer
 */
static inline int
copy_lastpkt(mctx_t mctx, int sock, int side, session *c)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	pkt_vec *rp = c->raw_pkt + c->raw_cnt;
	if (!rp->data) {
		if (!(rp->data = MPAllocateChunk(mmtls->rawpkt_pool)))
			EXIT_WITH_ERROR("rawpkt pool alloc failed");
	}
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
	struct pkt_info p;
	if (mtcp_getlastpkt(mctx, sock, side, &p) == -1)
		EXIT_WITH_ERROR("failed to get packet info");
	memcpy(rp->data, p.ethh, p.eth_len);
	rp->len = p.eth_len;
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, sock, side, &pctx) == -1)
		EXIT_WITH_ERROR("failed to get packet context");
	memcpy(rp->data, pctx->p.ethh, pctx->p.eth_len);
	rp->len = pctx->p.eth_len;
#endif
	c->raw_len += rp->len;
	c->raw_cnt++;
	if ((c->raw_cnt == MAX_RAW_PKT_NUM) ||
		(c->raw_len > MAX_BUF_LEN)) {
		MPFreeChunk(mmtls->rawpkt_pool, rp->data);
		c->raw_cnt = c->raw_len = 0;
		return MISSING_KEY;
	}
	(rp + 1)->data = rp->data + rp->len;
	return 1;
}
/*----------------------------------------------------------------------------*/
static inline int
stall_lastpkt(mctx_t mctx, int sock, int side, session *c)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	mmctx_t mmctx = mmtls->mmctx;
	if (mmtls->cb[ON_TLS_STALL])
		mmtls->cb[ON_TLS_STALL](mmctx, sock, side);
	if (copy_lastpkt(mctx, sock, side, c) == MISSING_KEY)
		return MISSING_KEY;
	if (mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP) == -1)
		EXIT_WITH_ERROR("drop failed");
	return 1;
}
/*---------------------------------------------------------------------------*/
/* Send copied raw packets
 * After send, free mempool
 */
static inline void
resend_lastpkts(mctx_t mctx, int sock, session *c)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	pkt_vec *rp = c->raw_pkt;
	if (c->raw_cnt == 0)
		return;
	while (rp < c->raw_pkt + c->raw_cnt) {
		if (!rp->data)
			printf("null packet!\n");
		if (mtcp_sendpkt_raw(mctx, sock, rp->data, rp->len) < 0) {
			WARNING_PRINT("[core %d] failed to send stalled packets", mctx->cpu);
			break;
		}
		rp++;
	}
	assert(c->raw_pkt->data);
	MPFreeChunk(mmtls->rawpkt_pool, c->raw_pkt->data);
	c->raw_cnt = c->raw_len = 0;
}
/*----------------------------------------------------------------------------*/
/* Called when received new packet from monitoring stream socket (sock, side) */
static inline void
mmtls_core(mctx_t mctx, int sock, int side, session *c)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	session_ctx *tls_ctx = &c->sess_ctx[side];
	int len, ret, stall = 0;

	if (c->drop) {
		if (mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP) == -1)
			EXIT_WITH_ERROR("drop failed");
		return;
	}

	if ((!c->has_key) && (c->tls_state == TLS_ESTABLISHED)) {
		ret = stall_lastpkt(mctx, sock, side, c);
		if (ret == MISSING_KEY) {
			/* client did not send keys */
			side = MOS_SIDE_SVR;
			goto Abnormal;
		}
		stall = 1;
	}

#ifndef ZERO_COPY
	while (true) {
		if ((len = mtcp_peek(mctx, sock, side, (char *)tls_ctx->buf + tls_ctx->tail,
							MAX_BUF_LEN - tls_ctx->tail)) <= 0) {
			return;
		}
		tls_ctx->tail += len;
		// c->sess_ctx[side].peek_len += len; /* for debugging */
		if ((ret = process_data(mctx, sock, side, c)) < 0)
			goto Abnormal;
		if ((ret == NO_KEY) && !stall) {
			ret = stall_lastpkt(mctx, sock, side, c);
			if (ret == MISSING_KEY) {
				/* client did not send keys */
				side = MOS_SIDE_SVR;
				goto Abnormal;
			}
		}
		/* if cipher is full, move buffer to left by head offset and re-peek */
		if (tls_ctx->tail == MAX_BUF_LEN) {
			// printf("cipher full\n");
			memcpy(tls_ctx->buf, tls_ctx->buf + tls_ctx->head,
					MAX_BUF_LEN - tls_ctx->head);
			tls_ctx->tail -= tls_ctx->head;
			tls_ctx->head = 0;
			continue;
		}
#if VERBOSE_TCP
		hexdump(NULL, tls_ctx->buf + tls_ctx->head, len);
#endif
		break;
	}
#else
	while (true) {
		tls_ctx->buf = mtcp_get_record(mctx, sock, side, &len);
		if (!tls_ctx->buf)
			return;
		if (len > MAX_RECORD_LEN + TLS_HEADER_LEN) {
			ret = INVALID_RECORD_LEN;
			goto Abnormal;
		}

		tls_ctx->record_len = len - TLS_HEADER_LEN;
		// c->sess_ctx[side].peek_len += len; /* for debugging */
		ret = process_data(mctx, sock, side, c);
		if (ret < 0)
			goto Abnormal;
		if (ret == NO_KEY) {
			if (!stall) {
				ret = stall_lastpkt(mctx, sock, side, c);
				if (ret == MISSING_KEY) {
					/* client did not send keys */
					side = MOS_SIDE_SVR;
					goto Abnormal;
				}
			}
			break;
		}
		/* ret > 0, move poff to next record */
		if (mtcp_move_poff(mctx, sock, side, len) < 0)
			EXIT_WITH_ERROR("mtcp_move_poff failed");
#if VERBOSE_TCP
		hexdump(NULL, tls_ctx->buf, len);
#endif
	}
#endif
	return;
Abnormal:
	/* handle callback */
	c->err_code = ret;
	if (mmtls->cb[ON_TLS_ERROR])
		mmtls->cb[ON_TLS_ERROR](mmtls->mmctx, sock, side);
	else
		handle_malicious(mctx, sock, side, ret);
}
/*----------------------------------------------------------------------------*/
/* Create connection structure */
static void
cb_tls_start(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	mmctx_t mmctx = mmtls->mmctx;
	create_conn_info(mctx, sock);
	/* handle callback */
	if (mmtls->cb[ON_TLS_SESSION_START])
		mmtls->cb[ON_TLS_SESSION_START](mmctx, sock, side);
}
/*----------------------------------------------------------------------------*/
/* Destroy connection structure */
static void
cb_tls_end(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	mmctx_t mmctx = mmtls->mmctx;
	/* handle callback */
	if (mmtls->cb[ON_TLS_SESSION_END])
		mmtls->cb[ON_TLS_SESSION_END](mmctx, sock, side);
	remove_conn_info(mctx, sock);
}
/*----------------------------------------------------------------------------*/
/* Called when received new packet from monitoring stream socket (sock, side) */
static void
cb_tls_pkt_in(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	session *c;
	if (!(c = mtcp_get_uctx(mctx, sock)))
		return;
	mmtls_core(mctx, sock, side, c);
}
/*---------------------------------------------------------------------------*/
/* This function is called when endpoints' rb is larger than mOS rb */
static void
cb_tls_buf_full(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	printf("buf full event called\n");
	session *c;
	if (!(c = mtcp_get_uctx(mctx, sock)))
		/* retransmitted packet in removed conn */
		return;

	/* if recv buffer is full, drop last packet */
	if (mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP) == -1)
		EXIT_WITH_ERROR("drop failed");

	/* resize buffer ~ 1MB */
	/* we currently do not use below */
#if 0
	struct tcp_buf_info optval;
	socklen_t optlen;
	int rb_size;
	optlen = sizeof(optval);
	if (mtcp_getsockopt(mctx, sock, SOL_MONSOCKET, side + MOS_INFO_CLIBUF,
						(void *)&optval, &optlen) == -1)
		EXIT_WITH_ERROR("mtcp_getsockopt failed");
	rb_size = optval.tcpbi_recv_buf_size;
	
	if (rb_size <= 1048576) {
		rb_size += 262144;
		printf("resized buf len: %d\n", rb_size);
		optlen = sizeof(rb_size);
		if (mtcp_setsockopt(mctx, sock, SOL_MONSOCKET, side + MOS_CLIBUF,
							(void *)&rb_size, optlen) == -1) {
			WARNING_PRINT("[core %d] buffer resizing failed", mctx->cpu);
			if (mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP) == -1)
				EXIT_WITH_ERROR("drop failed");
		}
	}
#endif

	mmtls_core(mctx, sock, side, c);
}
/*---------------------------------------------------------------------------*/
/* Called when received new raw packet from raw monitoring socket (rsock) */
static void
cb_new_key(mctx_t mctx, int rsock, int side, uint64_t events, filter_arg_t *arg)
{
	struct mmtls_manager *mmtls = g_mmtls + mctx->cpu;
	mmctx_t mmctx = mmtls->mmctx;
	int sock;
	session *c;
	struct session_address addr;
	uint8_t *udph, *payload;
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
	struct pkt_info p;
	if (mtcp_getlastpkt(mctx, rsock, side, &p) == -1)
		EXIT_WITH_ERROR("mtcp_getlastpkt failed");
	udph = (uint8_t *)(p.iph) + IP_HEADER_LEN;
	payload = udph + UDP_HEADER_LEN;
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, rsock, side, &pctx) == -1)
		EXIT_WITH_ERROR("mtcp_getlastpkt failed");
	udph = (uint8_t *)(pctx->p.iph) + IP_HEADER_LEN;
	payload = udph + UDP_HEADER_LEN;
#endif
	if (mtcp_setlastpkt(mctx, rsock, side, 0, NULL, 0, MOS_DROP) == -1)
		EXIT_WITH_ERROR("drop failed");
#if VERBOSE_KEY
	fprintf(stdout,
			"\n--------------------------------------------------\n"
			"[%s] core: %d, rsock: %d, side: %u\n",
			__FUNCTION__, mctx->cpu, rsock, side);
#endif

	/*
	 * key will be used at mirrored client (server) recv buffer
	 * contents in recv buffer are sent by server (client)
	 * so, save the server (client) key at client (server) context
	 */
	addr = (struct session_address) {
		ntohl(pctx->p.iph->saddr),
		ntohl(pctx->p.iph->daddr),
		ntohs(*(uint16_t *)udph),
		ntohs(*((uint16_t *)udph + 1))
	};
	if ((sock = mtcp_addrtosock(mctx, (session_address_t)&addr, pctx->p.rss_hash)) == -1) {
		WARNING_PRINT("[core %d] orphan key received", mctx->cpu);
		return;
	}
	c = create_conn_info(mctx, sock);
	/* check crandom */
	if (memcmp(c->sess_info.client_random, payload, TLS_CLIENT_RANDOM_LEN)) {
		WARNING_PRINT("[core %d] orphan key received", mctx->cpu);
		return;
	}
	parse_tls_key(payload + TLS_CLIENT_RANDOM_LEN,
				&c->sess_info.version,
				&c->sess_info.cipher_suite,
				c->sess_ctx[MOS_SIDE_SVR].key_info,
				c->sess_ctx[MOS_SIDE_CLI].key_info);
	c->has_key = 1;
	// if (mtcp_register_callback(mctx, sock, MOS_ON_CONN_NEW_DATA,
	// 						   MOS_NULL, cb_pkt_in) == -1)
	// 	EXIT_WITH_ERROR("Failed to register cb_pkt_in() on MOS_ON_CONN_NEW_DATA");
	/* it did not work */
	// if (mtcp_unregister_callback(mctx, sock, MOS_ON_PKT_IN,
	// 							 MOS_HK_RCV) == -1)
	// 	EXIT_WITH_ERROR("Failed to unregister cb_pkt_in() on MOS_ON_PKT_IN");
	if (mmtls->cb[ON_TLS_RECV_KEY])
		mmtls->cb[ON_TLS_RECV_KEY](mmctx, sock, MOS_SIDE_SVR);
	resend_lastpkts(mctx, sock, c);

	return;
}
/*---------------------------------------------------------------------------*/
static inline int
register_key_callback(mctx_t mctx, int rsock)
{
	union monitor_filter ft = {0};
	ft.raw_pkt_filter = "ip[1] == 0xff and ip[9] == 0x11";
	if (mtcp_bind_monitor_filter(mctx, rsock, &ft) == -1)
		return -1;
	if (mtcp_register_callback(mctx, rsock, MOS_ON_PKT_IN,
							MOS_NULL, cb_new_key) == -1)
		return -1;

	return 0;
}
/*---------------------------------------------------------------------------*/
static inline int
register_tls_callback(mctx_t mctx, int msock)
{
	union monitor_filter ft = {0};
	ft.stream_syn_filter = "tcp port 443";
	if (mtcp_bind_monitor_filter(mctx, msock, &ft) == -1)
		return -1;
	if (mtcp_register_callback(mctx, msock, MOS_ON_CONN_START,
							   MOS_HK_RCV, cb_tls_start) == -1)
		return -1;
	if (mtcp_register_callback(mctx, msock, MOS_ON_CONN_END,
							   MOS_HK_RCV, cb_tls_end) == -1)
		return -1;
	if (mtcp_register_callback(mctx, msock, MOS_ON_PKT_IN,
							   MOS_HK_RCV, cb_tls_pkt_in) == -1)
		return -1;
	if (mtcp_register_callback(mctx, msock, MOS_ON_ERROR,
							   MOS_NULL, cb_tls_buf_full) == -1)
		return -1;
	(void)cb_tls_buf_full;

	return 0;
}
/*---------------------------------------------------------------------------*/
int mmtls_init(const char *fname, int num_cpus)
{
	if (mtcp_init(fname) == -1)
		return -1;

	/* Register signal handler */
	if (mtcp_register_signal(SIGINT, sigint_handler) == SIG_ERR)
		return -1;

	/* set the core limit */
	if (mtcp_getconf(&g_mcfg) == -1)
		return -1;
	g_mcfg.num_cores = num_cpus;
	if (mtcp_setconf(&g_mcfg) == -1)
		return -1;
	g_mmtls = calloc(num_cpus, sizeof(struct mmtls_manager));
	if (!g_mmtls)
		return -1;
	
	return 0;
}
/*---------------------------------------------------------------------------*/
mmctx_t mmtls_create_context(int cpu)
{
	struct mmtls_manager *mmtls;
	int msock_raw, msock_tls;
	if (cpu >= g_mcfg.num_cores || cpu < 0)
		/* invalid number of cores */
		return NULL;
	mmtls = g_mmtls + cpu;
	if (!(mmtls->mmctx = (mmctx_t)calloc(1, sizeof(struct mmtls_context))))
		return NULL;
	mmtls->mmctx->cpu = cpu;

	/* Run mOS for each CPU core */
	if (!(mmtls->mctx = mtcp_create_context(cpu)))
		return NULL;
	
	if ((mmtls->ssl_ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}
    if ((mmtls->ssl = SSL_new(mmtls->ssl_ctx)) == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

	/* create CIPHER context */
	if (!(mmtls->evp_ctx = EVP_CIPHER_CTX_new()))
		return NULL;
		
	/* create mem pools */
	if (!(mmtls->ci_pool = MPCreate(sizeof(session),
					sizeof(session) * g_mcfg.max_concurrency, 0)))
		return NULL;
	if (!(mmtls->rawpkt_pool = MPCreate(MAX_BUF_LEN,
						MAX_BUF_LEN * g_mcfg.max_concurrency, 0)))
		return NULL;
#ifndef ZERO_COPY
	if (!(mmtls->cli_buffer_pool = MPCreate(MAX_BUF_LEN,
						MAX_BUF_LEN * g_mcfg.max_concurrency, 0)))
		return NULL;
	/* server side receive buffer is supposed to be much smaller */
	if (!(mmtls->svr_buffer_pool = MPCreate(MAX_BUF_LEN,
						MAX_BUF_LEN * g_mcfg.max_concurrency, 0)))
		return NULL;
#endif
	
	/* Make a raw packet monitoring socket */
	if ((msock_raw = mtcp_socket(mmtls->mctx, AF_INET,
								MOS_SOCK_MONITOR_RAW, 0)) == -1)
		return NULL;

	/* Register raw packet callback for key delivery */
	if (register_key_callback(mmtls->mctx, msock_raw) == -1)
		return NULL;

	/* Make a tls stream data monitoring socket */
	if ((msock_tls = mtcp_socket(mmtls->mctx, AF_INET,
								MOS_SOCK_MONITOR_STREAM, 0)) == -1)
		return NULL;

	/* Register stream data callback for TCP connections */
	if (register_tls_callback(mmtls->mctx, msock_tls) == -1)
		return NULL;

#ifdef CHECK_TCP_MONITORING
	int msock_stream;
	/* Make a tcp stream data monitoring socket */
	if ((msock_stream = mtcp_socket(mmtls->mctx, AF_INET,
									MOS_SOCK_MONITOR_STREAM, 0)) == -1)
		return NULL;

	/* Register stream data callback for TCP connections */
	if (register_tcp_callback(mmtls->mctx, msock_stream) == -1)
		return NULL;
#endif
	for (int i = 0; i < NUM_MMTLS_CALLBACK; i++)
		mmtls->cb[i] = NULL;
	
	return mmtls->mmctx;
}
/*---------------------------------------------------------------------------*/
int mmtls_destroy()
{
	for (int i = 0; i < g_mcfg.num_cores; i++) {
		/* free allocated memories */
#ifndef ZERO_COPY
		MPDestroy(g_mmtls[i].cli_buffer_pool);
		MPDestroy(g_mmtls[i].svr_buffer_pool);
#endif
		MPDestroy(g_mmtls[i].rawpkt_pool);
		MPDestroy(g_mmtls[i].ci_pool);
		SSL_free(g_mmtls[i].ssl);
		SSL_CTX_free(g_mmtls[i].ssl_ctx);
		/* free EVP context buffer */
		EVP_CIPHER_CTX_free(g_mmtls[i].evp_ctx);
		/* free mmtls context */
		free(g_mmtls[i].mmctx);
	}
	if (mtcp_destroy() == -1)
		return -1;

	return 0;
}
/*---------------------------------------------------------------------------*/
int mmtls_register_callback(mmctx_t mmctx, event_t event, mmtls_cb cb)
{
	struct mmtls_manager *mmtls;
	if (!mmctx)
		/* mmtls context is not created */
		return -1;
	if (mmctx->cpu > g_mcfg.num_cores || mmctx->cpu < 0)
		/* invalid number of cores */
		return -1;
	mmtls = g_mmtls + mmctx->cpu;
	if (event >= NUM_MMTLS_CALLBACK)
		return -1;
	mmtls->cb[event] = cb;

	return 0;
}
/*---------------------------------------------------------------------------*/
int mmtls_deregister_callback(mmctx_t mmctx, event_t event)
{
	return mmtls_register_callback(mmctx, event, NULL);
}
/*---------------------------------------------------------------------------*/
int mmtls_pause_monitor(mmctx_t mmctx, int cid, int side, int len)
{
	session *c;
	if (!(c = mtcp_get_uctx(g_mmtls[mmctx->cpu].mctx, cid)))
		return -1;
	c->stop_len[side] = len;
	
	return 0;
}
/*---------------------------------------------------------------------------*/
int mmtls_resume_monitor(mmctx_t mmctx, int cid, int side)
{
	session *c;
	if (!(c = mtcp_get_uctx(g_mmtls[mmctx->cpu].mctx, cid)))
		return -1;
	c->stop_len[side] = 0;

	return 0;
}
/*---------------------------------------------------------------------------*/
void mmtls_app_join(mmctx_t mmctx)
{
	mtcp_app_join(g_mmtls[mmctx->cpu].mctx);
}
/*---------------------------------------------------------------------------*/
int mmtls_get_record(mmctx_t mmctx, int cid, int side,
					 char *buf, int *len, uint8_t *type)
{
	session *c = NULL;
	session_ctx *tls_ctx;
	uint8_t *record; // record includes header
	int ret, retry_cnt = 0;
	uint16_t version;
	
	if (!len) {
		ret = WRONG_USAGE;
		goto Error;
	}
	if (!(c = mtcp_get_uctx(g_mmtls[mmctx->cpu].mctx, cid))) {
		ret = ORPHAN_ERR;
		goto Error;
	}
	version = c->sess_info.version;
	if ((version != TLS_1_2_VERSION) &&
		(version != TLS_1_3_VERSION)) {
		ret = INVALID_VERSION;
		goto Error;
	}
	if (!c->evp_cipher) {
		ret = INVALID_CIPHER_SUITE;
		goto Error;
	}
	tls_ctx = &c->sess_ctx[side];
#ifndef ZERO_COPY
	record = tls_ctx->buf + tls_ctx->head;
#else
	if (!tls_ctx->buf) {
		/* please call this function on ON_NEW_RECORD event */
		ret = WRONG_USAGE;
		goto Error;
	}
	record = tls_ctx->buf;
#endif
	if (!buf) {
		/*
		 * if application buffer is NULL,
		 * just gives length and type, and do not decrypt
		 */
		ret = plaintext_len(tls_ctx,
							c->evp_cipher, c->evp_md);
	}
	else {
		/* 
		 * if application buffer is given,
		 * decrypt to the buffer, and gives length and type
		 */
Retry:
		ret = get_plaintext(mmctx, tls_ctx,
							version, c->evp_cipher, c->evp_md,
							record, (uint8_t *)buf);
		if (ret < 0) {
			if (!c->svr_done && retry_cnt < 2) {
				tls_ctx->tls_seq++;
				retry_cnt++;
				goto Retry;
			}
			goto Error;
		}
	}
	*len = ret;
	if (type)
		*type = *record;
	
	return 0;

Error:
	/* on Error, length and type are returned as 0 */
	if (c)
		c->err_code = ret;
	*len = 0;
	if (type)
		*type = 0;

	return -1;
}
/*---------------------------------------------------------------------------*/
int mmtls_reset_conn(mmctx_t mmctx, int cid)
{
	session *c;
	if (!(c = mtcp_get_uctx(g_mmtls[mmctx->cpu].mctx, cid)))
		/* already finished connection */
		return 0;
	c->drop = 1;
	if (mtcp_setlastpkt(g_mmtls[mmctx->cpu].mctx, cid,
						MOS_SIDE_CLI, 0, NULL, 0, MOS_DROP) == -1)
		return -1;
	if (mtcp_setlastpkt(g_mmtls[mmctx->cpu].mctx, cid,
						MOS_SIDE_SVR, 0, NULL, 0, MOS_DROP) == -1)
		return -1;
	if (mtcp_reset_conn(g_mmtls[mmctx->cpu].mctx, cid) < 0)
		return -1;
	remove_conn_info(g_mmtls[mmctx->cpu].mctx, cid);

	return 0;
}
/*---------------------------------------------------------------------------*/
/* still in development */
int mmtls_offload_ctl(mmctx_t mmctx, int cid, int side, int cmd)
{
	session *c;
	void *flow;
	if (!(c = mtcp_get_uctx(g_mmtls[mmctx->cpu].mctx, cid)))
		return -1;
	if (cmd == OFFLOAD_BYPASS || cmd == OFFLOAD_DROP) {
		/* check whether already offloaded */
		// if (c->bypass || c->drop)
		// 	return 0;
		/* Otherwise, offload to e-switch */
		flow = mtcp_offload_flow(g_mmtls[mmctx->cpu].mctx, cid, side, cmd);
		if (!flow)
			return -1;
		c->offload_flow = flow;
		if (cmd == OFFLOAD_BYPASS)
			c->bypass = 1;
		else if (cmd == OFFLOAD_DROP)
			c->drop = 1;
	}
	if (cmd == ONLOAD) {
		/* check whether already onloaded */
		if (!c->bypass && !c->drop)
			return 0;
		/* Otherwise, onload to mOS */
		if (mtcp_onload_flow(g_mmtls[mmctx->cpu].mctx,
			cid, side, c->offload_flow) < 0)
			return -1;
		c->bypass = c->drop = 0;
	}

	return 0;
}
/*---------------------------------------------------------------------------*/
int mmtls_get_error(mmctx_t mmctx, int cid)
{
	session *c;
	if (!(c = mtcp_get_uctx(g_mmtls[mmctx->cpu].mctx, cid)))
		return -1;

	return c->err_code;
}
/*---------------------------------------------------------------------------*/
int mmtls_get_tls_info(mmctx_t mmctx, int cid,
					   session_info *info, uint16_t bitmask)
{
	session *c;
	if (!info)
		return -1;
	if (!(c = mtcp_get_uctx(g_mmtls[mmctx->cpu].mctx, cid)))
		return -1;
	if (bitmask & VERSION)
		info->version = c->sess_info.version;
	if (bitmask & CIPHER_SUITE)
		info->cipher_suite = c->sess_info.cipher_suite;
	// do we need to present it in sockaddr_in structure?
	if (bitmask & SOCK_ADDR) {
		info->cli_ip = c->sess_info.cli_ip;
		info->svr_ip = c->sess_info.svr_ip;
		info->cli_port = c->sess_info.cli_port;
		info->svr_port = c->sess_info.svr_port;
	}
	if (bitmask & SNI) {
		info->sni_type = c->sess_info.sni_type;
		info->sni_len = c->sess_info.sni_len;
		strcpy((char *)info->sni, (char *)c->sess_info.sni);
	}
	if (bitmask & CLIENT_RANDOM)
		memcpy(info->client_random, c->sess_info.client_random,
				TLS_CLIENT_RANDOM_LEN);
	if (bitmask & SERVER_RANDOM)
		memcpy(info->server_random, c->sess_info.server_random,
				TLS_SERVER_RANDOM_LEN);

	return 0;
}
/*---------------------------------------------------------------------------*/
int mmtls_set_uctx(mmctx_t mmctx, int cid, void *uctx)
{
	session *c;
	if (!(c = mtcp_get_uctx(g_mmtls[mmctx->cpu].mctx, cid)))
		return -1;
	c->uctx = uctx;

	return 0;
}
/*---------------------------------------------------------------------------*/
void *mmtls_get_uctx(mmctx_t mmctx, int cid)
{
	session *c;
	if (!(c = mtcp_get_uctx(g_mmtls[mmctx->cpu].mctx, cid)))
		return NULL;
		
	return c->uctx;
}
/*---------------------------------------------------------------------------*/
/* only used for evaluation */
int mmtls_get_stallcnt(mmctx_t mmctx, int cid)
{
	session *c;
	if (!(c = mtcp_get_uctx(g_mmtls[mmctx->cpu].mctx, cid)))
		return -1;

	return c->raw_cnt;
}
/*---------------------------------------------------------------------------*/
