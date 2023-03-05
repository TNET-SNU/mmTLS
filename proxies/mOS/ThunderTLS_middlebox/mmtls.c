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
#include "../util/include/rss.h"
#include "../core/src/include/memory_mgt.h"

/* Maximum CPU cores */
#define MAX_CPUS 16

/* Default path to mOS configuration file */
#define MOS_CONFIG_FILE "config/mos.conf"

#define IP_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define TCP_HEADER_LEN 20
#define TLS_HEADER_LEN 5

#define VERBOSE_TCP 1
#define VERBOSE_TLS 1
#define VERBOSE_KEY 1
#define VERBOSE_STALL 0
#define VERBOSE_DEBUG 0

/* Mode */
#define IPS 1
#define IDS (!IPS)
#define KEY_MAPPING 1
#define CNT_CONN 1
#define CNT_KEY 1
#define CORRECTNESS_CHECK 0
#define MAX_FILE_NAME_LEN	64
/*---------------------------------------------------------------------------*/
mmtls_cb OnTLSSessionStart = NULL;
mmtls_cb OnTLSSessionEnd = NULL;
mmtls_cb OnTLSHandshakeStart = NULL;
mmtls_cb OnTLSHandshakeEnd = NULL;
mmtls_cb OnNewTLSRecord = NULL;
mmtls_cb OnMalicious = NULL;
/*---------------------------------------------------------------------------*/
struct debug_cnt {
	int ins;
	int del;
	int shash;
	int chash;
	int key;
	int cr;
} g_cnt[MAX_CPUS] = {{0}};
mctx_t g_mctx[MAX_CPUS]; /* mOS context */
mem_pool_t g_ci_pool[MAX_CPUS] = {NULL};
mem_pool_t g_rawpkt_pool[MAX_CPUS] = {NULL};
mem_pool_t g_cli_cipher_pool[MAX_CPUS] = {NULL};
mem_pool_t g_svr_cipher_pool[MAX_CPUS] = {NULL};
/*---------------------------------------------------------------------------*/
/* EVP Cipher context for decryption */
EVP_CIPHER_CTX *g_evp_ctx[MAX_CPUS];
/* OpenSSL context to find IANA standard name */
SSL_CTX *g_ssl_ctx;
SSL *g_ssl;
/* miscellaneous */
int g_measure_delay = 0;
FILE *g_delay_fp;
/*---------------------------------------------------------------------------*/
/* Signal handler */
static void
sigint_handler(int signum)
{
	/* Terminate the program if any interrupt happens */
	for (int i = 0; i < MAX_CPUS; i++)
		mtcp_destroy_context(g_mctx[i]);
	exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
/* Dump bytestream in hexademical form */
static inline void
hexdump(char *title, uint8_t *buf, size_t len)
{
#if VERBOSE_TCP | VERBOSE_TLS | VERBOSE_KEY | VERBOSE_DEBUG | 1
	if (title)
		fprintf(stdout, "%s\n", title);
	for (size_t i = 0; i < len; i++)
		fprintf(stdout, "%02X%c", buf[i], ((i + 1) % 16 ? ' ' : '\n'));
		// fprintf(stdout, "%02X", buf[i]);
	fprintf(stdout, "\n");
#endif
}
/*---------------------------------------------------------------------------*/
/* Print AAD, TAG, and decrypted plain text */
static inline void
print_text(uint8_t *aad, int aad_len,
		   uint8_t *tag, int tag_len,
		   uint8_t *plain, int plain_len)
{
#if VERBOSE_DEBUG
	INFO_PRINT("\n--------------------------------------------------\n");
	if (aad)
		hexdump("[aad]", aad, aad_len);
	if (tag)
		hexdump("[tag]", tag, tag_len);
	fprintf(stdout, "plaintext_len: 0x%x\n", plain_len);
	if (cipher)
		hexdump("[plain text]", plain, plain_len);
#endif /* !VERBOSE_DEBUG */
}
/*---------------------------------------------------------------------------*/
static inline void
print_conn_stat(mctx_t mctx, conn_info *c)
{
	if (g_measure_delay)
		fprintf(g_delay_fp, "%lf\n",
			// (double)c->ci_clock_stall / CLOCKS_PER_SEC,
			// (double)c->ci_clock_resend / CLOCKS_PER_SEC,
			(double)c->ci_key_delay / CLOCKS_PER_SEC);
#if CNT_CONN
	struct debug_cnt sum = {0,};
	for (int i = 0; i < MAX_CPUS; i++) {
		sum.ins += g_cnt[i].ins;
		sum.del += g_cnt[i].del;
		sum.key += g_cnt[i].key;
	}
	fprintf(stdout,
			"\n--------------------------------------------------\n"
			"[CORE: %d]\n"
			"CLIENT: %lu B\n"
			"CLIENT peek: %lu B\n"
			"SERVER: %lu B\n"
			"SERVER peek: %lu B\n"
			"Record cnt: %lu\n"
			"Insert conn cnt: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n"
			"Total insert conn: %d\n"
			"Remove conn cnt: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n"
			"Total remove conn: %d\n"
			"key cnt: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n"
			"Total key: %d\n",
			mctx->cpu,
			c->ci_tls_ctx[MOS_SIDE_CLI].decrypt_len,
			c->ci_tls_ctx[MOS_SIDE_CLI].peek_len,
			c->ci_tls_ctx[MOS_SIDE_SVR].decrypt_len,
			c->ci_tls_ctx[MOS_SIDE_SVR].peek_len,
			c->ci_tls_ctx[MOS_SIDE_CLI].tc_tls_seq + 
			c->ci_tls_ctx[MOS_SIDE_SVR].tc_tls_seq,
			/* master core: num of keys */
			g_cnt[0].ins, g_cnt[1].ins, g_cnt[2].ins, g_cnt[3].ins,
			g_cnt[4].ins, g_cnt[5].ins, g_cnt[6].ins, g_cnt[7].ins,
			g_cnt[8].ins, g_cnt[9].ins, g_cnt[10].ins, g_cnt[11].ins,
			g_cnt[12].ins, g_cnt[13].ins, g_cnt[14].ins, g_cnt[15].ins,
			sum.ins,
			g_cnt[0].del, g_cnt[1].del, g_cnt[2].del, g_cnt[3].del,
			g_cnt[4].del, g_cnt[5].del, g_cnt[6].del, g_cnt[7].del,
			g_cnt[8].del, g_cnt[9].del, g_cnt[10].del, g_cnt[11].del,
			g_cnt[12].del, g_cnt[13].del, g_cnt[14].del, g_cnt[15].del,
			sum.del,
			g_cnt[0].key, g_cnt[1].key, g_cnt[2].key, g_cnt[3].key,
			g_cnt[4].key, g_cnt[5].key, g_cnt[6].key, g_cnt[7].key,
			g_cnt[8].key, g_cnt[9].key, g_cnt[10].key, g_cnt[11].key,
			g_cnt[12].key, g_cnt[13].key, g_cnt[14].key, g_cnt[15].key,
			sum.key);
#endif
	// if (c->ci_tls_ctx[MOS_SIDE_CLI].decrypt_len == 0)
	// 	EXIT_WITH_ERROR("decrypt_len = 0");
}
/*---------------------------------------------------------------------------*/
/* Create connection structure for new connection */
static inline conn_info *
create_conn_info(mctx_t mctx, int sock)
{
	conn_info *c;
	/* already created */
	if ((c = mtcp_get_uctx(mctx, sock)))
		return c;
	if (!(c = (conn_info *)MPAllocateChunk(g_ci_pool[mctx->cpu])))
		EXIT_WITH_ERROR("conn info pool alloc failed");
	/* MPAlloc needs memset */
	memset(c, 0, sizeof(conn_info));
	if (!(c->ci_tls_ctx[MOS_SIDE_CLI].tc_cipher.buf = 
		MPAllocateChunk(g_cli_cipher_pool[mctx->cpu])))
		EXIT_WITH_ERROR("record pool alloc failed");
	if (!(c->ci_tls_ctx[MOS_SIDE_SVR].tc_cipher.buf = 
		MPAllocateChunk(g_svr_cipher_pool[mctx->cpu])))
		EXIT_WITH_ERROR("record pool alloc failed");
	/* Insert the structure to the queue */
	mtcp_set_uctx(mctx, sock, c);
	if (OnTLSSessionStart) {
		OnTLSSessionStart(mctx->cpu, sock, MOS_SIDE_CLI);
		OnTLSSessionStart(mctx->cpu, sock, MOS_SIDE_SVR);
	}

#if CNT_CONN
	g_cnt[mctx->cpu].ins++;
#endif
	return c;
}
/*---------------------------------------------------------------------------*/
/* remove connection structure
 * in IDS, if some ciphers are pending as undecrypted, postpone destroy
 */
static inline void
remove_conn_info(mctx_t mctx, int sock)
{
	conn_info *c;
	/* already removed */
	if (!(c = mtcp_get_uctx(mctx, sock)))
		return;
#if IDS
	if (!c->ci_has_key) {
		c->ci_tls_state = TO_BE_DESTROYED;
		return;
	}
#endif
	if (c->ci_tls_ctx[MOS_SIDE_CLI].tc_cipher.buf)
		MPFreeChunk(g_cli_cipher_pool[mctx->cpu],
					c->ci_tls_ctx[MOS_SIDE_CLI].tc_cipher.buf);
	if (c->ci_tls_ctx[MOS_SIDE_SVR].tc_cipher.buf)
		MPFreeChunk(g_svr_cipher_pool[mctx->cpu],
					c->ci_tls_ctx[MOS_SIDE_SVR].tc_cipher.buf);
	MPFreeChunk(g_ci_pool[mctx->cpu], c);

	if (OnTLSSessionEnd) {
		OnTLSSessionEnd(mctx->cpu, sock, MOS_SIDE_CLI);
		OnTLSSessionEnd(mctx->cpu, sock, MOS_SIDE_SVR);
	}

#if CNT_CONN
	g_cnt[mctx->cpu].del++;
#endif
	print_conn_stat(mctx, c);
}
/*---------------------------------------------------------------------------*/
static inline void
handle_malicious(mctx_t mctx, int sock, int side, int code)
{
	WARNING_PRINT("[core %d] malicious code: %d", mctx->cpu, code);
	if (mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP) == -1)
		EXIT_WITH_ERROR("mtcp_setlastpkt failed");
	if (mtcp_reset_conn(mctx, sock) < 0)
		EXIT_WITH_ERROR("mtcp_reset_conn failed");
	remove_conn_info(mctx, sock);
}
/*---------------------------------------------------------------------------*/
/* Decrypt single TLS record with given key_info */
/* Return length of decrypted data, -1 of error */
static int
decrypt_tls_12_cbc(EVP_CIPHER_CTX *evp_ctx,
				   const EVP_CIPHER *evp_cipher,
				   const EVP_MD *evp_md,
				   uint8_t *data, uint8_t *plain,
				   uint8_t *key_info, uint64_t tls_seq,
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
	print_text(NULL, 0, tag, tag_len, plain, len);

	// printf("success to decrypt one record!\n");
	return len;
}
/*---------------------------------------------------------------------------*/
static int
decrypt_tls_12_gcm(EVP_CIPHER_CTX *evp_ctx,
				   const EVP_CIPHER *evp_cipher,
				   const EVP_MD *evp_md,
				   uint8_t *data, uint8_t *plain,
				   uint8_t *key_info, uint64_t tls_seq,
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
	if (!EVP_DecryptUpdate(evp_ctx, NULL, &len, aad, EVP_AEAD_TLS1_AAD_LEN))
		return DECRYPT_ERR;
	if ((len = EVP_Cipher(evp_ctx, plain, cipher, cipher_len)) <= 0)
		return DECRYPT_ERR;
	
	/* check tag */
	if (!EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
		return INTEGRITY_ERR;
	if (EVP_DecryptFinal(evp_ctx, tag, &flen) <= 0)
		return INTEGRITY_ERR;
	len += flen;

	/* print value and results */
	assert(cipher_len == len);
	print_text(aad, EVP_AEAD_TLS1_AAD_LEN, tag, tag_len, plain, len);

	return len;
}
/*---------------------------------------------------------------------------*/
/* Decrypt single TLS record with given key_info */
/* Return length of decrypted data, -1 of error */
static int
decrypt_tls_13_gcm(EVP_CIPHER_CTX *evp_ctx,
				   const EVP_CIPHER *evp_cipher,
				   const EVP_MD *evp_md,
				   uint8_t *data, uint8_t *plain,
				   uint8_t *key_info, uint64_t tls_seq,
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
	if (!EVP_DecryptUpdate(evp_ctx, NULL, &len, aad, TLS_HEADER_LEN))
		return DECRYPT_ERR;
	if ((len = EVP_Cipher(evp_ctx, plain, cipher, cipher_len)) <= 0)
		return DECRYPT_ERR;

	/* check tag */
	if (!EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
		return INTEGRITY_ERR;
	if (EVP_DecryptFinal(evp_ctx, tag, &flen) <= 0)
		return INTEGRITY_ERR;
	len += flen;
	assert(cipher_len == len);

	/* print value and results */
	print_text(aad, TLS_HEADER_LEN, tag, tag_len, plain, len);

	/* TLS1.3 has diguised record type at the end of plaintext */
	if (*(plain + len - 1) != APPLICATION_DATA)
		return 0;

	return len - 1;
}
/*---------------------------------------------------------------------------*/
/* Decrypt single TLS record with given key_info */
/* Return length of decrypted data, -1 of error */
static inline int
decrypt_tls(EVP_CIPHER_CTX *evp_ctx,
			const EVP_CIPHER *evp_cipher,
			const EVP_MD *evp_md,
			uint16_t tls_version,
			uint8_t *data, uint8_t *plain,
			uint8_t *key_info, uint64_t tls_seq,
			uint16_t cipher_len)
{
	/* gcm */
	if (EVP_CIPHER_get_flags(evp_cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
		if (tls_version == TLS_1_3_VERSION)
			return decrypt_tls_13_gcm(evp_ctx, evp_cipher, evp_md,
									  data, plain, key_info, tls_seq, cipher_len);
		else if (tls_version == TLS_1_2_VERSION)
			return decrypt_tls_12_gcm(evp_ctx, evp_cipher, evp_md,
									  data, plain, key_info, tls_seq, cipher_len);
	}
	/* CBC */
	else
		return decrypt_tls_12_cbc(evp_ctx, evp_cipher, evp_md,
								  data, plain, key_info, tls_seq, cipher_len);

	return NOT_SUPPORTED;
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
	*version = be16toh(*(uint16_t *)ptr);
	ptr += sizeof(uint16_t);
	*cipher_suite = be16toh(*(uint16_t *)ptr);
	ptr += sizeof(uint16_t);
	info_size = be16toh(*(uint16_t *)ptr);
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
static inline int
parse_tls_record(tls_buffer *cipher, uint8_t *record_type)
{
	uint8_t *ptr;
	int record_len;

	/* Parse header of new record */
	if (cipher->chead + TLS_HEADER_LEN > cipher->ctail)
		return 0; // TLS header is incomplete

	ptr = cipher->buf + cipher->chead;
	*record_type = *ptr;
	record_len = be16toh(*(uint16_t *)(ptr + 3));
	if (cipher->chead + record_len + TLS_HEADER_LEN > cipher->ctail)
		return 0; // TLS record is incomplete

#if VERBOSE_TLS
	fprintf(stdout,
			"\n--------------------------------------------------\n"
			"[%s] Parse new record to follow session\n"
			"Record type %x\n"
			"length %u (TCP %u ~ %u)\n"
			"cipher len %u\n",
			__FUNCTION__, *record_type, record_len + TLS_HEADER_LEN, cipher->chead,
			cipher->chead + record_len + TLS_HEADER_LEN, record_len);
	hexdump("Dump of ciphertext of the record:", ptr, record_len + TLS_HEADER_LEN);
#endif /* VERBOSE_TLS */

	return record_len;
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
static inline bool
update_conn_info(mctx_t mctx, int sock, int side, conn_info *c,
				 uint8_t record_type, int record_len, uint8_t *record)
{
	const char *IANA_cipher_name;
	const SSL_CIPHER *ssl_cipher;
	uint8_t *cipher_suite;
	uint16_t total_ex_len, ex_type, ex_len, ex_val;

	if (record_type == HANDSHAKE) {
		record += TLS_HEADER_LEN;
		if (*record == CLIENT_HS) {
			if ((side != MOS_SIDE_SVR) || (c->ci_tls_state != INITIAL_STATE))
				return NO_DECRYPT;

			c->ci_tls_state = RECV_CH;
			/* TLS HS header */
			record += TLS_HANDSHAKE_HEADER_LEN;
			/* protocol version */
			record += sizeof(uint16_t);
			if (OnTLSHandshakeStart)
				OnTLSHandshakeStart(mctx->cpu, sock, side);

			return NO_DECRYPT;
		}
		/* if someone wants to monitor tls stack, we can provide below */
		else if (*record == SERVER_HS) {
			if ((side != MOS_SIDE_CLI) || (c->ci_tls_state != RECV_CH))
				return NO_DECRYPT;

			c->ci_tls_state = RECV_SH;
			/* TLS HS header */
			record += TLS_HANDSHAKE_HEADER_LEN;
			/* protocol version */
			c->ci_tls_version = be16toh(*(uint16_t *)record);
			record += sizeof(uint16_t);
			/* TLS1.3 server random */
			record += TLS_SERVER_RANDOM_LEN;
			/* pass session id (one byte len field) */
			record += 1 + *record;
			/* cipher suite */
			cipher_suite = record;
			c->ci_cipher_suite = be16toh(*(uint16_t *)record);
			record += sizeof(uint16_t);
			/* compression method */
			record++;
			/* total extension length */
			total_ex_len = be16toh(*(uint16_t *)record);
			record += sizeof(uint16_t);
			/* find protocol extension */
			while (total_ex_len > 0) {
				ex_type = be16toh(*(uint16_t *)record);
				ex_len = be16toh(*((uint16_t *)record + 1));
				if ((ex_type == TLSEXT_TYPE_supported_versions) &&
					(ex_len == sizeof(uint16_t))) {
					ex_val = be16toh(*((uint16_t *)record + 2));
					if (ex_val == TLS_1_3_VERSION) {
						c->ci_tls_version = TLS_1_3_VERSION;
						break;
					}
				}
				else {
					record += 2 * sizeof(uint16_t) + ex_len;
					total_ex_len -= 2 * sizeof(uint16_t) + ex_len;
				}
			}
			goto Select_cipher;
		}
		// else if (*record == SERVER_HS_FINISHED) {
		// 	/* in TLS1.2, HS FINISHED from server is the end of HS */
		// 	/* and this is not to be decrypted */
		// 	if ((side == MOS_SIDE_CLI) &&
		// 		(c->ci_tls_state == RECV_SH))
		// 		c->ci_tls_state = TLS_ESTABLISHED;
		// }
	}
	else if (record_type == APPLICATION_DATA) {
		if (c->ci_tls_state >= TLS_ESTABLISHED)
			return DO_DECRYPT;
		if (c->ci_tls_state == RECV_SH) {
			/* TLS1.3 */
			if (c->ci_tls_version == TLS_1_3_VERSION) {
				/* check handshake done from client */
				if ((side == MOS_SIDE_SVR) &&
					(record_len == (TLS_HANDSHAKE_HEADER_LEN + 
									EVP_MD_size(c->ci_evp_md) + 
									EVP_GCM_TLS_TAG_LEN + 
									TLS_RECORD_TYPE_LEN))) {

					c->ci_tls_state = TLS_ESTABLISHED;

					if (OnTLSHandshakeEnd)
						OnTLSHandshakeEnd(mctx->cpu, sock, side);
				}
			}
			/* TLS1.2 */
			else if (c->ci_tls_version == TLS_1_2_VERSION) {
				c->ci_tls_state = TLS_ESTABLISHED;
				return DO_DECRYPT;
			}
			else
				EXIT_WITH_ERROR("Not supported TLS version");
		}
	}

	return NO_DECRYPT;

Select_cipher:
	if (!(ssl_cipher = SSL_CIPHER_find(g_ssl, cipher_suite)))
		EXIT_WITH_ERROR("Not supported cipher suite");
	if (!(IANA_cipher_name = SSL_CIPHER_standard_name(ssl_cipher)))
		EXIT_WITH_ERROR("Not supported cipher suite");
	if (strstr(IANA_cipher_name, "_GCM_")) {
		if (strstr(IANA_cipher_name, "AES_256")) {
			c->ci_evp_cipher = EVP_aes_256_gcm();
			c->ci_evp_md = EVP_sha384();
		}
		else if (strstr(IANA_cipher_name, "AES_128")) {
			c->ci_evp_cipher = EVP_aes_128_gcm();
			c->ci_evp_md = EVP_sha256();
		}
		else
			EXIT_WITH_ERROR("Not supported cipher suite");
	}
	else if (strstr(IANA_cipher_name, "_CBC_")) {
		if (strstr(IANA_cipher_name, "AES_128_CBC_SHA256")) {
			c->ci_evp_cipher = EVP_aes_128_cbc();
			c->ci_evp_md = EVP_sha256();
		}
		else if (strstr(IANA_cipher_name, "AES_256_CBC_SHA256")) {
			c->ci_evp_cipher = EVP_aes_256_cbc();
			c->ci_evp_md = EVP_sha256();
		}
		else
			EXIT_WITH_ERROR("Not supported cipher suite");
	}
	else
		EXIT_WITH_ERROR("Not supported cipher suite");

	return NO_DECRYPT;
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
process_data(mctx_t mctx, int sock, int side, conn_info *c, tls_buffer *tb)
{
	tls_context *ctx = &c->ci_tls_ctx[side];
	int parse_len; /* TLS header not included */
	int decrypt_len;
	uint8_t record_type;

	/* decrypt complete records */
	while ((parse_len = parse_tls_record(tb, &record_type)) > 0) {
		if (update_conn_info(mctx, sock, side, c,
							 record_type, parse_len, tb->buf + tb->chead)) {
			if (!c->ci_has_key)
				return NO_KEY;
			if (c->ci_mon_state == RUN_MON)
				/* 1. use below when decrypt on */
				decrypt_len = decrypt_tls(g_evp_ctx[mctx->cpu],
										c->ci_evp_cipher,
										c->ci_evp_md,
										c->ci_tls_version,
										tb->buf + tb->chead,
										tb->buf + tb->phead,
										ctx->tc_key_info,
										ctx->tc_tls_seq,
										parse_len);
			else if (c->ci_mon_state == STOP_MON)
				/* 2. use below when decrypt off */
				decrypt_len = (parse_len > EVP_GCM_TLS_TAG_LEN + 1)?
							  (parse_len - EVP_GCM_TLS_TAG_LEN - 1):0;
			else
				decrypt_len = 0;
			ctx->tc_tls_seq++;
			if (decrypt_len < 0)
				return decrypt_len;
			tb->ptail += decrypt_len;
			c->ci_tls_ctx[side].decrypt_len += decrypt_len; // for debugging
			
			if (OnNewTLSRecord)
				OnNewTLSRecord(mctx->cpu, sock, side);

			tb->ptail = 0;
		}
		/* move to next record */
		tb->chead += TLS_HEADER_LEN + parse_len;
	}

	return 1;
}
/*---------------------------------------------------------------------------*/
/* Allocate new chunk from raw packet mempool for raw packet buffer
 * Copy the last raw packet to raw packet buffer
 */
static inline int
copy_lastpkt(mctx_t mctx, int sock, int side, conn_info *c)
{
	pkt_vec *rp = c->ci_raw_pkt + c->ci_raw_cnt;
	if (!rp->data) {
		if (!(rp->data = MPAllocateChunk(g_rawpkt_pool[mctx->cpu])))
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
	c->ci_raw_len += rp->len;
	c->ci_raw_cnt++;
	if ((c->ci_raw_cnt == MAX_RAW_PKT_NUM) ||
		(c->ci_raw_len > MAX_BUF_LEN)) {
		MPFreeChunk(g_rawpkt_pool[mctx->cpu], rp->data);
		c->ci_raw_cnt = c->ci_raw_len = 0;
		return MISSING_KEY;
	}
	(rp + 1)->data = rp->data + rp->len;
	return 1;
}
/*----------------------------------------------------------------------------*/
static inline int
stall_lastpkt(mctx_t mctx, int sock, int side, conn_info *c)
{
	if (g_measure_delay && (c->ci_clock_stall == 0))
		c->ci_clock_stall = clock();
	if (copy_lastpkt(mctx, sock, side, c) == MISSING_KEY) {
		WARNING_PRINT("[core %d] key missing", mctx->cpu);
		return MISSING_KEY;
	}
	if (mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP) == -1)
		EXIT_WITH_ERROR("drop failed");
	return 1;
}
/*---------------------------------------------------------------------------*/
/* Send copied raw packets
 * After send, free mempool
 */
static inline void
resend_lastpkts(mctx_t mctx, int sock, conn_info *c)
{
	pkt_vec *rp = c->ci_raw_pkt;
	if (c->ci_raw_cnt == 0)
		return;
	while (rp < c->ci_raw_pkt + c->ci_raw_cnt) {
		if (!rp->data)
			printf("null packet!\n");
		if (mtcp_sendpkt_raw(mctx, sock, rp->data, rp->len) < 0) {
			WARNING_PRINT("[core %d] failed to send stalled packets", mctx->cpu);
			break;
		}
		rp++;
	}
#if VERBOSE_STALL
	fprintf(stdout,
			"\n--------------------------------------------------\n"
			"[%s] core: %d, sock: %u\nsent %d stalled pkts\n",
			__FUNCTION__, mctx->cpu, c->ci_sock, c->ci_raw_cnt);
#endif
	assert(c->ci_raw_pkt->data);
	MPFreeChunk(g_rawpkt_pool[mctx->cpu], c->ci_raw_pkt->data);
	c->ci_raw_cnt = c->ci_raw_len = 0;
}
/*----------------------------------------------------------------------------*/
/* Called when received new packet from monitoring stream socket (sock, side) */
static inline void
peek_and_process(mctx_t mctx, int sock, int side, conn_info *c)
{
	tls_buffer *tb;
	int len, ret;
	while (true) {
		tb = &c->ci_tls_ctx[side].tc_cipher;
		if ((len = mtcp_peek(mctx, sock, side, (char *)tb->buf + tb->ctail,
							MAX_BUF_LEN - tb->ctail)) <= 0) {
			return;
		}
		tb->ctail += len;
		c->ci_tls_ctx[side].peek_len += len; /* for debugging */
		if ((ret = process_data(mctx, sock, side, c, tb)) < 0) {
			if (OnMalicious) {
				c->ci_err_code = ret;
				OnMalicious(mctx->cpu, sock, side);
			}
			else
				handle_malicious(mctx, sock, side, ret);
			return;
		}
		if (ret == NO_KEY)
			if (stall_lastpkt(mctx, sock, side, c) == MISSING_KEY) {
				if (OnMalicious) {
					c->ci_err_code = MISSING_KEY;
					OnMalicious(mctx->cpu, sock, side);
				}
				else
					handle_malicious(mctx, sock, side, MISSING_KEY);
				return;
			}
		/* if cipher is full, move buffer to left by head offset and re-peek */
		if (tb->ctail == MAX_BUF_LEN) {
			// printf("cipher full\n");
			memcpy(tb->buf, tb->buf + tb->chead, MAX_BUF_LEN - tb->chead);
			tb->ctail -= tb->chead;
			tb->chead = 0;
		}
		else
			break;
	}
#if VERBOSE_TCP
	hexdump(NULL, tb->buf + tb->chead, len);
#endif
}
/*----------------------------------------------------------------------------*/
/* Called when received new packet from monitoring stream socket (sock, side) */
static void
cb_pkt_in(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	conn_info *c;
	if (!(c = mtcp_get_uctx(mctx, sock)))
		/* retransmitted packet in removed conn */
		return;
	if ((!c->ci_has_key) && (c->ci_tls_state == TLS_ESTABLISHED))
		if (stall_lastpkt(mctx, sock, side, c) == MISSING_KEY) {
			if (OnMalicious) {
				c->ci_err_code = MISSING_KEY;
				OnMalicious(mctx->cpu, sock, side);
			}
			handle_malicious(mctx, sock, side, MISSING_KEY);
			return;
		}
	peek_and_process(mctx, sock, side, c);
}
/*----------------------------------------------------------------------------*/
/* Called when received new packet from monitoring stream socket (sock, side) */
static void
cb_conn_on_new_data(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	conn_info *c;
	if (!(c = mtcp_get_uctx(mctx, sock)))
		/* retransmitted packet in removed conn */
		return;
	peek_and_process(mctx, sock, side, c);
}
/*----------------------------------------------------------------------------*/
/* Destroy connection structure */
static void
cb_conn_end(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	remove_conn_info(mctx, sock);
}
/*---------------------------------------------------------------------------*/
/* This function is called when endpoints' rb is larger than mOS rb */
static void
cb_buf_full(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	conn_info *c;
	if (!(c = mtcp_get_uctx(mctx, sock)))
		/* retransmitted packet in removed conn */
		return;

	/* if recv buffer is full, drop last packet */
	if (mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP) == -1)
		EXIT_WITH_ERROR("drop failed");

	/* resize buffer ~ 1MB */
	/* we currently do not use below */
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

	peek_and_process(mctx, sock, side, c);
}
/*----------------------------------------------------------------------------*/
/* Create connection structure */
static void
cb_conn_start(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	create_conn_info(mctx, sock);
}
/*---------------------------------------------------------------------------*/
/* Called when received new raw packet from raw monitoring socket (rsock) */
static void
cb_new_key(mctx_t mctx, int rsock, int side, uint64_t events, filter_arg_t *arg)
{
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
	int sock;
	conn_info *c;
	struct session_address addr = (struct session_address) {
		ntohl(pctx->p.iph->saddr),
		ntohl(pctx->p.iph->daddr),
		ntohs(*(uint16_t *)udph),
		ntohs(*((uint16_t *)udph + 1))
	};
	if ((sock = mtcp_addrtosock(mctx, (session_address_t)&addr)) == -1) {
		WARNING_PRINT("[core %d] orphan key received", mctx->cpu);
		return;
	}
	c = create_conn_info(mctx, sock);
#if CNT_KEY
	g_cnt[mctx->cpu].key++;
	printf("key found: %d\n",
			g_cnt[0].key + g_cnt[1].key + g_cnt[2].key + g_cnt[3].key + 
			g_cnt[4].key + g_cnt[5].key + g_cnt[6].key + g_cnt[7].key + 
			g_cnt[8].key + g_cnt[9].key + g_cnt[10].key + g_cnt[11].key + 
			g_cnt[12].key + g_cnt[13].key + g_cnt[14].key + g_cnt[15].key);
#endif
	parse_tls_key(payload + TLS_CLIENT_RANDOM_LEN,
				&c->ci_tls_version,
				&c->ci_cipher_suite,
				c->ci_tls_ctx[MOS_SIDE_SVR].tc_key_info,
				c->ci_tls_ctx[MOS_SIDE_CLI].tc_key_info);
	c->ci_has_key = 1;
	// if (mtcp_register_callback(mctx, sock, MOS_ON_CONN_NEW_DATA,
	// 						   MOS_NULL, cb_conn_on_new_data) == -1)
	// 	EXIT_WITH_ERROR("Failed to register cb_conn_on_new_data() on MOS_ON_CONN_NEW_DATA");
	/* it did not work */
	// if (mtcp_unregister_callback(mctx, sock, MOS_ON_PKT_IN,
	// 							 MOS_HK_RCV) == -1)
	// 	EXIT_WITH_ERROR("Failed to unregister cb_pkt_in() on MOS_ON_PKT_IN");
	(void)cb_conn_on_new_data;
	if (g_measure_delay && (c->ci_clock_stall)) {
		c->ci_clock_resend = clock();
		c->ci_key_delay = c->ci_clock_resend - c->ci_clock_stall;
	}
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
register_data_callback(mctx_t mctx, int msock)
{
	if (mtcp_register_callback(mctx, msock, MOS_ON_CONN_START,
							   MOS_HK_RCV, cb_conn_start) == -1)
		return -1;
	if (mtcp_register_callback(mctx, msock, MOS_ON_CONN_END,
							   MOS_HK_RCV, cb_conn_end) == -1)
		return -1;
	if (mtcp_register_callback(mctx, msock, MOS_ON_PKT_IN,
							   MOS_HK_RCV, cb_pkt_in) == -1)
		return -1;
	if (mtcp_register_callback(mctx, msock, MOS_ON_ERROR,
							   MOS_NULL, cb_buf_full) == -1)
		return -1;
	return 0;
}
/*---------------------------------------------------------------------------*/
int mmtls_init(const char *fname, int num_cpus)
{
	struct mtcp_conf mcfg;
	int i;
	if (mtcp_init(fname) == -1)
		return -1;

	/* Register signal handler */
	if (mtcp_register_signal(SIGINT, sigint_handler) == SIG_ERR)
		return -1;

	if ((g_ssl_ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
    if ((g_ssl = SSL_new(g_ssl_ctx)) == NULL) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

	/* set the core limit */
	if (mtcp_getconf(&mcfg) == -1)
		return -1;
	mcfg.num_cores = num_cpus;
	if (mtcp_setconf(&mcfg) == -1)
		return -1;

	for (i = 0; i < num_cpus; i++) {
		/* create mem pools */
		if (!(g_ci_pool[i] = MPCreate(sizeof(conn_info),
						sizeof(conn_info) * mcfg.max_concurrency, 0)))
			return -1;
		if (!(g_rawpkt_pool[i] = MPCreate(MAX_BUF_LEN,
							MAX_BUF_LEN * mcfg.max_concurrency, 0)))
			return -1;
		if (!(g_cli_cipher_pool[i] = MPCreate(MAX_BUF_LEN,
							MAX_BUF_LEN * mcfg.max_concurrency, 0)))
			return -1;
		/* server side receive buffer is supposed to be much smaller */
		if (!(g_svr_cipher_pool[i] = MPCreate(MAX_BUF_LEN,
							MAX_BUF_LEN * mcfg.max_concurrency, 0)))
			return -1;
	}
	
	return 0;
}
/*---------------------------------------------------------------------------*/
mmtls_t mmtls_create_context(int cpu)
{
	int msock_raw, msock_stream;
	mmtls_t mmtls_ctx = calloc(1, sizeof(struct mmtls_context));

	mmtls_ctx->cpu = cpu;
	// mmtls_ctx->OnNewTLSRecord = NULL;
	// mmtls_ctx->OnTLSHandshakeEnd = NULL;
	// mmtls_ctx->OnTLSHandshakeStart = NULL;
	// mmtls_ctx->OnTLSSessionEnd = NULL;
	// mmtls_ctx->OnTLSSessionStart = NULL;

	/* Run mOS for each CPU core */
	if (!(g_mctx[cpu] = mtcp_create_context(cpu)))
		return NULL;

	/* create CIPHER context */
	if (!(g_evp_ctx[cpu] = EVP_CIPHER_CTX_new()))
		return NULL;
	
	/* Make a raw packet monitoring socket */
	if ((msock_raw = mtcp_socket(g_mctx[cpu], AF_INET,
								MOS_SOCK_MONITOR_RAW, 0)) == -1)
		return NULL;

	/* Register raw packet callback for key delivery */
	if (register_key_callback(g_mctx[cpu], msock_raw) == -1)
		return NULL;

	/* Make a stream data monitoring socket */
	if ((msock_stream = mtcp_socket(g_mctx[cpu], AF_INET,
									MOS_SOCK_MONITOR_STREAM, 0)) == -1)
		return NULL;

	/* Register stream data callback for TCP connections */
	if (register_data_callback(g_mctx[cpu], msock_stream) == -1)
		return NULL;
	
	return mmtls_ctx;
}
/*---------------------------------------------------------------------------*/
int mmtls_destroy()
{
	SSL_free(g_ssl);
	SSL_CTX_free(g_ssl_ctx);
	if (mtcp_destroy() == -1)
		return -1;
	return 0;
}
/*---------------------------------------------------------------------------*/
int mmtls_register_callback(mmtls_t mmtls, event_t event, mmtls_cb cb)
{
	if (event == ON_TLS_SESSION_START)
		OnTLSSessionStart = cb;
	else if (event == ON_TLS_SESSION_END)
		OnTLSSessionEnd = cb;
	else if (event == ON_TLS_HANDSHAKE_START)
		OnTLSHandshakeStart = cb;
	else if (event == ON_TLS_HANDSHAKE_END)
		OnTLSHandshakeEnd = cb;
	else if (event == ON_NEW_TLS_RECORD)
		OnNewTLSRecord = cb;
	else
		return -1;
	return 0;
}
/*---------------------------------------------------------------------------*/
void mmtls_app_join(int i)
{
	mtcp_app_join(g_mctx[i]);
	/* free allocated memories */
	MPDestroy(g_cli_cipher_pool[i]);
	MPDestroy(g_svr_cipher_pool[i]);
	MPDestroy(g_rawpkt_pool[i]);
	MPDestroy(g_ci_pool[i]);
	/* free EVP context buffer */
	EVP_CIPHER_CTX_free(g_evp_ctx[i]);
}
/*---------------------------------------------------------------------------*/
int mmtls_get_record(mmtls_t mmctx, int cid, int side, uint8_t *buf)
{
	conn_info *c;
	if (!(c = mtcp_get_uctx(g_mctx[mmctx->cpu], cid)))
		return -1;
	tls_buffer *tb = &c->ci_tls_ctx[side].tc_cipher;
	if (!tb->ptail)
		return -1; // please call me OnNewTLSRecord
	if (c->ci_mon_state != RUN_MON)
		return -1;
	memcpy(buf, tb->buf + tb->phead, tb->ptail - tb->phead);
	return tb->ptail - tb->phead;
}
/*---------------------------------------------------------------------------*/
int mmtls_get_err(mmtls_t mmctx, int cid, int side)
{
	conn_info *c;
	if (!(c = mtcp_get_uctx(g_mctx[mmctx->cpu], cid)))
		return -1;
	return c->ci_err_code;
}
/*---------------------------------------------------------------------------*/
void mmtls_drop_packet(mmtls_t mmctx, int cid, int side)
{
	if (mtcp_setlastpkt(g_mctx[mmctx->cpu], cid, side, 0, NULL, 0, MOS_DROP) == -1)
		EXIT_WITH_ERROR("mtcp_setlastpkt failed");
}
/*---------------------------------------------------------------------------*/
void mmtls_reset_conn(mmtls_t mmctx, int cid, int side)
{
	if (mtcp_reset_conn(g_mctx[mmctx->cpu], cid) < 0)
		EXIT_WITH_ERROR("mtcp_reset_conn failed");
	remove_conn_info(g_mctx[mmctx->cpu], cid);
}
/*---------------------------------------------------------------------------*/
uint16_t mmtls_get_version(mmtls_t mmctx, int cid, int side)
{
	conn_info *c;
	if (!(c = mtcp_get_uctx(g_mctx[mmctx->cpu], cid)))
		return 0;
	return c->ci_tls_version;
}
/*---------------------------------------------------------------------------*/
uint16_t mmtls_get_cipher(mmtls_t mmctx, int cid, int side)
{
	conn_info *c;
	if (!(c = mtcp_get_uctx(g_mctx[mmctx->cpu], cid)))
		return 0;
	return c->ci_cipher_suite;
}
/*---------------------------------------------------------------------------*/
int mmtls_set_monopt(mmtls_t mmctx, int cid, int side, int opt)
{
	conn_info *c;
	if (!(c = mtcp_get_uctx(g_mctx[mmctx->cpu], cid)))
		return -1;
	c->ci_mon_state = opt;
	return 0;
}
/*---------------------------------------------------------------------------*/
