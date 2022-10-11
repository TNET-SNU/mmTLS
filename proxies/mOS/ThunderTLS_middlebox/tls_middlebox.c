#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <asm/byteorder.h>
#include <assert.h>
#include <signal.h>
#include <sys/queue.h>
#include <errno.h>
#include <endian.h>
#include <mos_api.h>
#include <openssl/evp.h>
#include "cpu.h"
#include "include/thash.h"
#include "../util/include/rss.h"
#include "../core/src/include/memory_mgt.h"

/* Maximum CPU cores */
#define MAX_CORES 32
#define LEADER_CORE	0

/* Default path to mOS configuration file */
#define MOS_CONFIG_FILE "config/mos.conf"

#define IP_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define TCP_HEADER_LEN 20
#define TLS_HEADER_LEN 5

#define VERBOSE_TCP 0
#define VERBOSE_TLS 0
#define VERBOSE_KEY 0
#define VERBOSE_STALL 0
#define VERBOSE_DEBUG 0
#define DESTROY_CHECK 0

#define EXIT_WITH_ERROR(fmt, args...) { \
	ERROR_PRINT(fmt, ##args); \
	exit(EXIT_FAILURE); \
}

/* Mode */
#define IPS 1
#define IDS (!IPS)
/*----------------------------------------------------------------------------*/
/* Core */
int g_max_cores;		  /* Number of CPU cores to be used */
#define CNT_CONN 1
#if CNT_CONN
struct debug_cnt {
	int ins;
	int del;
	int hash;
};
struct debug_cnt g_cnt[MAX_CORES] = {{0,},};
#endif
mctx_t g_mctx[MAX_CORES]; /* mOS context */

/* ToDo: combine to user context */
struct uctx {
	mem_pool_t ci_pool;
	mem_pool_t ste_pool;
	mem_pool_t cte_pool;
	mem_pool_t rawpkt_pool;
	mem_pool_t cli_cipher_pool;
	mem_pool_t cli_plain_pool;
	mem_pool_t svr_cipher_pool;
	mem_pool_t svr_plain_pool;
	st_hashtable *st;
	ct_hashtable *ct;
	int l_tail;
	EVP_CIPHER_CTX *evp_ctx;
};

mem_pool_t g_ci_pool[MAX_CORES] = {NULL};
mem_pool_t g_ste_pool[MAX_CORES] = {NULL};
mem_pool_t g_cte_pool[MAX_CORES] = {NULL};
mem_pool_t g_rawpkt_pool[MAX_CORES] = {NULL};
mem_pool_t g_cli_cipher_pool[MAX_CORES] = {NULL};
mem_pool_t g_cli_plain_pool[MAX_CORES] = {NULL};
mem_pool_t g_svr_cipher_pool[MAX_CORES] = {NULL};
mem_pool_t g_svr_plain_pool[MAX_CORES] = {NULL};
#if CORRECTNESS_CHECK
static FILE *g_fp;
#endif
/*----------------------------------------------------------------------------*/
/* Hash table of TLS connections */
st_hashtable *g_st[MAX_CORES]; /* socket based */
ct_hashtable *g_ct[MAX_CORES]; /* client random based */
/* circular queue of <client random, key> pare */
keytable *g_kt;
int l_tail[MAX_CORES] = {0, };
int g_tail = 0;
/* OpenSSL Cipher context for decryption */
EVP_CIPHER_CTX *g_evp_ctx[MAX_CORES];
/*----------------------------------------------------------------------------*/
/* Signal handler */
static void
sigint_handler(int signum)
{
	/* Terminate the program if any interrupt happens */
	for (int i = 0; i < g_max_cores; i++)
		mtcp_destroy_context(g_mctx[i]);
	exit(EXIT_SUCCESS);
}
/*----------------------------------------------------------------------------*/
/* Dump bytestream in hexademical form */
static inline void
hexdump(char *title, uint8_t *buf, size_t len)
{
#if VERBOSE_TCP | VERBOSE_TLS | VERBOSE_KEY | VERBOSE_DEBUG
	fprintf(stdout, "%s\n", title);
	for (size_t i = 0; i < len; i++)
		fprintf(stdout, "%02X%c", buf[i], ((i + 1) % 16 ? ' ' : '\n'));
	fprintf(stdout, "\n");
#endif
}
/*----------------------------------------------------------------------------*/
/* Print AAD, TAG, cipher text and decrypted plain text */
static inline void
print_text(uint8_t *aad, uint8_t *tag, uint8_t *cipher, uint8_t *plain,
		   int cipher_len, int plain_len)
{
#if VERBOSE_DEBUG
	INFO_PRINT("\n--------------------------------------------------\n");
	hexdump("[aad]", aad, TLS_CIPHER_AES_GCM_256_AAD_SIZE);
	hexdump("[tag]", tag, TLS_CIPHER_AES_GCM_256_TAG_SIZE);

	fprintf(stdout, "ciphertext_len: 0x%x\n", cipher_len);
	hexdump("[cipher text]", cipher, cipher_len);
	fprintf(stdout, "plaintext_len: 0x%x\n", plain_len);
	hexdump("[plain text]", plain, plain_len);
#endif /* !VERBOSE_DEBUG */
}
/*----------------------------------------------------------------------------*/
static inline bool
has_key(conn_info *c)
{
	return (c->ci_tls_ctx[MOS_SIDE_CLI].tc_key_info.key_mask & 0x0f) == 0x0f;
}
/*----------------------------------------------------------------------------*/
static inline int
consume_plaintext(uint32_t len, uint8_t *text)
{
	int i = 0;
#if CORRECTNESS_CHECK
	for (i = 0; i < len; i++)
		fprintf(g_fp, "%02X", text[i]);
#else
#endif
	return i;
}
/*----------------------------------------------------------------------------*/
static inline void
print_conn_stat(mctx_t mctx, conn_info *c)
{
#if CNT_CONN
	struct debug_cnt sum = {0,};
#if 1
	for (int i = 0; i < g_max_cores; i++) {
#else
	for (int i = 1; i < g_max_cores; i++) {
#endif
		sum.ins += g_cnt[i].ins;
		sum.del += g_cnt[i].del;
		sum.hash += g_st[i]->ht_count;	
	}
	fprintf(stdout,
			"\n--------------------------------------------------\n"
			"[CORE: %d]\n"
			"CLIENT: %lu B\n"
			"CLIENT peek: %lu B\n"
			"SERVER: %lu B\n"
			"SERVER peek: %lu B\n"
			"Record cnt: %lu\n"
			"Key cnt: %d\n"
			"Insert conn cnt: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n"
			"Total insert conn: %d\n"
			"Remove conn cnt: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n"
			"Total remove conn: %d\n"
			"Total hash conn: %d\n",
			mctx->cpu,
			c->ci_tls_ctx[MOS_SIDE_CLI].decrypt_len,
			c->ci_tls_ctx[MOS_SIDE_CLI].peek_len,
			c->ci_tls_ctx[MOS_SIDE_SVR].decrypt_len,
			c->ci_tls_ctx[MOS_SIDE_SVR].peek_len,
			c->ci_tls_ctx[MOS_SIDE_CLI].tc_record_cnt + 
			c->ci_tls_ctx[MOS_SIDE_SVR].tc_record_cnt,
			g_cnt[0].ins, /* master core: num of keys */
			g_cnt[1].ins, g_cnt[2].ins, g_cnt[3].ins, g_cnt[4].ins,
			g_cnt[5].ins, g_cnt[6].ins, g_cnt[7].ins, g_cnt[8].ins,
			g_cnt[9].ins, g_cnt[10].ins, g_cnt[11].ins, g_cnt[12].ins,
			g_cnt[13].ins, g_cnt[14].ins, g_cnt[15].ins, g_cnt[16].ins,
			sum.ins,
			g_cnt[1].del, g_cnt[2].del, g_cnt[3].del, g_cnt[4].del,
			g_cnt[5].del, g_cnt[6].del, g_cnt[7].del, g_cnt[8].del,
			g_cnt[9].del, g_cnt[10].del, g_cnt[11].del, g_cnt[12].del,
			g_cnt[13].del, g_cnt[14].del, g_cnt[15].del, g_cnt[16].del,
			sum.del,
			sum.hash);
#endif
}
/*----------------------------------------------------------------------------*/
static void
remove_conn_info(mctx_t mctx, conn_info *c)
{
#if CNT_CONN
	g_cnt[mctx->cpu].del++;
#endif
	if (!ct_remove(g_ct[mctx->cpu], c->ci_client_random, g_cte_pool[mctx->cpu]))
		WARNING_PRINT("[core %d] No session with given client random", mctx->cpu);
	if (!st_remove(g_st[mctx->cpu], c->ci_sock, g_ste_pool[mctx->cpu]))
		WARNING_PRINT("[core %d] No session with given sock", mctx->cpu);
	if (c->ci_tls_ctx[MOS_SIDE_CLI].tc_cipher.buf)
		MPFreeChunk(g_cli_cipher_pool[mctx->cpu],
					c->ci_tls_ctx[MOS_SIDE_CLI].tc_cipher.buf);
	if (c->ci_tls_ctx[MOS_SIDE_SVR].tc_cipher.buf)
		MPFreeChunk(g_svr_cipher_pool[mctx->cpu],
					c->ci_tls_ctx[MOS_SIDE_SVR].tc_cipher.buf);
	if (c->ci_tls_ctx[MOS_SIDE_CLI].tc_plain.buf)
		MPFreeChunk(g_cli_plain_pool[mctx->cpu],
					c->ci_tls_ctx[MOS_SIDE_CLI].tc_plain.buf);
	if (c->ci_tls_ctx[MOS_SIDE_SVR].tc_plain.buf)
		MPFreeChunk(g_svr_plain_pool[mctx->cpu],
					c->ci_tls_ctx[MOS_SIDE_SVR].tc_plain.buf);
	print_conn_stat(mctx, c);
	MPFreeChunk(g_ci_pool[mctx->cpu], c);
}
/*----------------------------------------------------------------------------*/
static void
handle_malicious(mctx_t mctx, int sock, int side, conn_info *c, int code)
{
	WARNING_PRINT("[core %d] malicious code: %d", mctx->cpu, code);
	if (c)
		remove_conn_info(mctx, c);
	if (mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP) < 0)
		EXIT_WITH_ERROR("mtcp_setlastpkt failed");
	if (mtcp_reset_conn(mctx, sock) < 0)
		EXIT_WITH_ERROR("mtcp_reset_conn failed");
}
/*----------------------------------------------------------------------------*/
/* Updates IV by XOR'ing it by # of records that have been alrady decrypted */
static inline void
update_iv(uint8_t iv[TLS_CIPHER_AES_GCM_256_IV_SIZE],
    	  uint8_t updated_iv[TLS_CIPHER_AES_GCM_256_IV_SIZE],
    	  uint64_t record_count)
{
	for (int i = 0; i < sizeof(record_count); i++)
    	updated_iv[TLS_CIPHER_AES_GCM_256_IV_SIZE - i - 1] =
        	iv[TLS_CIPHER_AES_GCM_256_IV_SIZE - i - 1] ^
        	((record_count >> (i * 8)) & LOWER_8BITS);
	memcpy(updated_iv, iv,
		TLS_CIPHER_AES_GCM_256_IV_SIZE - sizeof(record_count));
}
/*----------------------------------------------------------------------------*/
/* Decrypt single TLS record with given key_info */
/* Return length of decrypted data, -1 of error */
static inline int
decrypt_ciphertext(EVP_CIPHER_CTX *ctx, uint8_t *data, uint8_t *plain, 
				   uint8_t *key, uint8_t *iv, uint16_t cipher_len)
{
	uint8_t *aad, *tag, *cipher;
	int len = 0, outlen = 0;

	/* aad generate, aad is tls header in TLS1.3 */
	aad = data;
	/* tag generate */
	tag = data + TLS_HEADER_LEN + cipher_len -
		  TLS_CIPHER_AES_GCM_256_TAG_SIZE;
	cipher_len -= TLS_CIPHER_AES_GCM_256_TAG_SIZE;
	/* decrypt cipher text */
	cipher = data + TLS_HEADER_LEN;
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		return INIT_ALGORITHM_ERR;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
							 TLS_CIPHER_AES_GCM_256_IV_SIZE, NULL))
		return SET_IVLEN_ERR;
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		return SET_KEY_IV_ERR;
	if (!EVP_DecryptUpdate(ctx, NULL, &len, aad,
						   TLS_CIPHER_AES_GCM_256_AAD_SIZE))
		return SET_AAD_ERR;
	if (!EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len))
		return DECRYPT_ERR;
	outlen += len;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
							 TLS_CIPHER_AES_GCM_256_TAG_SIZE, tag))
		return SET_EXPECTED_TAG_ERR;
	if (EVP_DecryptFinal_ex(ctx, plain + len, &len) <= 0)
		return DECRYPT_FINAL_ERR;
	outlen += len;

	/* print value and results */
	assert(cipher_len == outlen);
	print_text(aad, tag, cipher, plain, cipher_len, outlen);

	/* ToDo: buffer is saved to plain text even it's not application data */
	return outlen;
}
/*----------------------------------------------------------------------------*/
/* Parse payload to get TLS session key data into key_info */
/* Return length of parsed data, -1 of error */
static int
parse_tls_key(uint8_t *data, tls_crypto_info *client, tls_crypto_info *server)
{
	uint16_t cipher_suite, key_mask;
	uint8_t *ptr;
	int key_len, iv_len;

	assert(client && server);
	ptr = data;
	cipher_suite = ntohs(*(uint16_t *)ptr);
	key_len = TLS_CIPHER_AES_GCM_256_KEY_SIZE;
	iv_len = TLS_CIPHER_AES_GCM_256_IV_SIZE;
	ptr += sizeof(cipher_suite);
	key_mask = ntohs(*((uint16_t *)ptr));
	client->key_mask |= key_mask;
	server->key_mask |= key_mask;
	ptr += sizeof(key_mask);
	if (key_mask & CLI_KEY_MASK) {
		memcpy(client->key, ptr, key_len);
		ptr += key_len;
	}
	if (key_mask & SRV_KEY_MASK) {
		memcpy(server->key, ptr, key_len);
		ptr += key_len;
	}
	if (key_mask & CLI_IV_MASK) {
		memcpy(client->iv, ptr, iv_len);
		ptr += iv_len;
	}
	if (key_mask & SRV_IV_MASK) {
		memcpy(server->iv, ptr, iv_len);
		ptr += iv_len;
	}
#if VERBOSE_KEY
	fprintf(stdout,
			"\n--------------------------------------------------\n"
			"[%s] Parsed new key\n", __FUNCTION__);
	hexdump("cli key", client->key, key_len);
	hexdump("srv key", server->key, key_len);
	hexdump("cli iv", client->iv, iv_len);
	hexdump("srv iv", server->iv, iv_len);
#endif

	return ptr - data;
}
/*----------------------------------------------------------------------------*/
/* Parse TCP payload to assemble single TLS record sending to server
 * Return byte of parsed record, 0 if no complete record
 */
static inline int
parse_tls_record(tls_buffer *cipher, uint8_t *record_type, uint8_t **payload)
{
	uint8_t *ptr;
	int record_len;

	/* Parse header of new record */
	if (cipher->head + TLS_HEADER_LEN > cipher->tail)
		return 0; // TLS header is incomplete
	ptr = cipher->buf + cipher->head;
	*record_type = *ptr;
	record_len = htons(*(uint16_t *)(ptr + 3));
	*payload = ptr + TLS_HEADER_LEN;
	if (cipher->head + record_len + TLS_HEADER_LEN > cipher->tail)
		return 0; // TLS record is incomplete

#if VERBOSE_TLS
	fprintf(stdout,
			"\n--------------------------------------------------\n"
			"[%s] Parse new record to follow session\n"
			"Record type %x, length %u (TCP %u ~ %u), cipher len %u\n",
			__FUNCTION__, *record_type, record_len, *head,
			*head + record_len + TLS_HEADER_LEN, record_len);
	hexdump("Dump of ciphertext of the record:", ptr, record_len);
#endif /* VERBOSE_TLS */

	return record_len;
}
/*----------------------------------------------------------------------------*/
/* Update version and state in connection information
 * Return
 * 0 if no need decrypt,
 * 1 if need decrypt,
 * -1 if suspected as malicious
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
update_conn_info(mctx_t mctx, conn_info *c, int side,
				 uint8_t record_type, uint8_t *payload)
{
	int *state = &c->ci_tls_state;
	switch (record_type) {
	case CHANGE_CIPHER_SPEC:
		if ((side == MOS_SIDE_CLI) &&
			(*state == SERVER_HELLO_RECV))
			*state = SERVER_CIPHER_SUITE_RECV;
		else if ((side == MOS_SIDE_SVR) &&
				(*state == SERVER_CIPHER_SUITE_RECV))
			*state = CLIENT_CIPHER_SUITE_RECV;
		else
			return CIPHER_SUITE_STATE_ERR;
		break;
	case ALERT:
		/* we do not handle alert record yet */
		break;
	case HANDSHAKE:
		if ((*payload == CLIENT_HS) && (*state == INITIAL_STATE)) {
			*state = CLIENT_HELLO_RECV;
			payload += TLS_HANDSHAKE_HEADER_LEN;
			/* Client Version (0x0303) */
			payload += sizeof(uint16_t);
			memcpy(c->ci_client_random, payload, TLS_1_3_CLIENT_RANDOM_LEN);
			if (ct_search(g_ct[mctx->cpu], c->ci_client_random)) {
				/* sent client random twice (not retransmitted) */
				return CLIENT_RANDOM_DUP;
			}
			if (ct_insert(g_ct[mctx->cpu], c->ci_client_random, c, g_cte_pool[mctx->cpu]) < 0)
				EXIT_WITH_ERROR("ct_element pool alloc failed");
		}
		else if ((*payload == SERVER_HS) && (*state == CLIENT_HELLO_RECV))
			*state = SERVER_HELLO_RECV;
		else
			return HANDSHAKE_ERR;
		break;
	case APPLICATION_DATA:
		if ((*state == SERVER_CIPHER_SUITE_RECV) && (side == MOS_SIDE_CLI))
			; /* record sent by server, seems to be certificate */
		else if ((*state == CLIENT_CIPHER_SUITE_RECV) &&
				(side == MOS_SIDE_SVR))
			*state = TLS_ESTABLISHED;
		else if (*state >= TLS_ESTABLISHED)
			return DO_DECRYPT;
		else
			return APPLICATION_DATA_ERR;
		break;
	default:
		return UNKNOWN_TYPE_ERR;
	}
	return NO_DECRYPT;
}
/*----------------------------------------------------------------------------*/
/* 1. Check whether peeked record is complete
 * 2. Parse the complete record
 * 3. Update connection info (e.g., state, client random)
 * 4. Decrypt if needed
 * 5. Move buffer head right by parsed bytes
 * 6. Return decrypted bytes, or -1 if error
 */
static int
process_data(mctx_t mctx, int sock, int side, conn_info *c,
			 tls_buffer *cipher, tls_buffer *plain)
{
	tls_context *ctx = &c->ci_tls_ctx[side];
	int parse_len; /* TLS header not included */
	uint8_t record_type;
	uint8_t *payload;
	int ret;
	int decrypt_len;
	int total_len = 0;
	uint8_t iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];

	/* decrypt complete records */
	while ((parse_len = parse_tls_record(cipher, &record_type, &payload)) > 0) {
		ret = update_conn_info(mctx, c, side, record_type, payload);
		if (ret < 0)
			return ret;
		if (ret == DO_DECRYPT) {
			update_iv(ctx->tc_key_info.iv, iv, ctx->tc_record_cnt++);
			decrypt_len = decrypt_ciphertext(g_evp_ctx[mctx->cpu],
											 cipher->buf + cipher->head,
											 plain->buf + plain->tail,
											 ctx->tc_key_info.key, iv,
											 parse_len);
			if (decrypt_len < 0)
				return decrypt_len;
			total_len += decrypt_len;
			// consume_plaintext(decrypt_len, plain->buf + plain->tail);
			plain->tail += decrypt_len;
			if (plain->tail + MAX_RECORD_LEN > MAX_BUF_LEN)
				plain->tail = 0;
		}
		/* move to next record */
		cipher->head += TLS_HEADER_LEN + parse_len;
	}
	return total_len;
}
/*----------------------------------------------------------------------------*/
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
	if (mtcp_getlastpkt(mctx, sock, side, &p) < 0)
		EXIT_WITH_ERROR("failed to get packet info");
	memcpy(rp->data, p.ethh, p.eth_len);
	rp->len = p.eth_len;
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, sock, side, &pctx) < 0)
		EXIT_WITH_ERROR("failed to get packet context");
	memcpy(rp->data, pctx->p.ethh, pctx->p.eth_len);
	rp->len = pctx->p.eth_len;
#endif
	c->ci_raw_len += rp->len;
	c->ci_raw_cnt++;
	if ((c->ci_raw_cnt == MAX_RAW_PKT_NUM) ||
		(c->ci_raw_len > MAX_RAW_PKT_BUF_LEN)) {
		MPFreeChunk(g_rawpkt_pool[mctx->cpu], rp->data);
		c->ci_raw_cnt = c->ci_raw_len = 0;
		return MISSING_KEY;
	}
	(rp + 1)->data = rp->data + rp->len;
	return 1;
}
/*----------------------------------------------------------------------------*/
/* Send copied raw packets
 * Use new API, mtcp_sendpkt_raw()
 * After send, free mempool
 */
static inline void
send_stalled_pkts(mctx_t mctx, conn_info *c)
{
	pkt_vec *rp = c->ci_raw_pkt;
	if (!c->ci_raw_cnt)
		return;
	while (rp < c->ci_raw_pkt + c->ci_raw_cnt) {
		if (mtcp_sendpkt_raw(mctx, c->ci_sock, rp->data, rp->len) < 0) {
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
/* Create connection structure for new connection */
static void
cb_create(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	conn_info *c;
	if ((c = st_search(g_st[mctx->cpu], sock)))
		return;

	if (!(c = (conn_info *)MPAllocateChunk(g_ci_pool[mctx->cpu])))
		EXIT_WITH_ERROR("conn info pool alloc failed");
	/* MPAlloc needs memset */
	memset(c, 0, sizeof(conn_info));
	/* Fill values of the connection structure */
	c->ci_sock = sock;
#if DEBUG_SOCKET
	socklen_t addrslen = sizeof(struct sockaddr) * 2;
	struct sockaddr addrs[2];
	if (mtcp_getpeername(mctx, sock, addrs, &addrslen,
						 MOS_SIDE_BOTH) < 0)
		EXIT_WITH_ERROR("mtcp_getpeername failed");
#endif
	/* Insert the structure to the queue */
	if (st_insert(g_st[mctx->cpu], sock, c, g_ste_pool[mctx->cpu]) < 0)
		EXIT_WITH_ERROR("st_element pool alloc failed");
#if CNT_CONN
	g_cnt[mctx->cpu].ins++;
#endif
}
/*----------------------------------------------------------------------------*/
/* Destroy connection structure
 * If some ciphers are pending as undecrypted, postpone destroy
 */
static void
cb_destroy(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	conn_info *c;
	if (!(c = st_search(g_st[mctx->cpu], sock)))
		return;
#if IDS
	if (!has_key(c)) {
		c->ci_tls_state = TO_BE_DESTROYED;
		return;
	}
#endif
	remove_conn_info(mctx, c);
}
/*----------------------------------------------------------------------------*/
/* Called when received new packet from monitoring stream socket (sock, side) */
static void
cb_new_data(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	conn_info *c;
	tls_buffer *cipher, *plain;
	int len;
#if 0
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
	struct pkt_info p;
	if (mtcp_getlastpkt(mctx, sock, side, &p) < 0)
		EXIT_WITH_ERROR("failed to get packet info");
	if (p.tcph->syn && !p.tcph->ack) {
		cb_create(mctx, sock, side, events, arg);
		return;
	}
	if (p.tcph->fin || p.tcph->rst) {
		cb_destroy(mctx, sock, side, events, arg);
		return;
	}
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, sock, side, &pctx) < 0)
		EXIT_WITH_ERROR("failed to get packet context");
	if (pctx->p.tcph->syn && !pctx->p.tcph->ack) {
		cb_create(mctx, sock, side, events, arg);
		return;
	}
	if (pctx->p.tcph->fin || pctx->p.tcph->rst) {
		cb_destroy(mctx, sock, side, events, arg);
		return;
	}
#endif
#endif
	if (!(c = st_search(g_st[mctx->cpu], sock)))
		return;

	/* allocate mempool if needed */
	cipher = &c->ci_tls_ctx[side].tc_cipher;
	if (!cipher->buf) {
		if (!(cipher->buf = MPAllocateChunk((side == MOS_SIDE_CLI)?
			g_cli_cipher_pool[mctx->cpu]:g_svr_cipher_pool[mctx->cpu])))
			EXIT_WITH_ERROR("record pool alloc failed");
	}
	plain = &c->ci_tls_ctx[side].tc_plain;
	if (!plain->buf) {
		if (!(plain->buf = MPAllocateChunk((side == MOS_SIDE_CLI)?
			g_cli_plain_pool[mctx->cpu]:g_svr_plain_pool[mctx->cpu])))
			EXIT_WITH_ERROR("plaintext pool alloc failed");
	}
#if IPS
	if ((c->ci_tls_state >= TLS_ESTABLISHED) && !has_key(c)) {
		if (copy_lastpkt(mctx, sock, side, c) < 0) {
			handle_malicious(mctx, sock, side, c, MISSING_KEY);
			return;
		}
		if (mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP) < 0)
			EXIT_WITH_ERROR("drop failed");
		return;
	}
#endif
PEEK:
	if ((len = mtcp_peek(mctx, sock, side, (char *)cipher->buf + cipher->tail,
						 MAX_BUF_LEN - cipher->tail)) <= 0)
		return;
	cipher->tail += len;
	c->ci_tls_ctx[side].peek_len += len;
#if IDS
	if ((c->ci_tls_state >= TLS_ESTABLISHED) && !has_key(c)) {
        if (cipher->tail == MAX_BUF_LEN)
			/* ToDo: allocate more pool */
            WARNING_PRINT("[core %d] Buffer overwrite occurred", mctx->cpu);
        return;
	}
#endif
	if ((len = process_data(mctx, sock, side, c, cipher, plain)) < 0) {
		handle_malicious(mctx, sock, side, c, len);
		return;
	}
	c->ci_tls_ctx[side].decrypt_len += len;
	/* if buffer is full, move buffer to left by head offset and re-peek */
	if (cipher->tail == MAX_BUF_LEN) {
		memcpy(cipher->buf, cipher->buf + cipher->head, MAX_BUF_LEN - cipher->head);
		cipher->tail -= cipher->head;
		cipher->head = 0;
		goto PEEK;
	}
#if VERBOSE_TCP
	hexdump(NULL, buf + *tail, len);
#endif
}
/*----------------------------------------------------------------------------*/
/* Called when received new raw packet from raw monitoring socket (rsock) */
static void
cb_new_key(mctx_t mctx, int rsock, int side, uint64_t events, filter_arg_t *arg)
{
	uint8_t *payload;
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
	struct pkt_info p;
	if (mtcp_getlastpkt(mctx, rsock, side, &p) < 0)
		EXIT_WITH_ERROR("mtcp_getlastpkt failed");
	payload = (uint8_t *)(p.iph) + IP_HEADER_LEN + UDP_HEADER_LEN;
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, rsock, side, &pctx) < 0)
		EXIT_WITH_ERROR("mtcp_getlastpkt failed");
	payload = (uint8_t *)(pctx->p.iph) + IP_HEADER_LEN + UDP_HEADER_LEN;
#endif
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
#if 1
	conn_info *c;
	if (!(c = ct_search(g_ct[mctx->cpu], payload)))
		return; // ignore this key
	parse_tls_key(payload + TLS_1_3_CLIENT_RANDOM_LEN + 1,
				&c->ci_tls_ctx[MOS_SIDE_SVR].tc_key_info,
				&c->ci_tls_ctx[MOS_SIDE_CLI].tc_key_info);
#if IDS
	int len;
	if (len = process_data(mctx, c, MOS_SIDE_CLI,
							&c->ci_tls_ctx[MOS_SIDE_CLI].tc_cipher,
							&c->ci_tls_ctx[MOS_SIDE_CLI].tc_plain) < 0) {
		handle_malicious(mctx, sock, side, c, len);
		return;
	}
	c->ci_tls_ctx[MOS_SIDE_CLI].decrypt_len += len;
	if (len = process_data(mctx, c, MOS_SIDE_SVR,
							&c->ci_tls_ctx[MOS_SIDE_SVR].tc_cipher,
							&c->ci_tls_ctx[MOS_SIDE_SVR].tc_plain) < 0) {
		handle_malicious(mctx, sock, side, c, len);
		return;
	}
	c->ci_tls_ctx[MOS_SIDE_SVR].decrypt_len += len;
	if (c->ci_tls_state == TO_BE_DESTROYED)
		remove_conn_info(mctx, c, 1);
#endif
	send_stalled_pkts(mctx, c);
	return;
#else
	memcpy(g_kt[g_tail].kt_client_random, payload, TLS_1_3_CLIENT_RANDOM_LEN);
	parse_tls_key(payload + TLS_1_3_CLIENT_RANDOM_LEN + 1,
				&g_kt[g_tail].kt_key_info[MOS_SIDE_SVR],
				&g_kt[g_tail].kt_key_info[MOS_SIDE_CLI]);
	g_kt[g_tail].kt_valid = 1;
	if (++g_tail == NUM_BINS)
		g_tail = 0;
	/* old key should not still exist */
	assert(!g_kt[g_tail].kt_valid);
#if CNT_CONN
	g_cnt[mctx->cpu].ins++;
#endif
#endif
}
/*----------------------------------------------------------------------------*/
/* Follower cores try to get new keys for their own TLS streams
 * This functions is registered as a thread function pointer
 * Registered by new API, mtcp_register_thread_callback()
 */
static void
find_key_and_process(mctx_t mctx)
{
	conn_info *c;
	int *tail = l_tail + mctx->cpu;
	keytable *walk = g_kt + *tail;
	while (*tail != g_tail) {
		if (walk->kt_valid) {
			if ((c = ct_search(g_ct[mctx->cpu], walk->kt_client_random))) {
				walk->kt_valid = 0;
				/* copy keys to local hashtable */
				c->ci_tls_ctx[MOS_SIDE_CLI].tc_key_info = walk->kt_key_info[MOS_SIDE_CLI];
				c->ci_tls_ctx[MOS_SIDE_SVR].tc_key_info = walk->kt_key_info[MOS_SIDE_SVR];
#if IDS
				int len;
				if (len = process_data(mctx, c, MOS_SIDE_CLI,
									&c->ci_tls_ctx[MOS_SIDE_CLI].tc_cipher,
									&c->ci_tls_ctx[MOS_SIDE_CLI].tc_plain) < 0) {
					handle_malicious(mctx, sock, side, c, len);
					return;
				}
				c->ci_tls_ctx[MOS_SIDE_CLI].decrypt_len += len;
				if (len = process_data(mctx, c, MOS_SIDE_SVR,
									&c->ci_tls_ctx[MOS_SIDE_SVR].tc_cipher,
									&c->ci_tls_ctx[MOS_SIDE_SVR].tc_plain) < 0) {
					handle_malicious(mctx, sock, side, c, len);
					return;
				}
				c->ci_tls_ctx[MOS_SIDE_SVR].decrypt_len += len;
				if (c->ci_tls_state == TO_BE_DESTROYED) {
					remove_conn_info(mctx, c, 1);
					return;
				}
#endif
				send_stalled_pkts(mctx, c);
#if VERBOSE_KEY
				fprintf(stdout,
						"\n--------------------------------------------------\n"
						"[%s] core: %d tail: %d local_tail: %d\n",
						__FUNCTION__, mctx->cpu, g_tail, *tail);
#endif
			}
		}
		walk++;
		if (++*tail == NUM_BINS) {
			*tail = 0;
			walk = g_kt;
		}
	}
}
/*----------------------------------------------------------------------------*/
static void
register_key_callback(mctx_t mctx, int rsock)
{
	union monitor_filter ft = {0};
	ft.raw_pkt_filter = "ip proto 17";
	/* Only leader core should receive key */
#if 0
	if (mctx->cpu == LEADER_CORE) {
#endif
		if (mtcp_bind_monitor_filter(mctx, rsock, &ft) < 0)
			EXIT_WITH_ERROR("Failed to bind ft to the listening socket!");
		if (mtcp_register_callback(mctx, rsock, MOS_ON_PKT_IN,
								MOS_NULL, cb_new_key))
			EXIT_WITH_ERROR("Failed to register cb_new_key()");
		return;
#if 0
	}
	/* For workers, make a per-thread callback to poll shared key table */
	if (mtcp_register_thread_callback(mctx, find_key_and_process))
		EXIT_WITH_ERROR("Failed to register find_key_and_process()");
#endif
	(void)find_key_and_process;
}
/*----------------------------------------------------------------------------*/
static void
register_data_callback(mctx_t mctx, int msock)
{
	if (mtcp_register_callback(mctx, msock, MOS_ON_CONN_START,
							   MOS_HK_RCV, cb_create))
		EXIT_WITH_ERROR("Failed to register cb_create()");
	if (mtcp_register_callback(mctx, msock, MOS_ON_CONN_END,
							   MOS_HK_RCV, cb_destroy))
		EXIT_WITH_ERROR("Failed to register cb_destroy()");
	if (mtcp_register_callback(mctx, msock, MOS_ON_PKT_IN,
							   MOS_HK_SND, cb_new_data))
		EXIT_WITH_ERROR("Failed to register cb_new_data()");
}
/*----------------------------------------------------------------------------*/
/* Register required callbacks */
static void
register_callbacks(mctx_t mctx)
{
	int msock_raw, msock_stream;
	
	/* Make a raw packet monitoring socket */
	if ((msock_raw = mtcp_socket(mctx, AF_INET,
								 MOS_SOCK_MONITOR_RAW, 0)) < 0)
		EXIT_WITH_ERROR("Failed to create monitor listening socket!");
	/* Register raw packet callback for key delivery */
	register_key_callback(mctx, msock_raw);

	/* Make a stream data monitoring socket */
	if ((msock_stream = mtcp_socket(mctx, AF_INET,
									MOS_SOCK_MONITOR_STREAM, 0)) < 0)
		EXIT_WITH_ERROR("Failed to create monitor listening socket!");
	/* Register stream data callback for TCP connections */
	register_data_callback(mctx, msock_stream);
}
/*----------------------------------------------------------------------------*/
/* Open monitoring socket and ready it for monitoring */
static void
init_monitor(mctx_t mctx)
{
	register_callbacks(mctx);
}
/*----------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
	int i;
	char *fname = MOS_CONFIG_FILE; /* path to the default mos config file */
	struct mtcp_conf mcfg;
	int num_cpus;
	int opt, rc;

	/* get the total # of cpu cores */
	num_cpus = GetNumCPUs();

	while ((opt = getopt(argc, argv, "c:f:")) != -1)
		switch (opt) {
		case 'c':
			if ((rc = atoi(optarg)) > num_cpus)
				EXIT_WITH_ERROR("failed to set core number\n"
							"request %u, but only %u available",
							rc, num_cpus);
			num_cpus = rc;
			break;
		case 'f':
			fname = optarg;
			break;
		default:
			printf("Usage: %s [-c num of cores] "
				   "[-f mos config_file]\n",
				   argv[0]);
			return 0;
		}
	g_max_cores = num_cpus;

	/* parse mos configuration file */
	if (mtcp_init(fname))
		EXIT_WITH_ERROR("failed to initialize mtcp");

	/* set the core limit */
	mtcp_getconf(&mcfg);
	mcfg.num_cores = g_max_cores;
	mtcp_setconf(&mcfg);

	/* Register signal handler */
	mtcp_register_signal(SIGINT, sigint_handler);

#if CORRECTNESS_CHECK
	/* to check correctness */
	if ((g_fp = fopen("plaintext.txt", "a+w")) < 0)
		EXIT_WITH_ERROR("open() failed");
#endif
	/* create global key table */
	if (!(g_kt = (keytable *)calloc(NUM_BINS, sizeof(keytable))))
		EXIT_WITH_ERROR("key table alloc failed");
	/* create hash table */
	for (i = 0; i < MAX_CORES; i++) {
		if (!(g_ct[i] = ct_create()))
			EXIT_WITH_ERROR("ct_create failed");
		if (!(g_st[i] = st_create()))
			EXIT_WITH_ERROR("st_create failed");
	}
	for (i = 0; i < g_max_cores; i++) {
		/* create CIPHER context */
		if (!(g_evp_ctx[i] = EVP_CIPHER_CTX_new()))
			EXIT_WITH_ERROR("EVP_CIPHER_CTX_new failed");
		/* create mem pools */
		/* 1. conn info mempool */
		if (!(g_ci_pool[i] = MPCreate(sizeof(conn_info),
						sizeof(conn_info) * mcfg.max_concurrency, 0)))
			EXIT_WITH_ERROR("conn info pool create failed");
		/* 2. socket based hashtable element mempool */
		if (!(g_ste_pool[i] = MPCreate(sizeof(st_element),
						sizeof(st_element) * mcfg.max_concurrency, 0)))
			EXIT_WITH_ERROR("st_element pool create failed");
		/* 3. client random based hashtable element mempool */
		if (!(g_cte_pool[i] = MPCreate(sizeof(ct_element),
						sizeof(ct_element) * mcfg.max_concurrency, 0)))
			EXIT_WITH_ERROR("ct_element pool create failed");
		/* 4. raw packet buffer mempool */
		if (!(g_rawpkt_pool[i] = MPCreate(MAX_RAW_PKT_BUF_LEN,
							MAX_RAW_PKT_BUF_LEN * mcfg.max_concurrency, 0)))
			EXIT_WITH_ERROR("rawpkt pool create failed");
		/* 5. client side cipher buffer mempool */
		if (!(g_cli_cipher_pool[i] = MPCreate(MAX_BUF_LEN,
							MAX_BUF_LEN * mcfg.max_concurrency, 0)))
			EXIT_WITH_ERROR("cli ciphertext pool create failed");
		/* 6. client side plain buffer mempool */
		if (!(g_cli_plain_pool[i] = MPCreate(MAX_BUF_LEN,
							MAX_BUF_LEN * mcfg.max_concurrency, 0)))
			EXIT_WITH_ERROR("cli plaintext pool create failed");
		/* 7. server side cipher buffer mempool */
		/* server side receive buffer is supposed to be much smaller */
		if (!(g_svr_cipher_pool[i] = MPCreate(MAX_BUF_LEN_SVR,
							MAX_BUF_LEN_SVR * mcfg.max_concurrency, 0)))
			EXIT_WITH_ERROR("svr ciphertext pool create failed");
		/* 8. server side plain buffer mempool */
		/* server side receive buffer is supposed to be much smaller */
		if (!(g_svr_plain_pool[i] = MPCreate(MAX_BUF_LEN_SVR,
							MAX_BUF_LEN_SVR * mcfg.max_concurrency, 0)))
			EXIT_WITH_ERROR("svr plaintext pool create failed");
		/* Run mOS for each CPU core */
		if (!(g_mctx[i] = mtcp_create_context(i)))
			EXIT_WITH_ERROR("mtcp_create_context failed");
		INFO_PRINT("[core %d] thread created", i);
		/* init monitor */
		init_monitor(g_mctx[i]);
	}

	/* wait until all threads finish */
	for (i = 0; i < g_max_cores; i++)
		mtcp_app_join(g_mctx[i]);

	mtcp_destroy();
	/* free global key table */
	free(g_kt);
	for (i = 0; i < g_max_cores; i++) {
		/* free allocated memories */
		MPDestroy(g_cli_cipher_pool[i]);
		MPDestroy(g_cli_plain_pool[i]);
		MPDestroy(g_svr_cipher_pool[i]);
		MPDestroy(g_svr_plain_pool[i]);
		MPDestroy(g_rawpkt_pool[i]);
		MPDestroy(g_ste_pool[i]);
		MPDestroy(g_cte_pool[i]);
		MPDestroy(g_ci_pool[i]);
		/* free hash tables */
		ct_destroy(g_ct[i]);
		st_destroy(g_st[i]);
		/* free EVP context buffer */
		EVP_CIPHER_CTX_free(g_evp_ctx[i]);
	}

	return EXIT_SUCCESS;
}
/*----------------------------------------------------------------------------*/
