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

#define AGENT_PORT "6666"

#define VERBOSE_TCP 0
#define VERBOSE_TLS 0
#define VERBOSE_KEY 0
#define VERBOSE_STALL 0
#define VERBOSE_DEBUG 0
#define DESTROY_CHECK 0

/* Mode */
#define IPS 1
#define IDS (!IPS)
/*----------------------------------------------------------------------------*/
/* Core */
int g_max_cores;		  /* Number of CPU cores to be used */
#define CNT_CONN 0
#if CNT_CONN
int g_cnt[MAX_CORES];	/* for debugging */
#endif
mctx_t g_mctx[MAX_CORES]; /* mOS context */
mem_pool_t g_ci_pool[MAX_CORES] = {NULL};
mem_pool_t g_st_element[MAX_CORES] = {NULL};
mem_pool_t g_ct_element[MAX_CORES] = {NULL};
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
/*----------------------------------------------------------------------------*/
/* Multi-core support */
keytable *g_kt; /* circular queue of <client random, key> pare */
int l_tail[MAX_CORES] = {0, };
volatile int g_tail = 0;
/*----------------------------------------------------------------------------*/
/* Key log agent */
char *g_port = AGENT_PORT;
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
	if (title)
		fprintf(stderr, "%s\n", title);
	for (size_t i = 0; i < len; i++)
		fprintf(stderr, "%02X%c", buf[i], ((i + 1) % 16 ? ' ' : '\n'));
	fprintf(stderr, "\n");
#endif
}
/*----------------------------------------------------------------------------*/
/* Print AAD, TAG, cipher text and decrypted plain text */
static inline void
print_text(uint8_t *aad, uint8_t *tag, uint8_t *cipher, uint8_t *plain,
		   int cipher_len, int plain_len)
{
#if VERBOSE_DEBUG
	fprintf(stderr, "*--------------------------------------------------------*\n");
	hexdump("[aad]", aad, TLS_CIPHER_AES_GCM_256_AAD_SIZE);
	hexdump("[tag]", tag, TLS_CIPHER_AES_GCM_256_TAG_SIZE);

	fprintf(stderr, "ciphertext_len: 0x%x\n", cipher_len);
	hexdump("[cipher text]", cipher, cipher_len);
	fprintf(stderr, "plaintext_len: 0x%x\n", plain_len);
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
remove_conn_info(mctx_t mctx, conn_info *c, int code)
{
	if (!ct_remove(g_ct[mctx->cpu], c->ci_client_random, g_ct_element[mctx->cpu]))
		ERROR_PRINT("Error: No session with given client random\n");
	if (!st_remove(g_st[mctx->cpu], c->ci_sock, g_st_element[mctx->cpu]))
		ERROR_PRINT("Error: No session with given sock\n");
#if CNT_CONN
	++g_cnt[mctx->cpu];
	static int i = 0;
	fprintf(stdout,
			"\nDestroy with code %d\n"
			"CORE: %d\n"
			"CLIENT: %lu B\n"
			"SERVER: %lu B\n"
			"Record#: %lu\n"
			"Leader core key: %d\n"
			"Follower core conn: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n"
			"Total conn: %d\n",
			code, mctx->cpu,
			c->ci_tls_ctx[MOS_SIDE_CLI].decrypt_len,
			c->ci_tls_ctx[MOS_SIDE_SVR].decrypt_len,
			c->ci_tls_ctx[MOS_SIDE_CLI].tc_record_cnt + 
			c->ci_tls_ctx[MOS_SIDE_SVR].tc_record_cnt,
			g_cnt[0], /* master core: num of keys */
			g_cnt[1], g_cnt[2], g_cnt[3], g_cnt[4],
			g_cnt[5], g_cnt[6], g_cnt[7], g_cnt[8],
			g_cnt[9], g_cnt[10], g_cnt[11], g_cnt[12],
			g_cnt[13], g_cnt[14], g_cnt[15], g_cnt[16],
			++i);
#endif

	MPFreeChunk(g_cli_cipher_pool[mctx->cpu],
				c->ci_tls_ctx[MOS_SIDE_CLI].tc_cipher.buf);
	MPFreeChunk(g_svr_cipher_pool[mctx->cpu],
				c->ci_tls_ctx[MOS_SIDE_SVR].tc_cipher.buf);
	MPFreeChunk(g_cli_plain_pool[mctx->cpu],
				c->ci_tls_ctx[MOS_SIDE_CLI].tc_plain.buf);
	MPFreeChunk(g_svr_plain_pool[mctx->cpu],
				c->ci_tls_ctx[MOS_SIDE_SVR].tc_plain.buf);
	MPFreeChunk(g_ci_pool[mctx->cpu], c);
}
/*----------------------------------------------------------------------------*/
static inline void
handle_malicious(mctx_t mctx, int sock, conn_info *c, const char *msg, int ercode)
{
	ERROR_PRINT("Malicious! code: %d / msg: %s\n", ercode, msg);
	if (mtcp_reset_conn(mctx, sock) < 0) {
		ERROR_PRINT("Reset failed\n");
		exit(EXIT_FAILURE);
	}
	remove_conn_info(mctx, c, 3);
}
/*----------------------------------------------------------------------------*/
/* Updates IV by XOR'ing it by # of records that have been alrady decrypted */
/* Return updated IV */
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
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		ERROR_PRINT("Error: Init algorithm failed\n");
		return -5;
	}
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
							 TLS_CIPHER_AES_GCM_256_IV_SIZE, NULL)) {
		ERROR_PRINT("Error: SET_IVLEN failed\n");
		return -6;
	}
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
		ERROR_PRINT("Error: Set KEY/IV faield\n");
		return -7;
	}
	if (!EVP_DecryptUpdate(ctx, NULL, &len, aad,
						   TLS_CIPHER_AES_GCM_256_AAD_SIZE)) {
		ERROR_PRINT("Error: Set AAD failed\n");
		return -8;
	}
	if (!EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len)) {
		ERROR_PRINT("Error: Decrypt failed\n");
		return -9;
	}
	outlen += len;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
							 TLS_CIPHER_AES_GCM_256_TAG_SIZE, tag)) {
		ERROR_PRINT("Error: Set expected TAG failed\n");
		return -10;
	}
	if (EVP_DecryptFinal_ex(ctx, plain + len, &len) <= 0) {
		fprintf(stderr, "Error: DecryptFinal failed\n");
		return -11;
	}
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
	fprintf(stderr, "[%s] Parse new record to follow session!\n",
			__FUNCTION__);
	fprintf(stderr, "Record type %x, length %u (TCP %u ~ %u), "
					"cipher len %u\n",
			*record_type, record_len, *head,
			*head + record_len + TLS_HEADER_LEN,
			record_len);
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
			return -1;
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
			if (ct_insert(g_ct[mctx->cpu], c->ci_client_random, c, g_ct_element[mctx->cpu]) < 0) {
				ERROR_PRINT("Error: ct_insert() call with duplicate client random..\n");
				exit(EXIT_FAILURE);
			}
		}
		else if ((*payload == SERVER_HS) && (*state == CLIENT_HELLO_RECV))
			*state = SERVER_HELLO_RECV;
		else
			return -2;
		break;
	case APPLICATION_DATA:
		if ((*state == SERVER_CIPHER_SUITE_RECV) && (side == MOS_SIDE_CLI))
			; /* record sent by server, seems to be certificate */
		else if ((*state == CLIENT_CIPHER_SUITE_RECV) &&
				(side == MOS_SIDE_SVR))
			*state = TLS_ESTABLISHED;
		else if (*state >= TLS_ESTABLISHED)
			return 1;
		else
			return -3;
		break;
	default:
		return -4;
	}
	return 0;
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
	int decrypt;
	int decrypt_len;
	int total = 0;
	uint8_t iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];

	/* decrypt complete records */
	while ((parse_len = parse_tls_record(cipher, &record_type, &payload)) > 0) {
		decrypt = update_conn_info(mctx, c, side, record_type, payload);
		if (decrypt < 0) {
			handle_malicious(mctx, sock, c, "state update", decrypt);
			return -1;
		}
		if (decrypt > 0) {
			update_iv(ctx->tc_key_info.iv, iv, ctx->tc_record_cnt++);
			decrypt_len = decrypt_ciphertext(g_evp_ctx[mctx->cpu],
											 cipher->buf + cipher->head,
											 plain->buf + plain->tail,
											 ctx->tc_key_info.key, iv,
											 parse_len);
			if (decrypt_len < 0) {
				handle_malicious(mctx, sock, c, "decrypt", decrypt_len);
				return -1;
			}
			// consume_plaintext(decrypt_len, plain->buf + plain->tail);
			plain->tail += decrypt_len;
			if (plain->tail + MAX_RECORD_LEN > MAX_BUF_LEN)
				plain->tail = 0;
			total += decrypt_len;
		}
		/* move to next record */
		cipher->head += TLS_HEADER_LEN + parse_len;
	}
	return total;
}
/*----------------------------------------------------------------------------*/
/* Allocate new chunk from raw packet mempool for raw packet buffer
 * Copy the last raw packet to raw packet buffer
 */
static inline int
copy_lastpkt(mctx_t mctx, int sock, int side, conn_info *c)
{
	pkt_vec *rp = c->ci_raw_pkt + c->ci_raw_cnt;
	if (!rp->data)
		if (!(rp->data = MPAllocateChunk(g_rawpkt_pool[mctx->cpu]))) {
			ERROR_PRINT("Error: [%s] rawpkt pool alloc failed\n", __FUNCTION__);
			exit(EXIT_FAILURE);
		}
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
	struct pkt_info p;
	if (mtcp_getlastpkt(mctx, sock, side, &p) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet info\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	memcpy(rp->data, p.ethh, p.eth_len);
	rp->len = p.eth_len;
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, sock, side, &pctx) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	memcpy(rp->data, pctx->p.ethh, pctx->p.eth_len);
	rp->len = pctx->p.eth_len;
	c->ci_raw_len += rp->len;
	c->ci_raw_cnt++;
#endif
	if ((c->ci_raw_cnt == MAX_RAW_PKT_NUM) ||
		(c->ci_raw_len > MAX_RAW_PKT_BUF_LEN)) {
		MPFreeChunk(g_rawpkt_pool[mctx->cpu], rp->data);
		c->ci_raw_cnt = c->ci_raw_len = 0;
		return -1;
	}
	(rp + 1)->data = rp->data + rp->len;
	return 0;
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
			ERROR_PRINT("Failed to send stalled packets\n");
			break;
		}
		rp++;
	}
#if VERBOSE_STALL
	fprintf(stderr,
			"\n--------------------------------------------------\n"
			"[%s] core: %d, sock: %u\nsent %d stalled pkts!\n",
			__FUNCTION__, mctx->cpu, c->ci_sock, c->ci_raw_cnt);
#endif
	MPFreeChunk(g_rawpkt_pool[mctx->cpu], c->ci_raw_pkt->data);
	c->ci_raw_cnt = c->ci_raw_len = 0;
}
/*----------------------------------------------------------------------------*/
/* Create connection structure for new connection */
static void
cb_create(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	conn_info *c;
	if (!(c = (conn_info *)MPAllocateChunk(g_ci_pool[mctx->cpu]))) {
		ERROR_PRINT("Error: [%s] conn info pool alloc failed\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	/* MPAlloc needs memset */
	memset(c, 0, sizeof(conn_info));
	/* Fill values of the connection structure */
	c->ci_sock = sock;
#if DEBUG_SOCKET
	socklen_t addrslen = sizeof(struct sockaddr) * 2;
	struct sockaddr addrs[2];
	if (mtcp_getpeername(mctx, sock, addrs, &addrslen,
						 MOS_SIDE_BOTH) < 0) {
		perror("mtcp_getpeername");
		/* it's better to stop here and do debugging */
		exit(EXIT_FAILURE);
	}
#endif
	/* Insert the structure to the queue */
	if (st_insert(g_st[mctx->cpu], sock, c, g_st_element[mctx->cpu]) < 0) {
		ERROR_PRINT("Error: [core %d] st_insert() call"
					"with duplicate socket..\n", mctx->cpu);
		MPFreeChunk(g_ci_pool[mctx->cpu], c);
		return;
	}
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
	if (c->ci_tls_state < TLS_ESTABLISHED) {
		handle_malicious(mctx, sock, c, "early fin", -12);
		return;
	}
	if (!has_key(c)) {
		c->ci_tls_state = TO_BE_DESTROYED;
		return;
	}
	remove_conn_info(mctx, c, 0);
}
/*----------------------------------------------------------------------------*/
/* Called when received new packet from monitoring stream socket */
static void
cb_new_data(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	conn_info *c;
	tls_buffer *cipher, *plain;
	int len;
	
	/* data callback is only for follower cores */
	assert((g_max_cores == 1) || (mctx->cpu != LEADER_CORE));

	if (!(c = st_search(g_st[mctx->cpu], sock)))
		return;
	/* allocate mempool if needed */
	cipher = &c->ci_tls_ctx[side].tc_cipher;
	if (!cipher->buf) {
		if (!(cipher->buf = MPAllocateChunk((side == MOS_SIDE_CLI)?
				g_cli_cipher_pool[mctx->cpu]:g_svr_cipher_pool[mctx->cpu]))) {
			ERROR_PRINT("Error: [%s] record pool alloc failed\n", __FUNCTION__);
			exit(EXIT_FAILURE);
		}
	}
	plain = &c->ci_tls_ctx[side].tc_plain;
	if (!plain->buf) {
		if (!(plain->buf = MPAllocateChunk((side == MOS_SIDE_CLI)?
				g_cli_plain_pool[mctx->cpu]:g_svr_plain_pool[mctx->cpu]))) {
			ERROR_PRINT("Error: [%s] plaintext pool alloc failed\n", __FUNCTION__);
			exit(EXIT_FAILURE);
		}
	}
#if IPS
	if ((c->ci_tls_state >= TLS_ESTABLISHED) && !has_key(c))
	{
		if (copy_lastpkt(mctx, sock, side, c) < 0)
			handle_malicious(mctx, sock, c, "too late key", 0);
		if (mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP) < 0) {
			ERROR_PRINT("Error: [%s] drop failed\n", __FUNCTION__);
			exit(EXIT_FAILURE);
		}
		return;
	}
#endif
PEEK:
	if ((len = mtcp_peek(mctx, sock, side, (char *)cipher->buf + cipher->tail,
						 MAX_BUF_LEN - cipher->tail)) <= 0)
		return;
	cipher->tail += len;
#if IDS
	if ((c->ci_tls_state >= TLS_ESTABLISHED) && !has_key(c))
	{
        if (cipher->tail == MAX_BUF_LEN)
			/* ToDo: allocate more pool */
            ERROR_PRINT("Warning: Buffer over write might cause fatal error!\n");
        return;
	}
#endif
	if ((len = process_data(mctx, sock, side, c, cipher, plain)) < 0)
		return;
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
/* Called when received new key packet from raw monitoring socket */
static void
cb_new_key(mctx_t mctx, int rsock, int side, uint64_t events, filter_arg_t *arg)
{
	conn_info *c;
	uint8_t *payload;
#if IDS
	int len;
#endif
	/* key callback is only for leader core */
	assert(mctx->cpu == LEADER_CORE);
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
	struct pkt_info p;
	if (mtcp_getlastpkt(mctx, rsock, side, &p) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet info\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	payload = (uint8_t *)(p.iph) + IP_HEADER_LEN + UDP_HEADER_LEN;
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, rsock, side, &pctx) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	payload = (uint8_t *)(pctx->p.iph) + IP_HEADER_LEN + UDP_HEADER_LEN;
#endif
#if VERBOSE_KEY
	fprintf(stderr, "\n--------------------------------------------------\n");
	fprintf(stderr, "[%s] core: %d, rsock: %d, side: %u\n",
			__FUNCTION__, mctx->cpu, rsock, side);
#endif

	/*
	 * key will be used at mirrored client (server) recv buffer
	 * contents in recv buffer are sent by server (client)
	 * so, save the server (client) key at client (server) context
	 */
	if (g_max_cores == 1) {
		c = ct_search(g_ct[mctx->cpu], payload);
		if (!c)
			return; // ignore this key
		parse_tls_key(payload + TLS_1_3_CLIENT_RANDOM_LEN + 1,
					&c->ci_tls_ctx[MOS_SIDE_SVR].tc_key_info,
					&c->ci_tls_ctx[MOS_SIDE_CLI].tc_key_info);
#if IPS
		send_stalled_pkts(mctx, c);
#elif IDS
		if (len = process_data(mctx, c, MOS_SIDE_CLI,
							  &c->ci_tls_ctx[MOS_SIDE_CLI].tc_cipher,
							  &c->ci_tls_ctx[MOS_SIDE_CLI].tc_plain) < 0)
			return;
		c->ci_tls_ctx[MOS_SIDE_CLI].decrypt_len += len;
		if (len = process_data(mctx, c, MOS_SIDE_SVR,
							  &c->ci_tls_ctx[MOS_SIDE_SVR].tc_cipher,
							  &c->ci_tls_ctx[MOS_SIDE_SVR].tc_plain) < 0)
			return;
		c->ci_tls_ctx[MOS_SIDE_SVR].decrypt_len += len;
		if (c->ci_tls_state == TO_BE_DESTROYED)
			remove_conn_info(mctx, c, 1);
#endif
		return;
	}
	memcpy(g_kt[g_tail].kt_client_random, payload, TLS_1_3_CLIENT_RANDOM_LEN);
	parse_tls_key(payload + TLS_1_3_CLIENT_RANDOM_LEN + 1,
				&g_kt[g_tail].kt_key_info[MOS_SIDE_SVR],
				&g_kt[g_tail].kt_key_info[MOS_SIDE_CLI]);
	g_kt[g_tail].kt_valid = 1;
	if (++g_tail == NUM_BINS)
		g_tail = 0;
#if CNT_CONN
	++g_cnt[mctx->cpu];
#endif
	/* old key should not still exist */
	assert(!g_kt[g_tail].kt_valid);
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
#if IDS
	int len;
#endif
	assert(mctx->cpu != LEADER_CORE);
	while (*tail != g_tail) {
		if (walk->kt_valid) {
			if ((c = ct_search(g_ct[mctx->cpu], walk->kt_client_random))) {
				walk->kt_valid = 0;
				/* copy keys to local hashtable */
				c->ci_tls_ctx[MOS_SIDE_CLI].tc_key_info = walk->kt_key_info[MOS_SIDE_CLI];
				c->ci_tls_ctx[MOS_SIDE_SVR].tc_key_info = walk->kt_key_info[MOS_SIDE_SVR];
#if IPS
				send_stalled_pkts(mctx, c);
#elif IDS
				if (len = process_data(mctx, c, MOS_SIDE_CLI,
									&c->ci_tls_ctx[MOS_SIDE_CLI].tc_cipher,
									&c->ci_tls_ctx[MOS_SIDE_CLI].tc_plain) < 0)
					return;
				c->ci_tls_ctx[MOS_SIDE_CLI].decrypt_len += len;
				if (len = process_data(mctx, c, MOS_SIDE_SVR,
									&c->ci_tls_ctx[MOS_SIDE_SVR].tc_cipher,
									&c->ci_tls_ctx[MOS_SIDE_SVR].tc_plain) < 0)
					return;
				c->ci_tls_ctx[MOS_SIDE_SVR].decrypt_len += len;
				if (c->ci_tls_state == TO_BE_DESTROYED) {
					remove_conn_info(mctx, c, 1);
					return;
				}
#endif
#if VERBOSE_KEY
				fprintf(stderr, "[%s] core: %d tail: %d local_tail: %d\n",
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
	ft.raw_pkt_filter = "ip proto 17 and port " AGENT_PORT;
	/* Only leader core should receive key */
	if (mctx->cpu == LEADER_CORE) {
		if (mtcp_bind_monitor_filter(mctx, rsock, &ft) < 0) {
			fprintf(stderr, "Failed to bind ft to the listening socket!\n");
			exit(EXIT_FAILURE);
		}
		if (mtcp_register_callback(mctx, rsock, MOS_ON_PKT_IN,
								MOS_NULL, cb_new_key)) {
			fprintf(stderr, "Failed to register cb_new_key()\n");
			exit(EXIT_FAILURE);
		}
		return;
	}
	/* For workers, make a per-thread callback to poll shared key table */
	if (mtcp_register_thread_callback(mctx, find_key_and_process)) {
		fprintf(stderr, "Failed to register find_key_and_process()\n");
		exit(EXIT_FAILURE);
	}
	/* to test simple forwarding */
	(void)cb_new_key;
	(void)find_key_and_process;
}
/*----------------------------------------------------------------------------*/
static void
register_data_callback(mctx_t mctx, int msock)
{
	if (mtcp_register_callback(mctx, msock, MOS_ON_CONN_START,
							   MOS_HK_RCV, cb_create)) {
		fprintf(stderr, "Failed to register cb_create()\n");
		exit(EXIT_FAILURE);
	}
	if (mtcp_register_callback(mctx, msock, MOS_ON_CONN_END,
							   MOS_HK_RCV, cb_destroy)) {
		fprintf(stderr, "Failed to register cb_destroy()\n");
		exit(EXIT_FAILURE);
	}
	if (mtcp_register_callback(mctx, msock, MOS_ON_PKT_IN,
							   MOS_HK_RCV, cb_new_data)) {
		fprintf(stderr, "Failed to register cb_new_data()\n");
		exit(EXIT_FAILURE);
	}
	/* to test simple forwarding */
	(void)cb_create;
	(void)cb_destroy;
	(void)cb_new_data;
}
/*----------------------------------------------------------------------------*/
/* Register required callbacks */
static void
register_callbacks(mctx_t mctx)
{
	int msock_raw, msock_stream;
	
	/* Make a raw packet monitoring socket */
	if ((msock_raw = mtcp_socket(mctx, AF_INET,
								 MOS_SOCK_MONITOR_RAW, 0)) < 0) {
		fprintf(stderr, "Failed to create monitor listening socket!\n");
		exit(EXIT_FAILURE);
	}
	/* Register raw packet callback for key delivery */
	register_key_callback(mctx, msock_raw);

	/* Make a stream data monitoring socket */
	if ((msock_stream = mtcp_socket(mctx, AF_INET,
									MOS_SOCK_MONITOR_STREAM, 0)) < 0) {
		fprintf(stderr, "Failed to create monitor listening socket!\n");
		exit(EXIT_FAILURE);
	}
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
			if ((rc = atoi(optarg)) > num_cpus) {
				fprintf(stderr, "Failed to set core number "
								"(request %u, but only %u available)\n",
						rc, num_cpus);
				exit(EXIT_FAILURE);
			}
			num_cpus = rc;
			break;
		case 'f':
			fname = optarg;
			break;
		case 'p':
			strcpy(g_port, optarg);
			break;
		default:
			printf("Usage: %s [-c num of cores] "
				   "[-f mos config_file] "
				   "[-p port from agent]\n",
				   argv[0]);
			return 0;
		}

	g_max_cores = num_cpus;

	/* parse mos configuration file */
	if (mtcp_init(fname)) {
		fprintf(stderr, "Failed to initialize mtcp.\n");
		exit(EXIT_FAILURE);
	}

	/* set the core limit */
	mtcp_getconf(&mcfg);
	mcfg.num_cores = g_max_cores;
	mtcp_setconf(&mcfg);

	/* Register signal handler */
	mtcp_register_signal(SIGINT, sigint_handler);

#if CORRECTNESS_CHECK
	/* to check correctness */
	if ((g_fp = fopen("plaintext.txt", "a+w")) < 0) {
		ERROR_PRINT("Error: open() failed");
		exit(EXIT_FAILURE);
	}
#endif
	
	/* create global key table */
	if (!(g_kt = (keytable *)calloc(NUM_BINS, sizeof(keytable)))) {
		ERROR_PRINT("Error: [%s] key table alloc failed\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < g_max_cores; i++) {
		/* create hash table */
		g_ct[i] = ct_create();
		g_st[i] = st_create();
		/* create CIPHER context */
		if (!(g_evp_ctx[i] = EVP_CIPHER_CTX_new())) {
			ERROR_PRINT("Error: cipher ctx creation failed\n");
			exit(EXIT_FAILURE);
		}
		/* create mem pools */
		/* 1. conn info mempool */
		if (!(g_ci_pool[i] = MPCreate(sizeof(conn_info),
						sizeof(conn_info) * mcfg.max_concurrency, 0))) {
			ERROR_PRINT("Error: [%s] conn info pool create failed\n", __FUNCTION__);
			exit(EXIT_FAILURE);
		}
		/* 2. socket based hashtable element mempool */
		if (!(g_st_element[i] = MPCreate(sizeof(st_element),
						sizeof(st_element) * mcfg.max_concurrency, 0))) {
			ERROR_PRINT("Error: [%s] st_element pool create failed\n", __FUNCTION__);
			exit(EXIT_FAILURE);
		}
		/* 3. client random based hashtable element mempool */
		if (!(g_ct_element[i] = MPCreate(sizeof(ct_element),
						sizeof(ct_element) * mcfg.max_concurrency, 0))) {
			ERROR_PRINT("Error: [%s] ct_element pool create failed\n", __FUNCTION__);
			exit(EXIT_FAILURE);
		}
		/* 4. raw packet buffer mempool */
		if (!(g_rawpkt_pool[i] = MPCreate(MAX_RAW_PKT_BUF_LEN,
							MAX_RAW_PKT_BUF_LEN * mcfg.max_concurrency, 0))) {
			ERROR_PRINT("Error: [%s] rawpkt pool create failed\n", __FUNCTION__);
			exit(EXIT_FAILURE);
		}
		/* 5. client side cipher buffer mempool */
		if (!(g_cli_cipher_pool[i] = MPCreate(MAX_BUF_LEN,
							MAX_BUF_LEN * mcfg.max_concurrency, 0))) {
			ERROR_PRINT("Error: [%s] cli ciphertext pool create failed\n", __FUNCTION__);
			exit(EXIT_FAILURE);
		}
		/* 6. client side plain buffer mempool */
		if (!(g_cli_plain_pool[i] = MPCreate(MAX_BUF_LEN,
							MAX_BUF_LEN * mcfg.max_concurrency, 0))) {
			ERROR_PRINT("Error: [%s] cli plaintext pool create failed\n", __FUNCTION__);
			exit(EXIT_FAILURE);
		}
		/* 7. server side cipher buffer mempool */
		/* server side receive buffer is supposed to be much smaller */
		if (!(g_svr_cipher_pool[i] = MPCreate(MAX_BUF_LEN_SVR,
							MAX_BUF_LEN_SVR * mcfg.max_concurrency, 0))) {
			ERROR_PRINT("Error: [%s] svr ciphertext pool create failed\n", __FUNCTION__);
			exit(EXIT_FAILURE);
		}
		/* 8. server side plain buffer mempool */
		/* server side receive buffer is supposed to be much smaller */
		if (!(g_svr_plain_pool[i] = MPCreate(MAX_BUF_LEN_SVR,
							MAX_BUF_LEN_SVR * mcfg.max_concurrency, 0))) {
			ERROR_PRINT("Error: [%s] svr plaintext pool create failed\n", __FUNCTION__);
			exit(EXIT_FAILURE);
		}
		/* Run mOS for each CPU core */
		if (!(g_mctx[i] = mtcp_create_context(i))) {
			fprintf(stderr, "Failed to craete mtcp context.\n");
			exit(EXIT_FAILURE);
		}
		/* init monitor */
		init_monitor(g_mctx[i]);
	}

	/* wait until all threads finish */
	for (i = 0; i < g_max_cores; i++) {
		mtcp_app_join(g_mctx[i]);
		fprintf(stderr, "Message test thread %d joined.\n", i);
	}

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
		MPDestroy(g_st_element[i]);
		MPDestroy(g_ct_element[i]);
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
