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

#include <openssl/evp.h>

#include <mos_api.h>
#include "cpu.h"
#include "include/tls.h"
#include "include/thash.h"
#include "../util/include/rss.h"
#include <rte_mbuf.h>

/* Maximum CPU cores */
#define MAX_CORES 16
/* Number of TCP flags to monitor */
#define NUM_FLAG 6
/* Default path to mOS configuration file */
#define MOS_CONFIG_FILE "config/mos.conf"

#define IP_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define TCP_HEADER_LEN 20
#define TLS_HEADER_LEN 5

#define MAX_LINE_LEN 1280

#define AGENT_SRC_IP 0x0a000109
#define AGENT_DST_IP 0x0a00010c
#define AGENT_PORT 6666

#define VERBOSE_TCP 0
#define VERBOSE_TLS 0
#define VERBOSE_KEY 0
#define VERBOSE_STALL 0
#define VERBOSE_DEBUG 0

#define UINT32_LT(a, b) ((int32_t)((a) - (b)) < 0)
#define UINT32_LEQ(a, b) ((int32_t)((a) - (b)) <= 0)
#define UINT32_GT(a, b) ((int32_t)((a) - (b)) > 0)
#define UINT32_GEQ(a, b) ((int32_t)((a) - (b)) >= 0)
#define UINT64_LT(a, b) ((int64_t)((a) - (b)) < 0)
#define UINT64_LEQ(a, b) ((int64_t)((a) - (b)) <= 0)
#define UINT64_GT(a, b) ((int64_t)((a) - (b)) > 0)
#define UINT64_GEQ(a, b) ((int64_t)((a) - (b)) >= 0)

#define CORRECTNESS_CHECK_MODE 0
#define MBUF_OFF 256
#define USE_MBUF 1
/*----------------------------------------------------------------------------*/
/* Core */
int g_max_cores;		  /* Number of CPU cores to be used */
mctx_t g_mctx[MAX_CORES]; /* mOS context */
#if USE_MBUF
static struct rte_mempool *g_mem_pool[MAX_CORES] = {NULL};
#endif
static FILE *g_fp;
/*----------------------------------------------------------------------------*/
/* Hash table of TLS connections */
struct ct_hashtable *g_ct[MAX_CORES]; /* client random based */
struct st_hashtable *g_st[MAX_CORES]; /* socket based */
/*----------------------------------------------------------------------------*/
/* Multi-core support */
struct keytable *g_kt; /* circular queue of <client random, key> pare */
int l_tail[MAX_CORES] = {
	0,
};
int g_tail = 0;
/*----------------------------------------------------------------------------*/
/* Key log agent */
int g_ip = AGENT_DST_IP;
int g_port = AGENT_PORT;
// static pthread_t g_thread;
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
	exit(0);
}
/*----------------------------------------------------------------------------*/
/* Dump bytestream in hexademical form */
static inline void
hexdump(char *title, uint8_t *buf, size_t len)
{
#if VERBOSE_TCP | VERBOSE_TLS | VERBOSE_KEY | VERBOSE_STALL | VERBOSE_DEBUG
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
has_key(tls_context *ctx)
{
	return (ctx->tc_key_info.key_mask & 0x0f) == 0x0f;
}
/*----------------------------------------------------------------------------*/
static int
consume_plaintext(uint32_t len, uint8_t *text)
{
#if CORRECTNESS_CHECK_MODE
	int i = 0;
	for (i = 0; i < len; i++)
		fprintf(g_fp, "%02X", text[i]);
	return i;
#else
	return len;
#endif
}
/*----------------------------------------------------------------------------*/
static inline void
remove_conn_info(mctx_t mctx, conn_info *c, int code)
{
	static int i = 0;
	if (!ct_remove(g_ct[mctx->cpu], c->ci_client_random))
		ERROR_PRINT("Error: No session with given client random\n");
	if (!st_remove(g_st[mctx->cpu], c->ci_sock))
		ERROR_PRINT("Error: No session with given sock\n");
	fprintf(stderr, "Destroy with code %d \nCORE: %d\nCLIENT: %lu B\nSERVER: %lu B\nRecord#: %lu\n%d\n",
		code, mctx->cpu,
		c->ci_tls_ctx[MOS_SIDE_CLI].decrypt_len,
		c->ci_tls_ctx[MOS_SIDE_SVR].decrypt_len,
		c->ci_tls_ctx[MOS_SIDE_CLI].tc_record_cnt + 
		c->ci_tls_ctx[MOS_SIDE_SVR].tc_record_cnt, ++i);
#if USE_MBUF
	rte_pktmbuf_free((struct rte_mbuf *)((uint8_t *)c - MBUF_OFF));
#else
	free(c);
#endif
}
/*----------------------------------------------------------------------------*/
/* Updates IV by XOR'ing it by # of records that have been alrady decrypted */
/* Return updated IV */
static inline void
update_iv(uint8_t iv[TLS_CIPHER_AES_GCM_256_IV_SIZE],
		  uint8_t updated_iv[TLS_CIPHER_AES_GCM_256_IV_SIZE],
		  uint64_t record_count)
{
	for (int i = 0; i < TLS_CIPHER_AES_GCM_256_IV_SIZE; i++)
		updated_iv[TLS_CIPHER_AES_GCM_256_IV_SIZE - i - 1] =
			iv[TLS_CIPHER_AES_GCM_256_IV_SIZE - i - 1] ^
			((record_count >> (i * 8)) & LOWER_8BITS);
}
/*----------------------------------------------------------------------------*/
/* Decrypt single TLS record with given key_info */
/* Return length of decrypted data, -1 of error */
static int
decrypt_ciphertext(mctx_t mctx, uint8_t *data, uint16_t cipher_len, uint8_t *plain, uint8_t *key, uint8_t *iv)
{
	uint8_t aad[TLS_CIPHER_AES_GCM_256_AAD_SIZE],
		tag[TLS_CIPHER_AES_GCM_256_TAG_SIZE];
	int final, len = 0, outlen = 0;
	uint8_t *ptr, *cipher;
	EVP_CIPHER_CTX *ctx;

	/* aad generate */
	memcpy(aad, data, TLS_CIPHER_AES_GCM_256_AAD_SIZE);
	// aad format: type(1B) version(2B) len(2B)
	// cipher_len = htons(*(uint16_t *)(aad +
	// 								 TLS_CIPHER_AES_GCM_256_AAD_SIZE -
	// 								 sizeof(uint16_t)));
	if (*aad != APPLICATION_DATA)
	{
		// this should not happen
		ERROR_PRINT("Error: Not APPLICATION DATA!!\n");
		return 0;
	}

	/* tag generate */
	ptr = data + TLS_HEADER_LEN + cipher_len -
		  TLS_CIPHER_AES_GCM_256_TAG_SIZE;
	memcpy(tag, ptr, TLS_CIPHER_AES_GCM_256_TAG_SIZE);
	cipher_len -= TLS_CIPHER_AES_GCM_256_TAG_SIZE;

	/* decrypt cipher text */
	cipher = data + TLS_HEADER_LEN;

	ctx = g_evp_ctx[mctx->cpu];
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
	{
		ERROR_PRINT("Error: Init algorithm failed\n");
		exit(-1);
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
							 TLS_CIPHER_AES_GCM_256_IV_SIZE, NULL))
	{
		ERROR_PRINT("Error: SET_IVLEN failed\n");
		exit(-1);
	}

	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
	{
		ERROR_PRINT("Error: Set KEY/IV faield\n");
		exit(-1);
	}

	if (!EVP_DecryptUpdate(ctx, NULL, &len, aad,
						   TLS_CIPHER_AES_GCM_256_AAD_SIZE))
	{
		ERROR_PRINT("Error: Set AAD failed\n");
		exit(-1);
	}

	if (!EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len))
	{
		ERROR_PRINT("Error: Decrypt failed\n");
		exit(-1);
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
							 TLS_CIPHER_AES_GCM_256_TAG_SIZE, tag))
	{
		ERROR_PRINT("Error: Set expected TAG failed\n");
		exit(-1);
	}

	outlen += len;
	// positive is success
	final = EVP_DecryptFinal_ex(ctx, plain + len, &len);
	outlen += len;

	/* print value and results */
	if (cipher_len != outlen)
		ERROR_PRINT("Error: decrypted text length unmatched!!\n");
	print_text(aad, tag, cipher, plain, cipher_len, outlen);

	if (final <= 0)
		return -1;

	/* ToDo: buffer is saved to plain text even it's not application data */
	return outlen;
}
/*----------------------------------------------------------------------------*/
/* Decrypt parsed TLS client records */
/* Return decrypted bytes, -1 of error */
static int
decrypt_tls_record(mctx_t mctx, tls_context *ctx, uint8_t *data, uint16_t record_len)
{
	struct tls_crypto_info *key_info = &ctx->tc_key_info;
	int len, consume;
	uint8_t iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];

	/* decrypt all well-recieved records */
	update_iv(key_info->iv, iv, ctx->tc_record_cnt);
	len = decrypt_ciphertext(mctx, data, record_len,
							ctx->tc_plaintext + ctx->tc_plain_len,
							key_info->key, iv);
	if (len < 0)
	{
		fprintf(stderr, "Error: decrypt failed\n");
		exit(-1); // to be replaced to conn. destroy
	}
	ctx->tc_record_cnt++;
	ctx->decrypt_len += len;
	
	consume = consume_plaintext(len, ctx->tc_plaintext + ctx->tc_plain_len);
	if (consume != len)
		fprintf(stderr, "Consumption late\n");
	ctx->tc_plain_len += len;
	if (ctx->tc_plain_len + MAX_RECORD_LEN > PLAIN_BUF_LEN)
		ctx->tc_plain_len = 0; /* reuse plain text buffer */

	return len;
}
/*----------------------------------------------------------------------------*/
/* Parse payload to get TLS session key data into key_info */
/* Return length of parsed data, -1 of error */
static int
parse_tls_key(uint8_t *data, struct tls_crypto_info *client, struct tls_crypto_info *server)
{
	uint16_t cipher_suite, key_mask;
	char *ptr = NULL;
	int key_len, iv_len;

	assert(client && server);

	ptr = (char *)data;
	cipher_suite = ntohs(*(uint16_t *)ptr);
	// client->cipher_type = cipher_suite;
	// server->cipher_type = cipher_suite;
	key_len = TLS_CIPHER_AES_GCM_256_KEY_SIZE;
	iv_len = TLS_CIPHER_AES_GCM_256_IV_SIZE;
	ptr += sizeof(cipher_suite);

	key_mask = ntohs(*((uint16_t *)ptr));
	client->key_mask |= key_mask;
	server->key_mask |= key_mask;
	ptr += sizeof(key_mask);

	if (key_mask & CLI_KEY_MASK)
	{
		memcpy(client->key, ptr, key_len);
		ptr += key_len;
	}
	if (key_mask & SRV_KEY_MASK)
	{
		memcpy(server->key, ptr, key_len);
		ptr += key_len;
	}
	if (key_mask & CLI_IV_MASK)
	{
		memcpy(client->iv, ptr, iv_len);
		ptr += iv_len;
	}
	if (key_mask & SRV_IV_MASK)
	{
		memcpy(server->iv, ptr, iv_len);
		ptr += iv_len;
	}
#if VERBOSE_KEY
	hexdump("cli key", client->key, key_len);
	hexdump("srv key", server->key, key_len);
	hexdump("cli iv", client->iv, iv_len);
	hexdump("srv iv", server->iv, iv_len);
#endif

	return ptr - (char *)data;
}
/*----------------------------------------------------------------------------*/
/* Parse TCP payload to assemble single TLS record sending to server */
/* Return byte of parsed record, 0 if no complete record */

/*
 * !Notice!
 *
 * side == MOS_SIDE_CLI means
 * client side recv buffer, whose contents are from server
 * side == MOS_SIDE_SVR means
 * server side recv buffer, whose contents are from client
 *
 */

static uint16_t
parse_and_decrypt_tls_record(mctx_t mctx, conn_info *c, int side)
{
	tls_context *ctx;
	uint8_t *ptr;
	uint8_t record_type;
	uint16_t version;
	uint16_t record_len;
	int *state;

	ctx = &c->ci_tls_ctx[side];
	state = &c->ci_tls_state;

	/* Parse header of new record */
	if (UINT64_GT(ctx->tc_tcp_seq + TLS_HEADER_LEN, ctx->tc_record_off))
		return 0; // TLS header is incomplete
	ptr = ctx->tc_record + ctx->tc_tcp_seq;
	record_type = *ptr;
	ptr += sizeof(uint8_t);

	version = htons(*(uint16_t *)ptr);
	ptr += sizeof(uint16_t);

	record_len = htons(*(uint16_t *)ptr);
	ptr += sizeof(uint16_t);

	/* Store TLS record info if complete */
	if (UINT64_GT(ctx->tc_tcp_seq + record_len + TLS_HEADER_LEN, ctx->tc_record_off))
		return 0; // TLS record is incomplete
	ctx->tc_tcp_seq += TLS_HEADER_LEN + record_len;

	/* Update context */
	if (ctx->tc_version < version)
		ctx->tc_version = version;

#if VERBOSE_TLS
	fprintf(stderr, "[%s] Parse new record to follow session!\n",
			__FUNCTION__);
	fprintf(stderr, "Record type %x, length %u (TCP %u ~ %u), "
					"cipher len %u\n",
			record_type, record_len, start_seq,
			start_seq + record_len + TLS_HEADER_LEN,
			record_len);
	if (record_len)
	{
		hexdump("Dump of ciphertext of the record:", ptr, record_len);
	}
#endif /* VERBOSE_TLS */

	switch (record_type)
	{
	case CHANGE_CIPHER_SPEC:
		if ((side == MOS_SIDE_CLI) &&
			(*state == SERVER_HELLO_RECV))
			*state = SERVER_CIPHER_SUITE_RECV;
		else if ((side == MOS_SIDE_SVR) &&
				 (*state == SERVER_CIPHER_SUITE_RECV))
			*state = CLIENT_CIPHER_SUITE_RECV;
		else
			goto MALICIOUS;
		break;
	case ALERT:
		break; // we do not handle alert record yet
	case HANDSHAKE:
		if ((*ptr == CLIENT_HS) && (*state == INITIAL_STATE))
		{
			*state = CLIENT_HELLO_RECV;
			ptr += TLS_HANDSHAKE_HEADER_LEN;
			ptr += sizeof(uint16_t); // Client Version (0x0303)
			memcpy(c->ci_client_random, ptr, TLS_1_3_CLIENT_RANDOM_LEN);
			if (ct_insert(g_ct[mctx->cpu], c->ci_client_random, c) < 0)
			{
				ERROR_PRINT("Error: ct_insert() failed\n");
				exit(-1); // replace to destroy
			}
		}
		else if ((*ptr == SERVER_HS) && (*state == CLIENT_HELLO_RECV))
			*state = SERVER_HELLO_RECV;
		else
			goto MALICIOUS;
		break;
	case APPLICATION_DATA:
		if ((*state == SERVER_CIPHER_SUITE_RECV) && (side == MOS_SIDE_CLI))
			; // record sent by server, seems to be certificate
		else if ((*state == CLIENT_CIPHER_SUITE_RECV) &&
				 (side == MOS_SIDE_SVR) &&
				 (record_len == HS_FINISHED_RECORD_LEN))
			*state = TLS_ESTABLISHED;
		else if (*state == TLS_ESTABLISHED) {
			decrypt_tls_record(mctx, ctx, ptr - TLS_HEADER_LEN, record_len);
			return record_len;
		}
		else
			goto MALICIOUS;
		break;
	default:
		goto MALICIOUS;
	}
	return record_len;

MALICIOUS:
	ERROR_PRINT("Suspected as malicious\n");
	if (mtcp_reset_conn(mctx, c->ci_sock) < 0) {
		ERROR_PRINT("Reset failed\n");
		exit(-1);
	}
	remove_conn_info(mctx, c, 3);
	
	return 0;
}
/*----------------------------------------------------------------------------*/
static inline void
copy_lastpkt(mctx_t mctx, int sock, int side, conn_info *c)
{
#if 1
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
	if (mtcp_getlastpkt(mctx, sock, side, p) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, sock, side, &pctx) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context\n", __FUNCTION__);
		return;
	}
#endif
	raw_pkt *rp = c->ci_raw_pkt + c->ci_raw_cnt;
	/* ToDo: Replace to mempool */
	if (!rp->data)
		rp->data = c->ci_raw_buf;
	memcpy(rp->data, pctx->p.ethh, pctx->p.eth_len);
	rp->len = pctx->p.eth_len;
	(rp + 1)->data = rp->data + rp->len;
	c->ci_raw_cnt++;
#endif
}
/*----------------------------------------------------------------------------*/
static inline void
send_stalled_pkts(mctx_t mctx, conn_info *c)
{
#if 1
	raw_pkt *rp;
	for (int i = 0; i < c->ci_raw_cnt; i++)
	{
		rp = c->ci_raw_pkt + i;
		if (mtcp_sendpkt_raw(mctx, c->ci_sock, rp->data, rp->len) < 0)
			continue;
	}
#if VERBOSE_STALL
	fprintf(stderr, "\n--------------------------------------------------\n");
	fprintf(stderr, "[%s] core: %d, sock: %u\nsent %d stalled pkts!\n",
			__FUNCTION__, mctx->cpu, c->ci_sock, c->tc_raw_cnt);
#endif
	c->ci_raw_cnt = 0;
#endif
}
/*----------------------------------------------------------------------------*/
/* Create connection structure for new connection */
static void
cb_creation(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	socklen_t addrslen = sizeof(struct sockaddr) * 2;
	struct sockaddr addrs[2];
	conn_info *c;
#if USE_MBUF
	c = rte_pktmbuf_mtod(rte_pktmbuf_alloc(g_mem_pool[mctx->cpu]), conn_info *);
#else
	c = calloc(1, sizeof(conn_info));
#endif
	if (!c)
	{
		ERROR_PRINT("Error: [%s]calloc failed\n", __FUNCTION__);
		exit(-1);
	}

	/* Fill values of the connection structure */
	c->ci_sock = sock;
	if (mtcp_getpeername(mctx, sock, addrs, &addrslen,
						 MOS_SIDE_BOTH) < 0)
	{
		perror("mtcp_getpeername");
		/* it's better to stop here and do debugging */
		exit(EXIT_FAILURE);
	}
	/* Insert the structure to the queue */
	if (st_insert(g_st[mctx->cpu], c->ci_sock, c) < 0)
	{
		ERROR_PRINT("Error: st_insert() call with duplicate socket..\n");
	}
}
/*----------------------------------------------------------------------------*/
/* Destroy connection structure */
static void
cb_destroy(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	conn_info *c;
	if (!(c = st_search(g_st[mctx->cpu], sock)))
		return; // replace to drop
	if (has_key(c->ci_tls_ctx) && has_key(c->ci_tls_ctx + 1))
		remove_conn_info(mctx, c, 0);
	else
		c->ci_tls_state = TO_BE_DESTROYED;
}
/*----------------------------------------------------------------------------*/
/* Update connection's TCP state of each side */
static void
cb_new_data(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	int len;
	conn_info *c;
	tls_context *ctx;

	if (!(c = st_search(g_st[mctx->cpu], sock)))
		return; // replace to drop
	
	ctx = &c->ci_tls_ctx[side];
	if (c->ci_tls_state == TLS_ESTABLISHED && !has_key(ctx))
	{
		copy_lastpkt(mctx, sock, side, c);
		mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP);
		return;
	}

PEEK:
	len = mtcp_peek(mctx, sock, side, (char *)ctx->tc_record + ctx->tc_record_off,
					MAX_BUF_LEN - ctx->tc_record_off);
	if (len > 0)
	{
		ctx->tc_record_off += len;
		/* Reassemble TLS record */
		while (parse_and_decrypt_tls_record(mctx, c, side));
	}
	/* if buffer is full */
	if (ctx->tc_record_off == MAX_BUF_LEN)
	{
		memcpy(ctx->tc_record, ctx->tc_record + ctx->tc_tcp_seq,
			   MAX_BUF_LEN - ctx->tc_tcp_seq);
		ctx->tc_record_off = MAX_BUF_LEN - ctx->tc_tcp_seq;
		ctx->tc_tcp_seq = 0;
		goto PEEK;
	}
#if VERBOSE_TCP
	hexdump(NULL, ctx->tc_record + ctx->tc_record, len);
#endif
}
/*----------------------------------------------------------------------------*/
/* Update connection's TCP state of each side */
static void
cb_new_key(mctx_t mctx, int raw_sock, int side, uint64_t events, filter_arg_t *arg)
{
	static int key_num = 0;
	conn_info *c;
	uint8_t *payload;
	struct tls_crypto_info *client, *server;
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
	struct pkt_info p;
	if (mtcp_getlastpkt(mctx, raw_sock, side, &p) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context!!!\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	payload = (uint8_t *)(p.iph) + IP_HEADER_LEN + UDP_HEADER_LEN;
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, raw_sock, side, &pctx) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context!!!\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	payload = (uint8_t *)(pctx->p.iph) + IP_HEADER_LEN + UDP_HEADER_LEN;
#endif
#if VERBOSE_KEY
	fprintf(stderr, "\n--------------------------------------------------\n");
	fprintf(stderr, "[%s] core: %d, raw_sock: %d, side: %u\n",
			__FUNCTION__, mctx->cpu, raw_sock, side);
#endif

	/*
	 * key will be used at mirrored client (server) recv buffer
	 * contents in recv buffer are sent by server (client)
	 * so, save the server (client) key at client (server) context
	 */
	c = ct_search(g_ct[mctx->cpu], payload);
	if (c)
	{
		fprintf(stdout, "key_num: %d\n", ++key_num);
		client = &c->ci_tls_ctx[MOS_SIDE_SVR].tc_key_info;
		server = &c->ci_tls_ctx[MOS_SIDE_CLI].tc_key_info;
		parse_tls_key(payload + TLS_1_3_CLIENT_RANDOM_LEN + 1, client, server);
		send_stalled_pkts(mctx, c);
		return;
	}

	memcpy(g_kt[g_tail].kt_client_random, payload, TLS_1_3_CLIENT_RANDOM_LEN);
	client = &g_kt[g_tail].kt_key_info[MOS_SIDE_SVR];
	server = &g_kt[g_tail].kt_key_info[MOS_SIDE_CLI];
	parse_tls_key(payload + TLS_1_3_CLIENT_RANDOM_LEN + 1, client, server);
	g_kt[g_tail].kt_valid = 1;
	if (++g_tail == NUM_BINS)
		g_tail = 0;
	/* if old key still exists */
	assert(!g_kt[g_tail].kt_valid);
}
/*----------------------------------------------------------------------------*/
static bool
check_is_key(mctx_t mctx, int raw_sock, int side, uint64_t events, filter_arg_t *arg)
{
	struct iphdr *iph;
	struct udphdr *udph;
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
	struct pkt_info p;
	if (mtcp_getlastpkt(mctx, raw_sock, side, &p) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	iph = p.iph;
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, raw_sock, side, &pctx) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	iph = pctx->p.iph;
#endif
	udph = (struct udphdr *)(iph + 1);
#if VERBOSE_KEY
	fprintf(stderr, "\n--------------------------------------------------\n");
	fprintf(stderr, "[%s] core: %d, raw_sock: %d, side: %u\n",
			__FUNCTION__, mctx->cpu, raw_sock, side);
#endif
	return (iph->protocol == IPPROTO_UDP) && (ntohs(udph->dest) == g_port) &&
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
		   (p.ip_len > IP_HEADER_LEN);
#else
		   (pctx->p.ip_len > IP_HEADER_LEN);
#endif
}
/*----------------------------------------------------------------------------*/
static void
find_key_and_decrypt(mctx_t mctx)
{
	static int key_num = 0;
	conn_info *c;
	struct keytable *walk;
	tls_context *ctx_cli, *ctx_srv;

	while (l_tail[mctx->cpu] != g_tail)
	{
		walk = g_kt + l_tail[mctx->cpu];
		if (walk->kt_valid)
		{
			c = ct_search(g_ct[mctx->cpu], walk->kt_client_random);
			if (c)
			{
				fprintf(stdout, "key num: %d\n", ++key_num);
				/* copy keys to local hashtable */
				ctx_cli = c->ci_tls_ctx;
				ctx_srv = ctx_cli + 1;
				ctx_cli->tc_key_info = walk->kt_key_info[MOS_SIDE_CLI];
				ctx_srv->tc_key_info = walk->kt_key_info[MOS_SIDE_SVR];
				send_stalled_pkts(mctx, c);
				walk->kt_valid = 0;
#if VERBOSE_KEY
				fprintf(stderr, "[%s] core: %d tail: %d local_tail: %d\n",
						__FUNCTION__, mctx->cpu, g_tail, l_tail[mctx->cpu]);
#endif
			}
		}
		if (++l_tail[mctx->cpu] == NUM_BINS)
			l_tail[mctx->cpu] = 0;
	}
}
/*----------------------------------------------------------------------------*/
static void
register_sessionkey_callback(mctx_t mctx, int msock)
{
	event_t ude_from_ctrl;
	ude_from_ctrl = mtcp_define_event(MOS_ON_PKT_IN, check_is_key, NULL);
	if (ude_from_ctrl == MOS_NULL_EVENT)
	{
		fprintf(stderr, "mtcp_define_event() failed!");
		exit(EXIT_FAILURE);
	}
	if (mtcp_register_callback(mctx, msock, ude_from_ctrl,
							   MOS_NULL, cb_new_key))
	{
		fprintf(stderr, "Failed to register cb_new_key()\n");
		exit(EXIT_FAILURE);
	}
}
/*----------------------------------------------------------------------------*/
static void
register_data_callback(mctx_t mctx, int msock)
{
	if (mtcp_register_callback(mctx, msock, MOS_ON_CONN_START,
							   MOS_HK_SND, cb_creation))
	{
		fprintf(stderr, "Failed to register cb_creation()\n");
		exit(-1); /* no point in proceeding if callback registration fails */
	}
	if (mtcp_register_callback(mctx, msock, MOS_ON_CONN_END,
							   MOS_HK_SND, cb_destroy))
	{
		fprintf(stderr, "Failed to register cb_destroy()\n");
		exit(-1); /* no point in proceeding if callback registration fails */
	}
	if (mtcp_register_callback(mctx, msock, MOS_ON_PKT_IN,
							   MOS_HK_RCV, cb_new_data))
	{
		fprintf(stderr, "Failed to register cb_new_data()\n");
		exit(-1); /* no point in proceeding if callback registration fails */
	}
}
/*----------------------------------------------------------------------------*/
/* Register required callbacks */
static void
register_callbacks(mctx_t mctx)
{
	int sock_key, msock_stream;
	int master_core;
	// struct sockaddr_in addr;
	// socklen_t addrlen = sizeof(struct sockaddr);

	/* Make a raw packet monitoring socket */
	if ((sock_key = mtcp_socket(mctx, AF_INET,
								 MOS_SOCK_MONITOR_RAW, 0)) < 0)
	{
		fprintf(stderr, "Failed to create monitor listening socket!\n");
		exit(-1); /* no point in proceeding if we don't have a listening socket */
	}
	
	// if ((sock_key = mtcp_socket(mctx, AF_INET,
	// 							 MOS_SOCK_STREAM_LISTEN, 0)) < 0)
	// {
	// 	fprintf(stderr, "Failed to create monitor listening socket!\n");
	// 	exit(-1); /* no point in proceeding if we don't have a listening socket */
	// }
	
    // memset(&addr, 0, addrlen);
    // addr.sin_family = AF_INET;
    // addr.sin_addr.s_addr = htonl(g_ip);
    // addr.sin_port = htons(g_port);
	// if (mtcp_bind(mctx, sock_key, (struct sockaddr *)&addr, addrlen) < 0) {
	// 	fprintf(stderr, "Failed to bind\n");
	// }
	// if (mtcp_listen(mctx, sock_key, 10) < 0) {
	// 	fprintf(stderr, "Failed to listen\n");
	// }
	// if (mtcp_accept(mctx, sock_key, (struct sockaddr *)&addr, &addrlen) < 0) {
	// 	fprintf(stderr, "Failed to accept\n");
	// }
	master_core = GetRSSCPUCore(AGENT_SRC_IP, AGENT_DST_IP,
								AGENT_PORT, AGENT_PORT, g_max_cores);
	/* Register UDE for session key from client */
	union monitor_filter ft = {0};
	ft.raw_pkt_filter = "ip proto 17";
	if (mtcp_bind_monitor_filter(mctx, sock_key, &ft) < 0)
	{
		fprintf(stderr, "Failed to bind ft to the listening socket!\n");
		exit(-1);
	}
	if (mctx->cpu == master_core)
		register_sessionkey_callback(mctx, sock_key);
	else /* For workers, make a per-thread callback to poll shared key table */
		if (mtcp_register_thread_callback(mctx, find_key_and_decrypt))
		{
			fprintf(stderr, "Failed to register find_key_and_decrypt()\n");
			exit(EXIT_FAILURE);
		}

	/* Make a stream data monitoring socket */
	if ((msock_stream = mtcp_socket(mctx, AF_INET,
									MOS_SOCK_MONITOR_STREAM, 0)) < 0)
	{
		fprintf(stderr, "Failed to create monitor listening socket!\n");
		exit(-1); /* no point in proceeding if we don't have a listening socket */
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
	int ret, i;
	char *fname = MOS_CONFIG_FILE; /* path to the default mos config file */
	struct mtcp_conf mcfg;
	/* char tls_middlebox_file[1024] = "config/tls_middlebox.conf"; */
	int num_cpus;
	int opt, rc;
	// struct rte_mempool *mp;

	/* get the total # of cpu cores */
	num_cpus = GetNumCPUs();

	while ((opt = getopt(argc, argv, "c:f:")) != -1)
	{
		switch (opt)
		{
		case 'c':
			if ((rc = atoi(optarg)) > num_cpus)
			{
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
			g_port = atoi(optarg);
			break;
		default:
			printf("Usage: %s [-c num of cores] "
				   "[-f mos config_file] "
				   "[-p port from agent]\n",
				   argv[0]);
			return 0;
		}
	}
	
	/* parse mos configuration file */
	ret = mtcp_init(fname);
	if (ret)
	{
		fprintf(stderr, "Failed to initialize mtcp.\n");
		exit(EXIT_FAILURE);
	}

	g_max_cores = num_cpus;

	/* set the core limit */
	mtcp_getconf(&mcfg);
	mcfg.num_cores = g_max_cores;
	mtcp_setconf(&mcfg);

	/* create hash table */
	for (i = 0; i < g_max_cores; i++)
	{
		g_ct[i] = ct_create();
		g_st[i] = st_create();
#if USE_MBUF
		g_mem_pool[i] = rte_mempool_create(NULL,
							mcfg.max_concurrency,
							sizeof(conn_info), 0, 0,
							rte_pktmbuf_pool_init, NULL,
							rte_pktmbuf_init, NULL,
							rte_lcore_to_socket_id(i), 0);
		if (g_mem_pool[i] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
#endif
	}
	g_kt = (struct keytable *)calloc(NUM_BINS, sizeof(struct keytable));
	if (!g_kt)
	{
		ERROR_PRINT("Error: calloc() failed\n");
		exit(-1);
	}

	/* create CIPHER context */
	for (i = 0; i < g_max_cores; i++)
	{
		g_evp_ctx[i] = EVP_CIPHER_CTX_new();
		if (!g_evp_ctx[i])
		{
			ERROR_PRINT("Error: cipher ctx creation failed\n");
			exit(-1);
		}
	}

	/* to check correctness */
	if ((g_fp = fopen("plaintext.txt", "a+w")) < 0) {
		ERROR_PRINT("Error: open() failed");
		exit(-1);
	}
	
	/* Register signal handler */
	mtcp_register_signal(SIGINT, sigint_handler);

	/* initialize monitor threads */
	for (i = 0; i < g_max_cores; i++)
	{
		/* Run mOS for each CPU core */
		if (!(g_mctx[i] = mtcp_create_context(i)))
		{
			fprintf(stderr, "Failed to craete mtcp context.\n");
			return -1;
		}

		/* init monitor */
		init_monitor(g_mctx[i]);
	}

	/* wait until all threads finish */
	for (i = 0; i < g_max_cores; i++)
	{
		mtcp_app_join(g_mctx[i]);
		fprintf(stderr, "Message test thread %d joined.\n", i);
	}

	mtcp_destroy();
	for (i = 0; i < g_max_cores; i++)
	{
		ct_destroy(g_ct[i]);
		st_destroy(g_st[i]);
	}

	/* free allocated memories */
	for (i = 0; i < g_max_cores; i++)
	{
#if USE_MBUF
		rte_mempool_free(g_mem_pool[i]);
#endif
		EVP_CIPHER_CTX_free(g_evp_ctx[i]);
	}
	free(g_kt);

	return EXIT_SUCCESS;
}
/*----------------------------------------------------------------------------*/
