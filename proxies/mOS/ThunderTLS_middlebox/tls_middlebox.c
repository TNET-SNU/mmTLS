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

#define AGENT_UDP_PORT 6666

#define VERBOSE_TCP 0
#define VERBOSE_TLS 0
#define VERBOSE_KEY 0
#define VERBOSE_DEBUG 0

#define UINT32_LT(a, b) ((int32_t)((a) - (b)) < 0)
#define UINT32_LEQ(a, b) ((int32_t)((a) - (b)) <= 0)
#define UINT32_GT(a, b) ((int32_t)((a) - (b)) > 0)
#define UINT32_GEQ(a, b) ((int32_t)((a) - (b)) >= 0)
/*----------------------------------------------------------------------------*/
/* Core */
int g_max_cores;		  /* Number of CPU cores to be used */
mctx_t g_mctx[MAX_CORES]; /* mOS context */
/*----------------------------------------------------------------------------*/
/* Hash table of TLS connections */
struct ct_hashtable *g_ct[MAX_CORES]; /* client random based */
struct st_hashtable *g_st[MAX_CORES]; /* socket based */
/*----------------------------------------------------------------------------*/
/* Multi-core support */
struct keytable *g_kt; /* circular queue of <client random, key> pare */
int l_tail[MAX_CORES] = {0,};
int g_tail = 0;
/*----------------------------------------------------------------------------*/
/* Key log agent port */
int g_port = AGENT_UDP_PORT;
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
static void
hexdump(char *title, uint8_t *buf, size_t len)
{
#if VERBOSE_TCP | VERBOSE_TLS | VERBOSE_KEY | VERBOSE_DEBUG
	if (title)
		fprintf(stderr, "%s\n", title);
	for (size_t i = 0; i < len; i++)
		fprintf(stderr, "%02X%c", buf[i], ((i + 1) % 16 ? ' ' : '\n'));
	fprintf(stderr, "\n");
#endif /* !VERBOSEs */
}
/*----------------------------------------------------------------------------*/
/* Print AAD, TAG, cipher text and decrypted plain text */
static void
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
no_pending_undecrypted(conn_info *c)
{
	return (c->ci_tls_ctx[MOS_SIDE_SVR].tc_buf_off == 
			c->ci_tls_ctx[MOS_SIDE_SVR].tc_undecrypt_tcp_seq) &&
		   (c->ci_tls_ctx[MOS_SIDE_CLI].tc_buf_off == 
			c->ci_tls_ctx[MOS_SIDE_CLI].tc_undecrypt_tcp_seq);
}
/*----------------------------------------------------------------------------*/
static inline bool
has_key(tls_context *ctx)
{
	return (ctx->tc_key_info.key_mask & 0x0f) == 0x0f;
}
/*----------------------------------------------------------------------------*/
static void
remove_conn_info(mctx_t mctx, conn_info *c)
{
	if (!ct_remove(g_ct[mctx->cpu], c->ci_client_random))
	{
		ERROR_PRINT("Error: No session with given client random\n");
	}
	if (!st_remove(g_st[mctx->cpu], c->ci_sock))
	{
		ERROR_PRINT("Error: No session with given sock\n");
	}
	free(c->ci_tls_ctx[MOS_SIDE_CLI].tc_plaintext);
	free(c->ci_tls_ctx[MOS_SIDE_SVR].tc_plaintext);
	free(c);
}
/*----------------------------------------------------------------------------*/
/* Updates IV by XOR'ing it by # of records that have been alrady decrypted */
/* Return updated IV */
static void
update_iv(uint8_t iv[TLS_CIPHER_AES_GCM_256_IV_SIZE],
		  uint8_t updated_iv[TLS_CIPHER_AES_GCM_256_IV_SIZE],
		  uint64_t record_count)
{
	for (int i = 0; i < TLS_CIPHER_AES_GCM_256_IV_SIZE; i++)
	{
		updated_iv[TLS_CIPHER_AES_GCM_256_IV_SIZE - i - 1] =
			iv[TLS_CIPHER_AES_GCM_256_IV_SIZE - i - 1] ^ 
			((record_count >> (i * 8)) & LOWER_8BITS);
	}
}
/*----------------------------------------------------------------------------*/
/* Decrypt single TLS record with given key_info */
/* Return length of decrypted data, -1 of error */
static int
decrypt_ciphertext(mctx_t mctx, uint8_t *data, uint8_t *plain, uint8_t *key, uint8_t *iv)
{
	uint8_t aad[TLS_CIPHER_AES_GCM_256_AAD_SIZE], 
			tag[TLS_CIPHER_AES_GCM_256_TAG_SIZE];
	int final, len = 0, outlen = 0;
	uint8_t *ptr, *cipher;
	EVP_CIPHER_CTX *ctx;
	uint16_t cipher_len;

	/* aad generate */
	memcpy(aad, data, TLS_CIPHER_AES_GCM_256_AAD_SIZE);
	// aad format: type(1B) version(2B) len(2B)
	cipher_len = htons(*(uint16_t *)(aad + 
									 TLS_CIPHER_AES_GCM_256_AAD_SIZE - 
									 sizeof(uint16_t)));
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
	{
		ERROR_PRINT("Error: decrypted text length unmatched!!\n");
	}
	print_text(aad, tag, cipher, plain, cipher_len, outlen);

	if (final <= 0)
		return -1;

	/* ToDo: buffer is saved to plain text even it's not application data */
	return outlen;
}
/*----------------------------------------------------------------------------*/
/* Decrypt parsed TLS client records */
/* Return number of decrypted record, -1 of error */
static int
decrypt_tls_record(mctx_t mctx, tls_context *ctx)
{
	struct tls_crypto_info *key_info = &ctx->tc_key_info;
	int len, decrypted_record_num = 0;
	uint8_t *key, iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
	key = key_info->key;
	
	if (!has_key(ctx))
		return -1;
	/* decrypt all well-recieved records */
	while (ctx->tc_buf_off >= ctx->tc_undecrypt_tcp_seq + 
							   ctx->tc_current_record_len)
	{
		update_iv(key_info->iv, iv, ctx->tc_current_tls_seq);
		len = decrypt_ciphertext(mctx, ctx->tc_buf + ctx->tc_undecrypt_tcp_seq,
								 ctx->tc_plaintext + ctx->tc_plain_len, key, iv);
		if (len < 0) {
			fprintf(stderr, "Error: decrypt failed\n");
			exit(-1); // to be replaced to conn. destroy
		}
		decrypted_record_num++;
		ctx->tc_current_tls_seq++;
		/* ToDo: modify this */
		ctx->tc_undecrypt_tcp_seq += TLS_HEADER_LEN + len +
									 TLS_CIPHER_AES_GCM_256_TAG_SIZE;
		ctx->tc_plain_len += len;
	}

	return decrypted_record_num;
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
	uint32_t start_seq;
	uint8_t *ptr;
	uint8_t record_type;
	uint16_t version;
	uint16_t record_len;
	int *state;
	int decrypt = 0;

	ctx = &c->ci_tls_ctx[side];
	state = &c->ci_tls_state;
	start_seq = ctx->tc_unparse_tcp_seq;

	/* Parse header of new record */
	if (UINT32_GT(start_seq + TLS_HEADER_LEN, ctx->tc_buf_off)) {
		// in this case, TLS header is incomplete, wait for next mtcp_peek
		return 0;
	}
	ptr = ctx->tc_buf + start_seq;
	record_type = *ptr;
	ptr += sizeof(uint8_t);

	version = htons(*(uint16_t *)ptr);
	ptr += sizeof(uint16_t);

	record_len = htons(*(uint16_t *)ptr);
	ptr += sizeof(uint16_t);
	ctx->tc_current_record_len = record_len;

	/* Store TLS record info if complete */
	if (UINT32_GT(start_seq + record_len + TLS_HEADER_LEN, ctx->tc_buf_off)) {
		// in this case, TLS record is incomplete, wait for next mtcp_peek
		return 0;
	}
	ctx->tc_unparse_tcp_seq += TLS_HEADER_LEN + record_len;

	/* Update context */
	/* ToDo: Add parsing cipher suite */
	if (ctx->tc_version < version)
	{
		ctx->tc_version = version;
	}

	/* ToDo: move below to separate function, e.g. PrintTLSStat() */
#if VERBOSE_TLS
	fprintf(stderr, "[%s] Parse new record to follow session!\n",
			__FUNCTION__);
	fprintf(stderr, "Record type %x, length %u (TCP %u ~ %u), "
					"cipher len %u\n",
			record_type, record_len, start_seq,
			start_seq + record_len + TLS_HEADER_LEN,
			record_len);
	if (record_len) {
		hexdump("Dump of ciphertext of the record:", ptr, record_len);
	}
#endif /* VERBOSE_TLS */

	switch(record_type)
	{
		case CHANGE_CIPHER_SPEC:
			if (side == MOS_SIDE_CLI) {
				// record sent by server
				if (*state == SERVER_HELLO_RECV)
					*state = SERVER_CYPHER_SUITE_RECV;
				else {
					ERROR_PRINT("Warning: tls state is not correct 1\n");
					exit(-1); // replace to destroy
				}
			}
			else {
				if (*state == SERVER_CYPHER_SUITE_RECV)
					*state = CLIENT_CYPHER_SUITE_RECV;
				else {
					ERROR_PRINT("Warning: tls state is not correct 2\n");
					exit(-1); // replace to destroy
				}
			}
			break;
		case ALERT:
			break; // we do not handle alert record yet
		case HANDSHAKE:
			if (*ptr == CLIENT_HS)
			{
				ptr += TLS_HANDSHAKE_HEADER_LEN;
				ptr += sizeof(uint16_t); // Client Version (0x0303)

				memcpy(c->ci_client_random, ptr, TLS_1_3_CLIENT_RANDOM_LEN);
				if (ct_insert(g_ct[mctx->cpu], c->ci_client_random, c) < 0)
				{
					ERROR_PRINT("Warning: ct_insert() failed\n");
					exit(-1); // replace to destroy
				}
				if (*state == INITIAL_STATE)
					*state = CLIENT_HELLO_RECV;
				else {
					ERROR_PRINT("Warning: tls state is not correct 3\n");
					exit(-1); // replace to destroy
				}
			}
			else if (*ptr == SERVER_HS)
			{
				if (*state == CLIENT_HELLO_RECV)
					*state = SERVER_HELLO_RECV;
				else {
					ERROR_PRINT("Warning: tls state is not correct 4\n");
					exit(-1); // replace to destroy
				}
			}
			break;
		case APPLICATION_DATA:
			if (*state == SERVER_CYPHER_SUITE_RECV) {
				if (side == MOS_SIDE_CLI) {
					; // record sent by server, seems to be certificate
				}
				else {
					ERROR_PRINT("Warning: this record is suspected as malicious\n");
					exit(-1); // replace to destroy
				}
			}
			else if (*state == CLIENT_CYPHER_SUITE_RECV) {
				if (side == MOS_SIDE_SVR) {
					if (record_len == HS_FINISHED_RECORD_LEN) {
						*state = TLS_ESTABLISHED;
					}
					else {
						ERROR_PRINT("Warning: this record is suspected as malicious\n");
						exit(-1); // replace to destroy
					}
				}
				else {
					ERROR_PRINT("Warning: this record is suspected as malicious\n");
					exit(-1); // replace to destroy
				}
			}
			else if (*state == TLS_ESTABLISHED)
			{
				if (decrypt_tls_record(mctx, ctx) > 0)
					// fprintf(stdout, "decrypt success!\n");
				// this should not happen
				if (no_pending_undecrypted(c) && (c->ci_to_be_destroyed)) {
					fprintf(stderr, "2. distroy by data callback, this should not happen\n");
					remove_conn_info(mctx, c);
				}
				decrypt = 1;
			}
			else
			{
				ERROR_PRINT("Error: unknown TLS state\n");
			}
			break;
		default:
			ERROR_PRINT("Error: unknown record type\n");
			exit(-1); // replace to destroy
	}
	
	if (!decrypt)
		ctx->tc_undecrypt_tcp_seq += TLS_HEADER_LEN + record_len;
		
	return record_len;
}
/*----------------------------------------------------------------------------*/
static void
copy_lastpkt(mctx_t mctx, int side, conn_info *c)
{
#if 1
	raw_pkt *rp = c->tc_raw_buf + c->tc_raw_cnt;
	struct pkt_info *p = &rp->raw_pkt_info;
	
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
	if (mtcp_getlastpkt(mctx, sock, side, p) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context!!!\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, c->ci_sock, side, &pctx) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context!!!\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	// shallow copy
	*p = pctx->p;
#endif
	// deep copy
	memcpy(rp->raw_pkt_buf, p->ethh, p->eth_len);
	c->tc_raw_cnt++;
	if (c->tc_raw_cnt == MAX_RAW_PKT_NUM)
	{
		fprintf(stderr, "Out of raw pkt buffer size\n");
		exit(EXIT_FAILURE); // replace to destroy
	}
	// point to raw buffer
	p->ethh = (struct ethhdr *)rp->raw_pkt_buf;
	p->iph = (struct iphdr *)((uint8_t *)p->ethh + 
							 ((uint8_t *)p->iph - (uint8_t *)p->ethh));
	p->tcph = (struct tcphdr *)((uint8_t *)p->iph + 
							   ((uint8_t *)p->tcph - (uint8_t *)p->iph));
	p->payload = (uint8_t *)p->tcph + 
				 ((uint8_t *)p->payload - (uint8_t *)p->tcph);
#endif
}
/*----------------------------------------------------------------------------*/
static void
send_stalled_pkts(mctx_t mctx, conn_info *c)
{
#if 1
	raw_pkt *rp;
	int i;

#if VERBOSE_TCP
	fprintf(stderr, "\n--------------------------------------------------\n");
	fprintf(stderr, "[%s] core: %d, sock: %u\n",
			__FUNCTION__, mctx->cpu, c->ci_sock);
#endif

	for (i = 0; i < c->tc_raw_cnt; i++)
	{
		rp = c->tc_raw_buf + i;
		if (mtcp_sendpkt_timestamp(mctx, c->ci_sock, &rp->raw_pkt_info) < 0)
		{
			ERROR_PRINT("Error: mtcp_sendpkt() failed\n");
			exit(EXIT_FAILURE);
		}
	}
	c->tc_raw_cnt = 0;
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
	/* ToDo: remove calloc */
	c = calloc(1, sizeof(conn_info));
	if (!c)
	{
		ERROR_PRINT("Error: [%s]calloc failed\n", __FUNCTION__);
		exit(-1);
	}
	c->ci_tls_ctx[MOS_SIDE_CLI].tc_plaintext = calloc(CLI_RECBUF_LEN, sizeof(uint8_t));
	if (!c->ci_tls_ctx[MOS_SIDE_CLI].tc_plaintext)
	{
		ERROR_PRINT("Error: [%s]calloc failed\n", __FUNCTION__);
		exit(-1);
	}
	c->ci_tls_ctx[MOS_SIDE_SVR].tc_plaintext = calloc(SVR_RECBUF_LEN, sizeof(uint8_t));
	if (!c->ci_tls_ctx[MOS_SIDE_SVR].tc_plaintext)
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
		ERROR_PRINT("Error: st_insert() failed\n");
		exit(-1);
	}
}
/*----------------------------------------------------------------------------*/
/* Destroy connection structure */
static void
cb_destroy(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	conn_info *c;
	if (!(c = st_search(g_st[mctx->cpu], sock)))
	{
		return; // replace to drop
	}
	// if decrypted all
	if (no_pending_undecrypted(c)) {
		fprintf(stderr, "0. destroy by teardown callback\n");
		remove_conn_info(mctx, c);
	}
	else {
		c->ci_to_be_destroyed = 1;
	}
}
/*----------------------------------------------------------------------------*/
/* Update connection's TCP state of each side */
static void
cb_new_data(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	uint16_t record_len;
	int len;
	conn_info *c;
	tls_context *ctx;

	if (!(c = st_search(g_st[mctx->cpu], sock)))
	{
		return; // replace to drop
	}

#if VERBOSE_TCP
	fprintf(stderr, "\n--------------------------------------------------\n");
	fprintf(stderr, "[%s] core: %d, sock: %u, c->sock: %u, side: %u\n",
			__FUNCTION__, mctx->cpu, sock, sock, side);
#endif

	ctx = &c->ci_tls_ctx[side];
	while ((len = mtcp_peek(mctx, sock, side,
							(char *)ctx->tc_buf + ctx->tc_buf_off,
							MAX_BUF_LEN - ctx->tc_buf_off)) > 0) {
		ctx->tc_buf_off += len;
		if (ctx->tc_buf_off == MAX_BUF_LEN) {
			break;
		}
	}

	if (len < 0) {
		/* Not in-order TLS packet */
		return;
	}
	/* Reassemble TLS record */
	while ((record_len = parse_and_decrypt_tls_record(mctx, c, side)) > 0)
	{
		;
	}
#if VERBOSE_TCP
	fprintf(stderr, "[%s] from %s, received %u B (seq %u ~ %u) TCP data!\n",
			__FUNCTION__, (side == MOS_SIDE_CLI) ? "server" : "client",
			len, ctx->tc_buf_off, ctx->tc_buf_off + len);
#endif
	/* if buffer is full */
	if (ctx->tc_buf_off == MAX_BUF_LEN) {
		memcpy(ctx->tc_buf, ctx->tc_buf + ctx->tc_unparse_tcp_seq,
				MAX_BUF_LEN - ctx->tc_unparse_tcp_seq);
		/* unparse seq = undecrypt seq after key recieved */
		/* assume this case happens after key recieve */
		ctx->tc_buf_off = MAX_BUF_LEN - ctx->tc_unparse_tcp_seq;
		ctx->tc_unparse_tcp_seq = 0;
		ctx->tc_undecrypt_tcp_seq = 0;
		/* check if un-peeked payload is left */
		len = mtcp_peek(mctx, sock, side,
						(char *)ctx->tc_buf + ctx->tc_buf_off,
						MAX_BUF_LEN - ctx->tc_buf_off);
		if (len > 0) {
			ctx->tc_buf_off += len;
			hexdump(NULL, ctx->tc_buf, ctx->tc_buf_off);
			while ((record_len = parse_and_decrypt_tls_record(mctx, c, side)) > 0)
			{
				;
			}
		}
	}
#if VERBOSE_TCP
	hexdump(NULL, ctx->tc_buf + ctx->tc_buf_off, len);
#endif
	if (c->ci_tls_state == TLS_ESTABLISHED && !has_key(ctx)) {
		copy_lastpkt(mctx, side, c);
		mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP);
	}
}
/*----------------------------------------------------------------------------*/
/* Update connection's TCP state of each side */
static void
cb_new_key(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	uint8_t *payload;
	struct tls_crypto_info *client, *server;
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
	struct pkt_info p;
	if (mtcp_getlastpkt(mctx, sock, side, &p) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context!!!\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	payload = (uint8_t *)(p.iph) + IP_HEADER_LEN + UDP_HEADER_LEN;
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, sock, side, &pctx) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context!!!\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	payload = (uint8_t *)(pctx->p.iph) + IP_HEADER_LEN + UDP_HEADER_LEN;
#endif
#if VERBOSE_KEY
	fprintf(stderr, "\n--------------------------------------------------\n");
	fprintf(stderr, "[%s] core: %d, sock: %d, side: %u\n",
			__FUNCTION__, mctx->cpu, sock, side);
#endif
	memcpy(g_kt[g_tail].kt_client_random, payload, TLS_1_3_CLIENT_RANDOM_LEN);
	payload += TLS_1_3_CLIENT_RANDOM_LEN + 1; // consider '\0'
	
	/*
	 * key will be used at mirrored client (server) recv buffer
	 * contents in recv buffer are sent by server (client)
	 * so, save the server (client) key at client (server) context
	 */
	client = &g_kt[g_tail].kt_key_info[MOS_SIDE_SVR];
	server = &g_kt[g_tail].kt_key_info[MOS_SIDE_CLI];
	parse_tls_key(payload, client, server);
	g_kt[g_tail].kt_valid = 1;
	if (++g_tail >= NUM_BINS * g_max_cores)
		g_tail = 0;
	// if old key still exists
	assert(!g_kt[g_tail].kt_valid);
}
/*----------------------------------------------------------------------------*/
static bool
check_is_key(mctx_t mctx, int msock, int side, uint64_t events, filter_arg_t *arg)
{
	struct iphdr *iph;
	struct udphdr *udph;
#ifdef MTCP_CB_GETCURPKT_CREATE_COPY
	struct pkt_info p;
	if (mtcp_getlastpkt(mctx, msock, side, &p) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context!!!\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	iph = p.iph;
#else
	struct pkt_ctx *pctx;
	if (mtcp_getlastpkt(mctx, msock, side, &pctx) < 0)
	{
		fprintf(stderr, "[%s] Failed to get packet context!!!\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
	iph = pctx->p.iph;
#endif
	udph = (struct udphdr *)(iph + 1);
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
	int i, found = 0;
	conn_info *c;
	struct keytable *walk;
	tls_context *ctx_cli, *ctx_srv;

	if (l_tail[mctx->cpu] == g_tail)
		return;

	for (i = l_tail[mctx->cpu]; i != g_tail; i++)
	{
		if (i == g_max_cores * NUM_BINS)
			i = 0;
		if (found)
			break;
		walk = g_kt + i;
		if (!walk->kt_valid)
			continue;
		c = ct_search(g_ct[mctx->cpu], walk->kt_client_random);
		if (!c)
		{
#if VERBOSE_KEY
			fprintf(stderr, "search failed\n");
#endif
			continue;
		}
		/* copy keys to local hashtable */
		ctx_cli = c->ci_tls_ctx;
		ctx_srv = ctx_cli + 1;
		ctx_cli->tc_key_info = walk->kt_key_info[MOS_SIDE_CLI];
		ctx_srv->tc_key_info = walk->kt_key_info[MOS_SIDE_SVR];
		walk->kt_valid = 0;
		found = 1;
	}
#if VERBOSE_KEY
	fprintf(stderr, "[%s] core: %d found: %d tail: %d local_tail[%d]: %d\n",
			__FUNCTION__, mctx->cpu, found, g_tail, mctx->cpu, l_tail[mctx->cpu]);
#endif
	l_tail[mctx->cpu] = i;
	if (!found)
		return;

	assert(has_key(ctx_cli) && has_key(ctx_srv));

	// if found key, decrypt buffered record
	decrypt_tls_record(mctx, ctx_cli);
	decrypt_tls_record(mctx, ctx_srv);

	/*
	* ToDo: call some DPI logic here
	* 1. evaluate app data
	* 2. drop this pkt if needed
	* 3. remove raw pkts if needed
	*/

	// if no problem
	
	if (c->tc_raw_cnt > 0) {
		send_stalled_pkts(mctx, c);
	}
	if (no_pending_undecrypted(c) && (c->ci_to_be_destroyed)) {
		fprintf(stderr, "1. destroy in key recv, fast teardown\n");
		remove_conn_info(mctx, c);
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
	// if (mtcp_register_callback(mctx, msock, MOS_ON_CONN_NEW_DATA,
	// 						   MOS_NULL, cb_new_data))
	if (mtcp_register_callback(mctx, msock, MOS_ON_PKT_IN,
							   MOS_HK_SND, cb_new_data))
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
	int msock_key, msock_stream;

	/* Make a raw packet monitoring socket */
	if ((msock_key = mtcp_socket(mctx, AF_INET,
								MOS_SOCK_MONITOR_RAW, 0)) < 0)
	{
		fprintf(stderr, "Failed to create monitor listening socket!\n");
		exit(-1); /* no point in proceeding if we don't have a listening socket */
	}
	/* Register UDE for session key from client */
	union monitor_filter ft = {0};
	ft.raw_pkt_filter = "ip proto 17";
	if (mtcp_bind_monitor_filter(mctx, msock_key, &ft) < 0)
	{
		fprintf(stderr, "Failed to bind ft to the listening socket!\n");
		exit(-1);
	}
	register_sessionkey_callback(mctx, msock_key);

	/* Make a stream data monitoring socket */
	if ((msock_stream = mtcp_socket(mctx, AF_INET,
								   MOS_SOCK_MONITOR_STREAM, 0)) < 0)
	{
		fprintf(stderr, "Failed to create monitor listening socket!\n");
		exit(-1); /* no point in proceeding if we don't have a listening socket */
	}
	/* Register stream data callback for TCP connections */
	register_data_callback(mctx, msock_stream);

	/* Make a per-thread callback to poll shared key table */
	if (mtcp_register_thread_callback(mctx, find_key_and_decrypt))
	{
		fprintf(stderr, "Failed to register find_key_and_decrypt()\n");
		exit(EXIT_FAILURE);
	}
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

	g_max_cores = num_cpus;

	/* create hash table */
	for (i = 0; i < g_max_cores; i++)
	{
		g_ct[i] = ct_create();
		g_st[i] = st_create();
	}
	g_kt = (struct keytable *)calloc(g_max_cores * NUM_BINS, sizeof(struct keytable));
	if (!g_kt)
	{
		ERROR_PRINT("Error: calloc() failed\n");
		exit(-1);
	}

	/* create CIPHER context */
	for (i = 0; i < g_max_cores; i++) {
		g_evp_ctx[i] = EVP_CIPHER_CTX_new();
		if (!g_evp_ctx[i]) {
			ERROR_PRINT("Error: cipher ctx creation failed\n");
			exit(-1);
		}
	}

	/* parse mos configuration file */
	ret = mtcp_init(fname);
	if (ret)
	{
		fprintf(stderr, "Failed to initialize mtcp.\n");
		exit(EXIT_FAILURE);
	}

	/* set the core limit */
	mtcp_getconf(&mcfg);
	mcfg.num_cores = g_max_cores;
	mtcp_setconf(&mcfg);

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
	free(g_kt);
	for (i = 0; i < g_max_cores; i++) {
		EVP_CIPHER_CTX_free(g_evp_ctx[i]);
	}

	return EXIT_SUCCESS;
}
/*----------------------------------------------------------------------------*/
