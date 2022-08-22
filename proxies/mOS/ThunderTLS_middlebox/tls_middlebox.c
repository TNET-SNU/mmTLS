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
#define MAX_CORES       16
/* Number of TCP flags to monitor */
#define NUM_FLAG        6
/* Default path to mOS configuration file */
#define MOS_CONFIG_FILE     "config/mos.conf"

/* multicore mode */
#define MC				1

#define IP_HEADER_LEN    		  20
#define UDP_HEADER_LEN   		  8
#define TLS_HEADER_LEN   		  5
#define TLS_HANDSHAKE_HEADER_LEN  4

#define MAX_LINE_LEN     1280

#define UDP_PORT      6666		/* only for debug */

#define VERBOSE_TCP   	0
#define VERBOSE_TLS   	0
#define VERBOSE_KEY   	0
#define VERBOSE_DEBUG   0

#define UINT32_LT(a,b)         ((int32_t)((a)-(b)) < 0)
#define UINT32_LEQ(a,b)        ((int32_t)((a)-(b)) <= 0)
#define UINT32_GT(a,b)         ((int32_t)((a)-(b)) > 0)
#define UINT32_GEQ(a,b)        ((int32_t)((a)-(b)) >= 0)
/*----------------------------------------------------------------------------*/
int g_max_cores;                              /* Number of CPU cores to be used */
mctx_t g_mctx[MAX_CORES];                     /* mOS context */
struct ct_hashtable **g_ct;					  /* hash table of connections with client random */
struct st_hashtable **g_st;					  /* hash table of connections with socket */
#if MC
typedef struct shared_q {					  /* key pair <client_random, key> */
	conn_info ci;
	int valid;
} shared_q;
struct shared_q *g_shared_q;				  /* circular queue of <client random, key> pare */
int local_tail[MAX_CORES];
int tail = 0;
#endif
/*----------------------------------------------------------------------------*/
/* Signal handler */
static void
sigint_handler(int signum)
{
    int i;

    /* Terminate the program if any interrupt happens */
    for (i = 0; i < g_max_cores; i++) {
        mtcp_destroy_context(g_mctx[i]);
	}

	exit(0);
}
/*----------------------------------------------------------------------------*/
/* Dump bytestream in hexademical form */
#if VERBOSE_TCP | VERBOSE_TLS | VERBOSE_KEY | VERBOSE_DEBUG
static void
hexdump(char *title, uint8_t *buf, size_t len)
{
	size_t i;

	if (title)
		fprintf(stderr, "%s\n", title);

    for (i = 0; i < len; i++)
		fprintf(stderr, "%02X%c", buf[i],
				((i + 1) % 16 ? ' ' : '\n'));
	fprintf(stderr, "\n");
}
#else
static void
hexdump(char *title, uint8_t *buf, size_t len)
{
}
#endif	/* !VERBOSEs */
/*----------------------------------------------------------------------------*/
/* Print AAD, TAG, cipher text and decrypted plain text */
#if VERBOSE_DEBUG
static void
print_text(uint8_t *aad, uint8_t *tag, uint8_t *cipher, uint8_t *plain, 
		   int cipher_len, int plain_len)
{
	fprintf(stderr,"*--------------------------------------------------------*\n");
	hexdump("[aad]", aad, TLS_CIPHER_AES_GCM_256_AAD_SIZE);
	hexdump("[tag]", tag, TLS_CIPHER_AES_GCM_256_TAG_SIZE);

	fprintf(stderr,"ciphertext_len: 0x%x\n", cipher_len);
	hexdump("[cipher text]", cipher, cipher_len);
	fprintf(stderr,"plaintext_len: 0x%x\n", plain_len);
	hexdump("[plain text]", plain, plain_len);
}
#else
static void
print_text(uint8_t *aad, uint8_t *tag, uint8_t *cipher, uint8_t *plain, 
		   int cipher_len, int plain_len)
{
}
#endif	/* !VERBOSE_DEBUG */
/*----------------------------------------------------------------------------*/
/* Decrypt single TLS record with given key_info */
/* Return length of decrypted data, -1 of error */
static int
decrypt_ciphertext(uint8_t *data, uint8_t *plain, uint8_t *key, uint8_t *iv)
{
	uint8_t aad[TLS_CIPHER_AES_GCM_256_AAD_SIZE], tag[TLS_CIPHER_AES_GCM_256_TAG_SIZE];
	int final, len = 0, outlen = 0;
	uint8_t *ptr, *cipher;
	EVP_CIPHER_CTX *ctx;
	uint16_t cipher_len;

	/* aad generate */
	memcpy(aad, data, TLS_CIPHER_AES_GCM_256_AAD_SIZE);
	cipher_len = htons(*(uint16_t*)(aad + TLS_CIPHER_AES_GCM_256_AAD_SIZE - sizeof(uint16_t)));   // aad format: type(1B) version(2B) len(2B)
	if (*aad != APPLICATION_DATA) {
		ERROR_PRINT("Error: Not APPLICATION DATA!!\n");
		exit(-1);
	}

	/* tag generate */
	ptr = data + TLS_HEADER_LEN + cipher_len - TLS_CIPHER_AES_GCM_256_TAG_SIZE;
	memcpy(tag, ptr, TLS_CIPHER_AES_GCM_256_TAG_SIZE);
	cipher_len -= TLS_CIPHER_AES_GCM_256_TAG_SIZE;

	/* decrypt cipher text */
	cipher = data + TLS_HEADER_LEN;
	ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
		ERROR_PRINT("Error: cipher ctx creation failed\n");
		exit(-1);
	}

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		ERROR_PRINT("Error: Init algorithm failed\n");
		exit(-1);
	}

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TLS_CIPHER_AES_GCM_256_IV_SIZE, NULL)) {
		ERROR_PRINT("Error: SET_IVLEN failed\n");
		exit(-1);
	}

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
		ERROR_PRINT("Error: Set KEY/IV faield\n");
		exit(-1);
	}

    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, TLS_CIPHER_AES_GCM_256_AAD_SIZE)) {
		ERROR_PRINT("Error: Set AAD failed\n");
		exit(-1);
	}

    if (!EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len)) {
		ERROR_PRINT("Error: Decrypt failed\n");
		exit(-1);
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TLS_CIPHER_AES_GCM_256_TAG_SIZE, tag)) {
		ERROR_PRINT("Error: Set expected TAG failed\n");
		exit(-1);
	}

    outlen += len;
    final = EVP_DecryptFinal_ex(ctx, plain + len, &len);		// positive is success
    outlen += len;

    EVP_CIPHER_CTX_free(ctx);

	/* print value and results */
	if (cipher_len != outlen) {
		ERROR_PRINT("Error: decrypted text length unmatched!!\n");
	}
	print_text(aad, tag, cipher, plain, cipher_len, outlen);

    if (final > 0) {
		fprintf(stderr, "decrypt success!\n");
    }
	else {
		fprintf(stderr, "Can't decrypt with given key. Might be handshake finish or etc..\n");
		// ERROR_PRINT("Error: decrypt failed, tag value didn't match\n");
	}

	/* ToDo: buffer is saved to plain text even it's not application data */
	return outlen;
}
/*----------------------------------------------------------------------------*/
/* Decrypt parsed TLS client records */
/* Return number of decrypted record, -1 of error */
static int
decrypt_tls_record(tls_context *ctx)
{
	struct tls_crypto_info *key_info = &ctx->tc_key_info;
	int len, ret = 0;
	uint8_t *key, *iv;

	if ((key_info->key_mask & 0xf) != 0xf){
		return -1;
	}
	key = key_info->key;	
	iv = key_info->iv;
	
	/* decrypt all parsed records */
	while (ctx->tc_unparse_tcp_seq != ctx->tc_undecrypt_tcp_seq) {
		len = decrypt_ciphertext(ctx->tc_buf + ctx->tc_undecrypt_tcp_seq,
								ctx->tc_plaintext + ctx->tc_plain_len, key, iv);
		if (len > 0) {
			ctx->tc_plain_len += len;
			ctx->tc_undecrypt_tcp_seq += TLS_HEADER_LEN + len + TLS_CIPHER_AES_GCM_256_TAG_SIZE;
			ret++;
		}
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
/* Parse payload to get TLS session key data into key_info */
/* Return length of parsed data, -1 of error */
static int
parse_tls_key(uint8_t *data, conn_info *c)
{
	struct tls_crypto_info *client, *server;
	uint16_t cipher_suite, key_mask;
	char *ptr = NULL;
	int key_len, iv_len;

	client = &c->ci_tls_ctx[!MOS_SIDE_CLI].tc_key_info;
	server = &c->ci_tls_ctx[!MOS_SIDE_SVR].tc_key_info;
	assert(client && server);

	ptr = (char*)data;
	
	cipher_suite = ntohs(*(uint16_t*)ptr);
	// client->cipher_type = cipher_suite;
	// server->cipher_type = cipher_suite;
	key_len = TLS_CIPHER_AES_GCM_256_KEY_SIZE;
	iv_len = TLS_CIPHER_AES_GCM_256_IV_SIZE;
	ptr += sizeof(cipher_suite);

	key_mask = ntohs(*((uint16_t*)ptr));
	client->key_mask |= key_mask;
	server->key_mask |= key_mask;
	ptr += sizeof(key_mask);
	
	if (key_mask & CLI_KEY_MASK) {
		hexdump("cli key", (uint8_t*)ptr, key_len);
			
		memcpy(client->key, ptr, key_len);
		ptr += key_len;
	}
	if (key_mask & SRV_KEY_MASK) {
		hexdump("srv key", (uint8_t*)ptr, key_len);
		
		memcpy(server->key, ptr, key_len);
		ptr += key_len;
	}
	if (key_mask & CLI_IV_MASK) {
		hexdump("cli iv", (uint8_t*)ptr, iv_len);
		
		memcpy(client->iv, ptr, iv_len);
		ptr += iv_len;
	}
	if (key_mask & SRV_IV_MASK) {
		hexdump("srv iv", (uint8_t*)ptr, iv_len);

		memcpy(server->iv, ptr, iv_len);
		ptr += iv_len;
	}

	return ptr - (char*)data;
}
/*----------------------------------------------------------------------------*/
/* Parse TCP payload to assemble single TLS record sending to server */
/* Return byte of parsed record, 0 if no complete record */
static uint16_t
parse_and_decrypt_tls_record(mctx_t mctx, conn_info *c, int side)
{
	tls_context *context;
	// tls_record *record;
	uint32_t start_seq;
	uint8_t *ptr;
	uint8_t record_type;
	uint16_t version;
	uint16_t record_len;

	context = &c->ci_tls_ctx[side];
	start_seq = context->tc_unparse_tcp_seq;

	assert(UINT32_GEQ(start_seq, context->tc_seq_head));

	/* Parse header of new record */
	if (UINT32_GT(start_seq + TLS_HEADER_LEN, context->tc_seq_tail)) {
		return 0;
	}

	ptr = context->tc_buf + start_seq - context->tc_seq_head;
	record_type = *ptr;
	ptr += sizeof(uint8_t);
	
	version = htons(*(uint16_t*)ptr);
	ptr += sizeof(uint16_t);

	record_len = htons(*(uint16_t*)ptr);
	ptr += sizeof(uint16_t);
	/* Store TLS record info if complete */
	if (UINT32_GT(start_seq + record_len + TLS_HEADER_LEN, context->tc_seq_tail)) {
		return 0;
	}

	// if (context->tc_record_cnt == MAX_RECORD_NUM) {
	// 	ERROR_PRINT("Error: Record number exceedes MAX_RECORD_NUM!!\n");
	// 	exit(-1);
	// }

	// /* record = &context->last_rec[side]; */
	// record = &context->tc_records[context->tc_record_tail];
	// record->tr_type = record_type;
	// record->tr_tcp_seq = start_seq;
	if (record_type == HANDSHAKE) {
		/* ToDo: We might need to verify HANDSHAKE_FINISHED */
		if (*ptr == 0x01) {						// Client Hello
			ptr += TLS_HANDSHAKE_HEADER_LEN;
			ptr += sizeof(uint16_t);		// Client Version (03 03)

			memcpy(c->ci_client_random, ptr, TLS_1_3_CLIENT_RANDOM_LEN);
			if (ct_insert(g_ct[mctx->cpu], c->ci_client_random, c) < 0) {
				ERROR_PRINT("Error: ct_insert() failed\n");
				exit(-1);
			}
		}
	}

	/* Update context */
	/* ToDo: Add parsing cipher suite */
	if (context->tc_version < version) {
		context->tc_version = version;
	}
	// context->tc_record_tail = (context->tc_record_tail+1) % MAX_RECORD_NUM;
	context->tc_unparse_tcp_seq += TLS_HEADER_LEN + record_len;
	
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
#endif	/* VERBOSE_TLS */

	if (record_type == APPLICATION_DATA) {
		decrypt_tls_record(context);
	}
	else {
		/* no need to decrypt */
		context->tc_undecrypt_tcp_seq += TLS_HEADER_LEN + record_len;
	}
	
	return record_len;
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
    if (!c) {
		ERROR_PRINT("Error: [%s]calloc failed\n", __FUNCTION__);
		exit(-1);
	}
	c->ci_tls_ctx[MOS_SIDE_CLI].tc_plaintext = calloc(CLI_RECBUF_LEN, sizeof(uint8_t));
	if (!c->ci_tls_ctx[MOS_SIDE_CLI].tc_plaintext) {
		ERROR_PRINT("Error: [%s]calloc failed\n", __FUNCTION__);
		exit(-1);
	}
	c->ci_tls_ctx[MOS_SIDE_SVR].tc_plaintext = calloc(SVR_RECBUF_LEN, sizeof(uint8_t));
	if (!c->ci_tls_ctx[MOS_SIDE_SVR].tc_plaintext) {
		ERROR_PRINT("Error: [%s]calloc failed\n", __FUNCTION__);
		exit(-1);
	}

    /* Fill values of the connection structure */
    c->ci_sock = sock;

    if (mtcp_getpeername(mctx, sock, addrs, &addrslen,
                         MOS_SIDE_BOTH) < 0) {
        perror("mtcp_getpeername");
        /* it's better to stop here and do debugging */
        exit(EXIT_FAILURE);
    }

    /* Insert the structure to the queue */
	if (st_insert(g_st[mctx->cpu], c->ci_sock, c) < 0) {
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

	if (!(c = st_search(g_st[mctx->cpu], sock))) {
		return;
	}

	if (!ct_remove(g_ct[mctx->cpu], c->ci_client_random)) {
		ERROR_PRINT("Error: No session with given client random\n");
	}
	if (!st_remove(g_st[mctx->cpu], c->ci_sock)) {
		ERROR_PRINT("Error: No session with given sock\n");
	}

    free(c);
}
/*----------------------------------------------------------------------------*/
/* Update connection's TCP state of each side */
static void
cb_new_data(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	uint16_t record_len;
	int len;
	uint32_t buf_off;
    conn_info *c;
	tls_context *ctx;
    /* socklen_t intlen = sizeof(int); */

	if (!(c = st_search(g_st[mctx->cpu], sock))) {
		return;
	}

#if VERBOSE_TCP
	fprintf(stderr, "\n--------------------------------------------------\n");
	fprintf(stderr, "[%s] core: %d, sock: %u, c->sock: %u, side: %u\n",
			__FUNCTION__, mctx->cpu, sock, sock, side);
#endif

	ctx = &c->ci_tls_ctx[side];
	buf_off = ctx->tc_seq_tail - ctx->tc_seq_head;
	/* ToDo: while() */
	len = mtcp_peek(mctx, sock, side,
					(char*)ctx->tc_buf + buf_off, MAX_BUF_LEN - buf_off);

	if (len > 0) {

#if VERBOSE_TCP
		fprintf(stderr, "[%s] from %s, received %u B (seq %u ~ %u) TCP data!\n",
				__FUNCTION__,  (side == MOS_SIDE_CLI) ? "server":"client",
				len, ctx->tc_seq_tail, ctx->tc_seq_tail + len);

		hexdump(NULL, ctx->tc_buf + buf_off, len);
#endif 

		ctx->tc_seq_tail += len;

		/* Reassemble TLS record */
		while((record_len = parse_and_decrypt_tls_record(mctx, c, side)) > 0) {
			;
		}
	}
}
/*----------------------------------------------------------------------------*/
/* Update connection's TCP state of each side */
static void
cb_new_key(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	struct pkt_info p;
	uint8_t *payload;
	conn_info *c;

	if (mtcp_getlastpkt(mctx, sock, side, &p) < 0) {
        fprintf(stderr, "Failed to get packet context!!!\n");
		exit(EXIT_FAILURE);
	}

	payload = (uint8_t*)(p.iph) + IP_HEADER_LEN + UDP_HEADER_LEN;
	
#if VERBOSE_KEY
	fprintf(stderr, "\n--------------------------------------------------\n");
	fprintf(stderr, "[%s] core: %d, sock: %d, side: %u\n",
			__FUNCTION__, mctx->cpu, sock, side);
	hexdump("In cb_new_key: client random", payload, TLS_1_3_CLIENT_RANDOM_LEN);
	if (p.ip_len > IP_HEADER_LEN) {
		fprintf(stderr, "[%s] p.iph: %p, p.ip_len: %u, ip payload: %p\n",
				__FUNCTION__, p.iph, p.ip_len, payload);
	}
#endif
	*(payload+TLS_1_3_CLIENT_RANDOM_LEN) = '\0';
#if MC
	c = &((g_shared_q + tail)->ci);
#else
	c = ct_search(g_ct[mctx->cpu], payload);
#endif
	if (!c) {
		ERROR_PRINT("Error: Can't find connection with Client Random\n");
		return;
	}
	payload += TLS_1_3_CLIENT_RANDOM_LEN;
	payload++;									// '\0'

	parse_tls_key(payload, c);
#if MC
	(g_shared_q + tail)->valid = 1;
	if (++tail >= NUM_BINS * g_max_cores)
		tail = 0;
	assert(!(g_shared_q + tail)->valid);
#else
	/* Decrypt records which reached before key arrival */
	decrypt_tls_record(&c->ci_tls_ctx[MOS_SIDE_CLI]);
	decrypt_tls_record(&c->ci_tls_ctx[MOS_SIDE_SVR]);
#endif
	/* mtcp_setsockopt(mctx, sock_mon, SOL_MONSOCKET, */
	/* 				MOS_TLS_SP, &key_info, sizeof(key_info)); */
	/* struct tls_crypto_info key_info_tmp; */
	/* socklen_t key_info_len = sizeof(key_info_tmp); */
	/* mtcp_getsockopt(mctx, sock_mon, SOL_MONSOCKET, */
	/* 				MOS_TLS_SP, &key_info_tmp, &key_info_len); */
	/* hexdump("Get tls_crypto_info:", (uint8_t*)&key_info_tmp, key_info_len); */
}
/*----------------------------------------------------------------------------*/
static bool
check_is_key(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	struct pkt_info p;
	struct udphdr *udph;

	if (mtcp_getlastpkt(mctx, sock, side, &p) < 0) {
        fprintf(stderr, "Failed to get packet context!!!\n");
		exit(EXIT_FAILURE);
	}

	udph = (struct udphdr*)(p.iph+1);

	if (p.iph->protocol == IPPROTO_UDP &&
		ntohs(udph->dest) == UDP_PORT &&
		p.ip_len > IP_HEADER_LEN)
		return 1;

	return 0;
}
/*----------------------------------------------------------------------------*/
#if MC
static void
find_key_and_decrypt(mctx_t mctx)
{
	if (local_tail[mctx->cpu] == tail)
		return;

	int i, found = 0;
	conn_info *c;
	shared_q *walk;
	for (i = local_tail[mctx->cpu]; i != tail; i++) {
		if (i == g_max_cores * 65536)
			i = 0;
		walk = g_shared_q + i;
		if (!walk->valid)
			continue;
		c = ct_search(g_ct[mctx->cpu], walk->ci.ci_client_random);
		if (!c) {
			fprintf(stderr, "search fail");
			continue;
		}
		/* copy keys to local hashtable */
		c->ci_tls_ctx->tc_key_info = walk->ci.ci_tls_ctx->tc_key_info;
		walk->valid = 0;
		found = 1;
		break;
	}
	local_tail[mctx->cpu] = i;
	fprintf(stderr, "[%s] core: %d found: %d tail: %d local_tail[%d]: %d\n",
		__FUNCTION__, mctx->cpu, found, tail, mctx->cpu, local_tail[mctx->cpu]);
	hexdump("client random", walk->ci.ci_client_random, TLS_1_3_CLIENT_RANDOM_LEN);
	if (found) {
		decrypt_tls_record(&c->ci_tls_ctx[MOS_SIDE_CLI]);
		decrypt_tls_record(&c->ci_tls_ctx[MOS_SIDE_SVR]);
	}
}
#endif
/*----------------------------------------------------------------------------*/
static void
register_sessionkey_callback(mctx_t mctx, int sock)
{
	event_t ude_from_ctrl;

	ude_from_ctrl = mtcp_define_event(MOS_ON_PKT_IN, check_is_key, NULL);
	if (ude_from_ctrl == MOS_NULL_EVENT) {
        fprintf(stderr, "mtcp_define_event() failed!");
		exit(EXIT_FAILURE);
	}
	
    if (mtcp_register_callback(mctx, sock, ude_from_ctrl,
                   MOS_NULL, cb_new_key)) {
        fprintf(stderr, "Failed to register cb_new_key()\n");
        exit(EXIT_FAILURE);
    }
#if MC
	/* slaves check whether added key is for themselves */
	if (mtcp_register_thread_callback(mctx, find_key_and_decrypt)) {
		fprintf(stderr, "Failed to register find_key_and_decrypt()\n");
		exit(EXIT_FAILURE);
	}
#endif
}
/*----------------------------------------------------------------------------*/
static void
register_data_callback(mctx_t mctx, int sock)
{
    if (mtcp_register_callback(mctx, sock, MOS_ON_CONN_START,
                   MOS_HK_SND, cb_creation)) {
        fprintf(stderr, "Failed to register cb_creation()\n");
        exit(-1); /* no point in proceeding if callback registration fails */
    }

    if (mtcp_register_callback(mctx, sock, MOS_ON_CONN_END,
                   MOS_HK_SND, cb_destroy)) {
        fprintf(stderr, "Failed to register cb_destroy()\n");
        exit(-1); /* no point in proceeding if callback registration fails */
    }

    if (mtcp_register_callback(mctx, sock, MOS_ON_CONN_NEW_DATA,
                   MOS_NULL, cb_new_data)) {
        fprintf(stderr, "Failed to register cb_new_data()\n");
        exit(-1); /* no point in proceeding if callback registration fails */
    }
}
/*----------------------------------------------------------------------------*/
/* Register required callbacks */
static void
register_callbacks(mctx_t mctx)
{
    int sock_key, sock_stream;

	/* Register UDE for session key from client */
    if ((sock_key = mtcp_socket(mctx, AF_INET,
                         MOS_SOCK_MONITOR_RAW, 0)) < 0) {
        fprintf(stderr, "Failed to create monitor listening socket!\n");
        exit(-1); /* no point in proceeding if we don't have a listening socket */
    }
	union monitor_filter ft = {0};
	ft.raw_pkt_filter = "ip proto 17";
	if (mtcp_bind_monitor_filter(mctx, sock_key, &ft) < 0) {
		fprintf(stderr, "Failed to bind ft to the listening socket!\n");
		exit(-1);
	}
	register_sessionkey_callback(mctx, sock_key);

	
	/* Register UDE for TCP connetions */
    if ((sock_stream = mtcp_socket(mctx, AF_INET,
                         MOS_SOCK_MONITOR_STREAM, 0)) < 0) {
        fprintf(stderr, "Failed to create monitor listening socket!\n");
        exit(-1); /* no point in proceeding if we don't have a listening socket */
    }
	register_data_callback(mctx, sock_stream);
}
/*----------------------------------------------------------------------------*/
/* Open monitoring socket and ready it for monitoring */
static void
init_monitor(mctx_t mctx)
{
    register_callbacks(mctx);
}
/*----------------------------------------------------------------------------*/
int
main(int argc, char **argv)
{
	int ret, i;
	char *fname = MOS_CONFIG_FILE; /* path to the default mos config file */
	struct mtcp_conf mcfg;
	/* char tls_middlebox_file[1024] = "config/tls_middlebox.conf"; */
	int num_cpus;
	int opt, rc;

	/* get the total # of cpu cores */
	num_cpus = GetNumCPUs();

	while ((opt = getopt(argc, argv, "c:f:")) != -1) {
		switch (opt) {
		case 'c':
			if ((rc=atoi(optarg)) > num_cpus) {
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
		default:
			printf("Usage: %s [-c num of cores] "
				   "[-f mos config_file]\n",
				   argv[0]);
			return 0;
		}
	}

	g_max_cores = num_cpus;

	/* create hash table */
	g_ct = (struct ct_hashtable**)calloc(g_max_cores, sizeof(struct ct_hashtable*));
	if (!g_ct) {
		ERROR_PRINT("Error: calloc() failed\n");
		exit(-1);
	}

	g_st = (struct st_hashtable**)calloc(g_max_cores, sizeof(struct st_hashtable*));
	if (!g_st) {
		ERROR_PRINT("Error: calloc() failed\n");
		exit(-1);
	}
	for (i = 0; i < g_max_cores; i++) {
		g_ct[i] = ct_create();
		g_st[i] = st_create();
	}
	g_shared_q = (shared_q *)calloc(g_max_cores, sizeof(shared_q) * NUM_BINS);

	/* parse mos configuration file */
	ret = mtcp_init(fname);
	if (ret) {
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
	for (i = 0; i < g_max_cores; i++) {
        /* Run mOS for each CPU core */
        if (!(g_mctx[i] = mtcp_create_context(i))) {
            fprintf(stderr, "Failed to craete mtcp context.\n");
            return -1;
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
	for (i = 0; i < g_max_cores; i++) {
		ct_destroy(g_ct[i]);
		st_destroy(g_st[i]);
	}
	free(g_shared_q);

	return EXIT_SUCCESS;
}
/*----------------------------------------------------------------------------*/
