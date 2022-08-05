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
// TAILQ_HEAD(, conn_info) g_sockq[MAX_CORES];   /* connection queue */
struct ct_hashtable *g_ct;					  /* hash table of connections with client random */
struct st_hashtable *g_st;					  /* hash table of connections with socket */
/**< ToDo: We should not use linked list for scalability */
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
/* Find connection structure by socket ID */
// static inline conn_info*
// find_connection(int cpu, int sock)
// {
//     conn_info *c;

//     TAILQ_FOREACH(c, &g_sockq[cpu], ci_link)
//         if (c->ci_sock == sock)
//             return c;

//     return NULL;
// }
/*----------------------------------------------------------------------------*/
/* Dump bytestream in hexademical form */
#if VERBOSE_TCP | VERBOSE_TLS | VERBOSE_KEY
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
// #if VERBOSE_KEY
// /* Parse session address */
// /* Return length of parsed data, -1 of error */
// static void
// dump_tls_key(struct tls_crypto_info *key_info, session_address_t sess_addr)
// {
// 	uint16_t cipher_suite = key_info->cipher_type;
// 	uint16_t mask = key_info->key_mask;
// 	uint16_t key_len;
// 	uint16_t iv_len;

// 	UNUSED(cipher_suite);
// 	key_len = TLS_CIPHER_AES_GCM_256_KEY_SIZE;
// 	iv_len = TLS_CIPHER_AES_GCM_256_IV_SIZE;

// 	fprintf(stderr, "------------------------------\n[%s] %x:%u -> %x:%u\n",
// 			__FUNCTION__, sess_addr->client_ip, sess_addr->client_port,
// 			sess_addr->server_ip, sess_addr->server_port);
	
// 	if (mask & CLI_KEY_MASK) {
// 		hexdump("client_write_key:", key_info->client_key, key_len);
// 	}
// 	if (mask & SRV_KEY_MASK) {
// 		hexdump("server_write_key:", key_info->server_key, key_len);
// 	}
// 	if (mask & CLI_IV_MASK) {
// 		hexdump("client_write_iv:", key_info->client_iv, iv_len);
// 	}
// 	if (mask & SRV_IV_MASK) {
// 		hexdump("server_write_iv:", key_info->server_iv, iv_len);
// 	}
// }
// #endif	/* VERBOSE_KEY */
/*----------------------------------------------------------------------------*/
/* Print AAD, TAG, cipher text and decrypted plain text */
#if VERBOSE_DEBUG
static void
print_text(uint8_t *aad, uint8_t *tag, uint8_t *cipher, char *plain, int cipher_len, int out_len)
{
	int i;

	fprintf(stderr,"*--------------------------------------------------------*\n");
	/* aad */
	fprintf(stderr,"[aad] ");
    for (i = 0; i < TLS_CIPHER_AES_GCM_256_AAD_SIZE; i++)
        fprintf(stderr,"%02hhX%c", aad[i],
                ((i + 1) % 16)? ' ' : '\n');
    fprintf(stderr,"\n");

	/* tag */
	fprintf(stderr,"[tag] ");
    for (i = 0; i < TLS_CIPHER_AES_GCM_256_TAG_SIZE; i++)
        fprintf(stderr,"%02hhX%c", tag[i],
                ((i + 1) % 16)? ' ' : '\n');
    fprintf(stderr,"\n");

	/* cipher text */
	fprintf(stderr,"ciphertext_len: 0x%x, ciphertext: \n", cipher_len);
    for (i = 0; i < cipher_len; i++)
        fprintf(stderr,"%02hhX%c", cipher[i],
                ((i + 1) % 16)? ' ' : '\n');
    fprintf(stderr,"\n");

	/* plain text */
    fprintf(stderr,"plaintext_len: 0x%x, plaintext: \n", out_len);
    for (i = 0; i < out_len; i++)
        fprintf(stderr,"%02hhX%c", plain[i],
                ((i + 1) % 16)? ' ' : '\n');
    fprintf(stderr,"\n");
}
#else
static void
print_text(uint8_t *aad, uint8_t *tag, uint8_t *cipher, char *plain, int cipher_len, int out_len)
{
}
#endif	/* !VERBOSE_DEBUG */
/*----------------------------------------------------------------------------*/
/* Decrypt single TLS record with given key_info */
/* Return length of decrypted data, -1 of error */
static int
decrypt_ciphertext(tls_record *rec, uint8_t *key, uint8_t *iv)
{
	uint8_t *cipher = rec->tr_ciphertext;
	uint8_t *plain = rec->tr_plaintext;
	int cipher_len = rec->tr_cipher_len;
	uint8_t aad[TLS_CIPHER_AES_GCM_256_AAD_SIZE], tag[TLS_CIPHER_AES_GCM_256_TAG_SIZE];
	int final, len = 0, outlen = 0;
	char *out;
	uint8_t *temp, *ptr;
	EVP_CIPHER_CTX *ctx;
	
	/* aad generate */
	temp = aad;
	*temp++ = APPLICATION_DATA;
	*temp++ = 0x03;		// 03 03: legacy protocol version of TLS 1.2
	*temp++ = 0x03;
	*(uint16_t*)(temp) = htobe16(cipher_len);	// length of record payload

	/* tag generate */
	ptr = cipher + cipher_len - TLS_CIPHER_AES_GCM_256_TAG_SIZE;
	memcpy(tag, (const uint8_t*)ptr, TLS_CIPHER_AES_GCM_256_TAG_SIZE);
	cipher_len -= TLS_CIPHER_AES_GCM_256_TAG_SIZE;						// optional

	/* decrypt cipher text */
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

	out = (char*)calloc(sizeof(char), outlen + len);
	if (!out) {
		ERROR_PRINT("Error: calloc() failed\n");
		exit(-1);
	}
    memcpy(out + outlen, plain, len);
    outlen += len;

    final = EVP_DecryptFinal_ex(ctx, plain+len, &len);;		// positive is success

    outlen += len;

    EVP_CIPHER_CTX_free(ctx);

	/* print value and results */
	print_text(aad, tag, cipher, out, cipher_len, outlen);

    if (final > 0) {
        fprintf(stderr, "decrypt success!\n");
    } 
	else {
		fprintf(stderr, "Can't decrypt with given key. Might be handshake finish or etc..\n");
		// ERROR_PRINT("Error: decrypt failed, tag value didn't match\n");
    }
	free(out);

	rec->tr_plain_len = outlen - TLS_CIPHER_AES_GCM_256_TAG_SIZE;
	
	return rec->tr_plain_len;
}
/*----------------------------------------------------------------------------*/
/* Decrypt parsed TLS records */
/* Return number of decrypted record, -1 of error */
static int
decrypt_tls_record(tls_context *tls_ctx)
{
	int side, idx;
	int start, end;
	struct tls_crypto_info *key_info = &tls_ctx->tc_key_info;
	uint8_t *key, *iv;
	tls_record *rec;
	int ret = 0;

	if ((key_info->key_mask & 0xf) != 0xf){
		return -1;
	}

	for (side = 0; side < 2; side++) {
		start = tls_ctx->tc_decrypt_record_idx[side];
		end = tls_ctx->tc_record_tail[side];

		if (side != MOS_SIDE_CLI) {
			key = key_info->client_key;	
			iv = key_info->client_iv;
		} else {
			key = key_info->server_key;	
			iv = key_info->server_iv;
		}

		idx = start;
		while(idx != end) {
			/* ToDo: only decrypt application data now */
			rec = &tls_ctx->tc_records[side][idx];
			if (rec->tr_type == APPLICATION_DATA) {
				if (decrypt_ciphertext(rec, key, iv) >= 0)
					ret++;
			}
			idx = (idx+1) % MAX_RECORD_NUM;
		}
		tls_ctx->tc_decrypt_record_idx[side] = end;
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
/* Parse payload to get TLS session key data into key_info */
/* Return length of parsed data, -1 of error */
static int
parse_tls_key(uint8_t *data, uint16_t datalen,
		    struct tls_crypto_info *key_info)
{
	uint16_t cipher_suite, key_mask;
	char *ptr = NULL;
	int key_len, iv_len;

	assert(key_info);

	ptr = (char*)data;
	
	cipher_suite = ntohs(*(uint16_t*)ptr);
	key_info->cipher_type = cipher_suite;
	key_len = TLS_CIPHER_AES_GCM_256_KEY_SIZE;
	iv_len = TLS_CIPHER_AES_GCM_256_IV_SIZE;
	ptr += sizeof(cipher_suite);

	key_mask = ntohs(*((uint16_t*)ptr));
	key_info->key_mask |= key_mask;
	ptr += sizeof(key_mask);

	hexdump("chunk:", (uint8_t*)ptr, datalen - 4);
	
	if (key_mask & CLI_KEY_MASK) {
		hexdump("cli key", (uint8_t*)ptr, key_len);
			
		memcpy(key_info->client_key, ptr, key_len);
		ptr += key_len;
	}
	if (key_mask & SRV_KEY_MASK) {
		hexdump("srv key", (uint8_t*)ptr, key_len);
		
		memcpy(key_info->server_key, ptr, key_len);
		ptr += key_len;
	}
	if (key_mask & CLI_IV_MASK) {
		hexdump("cli iv", (uint8_t*)ptr, iv_len);
		
		memcpy(key_info->client_iv, ptr, iv_len);
		ptr += iv_len;
	}
	if (key_mask & SRV_IV_MASK) {
		hexdump("srv iv", (uint8_t*)ptr, iv_len);

		memcpy(key_info->server_iv, ptr, iv_len);
		ptr += iv_len;
	}

	return ptr - (char*)data;
}
/*----------------------------------------------------------------------------*/
/* Parse TCP payload to assemble single TLS record */
/* Return byte of parsed record, 0 if no complete record */
static uint32_t
parse_tls_record(conn_info *c, int side)
{
	tls_context *tls_ctx;
	tls_record *record;
	uint32_t start_seq;
	uint8_t *ptr;
	uint8_t record_type;
	uint16_t version;
	uint16_t record_len;
	int ret, off = 0;
	uint8_t client_random[TLS_1_3_CLIENT_RANDOM_LEN];

	tls_ctx = &c->ci_tls_ctx;
	start_seq = tls_ctx->tc_unparse_tcp_seq[side];

	assert(UINT32_GEQ(start_seq, c->ci_seq_head[side]));

	/* Parse header of new record */
	if (UINT32_GT(start_seq + TLS_HEADER_LEN, c->ci_seq_tail[side])) {
		return 0;
	}

	ptr = c->ci_buf[side] + start_seq - c->ci_seq_head[side];
	record_type = *ptr + off;
	off += sizeof(uint8_t);
	
	version = htons(*(uint16_t*)(ptr + off));
	off += sizeof(uint16_t);

	record_len = htons(*(uint16_t*)(ptr + off));
	off += sizeof(uint16_t);

	/* Store TLS record info if complete */
	if (UINT32_GT(start_seq + record_len + TLS_HEADER_LEN, c->ci_seq_tail[side])) {
		return 0;
	}

	if (tls_ctx->tc_record_cnt[side] == MAX_RECORD_NUM) {
		fprintf(stderr, "Error!\n");
		exit(-1);
	}

	/* record = &tls_ctx->last_rec[side]; */
	record = &tls_ctx->tc_records[side][tls_ctx->tc_record_tail[side]];
	record->tr_type = record_type;
	record->tr_tcp_seq = start_seq;
	record->tr_rec_seq = tls_ctx->tc_record_cnt[side];

	if (record_type == APPLICATION_DATA) {
		memcpy(record->tr_ciphertext, ptr + TLS_HEADER_LEN,
			   record_len);
		record->tr_cipher_len = record_len;
	} 
	else if (record_type == HANDSHAKE) {
		/* ToDo: We might need to verify HANDSHAKE_FINISHED */
		if (*(ptr + off) == 0x01) {						// Client Hello
			off += TLS_HANDSHAKE_HEADER_LEN;
			off += sizeof(uint16_t);		// Client Version (03 03)

			memcpy(client_random, (const uint8_t*)(ptr + off), TLS_1_3_CLIENT_RANDOM_LEN);
			ret = ct_insert(g_ct, c, client_random);
			if (ret < 0) {
				ERROR_PRINT("Error: ct_insert() failed\n");
				exit(-1);
			}
		}
	}

	/* Update tls_ctx */
	/* ToDo: Add parsing cipher suite */
	if (tls_ctx->tc_version < version) {
		tls_ctx->tc_version = version;
	}
	tls_ctx->tc_record_tail[side] = (tls_ctx->tc_record_tail[side]+1) % MAX_RECORD_NUM;
	tls_ctx->tc_record_cnt[side]++;
	tls_ctx->tc_unparse_tcp_seq[side] += record_len + TLS_HEADER_LEN;
	tls_ctx->tc_last_rec_seq[side] = tls_ctx->tc_record_cnt[side];

	
	/* ToDo: move below to separate function, e.g. PrintTLSStat() */
#if VERBOSE_TLS
	fprintf(stderr, "[%s] Parse new record to follow session!\n",
			__FUNCTION__);
	fprintf(stderr, "Record type %x, length %u (TCP %u ~ %u), "
			"rec seq %lu, cipher len %u\n",
			record->tr_type, record->tr_tcp_seq, record_len,
			record->tr_tcp_seq + record_len + TLS_HEADER_LEN,
			record->tr_rec_seq, record->tr_cipher_len);
	if (record->tr_cipher_len) {
		hexdump("Dump of ciphertext of the record:",
				record->tr_ciphertext, record->tr_cipher_len);
	} 
#endif	/* VERBOSE_TLS */
	
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
	int ret;

	/* ToDo: remove calloc */
    c = calloc(sizeof(conn_info), 1);
    if (!c) {
		ERROR_PRINT("Error: [%s]calloc failed\n", __FUNCTION__);
		exit(-1);
	}

    /* Fill values of the connection structure */
    //c->ci_sock = sock;

	/* ToDo: remove conn_info.ci_addrs */
    if (mtcp_getpeername(mctx, sock, addrs, &addrslen,
                         MOS_SIDE_BOTH) < 0) {
        perror("mtcp_getpeername");
        /* it's better to stop here and do debugging */
        exit(EXIT_FAILURE);
    }

    /* Insert the structure to the queue */
	ret = st_insert(g_st, c, sock);
	if (ret < 0) {
		ERROR_PRINT("Error: st_insert() failed\n");
		exit(-1);
	}
    //TAILQ_INSERT_TAIL(&g_sockq[mctx->cpu], c, ci_link);
}
/*----------------------------------------------------------------------------*/
/* Destroy connection structure */
static void
cb_destroy(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
    conn_info *c;

    /*if (!(c = find_connection(mctx->cpu, sock))) {
        return;
	}*/
	if (!(c = st_search(g_st, sock))) {
		return;
	}

	ct_remove(g_ct, c);
	st_remove(g_st, c);
    //TAILQ_REMOVE(&g_sockq[mctx->cpu], c, ci_link);
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
    /* socklen_t intlen = sizeof(int); */

    /*if (!(c = find_connection(mctx->cpu, sock)))
        return;
	*/
	if (!(c = st_search(g_st, sock))) {
		return;
	}
#if VERBOSE_TCP
	fprintf(stderr, "\n--------------------------------------------------\n");
	fprintf(stderr, "[%s] sock: %u, c->sock: %u, side: %u\n",
			__FUNCTION__, sock, sock, side);
#endif

	
	buf_off = c->ci_seq_tail[side] - c->ci_seq_head[side];
	len = mtcp_peek(mctx, sock, side,
					(char*)c->ci_buf[side] + buf_off, MAX_BUF_LEN - buf_off);

	if (len > 0) {
#if VERBOSE_TCP
		fprintf(stderr, "[%s] from %s, received %u B (seq %u ~ %u) TCP data!\n",
				__FUNCTION__, (side == MOS_SIDE_CLI) ? "server":"client",
				len, c->ci_seq_tail[side], c->ci_seq_tail[side] + len);

		hexdump(NULL, c->ci_buf[side] + buf_off, len);
#endif 

		c->ci_seq_tail[side] += len;

		/* Reassemble TLS record */
		while((record_len = parse_tls_record(c, side)) > 0) {
			;
		}
		decrypt_tls_record(&c->ci_tls_ctx);
	}
}
/*----------------------------------------------------------------------------*/
/* Update connection's TCP state of each side */
static void
cb_new_key(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
	struct pkt_info p;
	uint8_t *payload, *ptr;
	uint16_t payloadlen;
	struct udphdr *udph;
	struct tls_crypto_info key_info;
	// int sock_mon = 0;
	int offset;
	uint16_t left_len;
	uint8_t client_random[TLS_1_3_CLIENT_RANDOM_LEN];
	conn_info *c;

	if (mtcp_getlastpkt(mctx, sock, side, &p) < 0) {
        fprintf(stderr, "Failed to get packet context!!!\n");
		exit(EXIT_FAILURE);
	}

	udph = (struct udphdr*)(p.iph+1);
	payload = (uint8_t*)(p.iph) + IP_HEADER_LEN + UDP_HEADER_LEN;
	payloadlen = htons(udph->len) - UDP_HEADER_LEN;
	
#if VERBOSE_KEY
	fprintf(stderr, "\n--------------------------------------------------\n");
	fprintf(stderr, "[%s] sock: %d, side: %u\n",
			__FUNCTION__, sock, side);
	if (p.ip_len > IP_HEADER_LEN) {
		fprintf(stderr, "[%s] p.iph: %p, p.ip_len: %u, ip payload: %p\n",
				__FUNCTION__, p.iph, p.ip_len, payload);
		fprintf(stderr, "[%s] src/dst port: %u -> %u, len: %u\n",
				__FUNCTION__, ntohs(udph->source), ntohs(udph->dest), htons(udph->len));

		fprintf(stderr, "[%s] from %s, received %u B KEY!\n", __FUNCTION__,
				(side == MOS_SIDE_CLI) ? "client":"server", payloadlen);

		hexdump(NULL, payload, payloadlen);
	}
#endif

	left_len = payloadlen;
	ptr = payload;
	
	offset = parse_tls_key(ptr, left_len, &key_info);
	ptr += offset;
	left_len -= offset;

	memcpy(client_random, ptr, TLS_1_3_CLIENT_RANDOM_LEN);

	c = ct_search(g_ct, client_random);
	if (!c) {
		ERROR_PRINT("Error: Can't find connection with Client Random\n");
		return;
	}

	// sock_mon = c->ci_sock;
	// fprintf(stderr, "sock: %d\n", sock_mon);
	// if (sock_mon < 0) {
	// 	ERROR_PRINT("Error: wrong socket descripotr\n");
	// 	exit(-1);
	// }

	/* Insert key info to the session */
	c->ci_tls_ctx.tc_key_info = key_info;
	
	/* Decrypt records which reached before key arrival */
	decrypt_tls_record(&c->ci_tls_ctx);

	return;

	
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
	else
		return 0;
}
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
    /* Initialize internal memory structures */
    // TAILQ_INIT(&g_sockq[mctx->cpu]);

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
			printf("Usage: %s [-c mos_config_file] "
				   "[-f simple_firewall_config_file]\n",
				   argv[0]);
			return 0;
		}
	}

	/* create hash table */
	g_ct = ct_create();
	g_st = st_create();

	/* parse mos configuration file */
	ret = mtcp_init(fname);
	if (ret) {
		fprintf(stderr, "Failed to initialize mtcp.\n");
		exit(EXIT_FAILURE);
	}

	/* set the core limit */
	mtcp_getconf(&mcfg);
	mcfg.num_cores = num_cpus;
	mtcp_setconf(&mcfg);

	/* Register signal handler */
    mtcp_register_signal(SIGINT, sigint_handler);

	/* initialize monitor threads */	
	for (i = 0; i < mcfg.num_cores; i++) {
        /* Run mOS for each CPU core */
        if (!(g_mctx[i] = mtcp_create_context(i))) {
            fprintf(stderr, "Failed to craete mtcp context.\n");
            return -1;
        }

        /* init monitor */
        init_monitor(g_mctx[i]);
	}

	/* wait until all threads finish */	
	for (i = 0; i < mcfg.num_cores; i++) {
		mtcp_app_join(g_mctx[i]);
	  	fprintf(stderr, "Message test thread %d joined.\n", i);	  
	}	
	
	mtcp_destroy();
	ct_destroy(g_ct);
	st_destroy(g_st);

	return EXIT_SUCCESS;
}
/*----------------------------------------------------------------------------*/
