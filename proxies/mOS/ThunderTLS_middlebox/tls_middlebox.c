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

#include <mos_api.h>
#include "cpu.h"
#include "tls.h"

/* Maximum CPU cores */
#define MAX_CORES       16
/* Number of TCP flags to monitor */
#define NUM_FLAG        6
/* Default path to mOS configuration file */
#define MOS_CONFIG_FILE     "config/mos.conf"

#define IP_HEADER_LEN    20
#define UDP_HEADER_LEN   8
#define TLS_HEADER_LEN   5

#define MAX_BUF_LEN      1048576    /* 1M */
#define MAX_LINE_LEN     1280

#define UDP_PORT      6666		/* only for debug */

#define VERBOSE_TCP   0
#define VERBOSE_TLS   0
#define VERBOSE_KEY   0
#define VERBOSE_DEBUG   0

#define UINT32_LT(a,b)         ((int32_t)((a)-(b)) < 0)
#define UINT32_LEQ(a,b)        ((int32_t)((a)-(b)) <= 0)
#define UINT32_GT(a,b)         ((int32_t)((a)-(b)) > 0)
#define UINT32_GEQ(a,b)        ((int32_t)((a)-(b)) >= 0)
/*----------------------------------------------------------------------------*/
struct connection {
    int sock;                      /* socket ID */
    struct sockaddr_in addrs[2];   /* Address of a client and a serer */
    int cli_state;                 /* TCP state of the client */
    int svr_state;                 /* TCP state of the server */

	uint8_t buf[2][MAX_BUF_LEN];
	uint32_t seq_head[2];
	uint32_t seq_tail[2];

	tls_context tls_ctx;
	
    TAILQ_ENTRY(connection) link;  /* link to next context in this core */
};

int g_max_cores;                              /* Number of CPU cores to be used */
mctx_t g_mctx[MAX_CORES];                     /* mOS context */
TAILQ_HEAD(, connection) g_sockq[MAX_CORES];  /* connection queue */
/**< ToDo: We should not use linked list for scalability */
/*----------------------------------------------------------------------------*/
/* Signal handler */
static void
sigint_handler(int signum)
{
    int i;

    /* Terminate the program if any interrupt happens */
    for (i = 0; i < g_max_cores; i++)
        mtcp_destroy_context(g_mctx[i]);

	exit(0);
}
/*----------------------------------------------------------------------------*/
/* Find connection structure by socket ID */
static inline struct connection *
find_connection(int cpu, int sock)
{
    struct connection *c;

    TAILQ_FOREACH(c, &g_sockq[cpu], link)
        if (c->sock == sock)
            return c;

    return NULL;
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
#if VERBOSE_KEY
/* Parse session address */
/* Return length of parsed data, -1 of error */
static void
DumpTLSKey(struct tls_crypto_info *key_info, session_address_t sess_addr)
{
	uint16_t cipher_suite = key_info->cipher_type;
	uint16_t mask = key_info->key_mask;
	uint16_t key_len;
	uint16_t iv_len;

	UNUSED(cipher_suite);
	key_len = TLS_CIPHER_AES_GCM_256_KEY_SIZE;
	iv_len = TLS_CIPHER_AES_GCM_256_IV_SIZE;

	fprintf(stderr, "------------------------------\n[%s] %x:%u -> %x:%u\n",
			__FUNCTION__, sess_addr->client_ip, sess_addr->client_port,
			sess_addr->server_ip, sess_addr->server_port);
	
	if (mask & CLI_KEY_MASK) {
		hexdump("client_write_key:", key_info->client_key, key_len);
	}
	if (mask & SRV_KEY_MASK) {
		hexdump("server_write_key:", key_info->server_key, key_len);
	}
	if (mask & CLI_IV_MASK) {
		hexdump("client_write_iv:", key_info->client_iv, iv_len);
	}
	if (mask & SRV_IV_MASK) {
		hexdump("server_write_iv:", key_info->server_iv, iv_len);
	}
}
#endif	/* VERBOSE_KEY */
/*----------------------------------------------------------------------------*/
/* Parse session address */
/* Return length of parsed data, -1 of error */
static int
ParseSessionAddr(uint8_t *data, uint16_t datalen,
				 session_address_t sess_addr)
{
	char *tok = NULL;
	uint32_t ip_addr;
	uint16_t port;

#if VERBOSE_DEBUG
	fprintf(stderr, "[%s]\n", __FUNCTION__);
	hexdump("", data, datalen);
#endif
	
	/* Parse src/dst IP address */
	if ((tok = strtok((char *)data, " ")) == NULL) {
		return -1;
	}
	ip_addr = strtol(tok, NULL, 16);
	sess_addr->client_ip = ip_addr;
	
	if ((tok = strtok(NULL, " ")) == NULL) {
		return -1;
	}
	ip_addr = strtol(tok, NULL, 16);
	sess_addr->server_ip = ip_addr;

	/* Parse src/dst port */
	if ((tok = strtok(NULL, " ")) == NULL) {
		return -1;
	}
	port = strtol(tok, NULL, 10);
	sess_addr->client_port = port;
	
	if ((tok = strtok(NULL, " ")) == NULL) {
		return -1;
	}
	port = strtol(tok, NULL, 10);
	sess_addr->server_port = port;

	if (tok == NULL) {
		return 0;
	}
	return (tok + strlen(tok) + 1) - (char *)data;
}
/*----------------------------------------------------------------------------*/
/* Parse payload to get TLS session key data into key_info */
/* Return length of parsed data, -1 of error */
static int
ParseTLSKey(uint8_t *data, uint16_t datalen,
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
		memcpy(key_info->client_iv, ptr, iv_len);
		ptr += iv_len;
	}
	if (key_mask & SRV_IV_MASK) {
		memcpy(key_info->client_iv, ptr, iv_len);
		ptr += iv_len;
	}

	return ptr - (char*)data;
}
/*----------------------------------------------------------------------------*/
/* Parse TCP payload to assemble single TLS record */
/* Return byte of parsed record, 0 if no complete record */
static uint32_t
ParseTLSRecord(struct connection *c, int side)
{
	tls_context *tls_ctx;
	tls_record *record;
	uint32_t start_seq;
	uint8_t *ptr;
	uint8_t record_type;
	uint16_t version;
	uint16_t record_len;
	int off = 0;
	
	tls_ctx = &c->tls_ctx;
	start_seq = tls_ctx->unparse_tcp_seq[side];

	assert(UINT32_GEQ(start_seq, c->seq_head[side]));

	/* Parse header of new record */
	if (UINT32_GT(start_seq + TLS_HEADER_LEN, c->seq_tail[side])) {
		return 0;
	}

	ptr = c->buf[side] + start_seq - c->seq_head[side];
	record_type = *ptr + off;
	off += sizeof(uint8_t);
	
	version = htons(*(uint16_t*)(ptr + off));
	off += sizeof(uint16_t);

	record_len = htons(*(uint16_t*)(ptr + off));
	off += sizeof(uint16_t);

	/* Store TLS record info if complete */
	if (UINT32_GT(start_seq + record_len + TLS_HEADER_LEN, c->seq_tail[side])) {
		return 0;
	}

	record = &tls_ctx->last_rec[side];
	record->type = record_type;
	record->tcp_seq = start_seq;
	record->rec_seq = tls_ctx->rec_cnt[side];

	if (record_type == APPLICATION_DATA) {
		memcpy(record->ciphertext, ptr + TLS_HEADER_LEN,
			   record_len);
		record->cipher_len = record_len;
	} else {
		/* ToDo: We might need to verify HANDSHAKE_FINISHED */
	}

	/* Update tls_ctx */
	if (tls_ctx->version < version) {
		tls_ctx->version = version;
	}

	/* ToDo: Add parsing cipher suite */
	
	tls_ctx->unparse_tcp_seq[side] += record_len + TLS_HEADER_LEN;
	tls_ctx->last_rec_seq[side] = tls_ctx->rec_cnt[side];
	tls_ctx->rec_cnt[side]++;

	
	/* ToDo: move below to separate function, e.g. PrintTLSStat() */
#if VERBOSE_TLS
	fprintf(stderr, "[%s] Parse new record to follow session!\n",
			__FUNCTION__);
	fprintf(stderr, "Record type %x, length %u (TCP %u ~ %u), "
			"rec seq %lu, cipher len %u\n",
			record->type, record->tcp_seq, record_len,
			record->tcp_seq + record_len + TLS_HEADER_LEN,
			record->rec_seq, record->cipher_len);
	if (record->cipher_len) {
		hexdump("Dump of ciphertext of the record:",
				record->ciphertext, record->cipher_len);
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
    struct connection *c;

    c = calloc(sizeof(struct connection), 1);
    if (!c)
        return;

    /* Fill values of the connection structure */
    c->sock = sock;
    if (mtcp_getpeername(mctx, c->sock, (void *)c->addrs, &addrslen,
                         MOS_SIDE_BOTH) < 0) {
        perror("mtcp_getpeername");
        /* it's better to stop here and do debugging */
        exit(EXIT_FAILURE);
    }

    /* Insert the structure to the queue */
    TAILQ_INSERT_TAIL(&g_sockq[mctx->cpu], c, link);
}
/*----------------------------------------------------------------------------*/
/* Destroy connection structure */
static void
cb_destroy(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
    struct connection *c;

    if (!(c = find_connection(mctx->cpu, sock)))
        return;

    TAILQ_REMOVE(&g_sockq[mctx->cpu], c, link);
    free(c);
}
/*----------------------------------------------------------------------------*/
/* Update connection's TCP state of each side */
static void
cb_new_data(mctx_t mctx, int sock, int side,
			uint64_t events, filter_arg_t *arg)
{
	uint16_t record_len;
	int len;
	uint32_t buf_off;

    struct connection *c;
    /* socklen_t intlen = sizeof(int); */

    if (!(c = find_connection(mctx->cpu, sock)))
        return;

#if VERBOSE_TCP
	fprintf(stderr, "\n--------------------------------------------------\n");
	fprintf(stderr, "[%s] sock: %u, c->sock: %u, side: %u\n",
			__FUNCTION__, sock, c->sock, side);
#endif

	
	buf_off = c->seq_tail[side] - c->seq_head[side];
	len = mtcp_peek(mctx, sock, side,
					(char*)c->buf[side] + buf_off, MAX_BUF_LEN - buf_off);

	if (len > 0) {
#if VERBOSE_TCP
		fprintf(stderr, "[%s] from %s, received %u B (seq %u ~ %u) TCP data!\n",
				__FUNCTION__, (side == MOS_SIDE_CLI) ? "client":"server",
				len, c->seq_tail[side], c->seq_tail[side] + len);

		hexdump(NULL, c->buf[side] + buf_off, len);
#endif 

		c->seq_tail[side] += len;

		/* Reassemble TLS record */
		while((record_len = ParseTLSRecord(c, side)) > 0) {
			;
		}
	}
}
/*----------------------------------------------------------------------------*/
/* Update connection's TCP state of each side */
static void
cb_new_key(mctx_t mctx, int sock, int side,
		   uint64_t events, filter_arg_t *arg)
{
	struct pkt_info p;
	uint8_t *payload, *ptr;
	uint16_t payloadlen;
	struct udphdr *udph;
	struct tls_crypto_info key_info;
	struct session_address sess_addr = {0};
	int sock_mon = 0;
	int offset;
	uint16_t left_len;

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
	
	offset = ParseTLSKey(ptr, left_len, &key_info);
	ptr += offset;
	left_len -= offset;

	offset = ParseSessionAddr(ptr, left_len, &sess_addr);
	sock_mon = mtcp_addrtosock(mctx, &sess_addr);
	fprintf(stderr, "sock: %d\n", sock_mon);

#if VERBOSE_KEY
	DumpTLSKey(&key_info, &sess_addr);
#endif

	if (sock_mon < 0) {
		return;
	}

	mtcp_setsockopt(mctx, sock_mon, SOL_MONSOCKET,
					MOS_TLS_SP, &key_info, sizeof(key_info));

	struct tls_crypto_info key_info_tmp;
	socklen_t key_info_len = sizeof(key_info_tmp);
	mtcp_getsockopt(mctx, sock_mon, SOL_MONSOCKET,
					MOS_TLS_SP, &key_info_tmp, &key_info_len);
	hexdump("Get tls_crypto_info:", (uint8_t*)&key_info_tmp, key_info_len);

	return;
}
/*----------------------------------------------------------------------------*/
static bool
CheckIsKey(mctx_t mctx, int sock,
		   int side, uint64_t events, filter_arg_t *arg)
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
RegisterSessionKeyCallback(mctx_t mctx, int sock)
{
	event_t ude_from_ctrl;

	ude_from_ctrl = mtcp_define_event(MOS_ON_PKT_IN, CheckIsKey, NULL);
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
RegisterDataCallback(mctx_t mctx, int sock)
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
RegisterCallbacks(mctx_t mctx)
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
	RegisterSessionKeyCallback(mctx, sock_key);

	
	/* Register UDE for TCP connetions */
    if ((sock_stream = mtcp_socket(mctx, AF_INET,
                         MOS_SOCK_MONITOR_STREAM, 0)) < 0) {
        fprintf(stderr, "Failed to create monitor listening socket!\n");
        exit(-1); /* no point in proceeding if we don't have a listening socket */
    }
	RegisterDataCallback(mctx, sock_stream);
}
/*----------------------------------------------------------------------------*/
/* Open monitoring socket and ready it for monitoring */
static void
InitMonitor(mctx_t mctx)
{
    /* Initialize internal memory structures */
    TAILQ_INIT(&g_sockq[mctx->cpu]);

    RegisterCallbacks(mctx);
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
        InitMonitor(g_mctx[i]);
	}

	/* wait until all threads finish */	
	for (i = 0; i < mcfg.num_cores; i++) {
		mtcp_app_join(g_mctx[i]);
	  	fprintf(stderr, "Message test thread %d joined.\n", i);	  
	}	
	
	mtcp_destroy();

	return EXIT_SUCCESS;
}
/*----------------------------------------------------------------------------*/

