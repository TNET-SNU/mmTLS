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

/* Maximum CPU cores */
#define MAX_CORES       16
/* Number of TCP flags to monitor */
#define NUM_FLAG        6
/* Default path to mOS configuration file */
#define MOS_CONFIG_FILE     "config/mos.conf"

#define MAX_BUF_LEN      1048576    /* 1M */
#define MAX_RECORD_LEN   16384		/* 16K */
#define TLS_HEADER_LEN   5

#define VERBOSE_TCP   0
#define VERBOSE_TLS   0

#define UINT32_LT(a,b)         ((int32_t)((a)-(b)) < 0)
#define UINT32_LEQ(a,b)        ((int32_t)((a)-(b)) <= 0)
#define UINT32_GT(a,b)         ((int32_t)((a)-(b)) > 0)
#define UINT32_GEQ(a,b)        ((int32_t)((a)-(b)) >= 0)
/*----------------------------------------------------------------------------*/
/* Global variables */
enum {
    CHANGE_CIPHER_SPEC  = 0x14,
    ALERT               = 0x15,
    HANDSHAKE           = 0x16,
    APPLICATION_DATA    = 0x17,
} tls_record_type;

typedef struct tls_record {
	uint8_t type;
	uint32_t tcp_seq;
	uint64_t rec_seq;

	uint8_t plaintext[MAX_RECORD_LEN];
	uint8_t ciphertext[MAX_RECORD_LEN];
	uint16_t plain_len;
	uint16_t cipher_len;
} tls_record;

typedef struct tls_context {
	uint16_t version;
	uint16_t cipher_suite;

	uint64_t last_rec_seq[2];
	uint32_t rec_cnt[2];
	
	uint32_t unparse_tcp_seq[2];
	/**< starting point to parse a new record */

	tls_record last_rec[2];
} tls_context;

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
#if VERBOSE_TCP | VERBOSE_TLS
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
#endif
/*----------------------------------------------------------------------------*/
/* Parse TCP payload to assemble single TLS record */
/* Return byte of parsed record, 0 if no complete record */
/* ToDo: This should be moved to separate source file */
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
	uint16_t len, record_len;
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
		fprintf(stderr, "[%s] %s received %u B (seq %u ~ %u) TCP data!\n",
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
/* Register required callbacks */
static void
RegisterCallbacks(mctx_t mctx, int sock, event_t ev_new_syn)
{
    /* Register callbacks */
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
/* Open monitoring socket and ready it for monitoring */
static void
InitMonitor(mctx_t mctx, event_t ev_new_syn)
{
    int sock;

    /* Initialize internal memory structures */
    TAILQ_INIT(&g_sockq[mctx->cpu]);

    /* create socket and set it as nonblocking */
    if ((sock = mtcp_socket(mctx, AF_INET,
                         MOS_SOCK_MONITOR_STREAM, 0)) < 0) {
        fprintf(stderr, "Failed to create monitor listening socket!\n");
        exit(-1); /* no point in proceeding if we don't have a listening socket */
    }

    RegisterCallbacks(mctx, sock, ev_new_syn);
}
/*----------------------------------------------------------------------------*/
int
main(int argc, char **argv)
{
	int ret, i;
	event_t ev_new_syn;
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
        InitMonitor(g_mctx[i], ev_new_syn);
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
