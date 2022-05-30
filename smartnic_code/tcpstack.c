#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_thash.h>
#include <rte_malloc.h>
#include <sched.h>
#include <rte_thread.h>

#include "tcpstack.h"
#if USE_HASHTABLE_FOR_ACTIVE_SESSION
#include "fhash.h"
#endif	/* USE_HASHTABLE_FOR_ACTIVE_SESSION */

#define B_TO_Mb(x) ((x) * 8 / 1000 / 1000)

#define ISN 1234

#define ETH_FOREACH_PORT(ps, n, i, p) \
	for (p=ps[0], i=0;		   \
		 i < n;				   \
		 i++, p=ps[i])

int test_flag = 1;
#if MEASURE_CLOCK
uint64_t tsc_start[MAX_CPUS] = {0}, tsc_end[MAX_CPUS];
uint64_t tsc_process[MAX_CPUS] = {0};
#endif

static int force_quit[MAX_CPUS] = {0};

#if defined (LOGGER)
/* logger related variable */
struct log_thread_context *g_logctx[MAX_CPUS] = {0};
static pthread_t log_thread[MAX_CPUS] = {0};
#endif

static uint8_t key[] = {
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05
};
#define RSS_BIT_MASK 0x000001FF
// extern uint8_t done[MAX_CPUS];
/*---------------------------------------------------------------------------*/
/* Function Prototype */

static inline void
clear_tcp_session(struct tcp_session *tcp);

static void
thread_local_init(int core_id);

static void
thread_local_destroy(int core_id);

static inline struct tcp_session *
pop_free_session(struct thread_context *ctx);

static void
process_packet(uint16_t core_id, uint16_t port,
			   struct rte_mbuf *m, uint32_t len);

static inline unsigned
check_ready(void);

/* ------------------------------------------------------------------------ */
#if LOG_STR_MAP
void
dump_str_log(struct thread_context *ctx)
{
    struct str_log *log;
    uint8_t *bk;
    uint32_t i;

    for (i = 0; i < ctx->str_log_cnt; i++) {
        log = &ctx->str_log[i];
        bk = (uint8_t *)&log->bk_ip;
        fprintf(stderr,
				"[core:%u] proxy_port: %u, %02u.%02u.%02u.%02u(SID:%u)\n",
                ctx->coreid, log->proxy_port,
                bk[0], bk[1], bk[2], bk[3], log->bk_sid);
    }
}
#endif
/* ------------------------------------------------------------------------ */
void
print_xstats(int port_id)
{
    int ret, len, i;

    struct rte_eth_xstat *xstats;
    struct rte_eth_xstat_name *xstats_names;
    static const char *stats_border = "_______";

    printf("PORT STATISTICS:\n================\n");
    len = rte_eth_xstats_get(port_id, NULL, 0);
    if (len < 0)
        rte_exit(EXIT_FAILURE,
                "rte_eth_xstats_get(%u) failed: %d", port_id,
                len);

    xstats = calloc(len, sizeof(*xstats));
    if (xstats == NULL)
        rte_exit(EXIT_FAILURE,
                "Failed to calloc memory for xstats");

    ret = rte_eth_xstats_get(port_id, xstats, len);
    if (ret < 0 || ret > len) {
        free(xstats);
        rte_exit(EXIT_FAILURE,
                "rte_eth_xstats_get(%u) len%i failed: %d",
                port_id, len, ret);
    }

    xstats_names = calloc(len, sizeof(*xstats_names));
    if (xstats_names == NULL) {
        free(xstats);
        rte_exit(EXIT_FAILURE,
                "Failed to calloc memory for xstats_names");
    }

    ret = rte_eth_xstats_get_names(port_id, xstats_names, len);
    if (ret < 0 || ret > len) {
        free(xstats);
        free(xstats_names);
        rte_exit(EXIT_FAILURE,
                "rte_eth_xstats_get_names(%u) len%i failed: %d",
                port_id, len, ret);
    }

    for (i = 0; i < len; i++) {
        if (xstats[i].value > 0)
			printf("Port %u: %s %s:\t\t%"PRIu64"\n",
				port_id, stats_border,
				xstats_names[i].name,
				xstats[i].value);
    }
}
/*---------------------------------------------------------------------------*/
#if VERBOSE_TCP
void
print_pkt_info(uint16_t core_id, uint16_t port, 
			   uint8_t *pktbuf, uint32_t len, int type)
{
    struct rte_ether_hdr *ethh;
    struct rte_ipv4_hdr *iph;
    uint16_t ip_len;
    struct rte_tcp_hdr *tcph;
    char recv_dst_hw[20];
    char recv_src_hw[20];
	uint32_t seq_no, ack_no;
    uint8_t *option;
    uint16_t option_len;
    uint8_t *payload;
    uint32_t payload_len;

    ethh = (struct rte_ether_hdr *)pktbuf;
	iph = (struct rte_ipv4_hdr *)(ethh + 1);
    tcph = (struct rte_tcp_hdr *)(iph + 1);
    payload = (uint8_t *)tcph + ((tcph->data_off & 0xf0) >> 2);

    ip_len = ntohs(iph->total_length);
    seq_no = ntohl(tcph->sent_seq);
    ack_no = ntohl(tcph->recv_ack);
    option = (uint8_t *)(tcph + 1);
    option_len = payload - option;
    payload_len = ip_len - (payload - (u_char *)iph);

#if !VERBOSE_RECV
	if (type == TCP_RECV)
		return;
#endif
#if !VERBOSE_SEND
	if (type == TCP_SEND)
		return;
#endif
#if 1
	if (type == TCP_RECV) {
		TCP_PRINT("\n\n"
				"----------Packet RECV Info--------------------------\n");
	} else {
		TCP_PRINT("\n\n"
				"----------Packet SEND Info--------------------------\n");
	}

    if (ethh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		/* UNUSED(recv_src_hw); */
		/* UNUSED(recv_dst_hw); */
		memset(recv_dst_hw, 0, 10);
		memset(recv_src_hw, 0, 10);

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
        sprintf(recv_dst_hw, "%x:%x:%x:%x:%x:%x",
                ethh->dst_addr.addr_bytes[0],
                ethh->dst_addr.addr_bytes[1],
                ethh->dst_addr.addr_bytes[2],
                ethh->dst_addr.addr_bytes[3],
                ethh->dst_addr.addr_bytes[4],
                ethh->dst_addr.addr_bytes[5]);

        sprintf(recv_src_hw, "%x:%x:%x:%x:%x:%x",
                ethh->src_addr.addr_bytes[0],
                ethh->src_addr.addr_bytes[1],
                ethh->src_addr.addr_bytes[2],
                ethh->src_addr.addr_bytes[3],
                ethh->src_addr.addr_bytes[4],
                ethh->src_addr.addr_bytes[5]);
#else
		sprintf(recv_dst_hw, "%x:%x:%x:%x:%x:%x",
				ethh->d_addr.addr_bytes[0],
				ethh->d_addr.addr_bytes[1],
				ethh->d_addr.addr_bytes[2],
				ethh->d_addr.addr_bytes[3],
				ethh->d_addr.addr_bytes[4],
				ethh->d_addr.addr_bytes[5]);

		sprintf(recv_src_hw, "%x:%x:%x:%x:%x:%x",
				ethh->s_addr.addr_bytes[0],
				ethh->s_addr.addr_bytes[1],
				ethh->s_addr.addr_bytes[2],
				ethh->s_addr.addr_bytes[3],
				ethh->s_addr.addr_bytes[4],
				ethh->s_addr.addr_bytes[5]);
#endif
		
        uint8_t *src, *dst;
        src = (uint8_t *)&iph->src_addr;
        dst = (uint8_t *)&iph->dst_addr;
		TCP_PRINT("core: %d, port: %d\n"
				/* "%x : %u (%s) -> %x : %u (%s)\n" */
				"%02u.%02u.%02u.%02u:%u -> %02u.%02u.%02u.%02u:%u\n"
				"seq: %u, ack: %u\n"
				"len: %u, option_len: %u, payload_len: %u\n",
				core_id, port,
				/* ntohl(iph->src_addr), ntohs(tcph->src_port), recv_src_hw, */
                /* ntohl(iph->dst_addr), ntohs(tcph->dst_port), recv_dst_hw, */
				src[0],src[1],src[2],src[3], ntohs(tcph->src_port),
				dst[0],dst[1],dst[2],dst[3], ntohs(tcph->dst_port),
				seq_no, ack_no,
				len, option_len, payload_len);
		TCP_PRINT("TCP flag: ");
		if (tcph->tcp_flags & TCP_FLAG_FIN)
			TCP_PRINT("FIN ");
		if (tcph->tcp_flags & TCP_FLAG_SYN)
			TCP_PRINT("SYN ");
		if (tcph->tcp_flags & TCP_FLAG_RST)
			TCP_PRINT("RST ");
		if (tcph->tcp_flags & TCP_FLAG_PSH)
			TCP_PRINT("PSH ");
		if (tcph->tcp_flags & TCP_FLAG_ACK)
			TCP_PRINT("ACK ");
		if (tcph->tcp_flags & TCP_FLAG_URG)
			TCP_PRINT("URG ");
		TCP_PRINT("\n\n");
	}
#endif

#if VERBOSE_CHUNK
	{
		unsigned z;
		fprintf(stderr, "\nReceived Packet buf (%p):\n", pktbuf);
		for (z = 0; z < len; z++)
			fprintf(stderr, "%02X%c", pktbuf[z],
					((z + 1) % 16 ? ' ' : '\n'));
		fprintf(stderr, "\n");
		fprintf(stderr, "\n");
	}
#endif /* VERBOSE_CHUNK */
}
#endif	/* VERBOSE_TCP */

#if VERBOSE_STAT
uint64_t rx_bytes_last[MAX_DPDK_PORT][MAX_CPUS];
uint64_t rx_pkts_last[MAX_DPDK_PORT][MAX_CPUS];
uint64_t tx_bytes_last[MAX_DPDK_PORT][MAX_CPUS];
uint64_t tx_pkts_last[MAX_DPDK_PORT][MAX_CPUS];
uint64_t rtx_bytes_last[MAX_DPDK_PORT][MAX_CPUS];
uint64_t rtx_pkts_last[MAX_DPDK_PORT][MAX_CPUS];

uint64_t global_rx_bytes_last[MAX_DPDK_PORT];
uint64_t global_rx_pkts_last[MAX_DPDK_PORT];
uint64_t global_tx_bytes_last[MAX_DPDK_PORT];
uint64_t global_tx_pkts_last[MAX_DPDK_PORT];
uint64_t global_rtx_bytes_last[MAX_DPDK_PORT];
uint64_t global_rtx_pkts_last[MAX_DPDK_PORT];
static inline void
print_stat(uint16_t *port_list, int16_t port_num) {

    uint32_t num_core = rte_lcore_count();
	uint16_t port;
	uint32_t i;
	int p_i = 0;

	ETH_FOREACH_PORT(port_list, port_num, p_i, port) {
		global_stat.rx_bytes[port] = 0;
		global_stat.rx_pkts[port] = 0;

		global_stat.tx_bytes[port] = 0;
		global_stat.tx_pkts[port] = 0;

		global_stat.rtx_bytes[port] = 0;
		global_stat.rtx_pkts[port] = 0;
	}

	for (i = 0; i < num_core; i++) {
		p_i = 0;
		ETH_FOREACH_PORT(port_list, port_num, p_i, port) {
			global_stat.rx_bytes[port] += ctx_array[i]->stat.rx_bytes[port];
			global_stat.rx_pkts[port] += ctx_array[i]->stat.rx_pkts[port];

			global_stat.tx_bytes[port] += ctx_array[i]->stat.tx_bytes[port];
			global_stat.tx_pkts[port] += ctx_array[i]->stat.tx_pkts[port];

			global_stat.rtx_bytes[port] += ctx_array[i]->stat.rtx_bytes[port];
			global_stat.rtx_pkts[port] += ctx_array[i]->stat.rtx_pkts[port];
		}
	}

	/* Per-Core Stat */
	int is_skip_stat = TRUE;
	p_i = 0;
	ETH_FOREACH_PORT(port_list, port_num, p_i, port) {
		if (global_stat.rx_pkts[port] - global_rx_pkts_last[port] != 0 ||
		   global_stat.tx_pkts[port] - global_tx_pkts_last[port] != 0)
			is_skip_stat = FALSE;
	}
	if (is_skip_stat)
		goto skip_stat;
	for (i = 0; i < num_core; i++) {
		fprintf(stderr, "[CPU %2d]\n", i);

		p_i = 0;
		ETH_FOREACH_PORT(port_list, port_num, p_i, port) {
#if VERBOSE_NIC_STAT
			//print_xstats(port);
#endif

			fprintf(stderr,
					"[CPU %2d] Port %d "
					"RX: %7lu(pps), %6.2f(Mbps), "
					"TX: %7lu(pps), %6.2f(Mbps), "
					"RTX: %7lu(pps), %6.2f(Mbps)\n",
					i, port,
					ctx_array[i]->stat.rx_pkts[port] - rx_pkts_last[port][i],
					B_TO_Mb((float)(ctx_array[i]->stat.rx_bytes[port] - rx_bytes_last[port][i])),
					ctx_array[i]->stat.tx_pkts[port] - tx_pkts_last[port][i],
					B_TO_Mb((float)(ctx_array[i]->stat.tx_bytes[port] - tx_bytes_last[port][i])),
					ctx_array[i]->stat.rtx_pkts[port] - rtx_pkts_last[port][i],
					B_TO_Mb((float)(ctx_array[i]->stat.rtx_bytes[port] - rtx_bytes_last[port][i])));

			rx_pkts_last[port][i] = ctx_array[i]->stat.rx_pkts[port];
			rx_bytes_last[port][i] = ctx_array[i]->stat.rx_bytes[port];
			tx_pkts_last[port][i] = ctx_array[i]->stat.tx_pkts[port];
			tx_bytes_last[port][i] = ctx_array[i]->stat.tx_bytes[port];
			rtx_pkts_last[port][i] = ctx_array[i]->stat.rtx_pkts[port];
			rtx_bytes_last[port][i] = ctx_array[i]->stat.rtx_bytes[port];
		}
	}

	fprintf(stderr,
			"\n[TOTAL]\n");

	p_i = 0;
	ETH_FOREACH_PORT(port_list, port_num, p_i, port) {
		fprintf(stderr,
				"[TOTAL] Port %d "
				"RX: %7lu (pps), %6.2f(Mbps), "
				"TX: %7lu(pps), %6.2f(Mbps), "
				"RTX: %7lu(pps), %6.2f(Mbps)\n",
				port,
				global_stat.rx_pkts[port] - global_rx_pkts_last[port],
				B_TO_Mb((float)(global_stat.rx_bytes[port] - global_rx_bytes_last[port])),
				global_stat.tx_pkts[port] - global_tx_pkts_last[port],
				B_TO_Mb((float)(global_stat.tx_bytes[port] - global_tx_bytes_last[port])),
				global_stat.rtx_pkts[port] - global_rtx_pkts_last[port],
				B_TO_Mb((float)(global_stat.rtx_bytes[port] - global_rtx_bytes_last[port])));
		global_rx_pkts_last[port] = global_stat.rx_pkts[port];
		global_rx_bytes_last[port] = global_stat.rx_bytes[port];
		global_tx_pkts_last[port] = global_stat.tx_pkts[port];
		global_tx_bytes_last[port] = global_stat.tx_bytes[port];
		global_rtx_pkts_last[port] = global_stat.rtx_pkts[port];
		global_rtx_bytes_last[port] = global_stat.rtx_bytes[port];
	}
 skip_stat:
	fprintf(stderr, "\n");
}

#endif	/* VERBOSE_STAT */

static inline void
clear_tcp_session(struct tcp_session *tcp)
{
    /* Do not touch coreid, ssl_session */
    tcp->state = TCP_SESSION_IDLE;
    tcp->portid = 0;

    tcp->src_ip = 0;
    tcp->src_port = 0;

    tcp->dst_ip = 0;
    tcp->dst_port = 0;

    tcp->window = 0;

	tcp->base_sent_seq = 0;
	tcp->base_recv_ack = 0;
	tcp->window = 0;

    tcp->total_sent = 0;

	if (tcp->sess_type == SESS_CLIENT) {
		tcp->is_nicsync = 0;
		tcp->send_log_start = 0;
		tcp->send_log_end = 0;
		tcp->sent_log_cnt = 0;
		tcp->pending_log_cnt = 0;
		tcp->sess_be_num = 0;
	} else if (tcp->sess_type == SESS_BACKEND) {
		tcp->be_log_start = 0;
		tcp->be_log_cnt = 0;
		tcp->ff_seqs_start = 0;
		tcp->ff_seqs_end = 0;
	}

	if (tcp->sess_type == SESS_CLIENT) {
		struct ssl_session *ssl = &tcp->ssl_session;
		ssl->state = SSL_SESSION_NOT_ESTABLISHED;
		ssl->num_current_records = 0;
		ssl->next_record_seq = 0;
		rte_eth_tls_device_free(tcp->portid, &ssl->tls_ctx);
		ssl->tls_ctx.next_record_num = 0;
	}
}

void
remove_session(struct tcp_session* sess)
{
	/* debug */
	DEBUG_PRINT("[%s] remove!\n", __FUNCTION__);

    struct thread_context *ctx = ctx_array[sess->coreid];

    assert(ctx->active_cnt > 0);

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    ht_remove(ctx->active_session_table, sess);
#else
    TAILQ_REMOVE(&ctx->active_session_q, sess->parent, active_session_link);
#endif  /* USE_HASHTABLE_FOR_ACTIVE_SESSION */
    ctx->active_cnt--;

    clear_tcp_session(sess);

    /* Insert back to free session queue */
    TAILQ_INSERT_TAIL(&ctx->free_session_q, sess, free_session_link);
    ctx->free_cnt++;
}
/* ------------------------------------------------------------------------ */
/* ToDo: why it is not inline, due to only one call in tcpstack.c? 
 * make it as macro for optimization */
int
is_tls_session(struct tcp_session *sess) {
    return (sess->ssl_session.state == SSL_SESSION_ESTABLISHED);
}
/* ------------------------------------------------------------------------ */
static void
thread_local_init(int core_id)
{
    struct thread_context* ctx;
	struct tcp_session *sess;
	struct pkt_blk *blk;
    struct dpdk_private_context* dpc;
    int nb_ports;
    int i, j;

	UNUSED(sess);

	/* Set core affinity */
	cpu_set_t cpus;
	int ret;
	CPU_ZERO(&cpus);
	CPU_SET(rte_lcore_id(), &cpus);
	ret = rte_thread_set_affinity(&cpus);
	if (ret < 0) {
		fprintf(stderr, "Failed to set thread affinity for core %d\n",
				core_id);
		exit(1);
	}
	
    nb_ports = rte_eth_dev_count_avail();

    /* Allocate memory for thread context */
    ctx_array[core_id] = calloc(1, sizeof(struct thread_context));
    ctx = ctx_array[core_id];
    if (ctx == NULL)
        rte_exit(EXIT_FAILURE,
                 "[CPU %d] Cannot allocate memory for thread_context, "
                 "errno: %d\n",
                 rte_lcore_id(), errno);

    ctx->ready = 0;
    ctx->coreid = (uint16_t)core_id;

    /* Allocate memory for dpdk private context */
    ctx->dpc = calloc(1, sizeof(struct dpdk_private_context));
    dpc = ctx->dpc;
    if (dpc == NULL)
        rte_exit(EXIT_FAILURE,
                 "[CPU %d] Cannot allocate memory for dpdk_private_context, "
                 "errno: %d\n",
                 rte_lcore_id(), errno);

    /* Assign packet mbuf pool to dpdk private context */
    dpc->pktmbuf_pool = pktmbuf_pool[core_id];

    /* Initialize Session Queues */
#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    ctx->active_session_table = create_ht(NUM_BINS);
    if (!ctx->active_session_table) {
		ERROR_PRINT("Cannot allocate memory for "
         		"session hashtable of core[%d]",
	        	rte_lcore_id());
		exit(EXIT_FAILURE);
    }
#else
    TAILQ_INIT(&ctx->active_session_q);
#endif	/* USE_HASHTABLE_FOR_ACTIVE_SESSION */
    ctx->active_cnt = 0;

    TAILQ_INIT(&ctx->free_session_q);
    ctx->free_cnt = 0;

    ctx->tcp_array = calloc(local_max_conn, sizeof(struct tcp_session *));

    /* Allocate memory for tcp sessions */
    for (j = 0; j < local_max_conn; j++) {
        ctx->tcp_array[j] = calloc(1, sizeof(struct tcp_session));
        if (ctx->tcp_array[j] == NULL) {
            ERROR_PRINT("Cannot allocate memory for"
					"%dth tcp array of core[%d]\n",
					j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

		sess = ctx->tcp_array[j];

        /* Insert Session into free_session_q */
        TAILQ_INSERT_TAIL(&ctx->free_session_q,
                          sess, free_session_link);
        ctx->free_cnt++;

        sess->ctx = ctx;
        sess->coreid = core_id;
    }

    ctx->decrease = 0;

    RTE_ETH_FOREACH_DEV(i) {
        ctx->stat.rx_bytes[i] = 0;
        ctx->stat.rx_pkts[i] = 0;

        ctx->stat.tx_bytes[i] = 0;
        ctx->stat.tx_pkts[i] = 0;

        ctx->stat.rtx_bytes[i] = 0;
        ctx->stat.rtx_pkts[i] = 0;
    }
}

static void
thread_local_destroy(int core_id)
{
    struct thread_context* ctx;
    struct dpdk_private_context* dpc;
    struct tcp_session* tcp;
    int port, i, ret;

    ctx = ctx_array[core_id];
    dpc = ctx->dpc;
    void *cur, *next;

    /* Remove sessions from queues */
    cur = TAILQ_FIRST(&ctx->free_session_q);
    while(cur != NULL) {
        next = (struct tcp_session *)TAILQ_NEXT((struct tcp_session *)cur,
                                                free_session_link);
        TAILQ_REMOVE(&ctx->free_session_q,
                     (struct tcp_session *)cur,
                     free_session_link);
        cur = next;
    }

#if !USE_HASHTABLE_FOR_ACTIVE_SESSION
    cur = TAILQ_FIRST(&ctx->active_session_q);
    while(cur != NULL) {
        next = (struct tcp_session *)TAILQ_NEXT((struct tcp_session *)cur,
                                                active_session_link);
        TAILQ_REMOVE(&ctx->active_session_q,
                     (struct tcp_session *)cur,
                     active_session_link);
        cur = next;
    }
#endif	/* !USE_HASHTABLE_FOR_ACTIVE_SESSION */

    /* Destroy each session */
    for (i = 0; i < local_max_conn; i++) {
        tcp = ctx->tcp_array[i];
        free(tcp);
    }

    free(ctx->tcp_array);

    /* Free dpdk private context */
    RTE_ETH_FOREACH_DEV(port) {
        if (dpc->rmbufs[port].len != 0) {
            free_pkts(dpc->rmbufs[port].m_table, dpc->rmbufs[port].len);
            dpc->rmbufs[port].len = 0;
        }
    }
    rte_mempool_free(dpc->pktmbuf_pool);
    free(ctx->dpc);

    /* Free thread context */
    free(ctx);
}

inline int
send_pkt_to_host(uint16_t core_id, uint16_t port,
				 uint8_t *pktbuf, uint32_t len)
{
	uint8_t *buf;

	TCP_PRINT("[send pkt to host] len: %u\n", len);
#if VERBOSE_MBUF
	fprintf(stderr, "[%s:%d][%p]\n", __func__, __LINE__, pktbuf);
#endif

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
	memcpy(((struct rte_ether_hdr*)pktbuf)->dst_addr.addr_bytes, HOST_MAC, 6);
#else
	memcpy(((struct rte_ether_hdr*)pktbuf)->d_addr.addr_bytes, HOST_MAC, 6);
#endif

	buf = get_wptr_tso(core_id, port, len, TCP_HEADER_LEN);
	if (buf == NULL) {
		ERROR_PRINT("[send pkt to host] can't get wptr!\n");
		return -1;
	}
	memcpy(buf, pktbuf, len);

#if VERBOSE_TCP
	print_pkt_info(core_id, port, buf, len, TCP_SEND);
#endif

	return 0;
}

static inline struct tcp_session *
pop_free_session(struct thread_context *ctx)
{
    struct tcp_session *target;

    target = TAILQ_FIRST(&ctx->free_session_q);
    if (unlikely(!target)) {
        ERROR_PRINT("Not enough session, and this must not happen!\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->free_session_q, target, free_session_link);
    ctx->free_cnt--;
    return target;
}

struct tcp_session *
search_tcp_session(struct thread_context *ctx,
                   uint32_t src_ip, uint16_t src_port,
                   uint32_t dst_ip, uint16_t dst_port)
{
    struct tcp_session *target, *ret;

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    ret = ht_search(ctx->active_session_table,
					src_ip, src_port, dst_ip, dst_port);
    UNUSED(target);
#else
    ret = NULL;
    TAILQ_FOREACH(target, &ctx->active_session_q, active_session_link) {
        assert(target->state != TCP_SESSION_IDLE);

        if ((target->src_ip == src_ip) &&
            (target->src_port == src_port) &&
            (target->dst_ip == dst_ip) &&
            (target->dst_port == dst_port))
            ret = target;
    }  
#endif	/* USE_HASHTABLE_FOR_ACTIVE_SESSION */

    return ret;
}

struct tcp_session *
insert_tcp_session(struct thread_context *ctx, uint16_t portid,
                   const unsigned char* src_mac, 
                   uint32_t src_ip, uint16_t src_port,
                   const unsigned char* dst_mac,
                   uint32_t dst_ip, uint16_t dst_port,
                   uint16_t window)
{
    struct tcp_session *target;
    int j;
	
    target = pop_free_session(ctx);
    assert(target);
    assert(target->state == TCP_SESSION_IDLE);

    for (j = 0; j < 6; j++) {
        target->src_mac[j] = src_mac[j];
        target->dst_mac[j] = dst_mac[j];
    }
    target->state = TCP_SESSION_RECEIVED;
    target->portid = portid;

    target->src_ip = src_ip;
    target->src_port = src_port;
    target->dst_ip = dst_ip;
    target->dst_port = dst_port;

    target->window = window;

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    ht_insert(ctx->active_session_table, target);
#else
    TAILQ_INSERT_TAIL(&ctx->active_session_q,
                      target, active_session_link);
#endif	/* USE_HASHTABLE_FOR_ACTIVE_SESSION */

    ctx->active_cnt++;

    return target;
}

static inline int
send_sack(struct tcp_session *sess, uint8_t *pktbuf)
{
	struct rte_ether_hdr *ethh;
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcph;
	uint8_t *buf;

	uint8_t *tcph_sack;
	uint32_t *sack_blk;
	uint32_t sack_blk_num;
	struct pkt_blk *ooo_blk;
	uint32_t pktlen;
	uint32_t tcph_len;
	int i;

	sack_blk_num = 0;
	for (ooo_blk = sess->ooo_blk; ooo_blk != NULL; ooo_blk = ooo_blk->next) {
		sack_blk_num++;
		if (sack_blk_num > 100) {
			fprintf(stderr, "[%s:%d][Arm:%d] sack_blk_num: %u\n",
				__func__, __LINE__, sess->coreid, sack_blk_num);
			fprintf(stderr, "ooo_blk - seq:%u, len:%u\n",
				ooo_blk->seq, ooo_blk->len);
		}
		if (sack_blk_num > 200)
			exit(1);
	}
	sack_blk_num = MIN(sack_blk_num, MAX_SACK_BLOCK_NUM);

	tcph_len = sess->tcph_len + 8 * sack_blk_num + 4;
	pktlen = ETHERNET_HEADER_LEN + IP_HEADER_LEN + tcph_len;

	buf = get_wptr_tso(sess->coreid, sess->portid, pktlen,
					   TCP_HEADER_LEN);
	if (buf == NULL) {
		ERROR_PRINT("[send sack] can't get wptr!\n");
		return -1;
	}
	rte_memcpy(buf, pktbuf, pktlen - (8*sack_blk_num + 4));

	/* modify pkt hdr */
	uint8_t tmp_mac[6];
	uint32_t tmp;
	ethh = (struct rte_ether_hdr *)buf;
    iph = (struct rte_ipv4_hdr *)(ethh + 1);
    tcph = (struct rte_tcp_hdr *)(iph + 1);

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
	memcpy(tmp_mac, ethh->dst_addr.addr_bytes, 6);
	memcpy(ethh->dst_addr.addr_bytes, ethh->src_addr.addr_bytes, 6);
	memcpy(ethh->src_addr.addr_bytes, tmp_mac, 6);
#else
	memcpy(tmp_mac, ethh->d_addr.addr_bytes, 6);
	memcpy(ethh->d_addr.addr_bytes, ethh->s_addr.addr_bytes, 6);
	memcpy(ethh->s_addr.addr_bytes, tmp_mac, 6);
#endif

	tmp = iph->dst_addr;
	iph->dst_addr = iph->src_addr;
	iph->src_addr = tmp;
	iph->total_length = htons(IP_HEADER_LEN + tcph_len);
	iph->fragment_offset = htons(0x4000);
	iph->hdr_checksum = 0;

	tmp = (uint32_t)tcph->dst_port;
	tcph->dst_port = tcph->src_port;
	tcph->src_port = (uint16_t)tmp;

	tcph->sent_seq = tcph->recv_ack;
	tcph->recv_ack = htonl(sess->base_sent_seq);
	tcph->rx_win = htons(8192);
	tcph->data_off = (tcph_len << 2) & 0xf0;
	tcph->cksum = 0;

	/* add SACK */
	tcph_sack = (uint8_t*)tcph + tcph_len - (8 * sack_blk_num + 4);
	sack_blk = (uint32_t*)(tcph_sack+4);

    *(tcph_sack)   = TCP_OPT_NOP;
    *(tcph_sack+1) = TCP_OPT_NOP;
    *(tcph_sack+2) = TCP_OPT_SACK;
    *(tcph_sack+3) = 8*sack_blk_num + 2;

	ooo_blk = sess->ooo_blk;
	for (i = 0; i < sack_blk_num; i++) {
		*(sack_blk++) = htonl(ooo_blk->seq);
		*(sack_blk++) = htonl(ooo_blk->seq + ooo_blk->len);
		ooo_blk = ooo_blk->next;
	}

#if VERBOSE_CHUNK
    {
        uint32_t z;

        OOO_PRINT("[send ooo] "
                    "report ooo to host (%u B)\n", pktlen);

        for (z = 0; z < pktlen; z++)
            fprintf(stderr, "%02X%c",
                    *((uint8_t *)(buf) + z),
                    ((z + 1) % 16) ? ' ' : '\n');
        fprintf(stderr, "\n");
    }
#endif  /* VERBOSE_CHUNK */

	return 0;
}

static void
process_packet(uint16_t core_id, uint16_t port, struct rte_mbuf *m,
                uint32_t len)
{
    struct rte_ether_hdr *ethh;
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcph;
    uint16_t ip_len;
	uint8_t *pktbuf;
    uint8_t *option;
    uint16_t option_len;
    uint8_t *payload;
    uint32_t payload_len;
    struct thread_context *ctx;
    struct tcp_session *sess;

	pktbuf = rte_pktmbuf_mtod(m, uint8_t *);
#if VERBOSE_MBUF
	fprintf(stderr, "\n\n[%s:%d] [%p]\n", __func__, __LINE__, pktbuf);
#endif

	/* /\* debug *\/ */
	/* DEBUG_PRINT("[process packet] m: %p, pktbuf: %p\n", */
	/* 			m, pktbuf); */

    ethh = (struct rte_ether_hdr *)pktbuf;
	iph = (struct rte_ipv4_hdr *)(ethh + 1);
    tcph = (struct rte_tcp_hdr *)(iph + 1);
    payload = (uint8_t *)tcph + ((tcph->data_off & 0xf0) >> 2);

    ctx = ctx_array[core_id];
	ip_len = ntohs(iph->total_length);
	payload_len = ip_len - (payload - (u_char *)iph);

    /* drop non-TCP packet */
    if (iph->next_proto_id != IPPROTO_TCP) {
		free_rm(core_id, port, m);
		return;
	}

#if VERBOSE_TCP
	print_pkt_info(core_id, port, pktbuf, len, TCP_RECV);
#endif

    option = (uint8_t *)(tcph + 1);
    option_len = payload - option;
    // ip_len = ntohs(iph->total_length);
    // payload_len = ip_len - (payload - (u_char *)iph);
    UNUSED(option_len);

	/* Forward control pkt from network: SYN, FIN, ACK, ... */
    if (tcph->tcp_flags & TCP_FLAG_SYN ||
		tcph->tcp_flags & TCP_FLAG_RST ||
		payload_len == 0) {

		TCP_PRINT("[process packet] port: %d, len: %d, "
			"ctrl packet from outside!\n",
			port, len);
	
		send_pkt_to_host(core_id, port, pktbuf, len);
		free_rm(core_id, port, m);
		return;
	}

	/* Now the packets should be application data from backend */
	/* Client packets does not enter NIC core */
	sess = search_tcp_session(ctx,
							  ntohl(iph->src_addr), ntohs(tcph->src_port),
							  ntohl(iph->dst_addr), ntohs(tcph->dst_port));

	if (sess == NULL) {
		TCP_PRINT("[process packet] no session, send to host!\n");
		send_pkt_to_host(core_id, port, pktbuf, len);
		free_rm(core_id, port, m);
		return;
	}

	if (unlikely(sess->sess_type != SESS_BACKEND)) {
		ERROR_PRINT("[process packet] "
				  "session is not for backend! just drop\n");
		/* debug */exit(EXIT_FAILURE);
		free_rm(core_id, port, m);
		return;
	}

	sess->be_seq = ntohl(tcph->sent_seq);
	sess->be_ack = ntohl(tcph->recv_ack);
	if (sess->tcph_len == 0) {
		sess->tcph_len = (tcph->data_off & 0xf0) >> 2;
		rte_memcpy(sess->hdrbuf, pktbuf,
				   ETHERNET_HEADER_LEN+IP_HEADER_LEN+sess->tcph_len);
	}
	sess->mbuf = m;
	
	/* now process packet - maybe simple forward */
	ERROR_PRINT("[%s] not implemented!\n", __FUNCTION__);
	exit(0);
	

	return;
}
/*---------------------------------------------------------------------------*/
/* ------------------------------------------------------------------------ */
static inline unsigned
check_ready(void)
{
    unsigned ready = 0;
    unsigned i;

    for (i = 0; i < rte_lcore_count(); i++)
        ready += ctx_array[i]->ready;

    if (ready > rte_lcore_count())
        assert(0);
    else if (ready == rte_lcore_count())
        return TRUE;

    return FALSE;
}
/* ------------------------------------------------------------------------ */
void
clean_thread(void)
{
	fprintf(stderr, "Cleaning DPDK threads...\n");
	int i;
	for (i = 0; i < MAX_CPUS; i ++) {
		force_quit[i] = 1;
	}
	print_xstats(0);
}
/* ------------------------------------------------------------------------ */
/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
int
proxyoff_main_loop(__attribute__((unused)) void *arg)
{
    uint16_t port, core_id;
    struct thread_context *ctx;
    int recv_cnt;
    int i;
	int num_port;
    int send_cnt;
    int processed_cnt;
    struct tcp_session* target;
	
	/* Variables for time measuring */
	uint64_t cur_tsc, prev_tsc;
	uint64_t tsc_hz = rte_get_tsc_hz();
	double diff;

	uint16_t port_list[RTE_MAX_ETHPORTS];
	int16_t port_num = 0;
	int p_i = 0;

    core_id = rte_lcore_id();
	num_port = rte_eth_dev_count_avail();

    thread_local_init(core_id);
    ctx = ctx_array[core_id];
    ctx->ready = 1;

	int nic_cores = rte_lcore_count();

    if (check_ready()) {
        fprintf(stderr, "CPU[%d] Initialization finished\n"
          		"Now start forwarding.\n\n", rte_lcore_id());
    }
    else {
        fprintf(stderr, "CPU[%d] Initialization finished\n"
	        	"Wait for other cores.\n\n", rte_lcore_id());
        while(!check_ready()) {}
        usleep(100);
    }
    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
			rte_eth_dev_socket_id(port) !=
			(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
				   "polling thread.\n\tPerformance will "
				   "not be optimal.\n", port);

    printf("Core %u forwarding packets. [Ctrl+C to quit]\n\n",
		   rte_lcore_id());

	/* Initialize port info, stat */
    RTE_ETH_FOREACH_DEV (port) {
		port_list[port_num] = port;
		port_num += 1;
	}
#if VERBOSE_STAT
    for (i = 0; i < MAX_CPUS; i++) {
        RTE_ETH_FOREACH_DEV (port) {
            rx_bytes_last[port][i] = 0;
            rx_pkts_last[port][i] = 0;
            tx_bytes_last[port][i] = 0;
            tx_pkts_last[port][i] = 0;
            rtx_bytes_last[port][i] = 0;
            rtx_pkts_last[port][i] = 0;
        }
    }
    RTE_ETH_FOREACH_DEV (port) {
        global_rx_bytes_last[port] = 0;
        global_rx_pkts_last[port] = 0;
        global_tx_bytes_last[port] = 0;
        global_tx_pkts_last[port] = 0;
        global_rtx_bytes_last[port] = 0;
        global_rtx_pkts_last[port] = 0;
    }
#endif	/* VERBOSE_STAT */

	/* Main loop
	 * Run until the application is quit or killed. */
    while (!force_quit[core_id]) {

		/* Main core manages global things: cookie, stat, ... */
		if (core_id == 0) {
			cur_tsc = rte_rdtsc_precise();
			diff = (cur_tsc - prev_tsc) / tsc_hz;
			if (unlikely(diff >= 0.5)) {
				/* Cookie Timevalue Update */
				if (t_minor == 63) {
					if (t_major == 31) {
						t_major = 0;
						t_minor = 0;
					}
					else {
						t_major++;
						t_minor = 0;
					}
				}
				else {
					t_minor++;
				}

#if VERBOSE_STAT
				/* Print per-core stat */
				print_stat(port_list, port_num);
#endif
				prev_tsc = cur_tsc;
			}
		}

		static int iter = 0;
		p_i = 0;
		ETH_FOREACH_PORT(port_list, port_num, p_i, port) {
			static uint32_t len;

			/* Receive Packets */
			recv_cnt = recv_pkts(core_id, port);

			/* Process Received Packets */
			for (i = 0; i < recv_cnt; i++) {
				struct rte_mbuf *m = get_rm(core_id, port, i, &len);

				if (likely(m != NULL)) {
					process_packet(core_id, port, m, len);
				} else {
					ERROR_PRINT("get_rm failed!\n");
					exit(EXIT_FAILURE);
				}
			}
		}

		p_i = 0;
		ETH_FOREACH_PORT(port_list, port_num, p_i, port) {
			send_cnt = send_pkts(core_id, port);
			UNUSED(send_cnt);
		}
		iter++;
    }

    thread_local_destroy(rte_lcore_id());
    return 0;
}
