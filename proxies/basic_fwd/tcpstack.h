#ifndef __TCPSTACK_H__
#define __TCPSTACK_H__

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <gmp.h>
#include <assert.h>
#include <byteswap.h>
#include <pthread.h>
#include <sched.h>

#include <time.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_mbuf.h>
#include <rte_hexdump.h>
#include <rte_version.h>

#include "option.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* #define RTE_TEST_TX_DESC_DEFAULT 128 */
/* #define RTE_TEST_RX_DESC_DEFAULT 1024 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

#define NUM_MBUFS           80000
/* #define MBUF_DATA_SIZE      20000 */
#define MBUF_DATA_SIZE      10000
#define MBUF_SIZE           (MBUF_DATA_SIZE + sizeof(struct rte_mbuf) \
				  			 + RTE_PKTMBUF_HEADROOM)
#define MBUF_CACHE_SIZE     250

#define MAX_PKT_BURST       32
#define MAX_CPUS            8
#define MAX_DPDK_PORT       8
#define MAX_TCP_PORT        65536

#define INIT_KEY_SIZE       16
#define INIT_IV_SIZE        16

#define RX_PTHRESH          8
#define RX_HTHRESH          8
#define RX_WTHRESH          4

#define TX_PTHRESH          36
#define TX_HTHRESH          0
#define TX_WTHRESH          0

#define RCV_BUF_SIZE    4000000
#define MAX_OOO_BUF     10
#define OOO_BUF_SIZE    500000

#define RX_IDLE_ENABLE      TRUE

#define ETHER_TYPE_META     0x0700

/* TCP Flags */
#define TCP_FLAG_FIN        0x01
#define TCP_FLAG_SYN        0x02
#define TCP_FLAG_RST        0x04
#define TCP_FLAG_PSH        0x08
#define TCP_FLAG_ACK        0x10
#define TCP_FLAG_URG        0x20

#define TCP_OPT_END             0
#define TCP_OPT_NOP             1
#define TCP_OPT_SACK_PERMITTED  4
#define TCP_OPT_SACK            5
#define TCP_OPT_TIMESTAMP       8

#define MAX_SACK_BLOCK_NUM  4

#define SSL_PORT            443

#define MAX_BACKEND_PER_CLIENT 10
#define MAX_PENDING_BUF        64
#define MAX_LOG                512
#define MAX_FRAME_FORMAT_SEQS  512
#define MAX_TLS_RECORD_SEQS    512

#define MAX_STREAM_PER_CONN 1024

#define htonll(x)   ((((uint64_t)htonl(x)) << 32) + htonl(x >> 32))
#define ntohll(x)   ((((uint64_t)ntohl(x)) << 32) + ntohl(x >> 32))

#ifdef MIN
#else
#define MIN(x, y)   ((int32_t)((x)-(y)) < 0 ? (x) : (y))
#endif

#ifdef MAX
#else
#define MAX(x, y)   ((int32_t)((x)-(y)) > 0 ? (x) : (y))
#endif

#define NUM_LT(a,b)         ((int32_t)((a)-(b)) < 0)
#define NUM_LEQ(a,b)        ((int32_t)((a)-(b)) <= 0)
#define NUM_GT(a,b)         ((int32_t)((a)-(b)) > 0)
#define NUM_GEQ(a,b)        ((int32_t)((a)-(b)) >= 0)
#define NUM_BETWEEN(a,b,c)  (NUM_GEQ(a,b) && NUM_LEQ(a,c))

#define MTU_SIZE            1500
#define ETHERNET_HEADER_LEN 14
#define IP_HEADER_LEN       20
#define TCP_HEADER_LEN      20
#define MAX_TCP_OPTION_LEN  40
#define TOTAL_HEADER_LEN    54
#define MAX_HEADER_LEN      100
#define MAX_METADATA_SIZE   1400

/* ToDo: remove this */
#define USE_WINE 1
#if !USE_WINE
#define HOST_MAC ((uint8_t[]){0x0c, 0x42, 0xa1, 0xe7, 0x1e, 0x16})
#define CLIENT_MAC ((uint8_t[]){0x98, 0x03, 0x9b, 0x7f, 0xc4, 0x90})
#define SERVER_MAC ((uint8_t[]){0x98, 0x03, 0x9b, 0x1e, 0xde, 0x3c}) /* Tree3 */
#else
#define HOST_MAC ((uint8_t[]){0x90, 0xe2, 0xba, 0x7c, 0x1f, 0xb0})
#define CLIENT_MAC ((uint8_t[]){0x90, 0xe2, 0xba, 0x7c, 0x23, 0x60}) /* Wine7 */
#define SERVER_MAC ((uint8_t[]){0x90, 0xe2, 0xba, 0x7a, 0xb0, 0x01}) /* Wine5 */
#endif


enum {TCP_RECV, TCP_SEND};
enum {SESS_CLIENT, SESS_BACKEND};

struct tcp_stat {
    uint64_t rx_bytes[MAX_DPDK_PORT];
    uint64_t rx_pkts[MAX_DPDK_PORT];

    uint64_t tx_bytes[MAX_DPDK_PORT];
    uint64_t tx_pkts[MAX_DPDK_PORT];

    uint64_t rtx_bytes[MAX_DPDK_PORT];
    uint64_t rtx_pkts[MAX_DPDK_PORT];
};

enum tcp_session_state {
    TCP_SESSION_IDLE,
    TCP_SESSION_RECEIVED,
    TCP_SESSION_SENT,
};

enum packet_type {
    PKT_TYPE_NONE,
    PKT_TYPE_HELLO,
    PKT_TYPE_FINISH,
};

enum record_hole_state {
	EMPTY,
	FILLING,
	FILL_ALL,
};

enum ssl_session_state {
    SSL_SESSION_NOT_ESTABLISHED,
    SSL_SESSION_HANDSHAKE,
    SSL_SESSION_ESTABLISHED,
};

/** structure for TLS session */
struct ssl_session {
    struct tcp_session* parent;
    struct thread_context* ctx;

    int         state;
	uint32_t    tls_add_byte;	/* TLS header + MAC length */
	uint8_t     is_ooo;
	uint8_t     tls_record_hole;
	/**< TRUE if the session is handling retransmitted pkts */
    uint16_t    num_current_records;
    uint64_t    cur_record_seq;
    uint64_t    next_record_seq;
	/**< TLS sequence for next latest packet (packet w/ higher TCP SEQ)
	 *   But if be's != 0, it indicates there should snd buf hole */

	struct pkt_blk *record_blk;
	/**< Buffer containing merged backend pkts belonged in a single record
	 *   Used in fwd_(m)buf_to_client() */

	struct pkt_blk *retrans_blk;
	/**< Buffer containing retransmission pkt belonged in a single record */
	uint32_t retrans_log_idx;
};

/* Information for one HTTP2 stream with client */
struct str_ctx {
	struct tcp_session *sess_cli;
	uint32_t sid;
};

/** Information on one HTTP frame block */
struct httpfr {
	/* http2 frame format */
    uint32_t len;
    uint8_t type;
    uint8_t flag;
	uint32_t be_sid;

	/* starting be/cli TCP seq */
	uint32_t start_seq;
	uint32_t cli_seq;

	uint32_t filled_byte;		
	/**< How many byte received in here includes ff */

	uint32_t tls_records_num;
	/**< Number of tls records in the frame. 
	     Used to calculate client seq offset */
	uint32_t batch_start_seq;
	/**< Starting TCP seq due to batching record */
};

/** Forwarded data information which is reported to the host.
 * One send_log contains one block received by backend and forwarded to the client. */
struct send_log {
	uint32_t start_seq;		/* start TCP sequence of fwd block */
	uint32_t last_seq;		/* next expected start TCP sequence */
	union{
		struct {
			uint16_t front_seq_off; /* removed byte in front of fwd block from the recv block */
			uint16_t rear_seq_off;  /* removed byte at the rear of fwd block from the recv block  */
		};
		uint32_t seq_off;		/* legacy. need to be removed */
	};
	uint64_t tls_rec_num;

	struct tcp_session *sess_be;
	uint32_t be_ip;			/* backend ip address */
	uint32_t be_port;		/* backend tcp port */
	uint32_t be_seq;		/* start TCP sequence of recv block */

	/* flags */
	uint8_t is_snd_hole:1;
};

/** Received data information which is received from the backend.
 * Refered when backend retransmits. */
struct be_log {
	/* TCP related log */
	uint32_t start_seq;
	uint32_t last_seq;
	uint32_t cli_seq;
	struct tcp_session *sess_cli;

	/* TLS related log */
	uint64_t tls_rec_num;

	/* HTTP2 related log */
	uint32_t ff_seqs_start;

	/* States for non-tls session */
	uint32_t ff_seqs[MAX_FRAME_FORMAT_SEQS];
	uint16_t ff_seqs_cnt;
};

/** Context for packet block.
 * SmartLB might not forward packet in zero-copy manner,
 * such as when receiving out-of-order packet or part of TLS record.
 * This structure buffers them temporarily */
struct pkt_blk {
	uint32_t seq;
	uint32_t len;

	uint8_t buf[OOO_BUF_SIZE];
	
	struct pkt_blk *prev;
	struct pkt_blk *next;

	TAILQ_ENTRY(pkt_blk) free_pkt_blk_link;
};

/* From mtcp */
struct tcp_ring_buffer {
    u_char* data;           /* buffered data */
    u_char* head;           /* pointer to the head */

    uint32_t head_offset;   /* offset for the head (head - data) */
    uint32_t tail_offset;   /* offset fot the last byte (null byte) */

    uint32_t last_len;           /* currently saved data length */
    uint32_t size;               /* total ring buffer size */

    /* TCP payload features */
    uint32_t head_seq;
    uint32_t init_seq;

    /* struct fragment_ctx* fctx; */
};

/** structure for TCP session */
struct tcp_session {
    struct thread_context* ctx;

    int             state;
	int             sess_type;

    uint16_t        coreid;
    uint16_t        portid;
	uint16_t		cpu_id;

	union {
		struct {
			uint8_t  src_mac[6];
			uint8_t  dst_mac[6];

			uint32_t src_ip;
			uint32_t dst_ip;

			uint16_t src_port;
			uint16_t dst_port;
		};
		struct {
			uint8_t  be_mac[6];
			uint8_t  proxy_mac[6];

			uint32_t be_ip;
			uint32_t proxy_ip;

			uint16_t be_port;
			uint16_t proxy_port;
		};
		struct {
			uint8_t  host_mac[6];
			uint8_t  cli_mac[6];

			uint32_t host_ip;
			uint32_t cli_ip;

			uint16_t host_port;
			uint16_t cli_port;
		};
	};

	uint32_t        tcph_len;
	uint32_t        next_frame_seq;
	uint8_t         hdrbuf[ETHERNET_HEADER_LEN+IP_HEADER_LEN+40];

	/*** client-proxy state ***/
	uint8_t         is_nicsync:1,
		            is_congestion:1;

	struct tcp_session *sess_bes[MAX_BACKEND_PER_CLIENT];
	uint16_t sess_be_num;
	
	struct send_log send_logs[MAX_LOG];
	struct send_log *buf_log_head;
	/**< First send_log which payload is not forwarded */	
	uint16_t        send_log_start;
	uint16_t        send_log_end;
	uint16_t        sent_log_cnt;
	uint16_t        pending_log_cnt;

    uint32_t        last_parse_seq; /* currently parsed sequence */
	uint32_t        cwnd;
	uint32_t        inflight_size;
	/*** client-proxy state end ***/

	/*** proxy-backend state ***/
	uint8_t         is_cur_snd_hole:1;
	uint32_t        snd_hole_seq;
	uint32_t        snd_hole_len;
	uint32_t        snd_hole_cli_seq;

	uint32_t        last_ack_seq; /* currently acked sequence of 'proxy' */
	
	struct tcp_session *sess_cli;
	uint32_t        be_seq;
	uint32_t        be_ack;
	uint32_t        cli_seq;
	struct str_ctx  strctx_map[MAX_STREAM_PER_CONN];
	struct pkt_blk  *ooo_blk;

	struct be_log   be_log[MAX_LOG];
	uint16_t        be_log_start;
	uint16_t        be_log_cnt;
	uint16_t        be_log_hole_idx;	/* idx of be log of hole */
	
	uint8_t         ff[9];
	uint32_t        ff_seqs[MAX_FRAME_FORMAT_SEQS];
	/**< TCP SEQs where frame formats are located */
	uint16_t        ff_seqs_start;
	uint16_t        ff_seqs_cnt;
	uint16_t        ff_seqs_end; /* for legacy */
	uint32_t        ff_seqs_start_cur_pkt;
	/**< First idx of ff_seqs in current snd pkt */

	struct tcp_ring_buffer *ring_buff;
	/**< Ring buffer to store recv data */

	struct httpfr   cur_fr;
	/**< States on current backend frame */
	struct httpfr   fr_parsing;
	/**< Frame which is ongoing to be parsed */
	struct rte_mbuf *mbuf;

	/* states for flow control */
	uint32_t recv_window;
	/*** proxy-backend state end ***/

    uint32_t        base_sent_seq;
    uint32_t        base_recv_ack;
    uint16_t        window;

    uint32_t        total_sent;

    uint32_t ts_start;          /* ts_val of SYN or SYNACK from the peer */
    uint32_t ts_ratio;          /* ts frequency ratio of the peer and this system */
    uint32_t ts_diff_offset;    /* peer-ours difference of ts at the beginning of this connection */
	uint32_t ts_start_client;
    uint32_t ts_last_ts_upd;

    struct ssl_session ssl_session;

    TAILQ_ENTRY(tcp_session) active_session_link;
    TAILQ_ENTRY(tcp_session) free_session_link;

	/* only for debug */
	FILE *log_debug;
	uint8_t flag_dropped:1,
		    flag_ooo:1;
};

struct mbuf_table {
    uint16_t len; /* length of queued packets */
    struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct dpdk_private_context {
	struct mbuf_table rmbufs[RTE_MAX_ETHPORTS];         /* received packets list */
    struct mbuf_table wmbufs_ctrl[RTE_MAX_ETHPORTS];
    struct mbuf_table wmbufs[RTE_MAX_ETHPORTS];
    struct rte_mempool *pktmbuf_pool;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];     
#ifdef RX_IDLE_ENABLE
    uint8_t rx_idle;
#endif
} __rte_cache_aligned;

struct thread_context {
	uint8_t force_quit;
    int ready;
    uint16_t coreid;

    struct dpdk_private_context *dpc;
    struct tcp_session** tcp_array;

	struct tcp_session *cli_sesses[MAX_PKT_BURST];
	uint16_t cli_sesses_cnt;

    int decrease;

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    struct hashtable *active_session_table;
#else
    TAILQ_HEAD(active_head, tcp_session) active_session_q;
#endif	/* USE_HASHTABLE_FOR_ACTIVE_SESSION */
    int active_cnt;

    TAILQ_HEAD(free_head, tcp_session) free_session_q;
    int free_cnt;

    struct tcp_stat stat;
};

static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh    =   RX_PTHRESH,
        .hthresh    =   RX_HTHRESH,
        .wthresh    =   RX_WTHRESH,
    },
    .rx_free_thresh =   32,
};

static const struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh    =   TX_PTHRESH,
        .hthresh    =   TX_HTHRESH,
        .wthresh    =   TX_WTHRESH,
    },
    .tx_free_thresh =   0,
    .tx_rs_thresh   =   0,
#if RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 0)
    .txq_flags      =   0x0,
#endif
};

#define OFF_PROTO 1234

extern struct tcp_stat global_stat;
extern struct rte_mempool *pktmbuf_pool[MAX_CPUS];
extern struct thread_context* ctx_array[MAX_CPUS];
extern uint8_t port_type[MAX_DPDK_PORT];
extern int max_conn;
extern int local_max_conn;
extern int num_host_cpu;

extern uint8_t t_major;
extern uint8_t t_minor;

/* Functions */
/*--------------------------------------------------------------------------*/
/* main.c */
void
global_destroy(void);

/*--------------------------------------------------------------------------*/
/* tcpstack.c */

#if VERBOSE_TCP
void
print_pkt_info(uint16_t core_id, uint16_t port,
               uint8_t *pktbuf, uint32_t len, int type);
#endif

int
proxyoff_main_loop(__attribute__((unused)) void *arg);

int
send_pkt_to_host(uint16_t core_id, uint16_t port,
				 uint8_t *pktbuf, uint32_t len);

struct tcp_session *
search_tcp_session(struct thread_context *ctx,
                   uint32_t cli_ip, uint16_t cli_port,
                   uint32_t server_ip, uint16_t server_port);

struct tcp_session *
insert_tcp_session(struct thread_context *ctx, uint16_t portid,
                   const uint8_t* cli_mac,
                   uint32_t cli_ip, uint16_t cli_port,
                   const uint8_t* server_mac,
                   uint32_t server_ip, uint16_t server_port,
                   uint16_t window);

void
remove_session(struct tcp_session* sess);

void
print_xstats(int port_id);

void
clean_thread(void);

/*--------------------------------------------------------------------------*/
/* dpdk_io.c */
void
free_pkts(struct rte_mbuf **mtable, unsigned len);

int
get_wmbuf_queue_len(uint16_t core_id, uint16_t port);

int32_t
recv_pkts(uint16_t core_id, uint16_t port);

uint8_t *
get_rptr(uint16_t core_id, uint16_t port, int index, uint32_t *len);

struct rte_mbuf *
get_rm(uint16_t core_id, uint16_t port, int index, uint32_t *len);

int
free_rm(uint16_t core_id, uint16_t port, struct rte_mbuf *m);

int
send_pkts(uint16_t core_id, uint16_t port);

uint8_t *
get_wptr_tso(uint16_t core_id, uint16_t port,
					   uint32_t pktsize, uint16_t l4_len);

int
insert_wm_tso(uint16_t core_id, uint16_t port,
              uint32_t pktsize, uint16_t l4_len, struct rte_mbuf *m);
/*--------------------------------------------------------------------------*/

#endif /* __TCPSTACK_H__ */

