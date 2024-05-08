/* for io_module_func def'ns */
#include "io_module.h"
/* for mtcp related def'ns */
#include "mtcp.h"
/* for errno */
#include <errno.h>
/* for close/optind */
#include <unistd.h>
/* for logging */
#include "debug.h"
/* for num_devices_* */
#include "config.h"
/* for rte_max_eth_ports */
#include <rte_common.h>
/* for rte_eth_rxconf */
#include <rte_ethdev.h>
/* for delay funcs */
#include <rte_cycles.h>
/* for ip pesudo-chksum */
#include <rte_ip.h>
#include <rte_tcp.h>
#define ENABLE_STATS_IOCTL		0
#ifdef ENABLE_STATS_IOCTL
/* for open */
#include <fcntl.h>
/* for ioctl */
#include <sys/ioctl.h>
#endif /* !ENABLE_STATS_IOCTL */
/* for retrieving rte version(s) */
#include <rte_version.h>
#include <rte_ethdev.h>
#include <rte_gtp.h>

/*----------------------------------------------------------------------------*/
/* Essential macros */
#define MAX_RX_QUEUE_PER_LCORE		MAX_CPUS
#define MAX_TX_QUEUE_PER_PORT		MAX_CPUS

#define LEADER_ISOLATION	0
#if LEADER_ISOLATION
	#define LEADER_CORE_NUM		0
#endif

#define KEY_MAPPING			1

#define USE_LRO				1
#if USE_LRO
	// #define MBUF_DATA_SIZE		65280
	// #define NB_MBUF				16383
	#define MBUF_DATA_SIZE		9024
	#define NB_MBUF				8191
	#define NB_MBUF_KEY			8191
#else
	#define MBUF_DATA_SIZE		RTE_ETHER_MAX_LEN
	#define NB_MBUF				65535
#endif
#define MBUF_SIZE 			(MBUF_DATA_SIZE + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MEMPOOL_CACHE_SIZE		256
//#define RX_IDLE_ENABLE			1
#define RX_IDLE_TIMEOUT			1	/* in micro-seconds */
#define RX_IDLE_THRESH			64

#define USE_CUSTOM_THRESH	0
/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 			8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 			8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 			4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the ConnectX-6 2 * 100 GbE
 * Controller and the DPDK mlx5_core PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 			36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH			0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH			0  /**< Default values of TX write-back threshold reg. */

#define MAX_PKT_BURST		16
#define MAX_PKT_BURST_KEY	64
#define MAX_PKT_BURST_RAW	64

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DATA_DESC_DEFAULT	/* 8192 */ /* 4096 */ 2048 /* 1024 */ /* 512 */ /* 256 */
#define RTE_TEST_RX_KEY_DESC_DEFAULT	/* 8192 */ 4096 /* 2048 */ /* 1024 */ /* 512 */ /* 256 */
#define RTE_TEST_TX_DESC_DEFAULT	/* 8192 */ /* 4096 */ /* 2048 */ 1024 /* 512 */ /* 256 */

static uint16_t nb_rxd_data = RTE_TEST_RX_DATA_DESC_DEFAULT;
#if KEY_MAPPING
/* In order to avoid key packet drop, use larger RX queue size */
static uint16_t nb_rxd_key = RTE_TEST_RX_KEY_DESC_DEFAULT;
#endif
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
/*----------------------------------------------------------------------------*/
/* packet memory pools for storing packet bufs */
#if KEY_MAPPING
static struct rte_mempool *pktmbuf_pool_key[MAX_CPUS] = {NULL};
#endif
static struct rte_mempool *pktmbuf_pool_raw[MAX_CPUS] = {NULL};
static struct rte_mempool *pktmbuf_pool[MAX_CPUS] = {NULL};
static uint8_t cpu_qid_map[RTE_MAX_ETHPORTS][MAX_CPUS] = {{0}};

static const uint8_t g_key[] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
};

//#define DEBUG				1
#ifdef DEBUG
/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
#endif

static struct rte_eth_dev_info dev_info[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode	= 	RTE_ETH_MQ_RX_RSS,
		.mtu = RTE_ETHER_MTU,
		.offloads	=	RTE_ETH_RX_OFFLOAD_RSS_HASH |
						RTE_ETH_RX_OFFLOAD_CHECKSUM |
						RTE_ETH_RX_OFFLOAD_RSS_HASH |
						RTE_ETH_RX_OFFLOAD_TCP_LRO,
		.max_lro_pkt_size =   MBUF_DATA_SIZE,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = (uint8_t *)g_key,
			.rss_key_len = sizeof(g_key),
			.rss_hf = RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP |
					  RTE_ETH_RSS_IP | RTE_ETH_RSS_L2_PAYLOAD
		},
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
		.offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
					RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
					RTE_ETH_TX_OFFLOAD_TCP_CKSUM |
                    RTE_ETH_TX_OFFLOAD_TCP_TSO
	},
};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = 		RX_PTHRESH, /* RX prefetch threshold reg */
		.hthresh = 		RX_HTHRESH, /* RX host threshold reg */
		.wthresh = 		RX_WTHRESH, /* RX write-back threshold reg */
	},
	.rx_free_thresh = 		32,
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = 		TX_PTHRESH, /* TX prefetch threshold reg */
		.hthresh = 		TX_HTHRESH, /* TX host threshold reg */
		.wthresh = 		TX_WTHRESH, /* TX write-back threshold reg */
	},
	.tx_free_thresh = 		0, /* Use PMD default values */
	.tx_rs_thresh = 		0, /* Use PMD default values */
};

struct mbuf_table {
	unsigned rlen; /* length of queued packets */
	unsigned wlen;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct mbuf_table_key {
	unsigned rlen; /* length of queued packets */
	struct rte_mbuf *m_table[MAX_PKT_BURST_KEY];
};

struct mbuf_table_raw {
	unsigned wlen; /* length of queued packets */
	struct rte_mbuf *m_table[MAX_PKT_BURST_RAW];
};

struct dpdk_private_context {
	struct mbuf_table rmbufs[RTE_MAX_ETHPORTS];
	/* shares mbufs with rmbufs by default */
	struct mbuf_table wmbufs[RTE_MAX_ETHPORTS];
	/* rmbufs for key receiving */
	struct mbuf_table_key rmbufs_key[RTE_MAX_ETHPORTS];
	/* does not share mbufs with rmbufs, is used for sending raw packets */
	struct mbuf_table_raw wmbufs_raw[RTE_MAX_ETHPORTS];
#ifdef RX_IDLE_ENABLE
	uint8_t rx_idle;
#endif
#ifdef ENABLE_STATS_IOCTL
	int fd;
#endif /* !ENABLE_STATS_IOCTL */
} __rte_cache_aligned;

#ifdef ENABLE_STATS_IOCTL
/**
 * stats struct passed on from user space to the driver
 */
struct stats_struct {
	uint64_t tx_bytes;
	uint64_t tx_pkts;
	uint64_t rx_bytes;
	uint64_t rx_pkts;
	uint8_t qid;
	uint8_t dev;
};
#endif /* !ENABLE_STATS_IOCTL */
/*----------------------------------------------------------------------------*/
static inline void
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
/*----------------------------------------------------------------------------*/
void
dpdk_init_handle(struct mtcp_thread_context *ctxt)
{
	struct dpdk_private_context *dpc;
	int i, j;
	char mempool_name[20];

	/* create and initialize private I/O module context */
	ctxt->io_private_context = calloc(1, sizeof(struct dpdk_private_context));
	if (ctxt->io_private_context == NULL) {
		TRACE_ERROR("Failed to initialize ctxt->io_private_context: "
			    "Can't allocate memory\n");
		exit(EXIT_FAILURE);
	}
	
	sprintf(mempool_name, "mbuf_pool-%d", ctxt->cpu);
	dpc = (struct dpdk_private_context *)ctxt->io_private_context;

	/* set wmbufs correctly */
	for (j = 0; j < g_config.mos->netdev_table->num; j++) {
		/* Allocate raw wmbufs for each registered port */
		for (i = 0; i < MAX_PKT_BURST_RAW; i++) {
			dpc->wmbufs_raw[j].m_table[i] = rte_pktmbuf_alloc(pktmbuf_pool_raw[ctxt->cpu]);
			if (dpc->wmbufs_raw[j].m_table[i] == NULL) {
				TRACE_ERROR("Failed to allocate %d:wmbuf[%d] on device %d!\n",
					    ctxt->cpu, i, j);
				exit(EXIT_FAILURE);
			}
		}
		/* set mbufs queue length to 0 to begin with */
		dpc->wmbufs_raw[j].wlen = 0;
	}

#ifdef ENABLE_STATS_IOCTL
	dpc->fd = open("/dev/dpdk-iface", O_RDWR);
	if (dpc->fd == -1) {
		TRACE_ERROR("Can't open /dev/dpdk-iface for context->cpu: %d! "
			    "Are you using mlx4/mlx5 driver?\n",
			    ctxt->cpu);
	}
#endif /* !ENABLE_STATS_IOCTL */
}
/*----------------------------------------------------------------------------*/
int
dpdk_send_pkts(struct mtcp_thread_context *ctxt, int nif)
{
	struct dpdk_private_context *dpc;
	mtcp_manager_t mtcp;
	int ret;
	int qid;
	int cnt;
	
	dpc = (struct dpdk_private_context *)ctxt->io_private_context;
	mtcp = ctxt->mtcp_manager;
	ret = 0;
	qid = cpu_qid_map[nif][ctxt->cpu];
	/* if queue is unassigned, skip it.. */
	if (unlikely(qid == 0xFF)) 
		return 0;
	
	/* if there are packets in the queue... flush them out to the wire */
	cnt = dpc->wmbufs[nif].wlen;
	if (cnt > 0) {
		struct rte_mbuf **pkts;
#ifdef ENABLE_STATS_IOCTL
		struct stats_struct ss;
#endif /* !ENABLE_STATS_IOCTL */
		pkts = dpc->wmbufs[nif].m_table;
#ifdef NETSTAT
		mtcp->nstat.tx_packets[nif] += cnt;
#ifdef ENABLE_STATS_IOCTL
		if (likely(dpc->fd) >= 0) {
			ss.tx_pkts = mtcp->nstat.tx_packets[nif];
			ss.tx_bytes = mtcp->nstat.tx_bytes[nif];
			ss.rx_pkts = mtcp->nstat.rx_packets[nif];
			ss.rx_bytes = mtcp->nstat.rx_bytes[nif];
			ss.qid = ctxt->cpu;
			ss.dev = nif;
			ioctl(dpc->fd, 0, &ss);
		}
#endif /* !ENABLE_STATS_IOCTL */
#else
		UNUSED(ss); 
		UNUSED(mtcp);
#endif
		do {
			/* tx cnt # of packets */
			ret = rte_eth_tx_burst(nif, qid, pkts, cnt);
			pkts += ret;
			cnt -= ret;
			/* if not all pkts were sent... then repeat the cycle */
		} while (cnt > 0);
		/* reset the len of mbufs var after flushing of packets */
		dpc->wmbufs[nif].wlen = 0;
	}

	/* if there are packets in the raw send queue... flush them out to the wire */
	cnt = dpc->wmbufs_raw[nif].wlen;
	if (cnt > 0) {
		struct rte_mbuf **pkts;
#ifdef ENABLE_STATS_IOCTL
		struct stats_struct ss;
#endif /* !ENABLE_STATS_IOCTL */
		pkts = dpc->wmbufs_raw[nif].m_table;
#ifdef NETSTAT
		mtcp->nstat.tx_packets[nif] += cnt;
#ifdef ENABLE_STATS_IOCTL
		if (likely(dpc->fd) >= 0) {
			ss.tx_pkts = mtcp->nstat.tx_packets[nif];
			ss.tx_bytes = mtcp->nstat.tx_bytes[nif];
			ss.rx_pkts = mtcp->nstat.rx_packets[nif];
			ss.rx_bytes = mtcp->nstat.rx_bytes[nif];
			ss.qid = ctxt->cpu;
			ss.dev = nif;
			ioctl(dpc->fd, 0, &ss);
		}
#endif /* !ENABLE_STATS_IOCTL */
#else
		UNUSED(ss); 
		UNUSED(mtcp);
#endif
		do {
			/* tx cnt # of packets */
			ret = rte_eth_tx_burst(nif, qid, pkts, cnt);
			pkts += ret;
			cnt -= ret;
			/* if not all pkts were sent... then repeat the cycle */
		} while (cnt > 0);
		// int i;
		// /* time to allocate fresh mbufs for the queue */
		// for (i = 0; i < cnt; i++) {
		// 	dpc->wmbufs_raw[nif].m_table[i] = rte_pktmbuf_alloc(pktmbuf_pool_raw[ctxt->cpu]);
		// 	/* error checking */
		// 	if (unlikely(dpc->wmbufs_raw[nif].m_table[i] == NULL)) {
		// 		TRACE_ERROR("Failed to allocate %d:wmbuf_raw[%d] on device %d!\n",
		// 			    ctxt->cpu, i, nif);
		// 		exit(EXIT_FAILURE);
		// 	}
		// }
		/* reset the len of mbufs var after flushing of packets */
		dpc->wmbufs_raw[nif].wlen = 0;
	}
	return ret;
}
/*----------------------------------------------------------------------------*/
uint8_t *
dpdk_get_wptr(struct mtcp_thread_context *ctxt, int nif, uint16_t pktsize)
{
	struct dpdk_private_context *dpc;
	mtcp_manager_t mtcp;
	struct rte_mbuf *m;
	uint8_t *ptr;
	int send_cnt;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;
	mtcp = ctxt->mtcp_manager;
	
	/* sanity check */
	if (unlikely(dpc->wmbufs_raw[nif].wlen == MAX_PKT_BURST_RAW)) {
		// return NULL;
		// fprintf(stdout, "burst pkt exceeded!\n");
		while(1) {
			send_cnt = dpdk_send_pkts(ctxt, nif);
			if (likely(send_cnt))
				break;
		}
	}
	m = dpc->wmbufs_raw[nif].m_table[dpc->wmbufs_raw[nif].wlen];
	/* retrieve the right write offset */
	ptr = rte_pktmbuf_mtod(m, uint8_t *);
	m->pkt_len = m->data_len = pktsize;
	m->nb_segs = 1;
	m->next = NULL;

	m->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
	if (pktsize > RTE_ETHER_MTU + ETHERNET_HEADER_LEN) {
		/* enable TSO */
		m->l2_len = ETHERNET_HEADER_LEN;
		m->l3_len = ((struct rte_ipv4_hdr *)(ptr + m->l2_len))->ihl << 2;
		m->l4_len = ((struct rte_tcp_hdr *)(ptr + m->l2_len + m->l3_len))->data_off >> 2;
		m->tso_segsz = RTE_ETHER_MTU - (m->l3_len + m->l4_len);
		m->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
	}

#ifdef NETSTAT
	mtcp->nstat.tx_bytes[nif] += pktsize + ETHER_OVR;
#endif
	
	/* increment the len of mbuf */
	dpc->wmbufs_raw[nif].wlen++;
	
	return ptr;
}
/*----------------------------------------------------------------------------*/
void
dpdk_set_wptr(struct mtcp_thread_context *ctxt, int out_nif,
				  int in_nif, int index)
{
	struct dpdk_private_context *dpc;
	mtcp_manager_t mtcp;
	struct rte_mbuf *m;
	uint8_t *ptr;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;
	mtcp = ctxt->mtcp_manager;
	
	/* sanity check */
	if (unlikely(dpc->wmbufs[out_nif].wlen == MAX_PKT_BURST))
		return;

	dpc->wmbufs[out_nif].m_table[dpc->wmbufs[out_nif].wlen] = 
		dpc->rmbufs[in_nif].m_table[index];

	m = dpc->rmbufs[in_nif].m_table[index];
	ptr = rte_pktmbuf_mtod(m, uint8_t *);
	m->dynfield1[0] = 0;

	m->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
	if (m->pkt_len > RTE_ETHER_MTU + ETHERNET_HEADER_LEN) {
		/* enable TSO */
		m->l2_len = ETHERNET_HEADER_LEN;
		m->l3_len = ((struct rte_ipv4_hdr *)(ptr + m->l2_len))->ihl << 2;
		m->l4_len = ((struct rte_tcp_hdr *)(ptr + m->l2_len + m->l3_len))->data_off >> 2;
		m->tso_segsz = RTE_ETHER_MTU - (m->l3_len + m->l4_len);
		m->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
	}
#ifdef NETSTAT
	mtcp->nstat.tx_bytes[out_nif] += m->pkt_len + ETHER_OVR;
#endif
	
	/* increment the len of mbuf */
	dpc->wmbufs[out_nif].wlen++;
	
	return;
}
/*----------------------------------------------------------------------------*/
static inline void
free_pkts(struct rte_mbuf **mtable, unsigned len)
{
	int i;
	
	/* free the freaking packets */
	for (i = 0; i < len; i++)
		if (mtable[i]->dynfield1[0] == 1) {
			rte_pktmbuf_free_seg(mtable[i]);
			RTE_MBUF_PREFETCH_TO_FREE(mtable[i+1]);
		}
}
/*----------------------------------------------------------------------------*/
int32_t
dpdk_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx)
{
	struct dpdk_private_context *dpc;
	int ret;
	uint8_t qid;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;
	qid = cpu_qid_map[ifidx][ctxt->cpu];
	
	/* if queue is unassigned, skip it.. */
	if (qid == 0xFF)
		return 0;
	
	if (dpc->rmbufs[ifidx].rlen != 0) {
		free_pkts(dpc->rmbufs[ifidx].m_table, dpc->rmbufs[ifidx].rlen);
		dpc->rmbufs[ifidx].rlen = 0;
	}
	
	/* rx from data mbuf */
	ret = rte_eth_rx_burst((uint8_t)ifidx, qid,
			dpc->rmbufs[ifidx].m_table, MAX_PKT_BURST);
	dpc->rmbufs[ifidx].rlen = ret;

#if KEY_MAPPING
	int ret_key;
	if (ifidx)
		goto Ret;

	if (dpc->rmbufs_key[ifidx].rlen != 0) {
		free_pkts(dpc->rmbufs_key[ifidx].m_table, dpc->rmbufs_key[ifidx].rlen);
		dpc->rmbufs_key[ifidx].rlen = 0;
	}

	/* rx from key mbuf */
	ret_key = rte_eth_rx_burst((uint8_t)ifidx, qid + g_config.mos->num_cores,
				dpc->rmbufs_key[ifidx].m_table, MAX_PKT_BURST_KEY);
	dpc->rmbufs_key[ifidx].rlen = ret_key;
	ret += ret_key;
Ret:
#endif

#ifdef RX_IDLE_ENABLE
	dpc->rx_idle = (likely(ret != 0)) ? 0 : dpc->rx_idle + 1;
#endif

	return ret;
}
/*----------------------------------------------------------------------------*/
uint8_t *
dpdk_get_rptr(struct mtcp_thread_context *ctxt, int ifidx, int index, uint16_t *len, uint32_t *rss_hash)
{
	struct dpdk_private_context *dpc;
	struct rte_mbuf *m;
	uint8_t *pktbuf;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;	

	if (index < dpc->rmbufs[ifidx].rlen)
		m = dpc->rmbufs[ifidx].m_table[index];
	else
		m = dpc->rmbufs_key[ifidx].m_table[index - dpc->rmbufs[ifidx].rlen];
	/* tag to check if the packet is a local or a forwarded pkt */
	m->dynfield1[0] = 1;
	
	/* don't enable pre-fetching... performance goes down */
	//rte_prefetch0(rte_pktmbuf_mtod(m, void *));
	pktbuf = rte_pktmbuf_mtod(m, uint8_t *);
	*len = ETH_HLEN + htons(*(uint16_t *)(pktbuf + ETH_HLEN + 2));
	*rss_hash = m->hash.rss;

	return pktbuf;
}
/*----------------------------------------------------------------------------*/
int
dpdk_get_nif(struct ifreq *ifr)
{
	int i;
	static int num_dev = -1;
	static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

	/* get mac addr entries of 'detected' dpdk ports */
	if (num_dev < 0) {
		num_dev = rte_eth_dev_count_avail();
		for (i = 0; i < num_dev; i++)
			rte_eth_macaddr_get(i, &ports_eth_addr[i]);
	}

	for (i = 0; i < num_dev; i++) {
		if (!memcmp(&ifr->ifr_addr.sa_data[0], &ports_eth_addr[i], ETH_ALEN))
			return i;
	}

	return -1;
}
/*----------------------------------------------------------------------------*/
int
dpdk_stall_pkts(struct mtcp_thread_context *ctxt, int nif, int idx)
{
	struct dpdk_private_context *dpc;
	struct rte_mbuf *m;
	int ret;
	int qid;
	
	dpc = (struct dpdk_private_context *)ctxt->io_private_context;
	ret = 0;
	qid = cpu_qid_map[nif][ctxt->cpu];
	/* if queue is unassigned, skip it.. */
	if (unlikely(qid == 0xFF)) 
		return 0;

	m = dpc->rmbufs[nif].m_table[idx];
	/* copy to wmbufs_raw */
	dpc->wmbufs_raw->m_table[dpc->wmbufs_raw->wlen] = m;
	dpc->wmbufs_raw->wlen++;

	/* remove from rmbufs */
	memcpy(m, m + 1, sizeof(m) * (dpc->rmbufs->rlen - 1 - idx));
	dpc->rmbufs->rlen--;

	return ret;
}
/*----------------------------------------------------------------------------*/
int32_t
dpdk_select(struct mtcp_thread_context *ctxt)
{
#ifdef RX_IDLE_ENABLE
	struct dpdk_private_context *dpc;
	
	dpc = (struct dpdk_private_context *) ctxt->io_private_context;
	if (dpc->rx_idle > RX_IDLE_THRESH) {
		dpc->rx_idle = 0;
		usleep(RX_IDLE_TIMEOUT);
	}
#endif
	return 0;
}
/*----------------------------------------------------------------------------*/
void
dpdk_destroy_handle(struct mtcp_thread_context *ctxt)
{
	struct dpdk_private_context *dpc;
	int i;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;	

	/* free wmbufs */
	for (i = 0; i < g_config.mos->netdev_table->num; i++)
		free_pkts(dpc->wmbufs_raw[i].m_table, MAX_PKT_BURST_RAW);

#ifdef ENABLE_STATS_IOCTL
	/* free fd */
	if (dpc->fd >= 0)
		close(dpc->fd);
#endif /* !ENABLE_STATS_IOCTL */

	/* free it all up */
	free(dpc);
}
/*----------------------------------------------------------------------------*/
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 			100 /* 100ms */
#define MAX_CHECK_TIME 			90 /* 9s (90 * 100ms) in total */

	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n\n");
		}
	}
}
/*----------------------------------------------------------------------------*/
static inline struct rte_flow *
offload_bypass(uint16_t portid, uint8_t *h_daddr, uint8_t *h_saddr,
			   rte_be32_t saddr, rte_be32_t daddr,
			   rte_be16_t sport, rte_be16_t dport, uint8_t proto)
{
	struct rte_flow_error err;
	struct rte_flow *flow;
	struct rte_flow_attr attr = {
		.group = 0,
		.priority = 1,
		.transfer = 1,
	};
	struct rte_flow_item patterns[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_PORT_ID,
			.spec = &(struct rte_flow_item_port_id){.id = portid}
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &(struct rte_flow_item_ipv4) {
				.hdr.src_addr = saddr,
				.hdr.dst_addr = daddr,
			},
			.mask = &rte_flow_item_ipv4_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_TCP,
			.spec = &(struct rte_flow_item_tcp) {
				.hdr.src_port = sport,
				.hdr.dst_port = dport,
			},
			.mask = &rte_flow_item_tcp_mask,
		},
		/* should be terminated with END pattern item */
		{.type = RTE_FLOW_ITEM_TYPE_END}
	};
	struct rte_flow_action actions[] = {
		/* modifying dst haddr works well */
    	{
			.type = RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
			.conf = &(struct rte_flow_action_modify_field) {
				.operation = (enum rte_flow_modify_op) RTE_FLOW_MODIFY_SET,
				.dst = (struct rte_flow_action_modify_data) {
					.field = RTE_FLOW_FIELD_MAC_DST
				},
				.src = (struct rte_flow_action_modify_data) {
					.field = RTE_FLOW_FIELD_POINTER,
					.pvalue = h_daddr,
				},
				.width = ETH_ALEN * 8
			}
		},
		{
			.type = RTE_FLOW_ACTION_TYPE_PORT_ID,
			.conf = &(struct rte_flow_action_port_id) {
				// .original = 1,
				.reserved = 0,
				.id = portid
			}
		},
		/* should be terminated with END action */
    	{.type = RTE_FLOW_ACTION_TYPE_END}
	};
	printf("offload_bypass called\n");
	if (rte_flow_validate(portid, &attr, patterns, actions, &err) < 0)
    	rte_exit(EXIT_FAILURE,
        	"flow rule validate failed: %s\n error type %u %s\n",
        	rte_strerror(rte_errno), err.type, err.message);
	flow = rte_flow_create(portid, &attr, patterns, actions, &err);
	if (!flow)
    	rte_exit(EXIT_FAILURE,
        	"flow rule create failed: %s\n error type %u %s\n",
        	rte_strerror(rte_errno), err.type, err.message);

	return flow;
}
/*----------------------------------------------------------------------------*/
static inline struct rte_flow *
offload_drop(uint16_t portid, rte_be32_t saddr, rte_be32_t daddr,
			 rte_be16_t sport, rte_be16_t dport, uint8_t proto)
{
	struct rte_flow_error err;
	struct rte_flow *flow;
	struct rte_flow_attr attr = {
		.group = 1,
		/* 
		 * DROP rule has higher priority (smaller is higher)
		 * than BYPASS rule
		 */
		.priority = 0,
    	.ingress = 1,
	};
	struct rte_flow_item_ipv4 ipv4_spec = {
    	.hdr.src_addr = saddr,
    	.hdr.dst_addr = daddr,
	};
	struct rte_flow_item_tcp tcp_spec = {
    	.hdr.src_port = sport,
    	.hdr.dst_port = dport,
	};
	struct rte_flow_item patterns[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &ipv4_spec,
			.mask = &rte_flow_item_ipv4_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_TCP,
			.spec = &tcp_spec,
			.mask = &rte_flow_item_tcp_mask,
		},
		/* should be terminated with END pattern item */
		{.type = RTE_FLOW_ITEM_TYPE_END}
	};
	struct rte_flow_action actions[] = {
    	{
			.type = RTE_FLOW_ACTION_TYPE_DROP,
		},
		/* should be terminated with END action */
    	{.type = RTE_FLOW_ACTION_TYPE_END}
	};
	printf("offload_drop called\n");
	if (rte_flow_validate(portid, &attr, patterns, actions, &err) < 0)
    	rte_exit(EXIT_FAILURE,
        	"flow rule validate failed: %s\n error type %u %s\n",
        	rte_strerror(rte_errno), err.type, err.message);
	flow = rte_flow_create(portid, &attr, patterns, actions, &err);
	if (!flow)
    	rte_exit(EXIT_FAILURE,
        	"flow rule create failed: %s\n error type %u %s\n",
        	rte_strerror(rte_errno), err.type, err.message);

	return flow;
}
/*----------------------------------------------------------------------------*/
void *
dpdk_offload_ctl(int nif, int cmd, void *argp)
{
	struct rte_ether_hdr *ethh = (struct rte_ether_hdr *)argp;
	struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(ethh + 1);
	struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)
		((unsigned char *)iph + ((iph->version_ihl & 0x0f) << 2));

	if (cmd == OFFLOAD_DROP)
		return offload_drop(nif, iph->src_addr, iph->dst_addr,
			tcph->src_port, tcph->dst_port, iph->next_proto_id);
	if (cmd == OFFLOAD_BYPASS)
		return offload_bypass(nif,
			ethh->dst_addr.addr_bytes, ethh->src_addr.addr_bytes,
			iph->src_addr, iph->dst_addr,
			tcph->src_port, tcph->dst_port, iph->next_proto_id);
	printf("Not supported cmd yet!\n");

	return NULL;
}
/*----------------------------------------------------------------------------*/
int
dpdk_onload_ctl(int nif, void *flow)
{
	printf("onload called\n");
	struct rte_flow_error err;
	int ret = rte_flow_destroy(nif, (struct rte_flow *)flow, &err);
	if (ret < 0)
    	rte_exit(EXIT_FAILURE,
        	"flow rule remove failed: %s\n error type %u %s\n",
        	rte_strerror(rte_errno), err.type, err.message);

	return ret;
}
/*----------------------------------------------------------------------------*/
#if LEADER_ISOLATION
void
data_flow_configure(uint16_t portid, uint16_t numq)
{
	uint16_t rss_queues[MAX_CPUS];
	struct rte_flow_attr attr = {
		.group = 1,
		.priority = 1,
    	.ingress = 1,
	};
	struct rte_flow_item patterns[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &(struct rte_flow_item_ipv4) {
				.hdr.next_proto_id = IPPROTO_TCP,
			},
			.mask = &(struct rte_flow_item_ipv4) {
				.hdr.next_proto_id = 0xff,
			},
		},
    	{.type = RTE_FLOW_ITEM_TYPE_END}
	};
	struct rte_flow_action actions[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_RSS,
			.conf = &(struct rte_flow_action_rss) {
				.types = ETH_RSS_TCP | ETH_RSS_UDP | ETH_RSS_IP,
				.key_len = sizeof(g_key),
				.queue_num = numq - 1,
				.key = g_key,
				.queue = rss_queues,
			},
		}
    	{.type = RTE_FLOW_ACTION_TYPE_END},
	};
	struct rte_flow_error err;
	
	/* Do RSS over N queues using the default RSS key */
	printf("[port %u] Configuring TCP flow RSS among queues\n",
		   (unsigned) portid);
	for (uint16_t i = 0; i < numq - 1; i++) {
		/* queue 0 --> core 1, queue 1 --> core 2, and so on */
		rss_queues[i] = i + 1;
		printf("rss_queues[%d]: %d\n", i, i + 1);
	}

	if (!rte_flow_create(portid, &attr, patterns, actions, &err))
    	rte_exit(EXIT_FAILURE,
        	"rss flow create failed: %s\n error type %u %s\n",
        	rte_strerror(rte_errno), err.type, err.message);
}
/*----------------------------------------------------------------------------*/
void
key_flow_configure(uint16_t portid, uint16_t numq)
{
	struct rte_flow_attr attr = {
		.group = 1,
		.priority = 0,
    	.ingress = 1,
	};
	struct rte_flow_item patterns[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &(struct rte_flow_item_ipv4) {
				.hdr.type_of_service = 0xff
			},
			.mask = &(struct rte_flow_item_ipv4) {
				.hdr.type_of_service = 0xff
			}
		},
    	{.type = RTE_FLOW_ITEM_TYPE_END}
	};
	struct rte_flow_action actions[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &(struct rte_flow_action_queue) {.index = 0},
		}
    	{.type = RTE_FLOW_ACTION_TYPE_END},
	};
	struct rte_flow_error err;

	printf("[port %u] Configuring key flow to queue 0\n",
		   (unsigned) portid);
	if (!rte_flow_create(portid, &attr, patterns, actions, &err))
    	rte_exit(EXIT_FAILURE,
        	"key flow create failed: %s\n error type %u %s\n",
        	rte_strerror(rte_errno), err.type, err.message);
}
#endif
/*----------------------------------------------------------------------------*/
#if KEY_MAPPING
void
data_flow_configure(uint16_t portid, uint16_t numq)
{
	uint16_t data_rss_queues[MAX_CPUS];
	struct rte_flow_attr attr = {
		.group = 0,
		.priority = 1,
    	.ingress = 1,
	};
	struct rte_flow_item patterns[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &(struct rte_flow_item_ipv4) {
				.hdr.next_proto_id = IPPROTO_TCP
			},
			.mask = &(struct rte_flow_item_ipv4) {
				.hdr.next_proto_id = 0xff
			},
		},
    	{.type = RTE_FLOW_ITEM_TYPE_END}
	};
	struct rte_flow_action actions[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_RSS,
			.conf = &(struct rte_flow_action_rss) {
				.types = RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_IP,
				.key_len = sizeof(g_key),
				.queue_num = numq,
				.key = g_key,
				.queue = data_rss_queues,
			}
		},
    	{.type = RTE_FLOW_ACTION_TYPE_END},
	};
	struct rte_flow_error err;

	/* Do RSS for session data over N queues using the default RSS key */
	printf("[port %u] Configuring session data RSS among %d ~ %d queues\n",
		   (unsigned) portid, numq, numq);
	for (uint16_t i = 0; i < numq; i++) {
		/* queue 0 --> core 0, queue 1 --> core 1, and so on */
		data_rss_queues[i] = i;
		printf("[queue %d] --> [core %d]\n", i, i);
	}

	if (!rte_flow_create(portid, &attr, patterns, actions, &err))
    	rte_exit(EXIT_FAILURE,
        	"rss flow create failed: %s\n error type %u %s\n",
        	rte_strerror(rte_errno), err.type, err.message);
}
/*----------------------------------------------------------------------------*/
void
key_flow_configure(uint16_t portid, uint16_t numq)
{
	uint16_t key_rss_queues[MAX_CPUS];
	struct rte_flow_attr attr = {
		.group = 0,
		.priority = 0,
    	.ingress = 1,
	};
	struct rte_flow_item patterns[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &(struct rte_flow_item_ipv4) {
				.hdr.next_proto_id = IPPROTO_UDP,
				.hdr.type_of_service = 0xff
			},
			.mask = &(struct rte_flow_item_ipv4) {
				.hdr.next_proto_id = 0xff,
				.hdr.type_of_service = 0xff
			},
		},
    	{.type = RTE_FLOW_ITEM_TYPE_END}
	};
	struct rte_flow_action actions[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_RSS,
			.conf = &(struct rte_flow_action_rss) {
				.types = RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_IP,
				.key_len = sizeof(g_key),
				.queue_num = numq,
				.key = g_key,
				.queue = key_rss_queues,
			}
		},
    	{.type = RTE_FLOW_ACTION_TYPE_END},
	};
	struct rte_flow_error err;

	/* Do RSS for session key over N queues using the default RSS key */
	printf("[port %u] Configuring session key RSS among %d ~ %d queues\n",
		   (unsigned) portid, numq, numq * 2 - 1);
	for (uint16_t i = 0; i < numq; i++) {
		/* queue 0 --> core 16, queue 1 --> core 17, and so on */
		key_rss_queues[i] = i + numq;
		printf("[queue %d] --> [core %d]\n", i + numq, i);
	}

	if (!rte_flow_create(portid, &attr, patterns, actions, &err))
    	rte_exit(EXIT_FAILURE,
        	"rss flow create failed: %s\n error type %u %s\n",
        	rte_strerror(rte_errno), err.type, err.message);
}
#endif
/*----------------------------------------------------------------------------*/
void
bypass_configure(uint16_t portid)
{
	printf("[port %u] Configuring bypass rule\n", (unsigned) portid);
	struct rte_flow_attr attr = {
		.group = 1,
		.priority = 3,
    	// .egress = 1,
		.transfer = 1,
	};
	struct rte_flow_item patterns[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &(struct rte_flow_item_ipv4){.hdr.next_proto_id = IPPROTO_TCP},
			.mask = &(struct rte_flow_item_ipv4){.hdr.next_proto_id = 0xff},
		},
    	{.type = RTE_FLOW_ITEM_TYPE_END}
	};
	struct rte_flow_action actions[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_PORT_ID,
			.conf = &(struct rte_flow_action_port_id) {
				.original = 1,
				.reserved = 0,
				.id = portid
			}
		},
    	{.type = RTE_FLOW_ACTION_TYPE_END},
	};
	struct rte_flow_error err;

	if (!rte_flow_create(portid, &attr, patterns, actions, &err))
    	rte_exit(EXIT_FAILURE,
        	"bypass rule create failed: %s\n error type %u %s\n",
        	rte_strerror(rte_errno), err.type, err.message);
}
/*----------------------------------------------------------------------------*/
void
dpdk_load_module_upper_half(void)
{
	int cpu = g_config.mos->num_cores, ret;
	uint32_t cpumask = 0;
	char cpumaskbuf[10];
	char mem_channels[5];

	/* set the log level */
	rte_log_set_level(RTE_LOGTYPE_PMD, 0);
	rte_log_set_level(RTE_LOGTYPE_MALLOC, 0);
	rte_log_set_level(RTE_LOGTYPE_MEMPOOL, 0);
	rte_log_set_level(RTE_LOGTYPE_RING, 0);
	rte_log_set_level(RTE_LOG_WARNING, 0);
	/* get the cpu mask */
	for (ret = 0; ret < cpu; ret++)
		cpumask = (cpumask | (1 << ret));
	sprintf(cpumaskbuf, "%X", cpumask);

	/* get the mem channels per socket */
	if (g_config.mos->nb_mem_channels == 0) {
		TRACE_ERROR("DPDK module requires # of memory channels "
				"per socket parameter!\n");
		exit(EXIT_FAILURE);
	}
	sprintf(mem_channels, "%d", g_config.mos->nb_mem_channels);

	/* initialize the rte env first, what a waste of implementation effort!  */
	char *argv[] = {"", 
	        "--iova-mode=va",
			"-c", 
			cpumaskbuf, 
			"-n", 
			mem_channels,
			"--proc-type=primary",
			// "-a",
			// "0000:18:00.0"
			// "-a",
			// "0000:18:00.1"
	};
	const int argc = 7;
	// const int argc = 9;

	/* 
	 * re-set getopt extern variable optind.
	 * this issue was a bitch to debug
	 * rte_eal_init() internally uses getopt() syscall
	 * mtcp applications that also use an `external' getopt
	 * will cause a violent crash if optind is not reset to zero
	 * prior to calling the func below...
	 * see man getopt(3) for more details
	 */
	optind = 0;

	/* initialize the dpdk eal env */
	ret = rte_eal_init(argc, argv);
	
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL args!\n");


	fprintf(stderr, "dev_cnt: %u\n", rte_eth_dev_count_avail());
}
/*----------------------------------------------------------------------------*/
void
dpdk_load_module_lower_half(void)
{
	int portid, rxlcore_id, ret;
	struct rte_eth_fc_conf fc_conf;	/* for Ethernet flow control settings */

	/* resetting cpu_qid mapping */
	memset(cpu_qid_map, 0xFF, sizeof(cpu_qid_map));

	if (!g_config.mos->multiprocess
			|| (g_config.mos->multiprocess && g_config.mos->multiprocess_is_master)) {
		/* we use two mbuf for one core, respectively data mbuf, key mbuf */
		for (rxlcore_id = 0; rxlcore_id < g_config.mos->num_cores; rxlcore_id++) {
			char name[20];
			/* create the mbuf pools for tx/rx of session data packets */
			sprintf(name, "mbuf_pool-%d-data", rxlcore_id);
			if (!(pktmbuf_pool[rxlcore_id] =
				rte_mempool_create(name, NB_MBUF,
						   MBUF_SIZE, MEMPOOL_CACHE_SIZE,
						   sizeof(struct rte_pktmbuf_pool_private),
						   rte_pktmbuf_pool_init, NULL,
						   rte_pktmbuf_init, NULL,
						   rte_lcore_to_socket_id(rxlcore_id), 0)))
				rte_exit(EXIT_FAILURE,
						"Cannot init data mbuf pool in rxlcore_id: %d\n", rxlcore_id);

			/* create the mbuf pools for rx of session key packet */
			sprintf(name, "mbuf_pool-%d-raw", rxlcore_id);
			if (!(pktmbuf_pool_raw[rxlcore_id] =
				rte_mempool_create(name, NB_MBUF,
						   MBUF_SIZE, MEMPOOL_CACHE_SIZE,
						   sizeof(struct rte_pktmbuf_pool_private),
						   rte_pktmbuf_pool_init, NULL,
						   rte_pktmbuf_init, NULL,
						   rte_lcore_to_socket_id(rxlcore_id), 0)))
				rte_exit(EXIT_FAILURE,
						"Cannot init raw mbuf pool in rxlcore_id: %d\n", rxlcore_id);
#if KEY_MAPPING
			/* create the mbuf pools for rx of session key packet */
			sprintf(name, "mbuf_pool-%d-key", rxlcore_id);
			if (!(pktmbuf_pool_key[rxlcore_id] =
				rte_mempool_create(name, NB_MBUF_KEY,
						   MBUF_SIZE, MEMPOOL_CACHE_SIZE,
						   sizeof(struct rte_pktmbuf_pool_private),
						   rte_pktmbuf_pool_init, NULL,
						   rte_pktmbuf_init, NULL,
						   rte_lcore_to_socket_id(rxlcore_id), 0)))
				rte_exit(EXIT_FAILURE,
						"Cannot init key mbuf pool in rxlcore_id: %d\n", rxlcore_id);
#endif
		}

		/* Initialize each port */
		for (portid = 0; portid < g_config.mos->netdev_table->num; portid++) {
			printf("\nportid: %d/%d\n\n", portid, g_config.mos->netdev_table->num);
			int num_queue = 0, eth_idx, i, queue_id;
			for (eth_idx = 0; eth_idx < g_config.mos->netdev_table->num; eth_idx++)
				if (portid == g_config.mos->netdev_table->ent[eth_idx]->ifindex)
					break;
			if (eth_idx == g_config.mos->netdev_table->num)
				continue;
			for (i = 0; i < sizeof(uint64_t) * 8; i++)
				if (g_config.mos->netdev_table->ent[eth_idx]->cpu_mask & (1L << i))
					num_queue++;
			
			/* check port capabilities */
			rte_eth_dev_info_get(portid, &dev_info[portid]);
			printf("dev_flags: %d\n", *dev_info[portid].dev_flags);
			printf("name of switch in port %d: %s\n", portid, dev_info[portid].switch_info.name);
			printf("domainid of switch in port %d: %d\n", portid, dev_info[portid].switch_info.domain_id);
			printf("portid of switch in port %d: %d\n", portid, dev_info[portid].switch_info.port_id);
			printf("rx domain of switch in port %d: %d\n", portid, dev_info[portid].switch_info.rx_domain);
			// *dev_info[portid].dev_flags |= RTE_ETH_DEV_REPRESENTOR;

			// struct rte_eth_representor_info info;
			// ret = rte_eth_representor_info_get(portid, &info);
			// if (ret < 0)
			// 	rte_exit(EXIT_FAILURE, "Cannot get representor info of device:"
			// 						   "err=%d, port=%u\n",
			// 						   ret, (unsigned) portid);
			// printf("pf id: %d\n", info.pf);

			/* re-adjust rss_hf */
			port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info[portid].flow_type_rss_offloads;
			assert(num_queue == g_config.mos->num_cores);
			/* set 'num_queues' (used for GetRSSCPUCore() in util.c) */
			num_queues = num_queue;
			
			/* init port */
			printf("[port %u] Initializing port... ", (unsigned) portid);
			fflush(stdout);
			if ((ret = rte_eth_dev_configure(portid,
										/* rx queue num */
										(KEY_MAPPING && (portid == 0)) ? (num_queue * 2) : num_queue,
										/* tx queue num */
										num_queue,
										&port_conf)) < 0)
				rte_exit(EXIT_FAILURE, "Cannot configure device:"
									   "err=%d, port=%u\n",
									   ret, (unsigned) portid);

			/* init two RX queue per CPU */
			fflush(stdout);
#ifdef DEBUG
			rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
#endif
			queue_id = 0;
			for (rxlcore_id = 0; rxlcore_id < g_config.mos->num_cores; rxlcore_id++) {
				if (!(g_config.mos->netdev_table->ent[eth_idx]->cpu_mask & (1L << rxlcore_id)))
					continue;
				
				/* first RX queue for data */
				if ((ret = rte_eth_rx_queue_setup(portid, queue_id, nb_rxd_data,
						rte_eth_dev_socket_id(portid),
						(USE_CUSTOM_THRESH) ? &rx_conf : &dev_info[portid].default_rxconf,
						pktmbuf_pool[rxlcore_id])) < 0)
					rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: "
										   "err=%d, port=%u, queue_id for data: %d\n",
										   ret, (unsigned) portid, rxlcore_id);
#if KEY_MAPPING
				if (portid == 0)
					/* second RX queue for key */
					if ((ret = rte_eth_rx_queue_setup(portid, queue_id + num_queue, nb_rxd_key,
							rte_eth_dev_socket_id(portid),
							(USE_CUSTOM_THRESH) ? &rx_conf : &dev_info[portid].default_rxconf,
							pktmbuf_pool_key[rxlcore_id])) < 0)
						rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: "
											"err=%d, port=%u, queue_id for key: %d\n",
											ret, (unsigned) portid, rxlcore_id + num_queue);
#endif

				cpu_qid_map[portid][rxlcore_id] = queue_id;
				queue_id++;
			}

			/* init one TX queue on each port per CPU */
			fflush(stdout);
			queue_id = 0;
			for (rxlcore_id = 0; rxlcore_id < g_config.mos->num_cores; rxlcore_id++) {
				if (!(g_config.mos->netdev_table->ent[eth_idx]->cpu_mask & (1L << rxlcore_id)))
					continue;
				if ((ret = rte_eth_tx_queue_setup(portid, queue_id, nb_txd,
						rte_eth_dev_socket_id(portid),
						(USE_CUSTOM_THRESH ) ? &tx_conf : &dev_info[portid].default_txconf)) < 0)
					rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: "
										   "err=%d, port=%u, queue_id: %d\n",
										   ret, (unsigned) portid, rxlcore_id);
				queue_id++;
			}

			/* Start device */
			ret = rte_eth_dev_start(portid);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
									   ret, (unsigned) portid);

			printf("done: \n");
			rte_eth_promiscuous_enable(portid);
			struct rte_flow_error err;
			ret = rte_flow_flush(portid, &err);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_flow_flush:err=%d, port=%u\n",
										ret, (unsigned) portid);
#if LEADER_ISOLATION
			if (num_queue > 1) {
				/* data packets to follower cores (core id: 1 ~ 15) */
				data_flow_configure(portid, num_queue);
				/* key packets to leader core (core id: 0) */
				key_flow_configure(portid, num_queue);
			}
#endif
#if KEY_MAPPING
			if (portid == 0) {
				/* data packets to queues with pktmbuf_pool 0 ~ 15 (core id: 0 ~ 15) */
				// bypass_configure(portid);
				data_flow_configure(portid, num_queue);
				/* key packets to queues with pktmbuf_pool_key 0 ~ 15 (core id: 0 ~ 15) */
				key_flow_configure(portid, num_queue);
			}
#endif
			// bypass_configure(portid);

#if 0
			static struct rte_flow_port_attr flow_port_attr[RTE_MAX_ETHPORTS];
			static struct rte_flow_port_info flow_port[RTE_MAX_ETHPORTS];
			struct rte_flow_queue_attr flow_queue_attr;
			struct rte_flow_queue_info flow_queue;
			struct rte_flow_error err;
			ret = rte_flow_info_get(portid, &flow_port[portid], &flow_queue, &err);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_flow_info_get: port=%u, err_type=%d, err_msg=%s\n",
									   (unsigned) portid, err.type, err.message);
			flow_port_attr[portid] =
				*(struct rte_flow_port_attr *)(&flow_port[portid].max_nb_counters);
			flow_queue_attr = 
				*(struct rte_flow_queue_attr *)(&flow_queue);
			printf("max_nb_counters: %d\n"
					"max_nb_aging: %d\n"
					"max_nb_meters: %d\n"
					"max_nb_conntrack: %d\n"
					"flags: %d\n"
					"max_size_of_each_queue: %d\n",
					flow_port_attr[portid].nb_counters,
					flow_port_attr[portid].nb_aging_objects,
					flow_port_attr[portid].nb_meters,
					flow_port_attr[portid].nb_conn_tracks,
					flow_port_attr[portid].flags,
					flow_queue.max_size);
			ret = rte_flow_configure(portid, &flow_port_attr[portid], num_queue, &flow_queue_attr, &err);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_flow_configure: port=%u, err_type=%d, err_msg=%s\n",
									   (unsigned) portid, err.type, err.message);
#endif

			/* retrieve current flow control settings per port */
			memset(&fc_conf, 0, sizeof(fc_conf));
			ret = rte_eth_dev_flow_ctrl_get(portid, &fc_conf);
			if (ret != 0) {
				rte_exit(EXIT_FAILURE, "Failed to get flow control info!\n");
			}

			/* and just disable the rx/tx flow control */
			fc_conf.mode = RTE_ETH_FC_NONE;
			ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
			if (ret != 0) {
				rte_exit(EXIT_FAILURE, "Failed to set flow control info!: errno: %d\n",
					 ret);
			}

#ifdef DEBUG
			printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
					(unsigned) portid,
					ports_eth_addr[portid].addr_bytes[0],
					ports_eth_addr[portid].addr_bytes[1],
					ports_eth_addr[portid].addr_bytes[2],
					ports_eth_addr[portid].addr_bytes[3],
					ports_eth_addr[portid].addr_bytes[4],
					ports_eth_addr[portid].addr_bytes[5]);
#endif
		}
		/* only check for link status if the thread is master */
		check_all_ports_link_status(g_config.mos->netdev_table->num, 0xFFFFFFFF);
	}
	else { /* g_config.mos->multiprocess && !g_config.mos->multiprocess_is_master */
		for (rxlcore_id = 0; rxlcore_id < g_config.mos->num_cores; rxlcore_id++) {
			char name[20];
			sprintf(name, "mbuf_pool-%d", rxlcore_id);
			/* initialize the mbuf pools */
			pktmbuf_pool[rxlcore_id] =
				rte_mempool_lookup(name);
			if (pktmbuf_pool[rxlcore_id] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
			for (portid = 0; portid < g_config.mos->netdev_table->num; portid++)
				cpu_qid_map[portid][rxlcore_id] = rxlcore_id;			
		}
		/* set 'num_queues' (used for GetRSSCPUCore() in util.c) */
		num_queues = g_config.mos->num_cores;
	}

}
/*----------------------------------------------------------------------------*/
io_module_func dpdk_module_func = {
	.load_module_upper_half		   = dpdk_load_module_upper_half,
	.load_module_lower_half		   = dpdk_load_module_lower_half,
	.init_handle		   = dpdk_init_handle,
	.link_devices		   = NULL,
	.release_pkt		   = NULL,
	.get_wptr   		   = dpdk_get_wptr,
	.set_wptr		   = dpdk_set_wptr,
	.send_pkts		   = dpdk_send_pkts,
	.get_rptr	   	   = dpdk_get_rptr,
	.get_nif		   = dpdk_get_nif,
	.recv_pkts		   = dpdk_recv_pkts,
	.stall_pkts		   = dpdk_stall_pkts,
	.select			   = dpdk_select,
	.destroy_handle		   = dpdk_destroy_handle,
	// .dev_ioctl		   = dpdk_dev_ioctl,
	.offload		   = dpdk_offload_ctl,
	.onload		   = dpdk_onload_ctl,
};
