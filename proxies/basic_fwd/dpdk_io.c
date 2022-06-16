#include "tcpstack.h"

/* ---------------------------------------------------------------------- */
static inline int
send_pkts_data(uint16_t core_id, uint16_t port) {
    struct dpdk_private_context *dpc;
    struct tcp_stat *stat = &ctx_array[core_id]->stat;
    int ret;

    dpc = ctx_array[core_id]->dpc;
    ret = 0;

    if (dpc->wmbufs[port].len > 0) {
        struct rte_mbuf **pkts;
        int cnt;

		cnt = dpc->wmbufs[port].len;
		pkts = dpc->wmbufs[port].m_table;
        do {
            ret = rte_eth_tx_burst(port, core_id, pkts, cnt);
            pkts += ret;
            cnt -= ret;
        } while (cnt > 0);
        dpc->wmbufs[port].len = 0;
    }
    stat->tx_pkts[port] += ret;

    return ret;
}
/* ---------------------------------------------------------------------- */
inline int
send_pkts(uint16_t core_id, uint16_t port) {
	return send_pkts_data(core_id, port);
}
/* ---------------------------------------------------------------------- */
inline void
free_pkts(struct rte_mbuf **mtable, unsigned len)
{
    unsigned i;

    for (i = 0; i < len; i++) {
#if VERBOSE_MBUF
        fprintf(stderr, "[%s:%d] pktbuf: %p\n", __func__, __LINE__,
            rte_pktmbuf_mtod(mtable[i], uint8_t *));
#endif
        rte_pktmbuf_free(mtable[i]);
        RTE_MBUF_PREFETCH_TO_FREE(mtable[i+1]);
    }
}
/* ---------------------------------------------------------------------- */
static inline int
flush_wmbuf(uint16_t core_id, uint16_t port)
{
	int send_cnt;

	while(1) {
		send_cnt = send_pkts_data(core_id, port);
		if (likely(send_cnt))
			break;
	}

	return send_cnt;
}
/* ---------------------------------------------------------------------- */
inline int
get_wmbuf_queue_len(uint16_t core_id, uint16_t port)
{
    struct dpdk_private_context *dpc;

	dpc = ctx_array[core_id]->dpc;

    return dpc->wmbufs[port].len;

}
/* ---------------------------------------------------------------------- */
inline int32_t
recv_pkts(uint16_t core_id, uint16_t port) {
    struct dpdk_private_context* dpc;
    int ret;
    struct tcp_stat *stat = &ctx_array[core_id]->stat;
    dpc = ctx_array[core_id]->dpc;

    if (dpc->rmbufs[port].len != 0) {
        free_pkts(dpc->rmbufs[port].m_table, dpc->rmbufs[port].len);
        dpc->rmbufs[port].len = 0;
    }

    assert(dpc->pkts_burst);
    ret = rte_eth_rx_burst((uint8_t)port, core_id,
                           dpc->pkts_burst, MAX_PKT_BURST);
	
    dpc->rx_idle = (likely(ret != 0)) ? 0 : dpc->rx_idle + 1;

    stat->rx_pkts[port] += ret;

    return ret;
}
/* ---------------------------------------------------------------------- */
inline uint8_t *
get_rptr(uint16_t core_id, uint16_t port, int index, uint32_t *len) {
    struct dpdk_private_context* dpc;
    struct rte_mbuf *m;
    uint8_t *pktbuf;
    struct tcp_stat *stat = &ctx_array[core_id]->stat;

    dpc = ctx_array[core_id]->dpc;

    m = dpc->pkts_burst[index];

    *len = m->pkt_len;

	if (!(m->buf_addr)) {
		fprintf(stderr, "[get rptr] invalid mbuf!\n");
		return NULL;
	}

    pktbuf = rte_pktmbuf_mtod(m, uint8_t *);

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
    if ((m->ol_flags & (RTE_MBUF_F_RX_L4_CKSUM_BAD |
						RTE_MBUF_F_RX_IP_CKSUM_BAD)) != 0) {
#else
    if ((m->ol_flags & (PKT_RX_L4_CKSUM_BAD | PKT_RX_IP_CKSUM_BAD)) != 0) {
#endif
        fprintf(stderr,
                "[CPU %d][Port %d] mbuf(index: %d) with invalid checksum: "
                "%p(%lu);\n",
                core_id, port, index, m, m->ol_flags);
        pktbuf = NULL;
    }

    stat->rx_bytes[port] += *len;

    return pktbuf;
}
/* ---------------------------------------------------------------------- */
inline struct rte_mbuf *
get_rm(uint16_t core_id, uint16_t port, int index, uint32_t *len) {
    struct dpdk_private_context* dpc;
    struct rte_mbuf *m;
    struct tcp_stat *stat = &ctx_array[core_id]->stat;

    dpc = ctx_array[core_id]->dpc;

    m = dpc->pkts_burst[index];

    *len = m->pkt_len;

	if (!(m->buf_addr)) {
		fprintf(stderr, "[get rptr] invalid mbuf!\n");
		return NULL;
	}

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
    if ((m->ol_flags & (RTE_MBUF_F_RX_L4_CKSUM_BAD |
						RTE_MBUF_F_RX_IP_CKSUM_BAD)) != 0) {
#else
    if ((m->ol_flags & (PKT_RX_L4_CKSUM_BAD | PKT_RX_IP_CKSUM_BAD)) != 0) {
#endif
        fprintf(stderr,
                "[CPU %d][Port %d] mbuf(index: %d) with invalid checksum: "
                "%p(%lu);\n",
                core_id, port, index, m, m->ol_flags);
		m = NULL;
    }

    stat->rx_bytes[port] += *len;

    return m;	
}

inline int
free_rm(uint16_t core_id, uint16_t port, struct rte_mbuf *m)
{
	struct dpdk_private_context* dpc;
	dpc = ctx_array[core_id]->dpc;

	dpc->rmbufs[port].m_table[dpc->rmbufs[port].len] = m;
	dpc->rmbufs[port].len++;

	return 0;
}
/* ---------------------------------------------------------------------- */
inline uint8_t *
get_wptr_tso(uint16_t core_id, uint16_t port, 
				   uint32_t pktsize, uint16_t l4_len) {
    struct dpdk_private_context *dpc;
    struct rte_mbuf *m;
    uint8_t *ptr;
    int len_mbuf;
    struct tcp_stat *stat = &ctx_array[core_id]->stat;

    dpc = ctx_array[core_id]->dpc;

    if (unlikely(dpc->wmbufs[port].len == MAX_PKT_BURST)) {
		flush_wmbuf(core_id, port);
    }

    /* sanity check */
	if (unlikely(dpc->wmbufs[port].len == MAX_PKT_BURST)) {
		/* debug */
		ERROR_PRINT("get_wptr_relay_tso can't get buffer!\n");
		exit(EXIT_FAILURE);

		return NULL;
	}

	/* alloc new m to fwd */
	m = rte_pktmbuf_alloc(pktmbuf_pool[core_id]);
	if (unlikely(m == NULL)) {
		ERROR_PRINT("[CPU %d] Failed to allocate wmbuf_relay on port %d\n",
					core_id, port);
		exit(EXIT_FAILURE);
		return NULL;
	}
	DPDK_PRINT("[get wptr tso] m->buf_addr: %lx, pktsize: %u\n",
            (uint64_t)m->buf_addr, pktsize);

    ptr = (void *)rte_pktmbuf_mtod(m, struct ether_hdr *);
    m->pkt_len = m->data_len = pktsize;
    m->nb_segs = 1;
    m->next = NULL;

	/* /\* enable TSO *\/ */
	m->l2_len = ETHERNET_HEADER_LEN;
	m->l3_len = IP_HEADER_LEN;
	m->l4_len = l4_len;
	m->tso_segsz = MTU_SIZE - (m->l3_len + m->l4_len);

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
	m->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
	if (pktsize > MTU_SIZE + ETHERNET_HEADER_LEN) {
		m->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
	} else {
		m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
	}
#else	
	m->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
	if (pktsize > MTU_SIZE + ETHERNET_HEADER_LEN) {
		m->ol_flags |= PKT_TX_TCP_SEG;
	} else {
		m->ol_flags |= PKT_TX_TCP_CKSUM;
	}
#endif

    len_mbuf = dpc->wmbufs[port].len;
    dpc->wmbufs[port].m_table[len_mbuf] = m;
    dpc->wmbufs[port].len += 1;

    stat->tx_bytes[port] += pktsize;

    return (uint8_t *)ptr;
}
/* ---------------------------------------------------------------------- */
inline int
insert_wm_tso(uint16_t core_id, uint16_t port,
              uint32_t pktsize, uint16_t l4_len, struct rte_mbuf *m) {

    struct dpdk_private_context *dpc;
    int len_mbuf;
    struct tcp_stat *stat = &ctx_array[core_id]->stat;

    dpc = ctx_array[core_id]->dpc;

    if (unlikely(dpc->wmbufs[port].len == MAX_PKT_BURST)) {
        flush_wmbuf(core_id, port);
    }

    /* sanity check */
    if (unlikely(dpc->wmbufs[port].len == MAX_PKT_BURST)) {
        /* debug */
        ERROR_PRINT("insert_wm_tso buffer become full!\n");
        exit(EXIT_FAILURE);

        return -1;
    }

    DPDK_PRINT("[insert wm tso] m->buf_addr: %lx, m->data_off: %x\n",
            (uint64_t)m->buf_addr, m->data_off);

    m->pkt_len = m->data_len = pktsize;
    m->nb_segs = 1;
    m->next = NULL;

    /* /\* enable TSO *\/ */
    m->l2_len = ETHERNET_HEADER_LEN;
    m->l3_len = IP_HEADER_LEN;
    m->l4_len = l4_len;
    m->tso_segsz = MTU_SIZE - (m->l3_len + m->l4_len);

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
    m->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
    if (pktsize > MTU_SIZE + ETHERNET_HEADER_LEN) {
        m->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
    } else {
        m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
    }
#else
    m->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
    if (pktsize > MTU_SIZE + ETHERNET_HEADER_LEN) {
        m->ol_flags |= PKT_TX_TCP_SEG;
    } else {
        m->ol_flags |= PKT_TX_TCP_CKSUM;
    }
#endif

    len_mbuf = dpc->wmbufs[port].len;
    dpc->wmbufs[port].m_table[len_mbuf] = m;
    dpc->wmbufs[port].len += 1;

    stat->tx_bytes[port] += pktsize;

    return 0;
}
