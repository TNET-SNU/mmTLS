/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */
#include <signal.h>
#include "tcpstack.h"
#include "option.h"
#include <rte_pdump.h>

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode        =   ETH_MQ_RX_RSS,
#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
		.max_lro_pkt_size = RTE_ETHER_MAX_LEN,
#else
        .max_rx_pkt_len =   RTE_ETHER_MAX_LEN,
#endif  /* 21.11 */
#if RTE_VERSION > RTE_VERSION_NUM(17, 8, 0, 0)
        .offloads       =   (
#if RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 0)
                                DEV_RX_OFFLOAD_CRC_STRIP |
#endif /* !18.05 */
#if USE_LRO
								DEV_RX_OFFLOAD_TCP_LRO |
#endif	/* USE_LRO */
#if 0
								DEV_RX_OFFLOAD_TIMESTAMP |
#endif
								0
                                /* DEV_RX_OFFLOAD_CHECKSUM */
                            ),
#endif /* !17.08 */
#if USE_LRO
		.max_lro_pkt_size =   MBUF_DATA_SIZE,

#endif	/* USE_LRO */
        .split_hdr_size =   0,
#if RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 0)
        .header_split   =   0,
        .hw_ip_checksum =   1,
        .hw_vlan_filter =   0,
        .jumbo_frame    =   0,
        .hw_strip_crc   =   1,
#endif /* !18.05 */
    },
    .rx_adv_conf = {
        .rss_conf   =   {
            .rss_key    =   NULL,
           /* .rss_hf     =   ETH_RSS_TCP | ETH_RSS_UDP | */
		   /* 	               ETH_RSS_IP | ETH_RSS_L2_PAYLOAD, */
            .rss_hf     =   ETH_RSS_IPV4 | ETH_RSS_TCP,
        },
    },
    .txmode = {
        .mq_mode    =   ETH_MQ_TX_NONE,
#if RTE_VERSION >= RTE_VERSION_NUM(18, 5, 0, 0)
        .offloads   =   (
                            DEV_TX_OFFLOAD_IPV4_CKSUM |
                            DEV_TX_OFFLOAD_UDP_CKSUM |
                            DEV_TX_OFFLOAD_TCP_CKSUM |
							DEV_TX_OFFLOAD_TCP_TSO
                        )
#endif
    },
};

int num_host_cpu;

struct tcp_stat global_stat;

struct rte_mempool *pktmbuf_pool[MAX_CPUS] = {NULL};
struct thread_context* ctx_array[MAX_CPUS] = {NULL};
uint8_t port_type[MAX_DPDK_PORT] = {0};
static struct rte_eth_dev_info dev_info[RTE_MAX_ETHPORTS];
int max_conn;
int local_max_conn;
uint8_t t_major = 0;
uint8_t t_minor = 0;
uint8_t done[MAX_CPUS] = {0};


static const uint16_t nb_rxd    =   RTE_TEST_RX_DESC_DEFAULT;
static const uint16_t nb_txd    =   RTE_TEST_TX_DESC_DEFAULT;

static void
global_init(void)
{
    int nb_ports, num_core, portid, rxlcore_id, ret;
    struct rte_eth_fc_conf fc_conf;
    char if_name[RTE_ETH_NAME_MAX_LEN];

    /* static uint8_t key[] = { */
    /*     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, */
    /*     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, */
    /*     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, */
    /*     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05 */
    /* }; */
    static uint8_t key[] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    };


    num_core = rte_lcore_count();
    if(num_core <= 0) {
		ERROR_PRINT("Zero or negative number of cores (%d) activated.\n",
					num_core);
        exit(EXIT_FAILURE);
    }

    nb_ports = rte_eth_dev_count_avail();
    if(nb_ports <= 0) {
		ERROR_PRINT("Zero or negative number of ports (%d) activated.\n",
					nb_ports);
        exit(EXIT_FAILURE);
    }

    /* Setting RSS Key */    
    port_conf.rx_adv_conf.rss_conf.rss_key = (uint8_t *)key;
    port_conf.rx_adv_conf.rss_conf.rss_key_len = sizeof(key);

    /* Packet mbuf pool Creation */
    for (rxlcore_id = 0; rxlcore_id < num_core; rxlcore_id++) {
        char name[RTE_MEMPOOL_NAMESIZE];
        sprintf(name, "mbuf_pool-%d", rxlcore_id);

		/* set buf size bigger for TSO */
		/* note: it can occupy memory severely */
        pktmbuf_pool[rxlcore_id] =
	        rte_pktmbuf_pool_create(name, (NUM_MBUFS/num_core) * nb_ports,
		    MBUF_CACHE_SIZE, 0, MBUF_SIZE, rte_socket_id());

        if(pktmbuf_pool[rxlcore_id] == NULL) {
            rte_exit(EXIT_FAILURE, "Cannot init mbuf pool, errno: %d\n",
                     rte_errno);
            fflush(stdout);
        }
    }
    fprintf(stderr, "mbuf_pool Created\n");

    /* Port Configuration and Activation */
    RTE_ETH_FOREACH_DEV(portid) {
        rte_eth_dev_get_name_by_port(portid, if_name);
        rte_eth_dev_info_get(portid, &dev_info[portid]);
#if RTE_VERSION >= RTE_VERSION_NUM(18, 5, 0, 0)
        port_conf.rx_adv_conf.rss_conf.rss_hf &=
                    dev_info[portid].flow_type_rss_offloads;
#endif

#if USE_LRO
		dev_info[portid].rx_offload_capa |= DEV_RX_OFFLOAD_TCP_LRO;
#endif

        fprintf(stderr, "Initializing port %u (%s) ... for %d cores\n",
                        (unsigned) portid, if_name, num_core);
        ret = rte_eth_dev_configure(portid, num_core, num_core, &port_conf);
        if(ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: "
                                   "err=%d, port=%u, cores: %d\n",
                                   ret, (unsigned) portid, num_core);

        for (rxlcore_id = 0; rxlcore_id < num_core; rxlcore_id++) {
            ret = rte_eth_rx_queue_setup(portid, rxlcore_id, nb_rxd,
                                         rte_eth_dev_socket_id(portid),
                                         &rx_conf, pktmbuf_pool[rxlcore_id]);
            if(ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_rx_queue_setup: "
                         "err=%d, port=%u, queueid: %d\n",
                         ret, (unsigned) portid, rxlcore_id);
        }

        for (rxlcore_id = 0; rxlcore_id < num_core; rxlcore_id++) {
            ret = rte_eth_tx_queue_setup(portid, rxlcore_id, nb_txd,
                                         rte_eth_dev_socket_id(portid),
                                         &tx_conf);
            if(ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_tx_queue_setup: "
                         "err=%d, port=%u, queueid: %d\n",
                         ret, (unsigned) portid, rxlcore_id);
        }

        ret = rte_eth_dev_start(portid);

        if(ret < 0)
            rte_exit(EXIT_FAILURE,
                     "rte_eth_dev_start:err=%d, port=%u\n",
                     ret, (unsigned) portid);

        rte_eth_promiscuous_enable(portid);

        /* Do not have to change flow control info for host side interface
         * 12 is the length of "0000:00:00.0" */
        // if(strlen(if_name) > 12) {
        //     port_type[portid] = 1;
        //     continue;
        // }

        memset(&fc_conf, 0, sizeof(fc_conf));
        ret = rte_eth_dev_flow_ctrl_get(portid, &fc_conf);
        if(ret != 0)
			ERROR_PRINT("Failed to get flow control into!\n");

        fc_conf.mode = RTE_FC_NONE;
        ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
        if(ret != 0)
			ERROR_PRINT("Failed to set flow control info!: errno: %d\n", ret);

    }
    fprintf(stderr, "Port Initialization Complete\n");

    RTE_ETH_FOREACH_DEV(portid) {
        global_stat.rx_bytes[portid] = 0;
        global_stat.rx_pkts[portid] = 0;

        global_stat.tx_bytes[portid] = 0;
        global_stat.tx_pkts[portid] = 0;

        global_stat.rtx_bytes[portid] = 0;
        global_stat.rtx_pkts[portid] = 0;
    }

    srand(time(NULL));
}

void
global_destroy(void)
{
    int portid;

    RTE_ETH_FOREACH_DEV(portid) {
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
    }
}

static int
parse_args(int argc, char *argv[])
{
    int o;

    while(-1 != (o = getopt(argc, argv, "m:c:h:"))) {
        switch(o) {
		case 'm':
			max_conn = atoi(optarg);
			if(max_conn > MAX_TCP_PORT) {
				ERROR_PRINT(
                            "max_conn cannot exceed maximum number of ports");
				return FALSE;
			}
			break;
		case 'c':
			num_host_cpu = atoi(optarg);
			break;

		case 'h':
		default:
			break;
        }
    }
    return TRUE;
}

/* ---------------------------------------------------------------------- */
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
        clean_thread();
	}
}
/* ---------------------------------------------------------------------- */
/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    unsigned lcore_id;
    unsigned i;
    int ret;

	/* Initialize the Environment Abstraction Layer (EAL). */
	ret = rte_eal_init(argc, argv);
	if(ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

#ifdef RTE_LIBRTE_PDUMP
	fprintf(stderr, "Initialize rte_pdump.\n");
    rte_pdump_init();
#endif

	argc -= ret;
	argv += ret;

    fprintf(stderr, "\nRTE EAL Initialization Complete\n");
    fprintf(stderr, "---------------------------------------------------\n\n");

    ret = parse_args(argc, argv);
    if(ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid Arguments\n");

    if(max_conn % rte_lcore_count()) {
        rte_exit(EXIT_FAILURE,
                 "max_conn should be a multiple of core num."
                 "max_conn: %d, num_core: %d\n",
                 max_conn, rte_lcore_count());
    }
    local_max_conn = max_conn / rte_lcore_count();
    fprintf(stderr, "Global Maximum Connection: %d\n"
                    "Maximum Connections per Thread: %d\n",
                    max_conn, local_max_conn);

    fprintf(stderr, "\nArgument Parsing Complete\n");
    fprintf(stderr, "---------------------------------------------------\n\n");

    global_init();

    fprintf(stderr, "\nGlobal Initialization Complete\n");
    fprintf(stderr, "---------------------------------------------------\n\n");

    fprintf(stderr, "Use Following Cores for SSL Offloaded Server\n");
    for (i = 0; i < rte_lcore_count(); i++) {
        fprintf(stderr, "%d", i);
        if(i != rte_lcore_count() - 1 )
            fprintf(stderr, ", ");
    }
    fprintf(stderr, "\n\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

	/* Call lcore_main on the master core only. */
#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
	rte_eal_mp_remote_launch(proxyoff_main_loop, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
#else
    rte_eal_mp_remote_launch(proxyoff_main_loop, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
#endif  /* 21.11 */
        if(rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }
    /* /\* Call lcore_main on the master core only. *\/ */
    /* rte_eal_mp_remote_launch(proxyoff_main_loop, NULL, CALL_MAIN); */
    /* RTE_LCORE_FOREACH_WORKER(lcore_id) { */
    /*     if(rte_eal_wait_lcore(lcore_id) < 0) { */
    /*         ret = -1; */
    /*         break; */
    /*     } */
    /* } */

    global_destroy();

	return 0;
}
