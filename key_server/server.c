//SSL-Server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <malloc.h>
#include <pthread.h>
#include <fcntl.h>
#include <resolv.h>
#include <signal.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/engine.h"

#define EXIT	0
#define SUCCESS	1

#define VERBOSE 0
#define STAT 1
#define UDP_CSUM 1

#define TLS_PORT 443
#define MAX_THREAD_NUM 16
#define MAX_FD_NUM 10000
#define BACK_LOG 100

#define KEYBLOCK_SIZE 120
#define BUF_SIZE (KEYBLOCK_SIZE + 8)
#define SEGMENT_SIZE (sizeof(struct udphdr) + KEYBLOCK_SIZE)
#define DGRAM_SIZE (sizeof(struct iphdr) + SEGMENT_SIZE)
#define RAW_PACKET_SIZE (sizeof(struct ether_header) + DGRAM_SIZE)

/* interface and MAC */
#define INTERFACE "ens2np0"
#define DST_MAC {0x08, 0xc0, 0xeb, 0x62, 0x45, 0x04}
#define SRC_MAC {0x98, 0x03, 0x9b, 0x7f, 0xc4, 0x9c}

enum {
	SSL_UNUSED = 0,
	SSL_ACCEPT_INCOMPLETED,
	SSL_ACCEPT_COMPLETED,
};

/* TLS from client */
SSL_CTX **g_ctx_arr;
size_t g_conn_cnt[MAX_THREAD_NUM];
struct ssl_info {
	SSL *ssl;
	uint16_t worker_id;
	uint16_t state;
} ssl_map[MAX_FD_NUM];

/* raw socket to proxy */
int g_sd;
uint8_t g_src_mac[ETH_ALEN];
uint8_t g_dst_mac[ETH_ALEN];

/*-----------------------------------------------------------------------------*/
static inline void
Usage()
{
	printf("Usage: ./key-server -c [thread number]\n");
	exit(EXIT_SUCCESS);
}
/*-----------------------------------------------------------------------------*/
static inline void
PrintStatistics(int signum)
{
	size_t conn_total_cnt = 0;
	printf("\n----------------------------------\n");
	for (int i = 0; i < MAX_THREAD_NUM; i++) {
		printf("[THREAD %d]: %lu\n", i, g_conn_cnt[i]);
		conn_total_cnt += g_conn_cnt[i];
		g_conn_cnt[i] = 0;
	}
	printf("[TOTAL]: %lu\n", conn_total_cnt);
	alarm(1);
}
/*-----------------------------------------------------------------------------*/
/* for psuedo header checksum */
static inline uint16_t
WrapAroundAdd(uint16_t *ptr, int nbytes) 
{
	register uint32_t sum = 0;
	uint16_t oddbyte;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((uint8_t *)&oddbyte) = *(uint8_t *)ptr;
		sum += oddbyte;
	}
	sum = (sum & 0xffff) + (sum >> 16);
	sum = sum + (sum >> 16);
	
	return (uint16_t)sum;
}
/*-----------------------------------------------------------------------------*/
static inline SSL_CTX *
InitServerCTX(void)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		printf("initserverCTX: error\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
	SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384");

	return ctx;
}
/*-----------------------------------------------------------------------------*/
static inline void
LoadCertificates(SSL_CTX* ctx , char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	if(SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
		printf("LoadCertificates: error\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if(SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
		printf("LoadCertificates: error\n");
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if(!SSL_CTX_check_private_key(ctx))	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}
/*-----------------------------------------------------------------------------*/
static inline void
ShowCerts(SSL* ssl)
{   X509 *cert;
	char *line;
	/* Get certificates (if available) */
	if (!(cert = SSL_get_peer_certificate(ssl)))
	   printf("No certificates.\n");
	else {
		/* printf("Server certificates:\n"); */
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		/* printf("Subject: %s\n", line); */
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		/* printf("Issuer: %s\n", line); */
		free(line);
		X509_free(cert);
	}
}
/*-----------------------------------------------------------------------------*/
static inline int
AcceptSSL(SSL* ssl) /* Serve the connection -- threadable */
{
	int accept_ret, accept_err_num;

	/* do SSL-protocol accept */
	if ((accept_ret = SSL_accept(ssl)) < 0) {
		/* printf("accept...incomplete\n"); */
		accept_err_num = SSL_get_error(ssl, accept_ret);
		if (accept_err_num == SSL_ERROR_WANT_READ ||
			accept_err_num == SSL_ERROR_WANT_WRITE) {
			return SSL_ACCEPT_INCOMPLETED;
		}
		else {
			fprintf(stderr, "AcceptSSL: error\n");
			ERR_print_errors_fp(stderr);
			return accept_ret;
		}
	} 
	
	/* printf("accept...complete!\n"); */
	return SSL_ACCEPT_COMPLETED;
}
/*-----------------------------------------------------------------------------*/
/*
 * Receives key from client via TLS
 * and sends key to middlebox via UDP
 * returns 1 if sends successfully, 0 if connection end
 */
static inline int
DeliverKey(SSL *ssl) {
	struct sockaddr_in client_addr = {0,};
	struct sockaddr_ll server_addr = {
		.sll_family = 0,
		.sll_protocol = ETH_P_IP,
		.sll_ifindex = if_nametoindex(INTERFACE),
		.sll_hatype = 0,
		.sll_pkttype = 0,
		.sll_halen = ETH_ALEN,
		.sll_addr = DST_MAC
	};
	socklen_t socketlen = sizeof(struct sockaddr_in);
	int sd = SSL_get_fd(ssl);
	int readbytes, sendbytes;

	/* 154B raw datagram (we use tos as 0xff for key delivery) */
	struct ether_frame {
		struct ether_header ethh;
		struct iphdr iph;
		struct udphdr udph;
		uint8_t payload[BUF_SIZE];
	} __attribute__ ((__packed__)) frame = {
		{
			.ether_dhost = DST_MAC,
			.ether_shost = SRC_MAC,
			.ether_type = htons(ETH_P_IP)
		},
		{
			.version = 0x4,
			.ihl = 0x5,
			.tos = 0xff,
			.tot_len = htons(DGRAM_SIZE), 
    		.id = 0,
    		.frag_off = 0,
			.ttl = 0xff,
			.protocol = IPPROTO_UDP,
			.check = 0
		},
		{{{
			.uh_ulen = htons(SEGMENT_SIZE),
			.uh_sum = 0
		}}}
	};
	// ShowCerts(ssl);

	/* fill payload */
	if ((readbytes = SSL_read(ssl, frame.payload, BUF_SIZE)) <= 0)
		return EXIT;

	/* fill headers */
	getpeername(sd, (struct sockaddr *)&client_addr, &socketlen);
	frame.iph.saddr = client_addr.sin_addr.s_addr;
	frame.iph.daddr = *(uint32_t *)(frame.payload + KEYBLOCK_SIZE);
	frame.udph.source = *(uint16_t *)(frame.payload + KEYBLOCK_SIZE + 4);
	frame.udph.dest = *(uint16_t *)(frame.payload + KEYBLOCK_SIZE + 6);
#if UDP_CSUM
	/* 12B pseudo header for udp csum */
	struct pseudo_header {
		uint32_t src;
		uint32_t dst;
		uint8_t padding;
		uint8_t proto;
		uint16_t udp_len;
	} psh = {
		.src = frame.iph.saddr,
		.dst = frame.iph.daddr,
		.padding = 0,
		.proto = IPPROTO_UDP,
		.udp_len = (SEGMENT_SIZE)
	};
	frame.udph.check = WrapAroundAdd((uint16_t *)&psh, sizeof(psh));
#endif
	while (((sendbytes = sendto(g_sd, &frame, RAW_PACKET_SIZE, 0,
							(struct sockaddr *)&server_addr,
							sizeof(struct sockaddr_ll))) == -1) &&
		   (errno == EINTR))
		;
	if (sendbytes == -1) {
		fprintf(stderr, "sendto() failed, errno: %d\n", errno);
		exit(EXIT_FAILURE);
	}
#if VERBOSE
	printf("[core %d] %d bytes read, %d bytes sent\n"
			"[client] ip: %u, port: %u\n"
			"[server] ip: %u, port: %u\n",
			sched_getcpu(), readbytes, sendbytes, 
			ntohl(frame.iph.saddr), ntohs(frame.udph.source),
			ntohl(frame.iph.daddr), ntohs(frame.udph.dest));
#endif

	return SUCCESS;
}
/*-----------------------------------------------------------------------------*/
void *
worker(void *arg)
{
	int worker_id = *(int *)arg;
	int epoll_fd, listen_fd, client_fd;
	int event_num;
	int optval = 1;
	struct sockaddr_in tls_client_addr = {0,};
	struct sockaddr_in tls_server_addr = {
		PF_INET,
		htons(TLS_PORT),
		{INADDR_ANY},
		{0,}
	};
	socklen_t len = sizeof(struct sockaddr_in);
	struct epoll_event listen_ev, client_ev, *events;
	SSL_CTX *ctx;
	const size_t EPOLL_SIZE = 100000;
	
#if VERBOSE
	printf("worker id: %d, cpu id: %d\n", worker_id, sched_getcpu());
#endif
	ctx = g_ctx_arr[worker_id];

	/* initialize epoll events */
	events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * EPOLL_SIZE);
	if ((epoll_fd = epoll_create(EPOLL_SIZE)) == -1)
		return NULL;

	/* listening socket */
	if ((listen_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Error: socket() failed\n");
		exit(EXIT_FAILURE);
	}
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) < 0) {
		fprintf(stderr, "Error: setsockopt() failed\n");
		exit(EXIT_FAILURE);
	}
	if (bind(listen_fd, (struct sockaddr *)&tls_server_addr, sizeof(tls_server_addr)) < 0) {
		perror("bind TCP listen socket");
		exit(EXIT_FAILURE);
	}
	if (listen(listen_fd, BACK_LOG) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	/* add listening socket fd into epoll fd */
	listen_ev.events = EPOLLIN;
	listen_ev.data.fd = listen_fd;
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &listen_ev);
	while (1) {
		event_num = epoll_wait(epoll_fd, events, EPOLL_SIZE, 0);
		if (event_num < 0) {
			perror("epoll_wait\n");
			break;
		}
		for (int i = 0; i < event_num; i++) {
			/* listening socket */
			if (events[i].data.fd == listen_fd) {
				client_fd = accept(listen_fd, (struct sockaddr *)&tls_client_addr, &len);
				
				ssl_map[client_fd].worker_id = worker_id;
				ssl_map[client_fd].state = SSL_UNUSED;

				fcntl(client_fd, F_SETFL, O_NONBLOCK);
				client_ev.events = EPOLLIN;
				client_ev.data.fd = client_fd;
				epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_ev);
			}
			else if (events[i].events & EPOLLIN) {
				if (worker_id != ssl_map[events[i].data.fd].worker_id) {
					fprintf(stderr, "Error: not thread safe\n");
					fprintf(stderr, "worker_id, ssl_map[clientfd].worker_id = %d, %d\n",
							worker_id, ssl_map[events[i].data.fd].worker_id);
					exit(EXIT_FAILURE);
				}
				/* start SSL handshake */
				if (ssl_map[events[i].data.fd].state == SSL_UNUSED) {
					/* get new SSL state with context */
					SSL *ssl;
					if ((ssl = SSL_new(ctx)) == NULL) {
						fprintf(stderr, "Error: ssl state create failed\n");
						exit(EXIT_FAILURE);
					}
					SSL_set_fd(ssl, events[i].data.fd);      /* set connection socket to SSL state */
					if (AcceptSSL(ssl) < 0) {
						fprintf(stderr, "Error: can't SSL_accept\n");
						close(events[i].data.fd);
						SSL_free(ssl);
						ssl_map[events[i].data.fd].state = SSL_UNUSED;
						continue;
					}

					/* add new ssl_info into ssl_map */
					struct ssl_info ssl_info;
					ssl_info.ssl = ssl;
					ssl_info.worker_id = worker_id;
					ssl_info.state = SSL_ACCEPT_INCOMPLETED;
					ssl_map[events[i].data.fd] = ssl_info;
				}
				/* continue SSL handshake */
				else if (ssl_map[events[i].data.fd].state == SSL_ACCEPT_INCOMPLETED) {
					static int accept_ret;
					SSL *ssl = ssl_map[events[i].data.fd].ssl;
					if ((accept_ret = AcceptSSL(ssl)) < 0) {
						fprintf(stderr, "Error: can't SSL_accept\n");
						close(events[i].data.fd);
						SSL_free(ssl);
						ssl_map[events[i].data.fd].state = SSL_UNUSED;
						continue;
					}
					ssl_map[events[i].data.fd].state = accept_ret;
				}
				/* receive encrypted data
				 * reply and close the connection if exit command */
				else if (ssl_map[events[i].data.fd].state == SSL_ACCEPT_COMPLETED) {
					SSL *ssl = ssl_map[events[i].data.fd].ssl;
					if (DeliverKey(ssl) == EXIT) {
						close(SSL_get_fd(ssl));
						SSL_free(ssl);         /* release SSL state */
						ssl_map[events[i].data.fd].state = SSL_UNUSED;
					}
					/* one connection established and closed successfully */
					g_conn_cnt[worker_id]++;
				}
			}
		}
	}
	printf("close!\n");
	close(listen_fd);          /* close server socket */
	SSL_CTX_free(ctx);         /* release context */

	return NULL;
}
/*-----------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
	pthread_t p_thread[MAX_THREAD_NUM];
	pthread_attr_t attr[MAX_THREAD_NUM];
	int tid[MAX_THREAD_NUM];
	cpu_set_t *cpusetp[MAX_THREAD_NUM];
	int c, cpu_size, thread_num = 1;

	if (getuid()) {
		printf("This program must be run as root/sudo user!\n");
		exit(EXIT_SUCCESS);
	}

	/* parse options */
	while ((c = getopt(argc, argv, "c:")) != -1) {
		if (c == 'c') {
			thread_num = atoi(optarg);
			if(thread_num < 1) {
				fprintf(stdout, "Usage: thread_num should be more than 0\n");
				exit(EXIT_SUCCESS);
			}
			else if (thread_num > MAX_THREAD_NUM) {
				fprintf(stdout, "Usage: thread_num should be less than %d\n", MAX_THREAD_NUM);
				exit(EXIT_SUCCESS);
			}
		}
		else {
			Usage();
		}
	}

	/* extend limit of available file descriptor number */
	const struct rlimit rlp = {MAX_FD_NUM, MAX_FD_NUM};
	struct rlimit rlp_copy;
	setrlimit(RLIMIT_NOFILE, &rlp);
	getrlimit(RLIMIT_NOFILE, &rlp_copy);
	fprintf(stdout, "[Info] file descriptor limit: %lu : %lu\n", rlp_copy.rlim_cur, rlp_copy.rlim_max);

	/* initialize SSL ctx */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	if ((g_ctx_arr = (SSL_CTX **)calloc(thread_num, sizeof(SSL_CTX *))) == NULL) {
		perror("can't allocate SSL_CTX\n");
		exit(EXIT_FAILURE);
	}
	for (int i = 0; i < thread_num; i++) {
		g_ctx_arr[i] = InitServerCTX();
		LoadCertificates(g_ctx_arr[i], "test.crt", "test.key");
	}

    /* setup raw socket to proxy */
	if ((g_sd = socket(PF_PACKET, SOCK_RAW, ETH_P_IP)) < 0) {
		fprintf(stderr, "Error: socket() failed\n");
		exit(EXIT_FAILURE);
	}

	/* get src MAC */
	struct ifreq s = {.ifr_name = INTERFACE};
	if (!ioctl(g_sd, SIOCGIFHWADDR, &s))
		memcpy(g_src_mac, s.ifr_addr.sa_data, ETH_ALEN);

	/* create threads */  
	for (int i = 0; i < thread_num; i++) {
		/* set core */
		if ((cpusetp[i] = CPU_ALLOC(thread_num)) == NULL) {
			fprintf(stderr, "Error: cpu_set initialize failed\n");
			exit(EXIT_FAILURE);
		}
		cpu_size = CPU_ALLOC_SIZE(thread_num);
		CPU_ZERO_S(cpu_size, cpusetp[i]);
		CPU_SET_S(i, cpu_size, cpusetp[i]);

		/* set thread attribute (core pinning) */
		if (pthread_attr_init(&attr[i]) != 0) {
			fprintf(stderr, "Error: thread attribute initialize failed\n");
			exit(EXIT_FAILURE);
		}
		pthread_attr_setaffinity_np(&attr[i], cpu_size, cpusetp[i]);

		/* create thread */
		tid[i] = i;
		g_conn_cnt[i] = 0;
		if (pthread_create(&p_thread[i], &attr[i], worker, (void *)&tid[i]) < 0) {
			fprintf(stderr, "Error: thread create failed\n");
			exit(EXIT_FAILURE);
		}
	}

	/* turn on the alarm for monitoring */
#if STAT
	signal(SIGALRM, PrintStatistics);
	alarm(2);
	while(1)
		sleep(1);
#endif

	/* wait threads */
	for (int i = 0; i < thread_num; i++) {
		pthread_join(p_thread[i], NULL);
		CPU_FREE(cpusetp[i]);
		SSL_CTX_free(g_ctx_arr[i]);         /* release context */
	}
	free(g_ctx_arr);
	close(g_sd);

	return 0;
}
