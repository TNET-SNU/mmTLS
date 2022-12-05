//SSL-Server.c
#define __USE_GNU
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
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

#define VERBOSE 0
#define STAT 1
#define UDP_CSUM 0

#define TLS_PORT 443
#define MAX_CPU 8
#define MAX_FD_NUM 10000
#define BACK_LOG 128

#define KEYBLOCK_SIZE 120
#define BUF_SIZE 128
#define SEGMENT_SIZE (sizeof(struct udphdr) + KEYBLOCK_SIZE)
#define DGRAM_SIZE (sizeof(struct iphdr) + SEGMENT_SIZE)
#define RAW_PACKET_SIZE (sizeof(struct ether_header) + DGRAM_SIZE)

#define RESET_BY_PEER 104

/* interface and MAC */
#define INTERFACE "p0"
// 0c:42:a1:e7:1e:16
#define DST_MAC {0x0c, 0x42, 0xa1, 0xe7, 0x1e, 0x16}
// 0c:42:a1:e7:1e:1a
#define SRC_MAC {0x0c, 0x42, 0xa1, 0xe7, 0x1e, 0x1a}

enum {
	SSL_UNUSED = 0,
	SSL_ACCEPT_INCOMPLETED,
	SSL_ACCEPT_COMPLETED,
};

enum {
	DELIVERY_SHUTDOWN = 0,
	DELIVERY_INCOMPLETED,
	DELIVERY_COMPLETED,
};

/* TLS from client */
SSL_CTX **g_ctx_arr;
int g_conn_cnt[MAX_CPU] = {0,};
int g_key_cnt[MAX_CPU] = {0,};
int g_total_key_cnt[MAX_CPU] = {0,};
int g_total_conn_cnt[MAX_CPU] = {0,};
struct ssl_info {
	SSL *ssl;
	uint16_t worker_id;
	uint16_t state;
	int offset;
	uint8_t payload[KEYBLOCK_SIZE];
} ssl_map[MAX_FD_NUM];

/* raw socket to proxy */
int g_sd;
uint8_t g_src_mac[ETH_ALEN];
uint8_t g_dst_mac[ETH_ALEN];
struct sockaddr_ll g_server_addr;
static __thread struct ether_frame {
	struct ether_header ethh;
	struct iphdr iph;
	struct udphdr udph;
} __attribute__ ((__packed__)) l_hdr;
static __thread uint8_t l_payload[BUF_SIZE];
static __thread struct iovec l_msg_iov[2];
static __thread struct mmsghdr l_msg[1];
#if UDP_CSUM
static __thread struct pseudo_header {
	uint32_t src;
	uint32_t dst;
	uint8_t padding;
	uint8_t proto;
	uint16_t udp_len;
} l_psh;
#endif
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
	int key_total_cnt = 0, key_per_sec = 0;
	int conn_total_cnt = 0, conn_per_sec = 0;
	printf("\n----------------------------------\n");
	for (int i = 0; i < MAX_CPU; i++) {
		printf("[THREAD %d]: total key: %d, key/s: %d, "
				"total conn: %d, conn/s: %d\n",
				i, g_total_key_cnt[i], g_key_cnt[i],
				g_total_conn_cnt[i], g_conn_cnt[i]);
		conn_per_sec += g_conn_cnt[i];
		key_per_sec += g_key_cnt[i];
		g_conn_cnt[i] = g_key_cnt[i] = 0;
		key_total_cnt += g_total_key_cnt[i];
		conn_total_cnt += g_total_conn_cnt[i];
	}
	printf("[TOTAL]: total key: %d, key/s: %d, "
			"total conn: %d, conn/s: %d\n",
			key_total_cnt, key_per_sec, conn_total_cnt, conn_per_sec);
	alarm(1);
}
/*-----------------------------------------------------------------------------*/
static inline void
hexdump(char *title, uint8_t *buf, size_t len)
{
	fprintf(stdout, "%s\n", title);
	for (size_t i = 0; i < len; i++)
		fprintf(stdout, "%02X%c", buf[i], ((i + 1) % 16 ? ' ' : '\n'));
	fprintf(stdout, "\n");
}
/*-----------------------------------------------------------------------------*/
static inline void
handle_error(const char *file, int lineno, const char *msg) {
	fprintf(stderr, "[Error] %s:%i %s\n", file, lineno, msg);
	ERR_print_errors_fp(stderr);
	exit(1);
}
#define int_error(msg) handle_error(__FILE__, __LINE__, msg)
/*-----------------------------------------------------------------------------*/
enum sslstatus { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL};
/* Obtain the return value of an SSL operation and convert into a simplified
 * error code, which is easier to examine for failure. */
static inline enum sslstatus
get_sslstatus(SSL *ssl, int n)
{
	switch (SSL_get_error(ssl, n))
	{
		case SSL_ERROR_NONE:
			return SSLSTATUS_OK;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			return SSLSTATUS_WANT_IO;
		case SSL_ERROR_ZERO_RETURN:
		case SSL_ERROR_SYSCALL:
		default:
			return SSLSTATUS_FAIL;
	}
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
	int accept_ret;

	/* do SSL-protocol accept */
	if ((accept_ret = SSL_accept(ssl)) < 0) {
		/* printf("accept...incomplete\n"); */
		if (get_sslstatus(ssl, accept_ret) == SSLSTATUS_WANT_IO)
			return SSL_ACCEPT_INCOMPLETED;
		else {
			fprintf(stderr, "AcceptSSL: error\n");
			ERR_print_errors_fp(stderr);
			return accept_ret;
		}
	}
	// printf("accept...complete!\n");

	return SSL_ACCEPT_COMPLETED;
}
/*-----------------------------------------------------------------------------*/
/*
 * Receives key from client via TLS
 * and sends key to middlebox via UDP
 * returns 1 if sends successfully, 0 if connection end
 */
static inline int
DeliverKey(struct ssl_info *si) {
	int offset, readbytes, sendbytes;
	struct sockaddr_in client_addr = {0,};
	socklen_t socketlen = sizeof(struct sockaddr_in);
	int status;

	// ShowCerts(ssl);
	/* ToDo: make loop to fill packets and send packets at once after loop */
	while (1) {
		/* fill payload */
		offset = si->offset;
		if (offset > 0) {
			/* fill previous payload */
			printf("incomplete key block remained\n");
			memcpy(l_payload, si->payload, offset);
		}
		do {
			if ((readbytes = SSL_read(si->ssl, l_payload + offset, BUF_SIZE - offset)) == 0)
				/* client called SSL_shutdown */
				return DELIVERY_SHUTDOWN;
			if (readbytes < 0) {
				status = get_sslstatus(si->ssl, readbytes);
				if (status == SSLSTATUS_FAIL) {
					if (errno == RESET_BY_PEER) {
						printf("[Warning] shutdown forced\n");
						return DELIVERY_SHUTDOWN;
					}
					else if (errno == EAGAIN)
						return DELIVERY_INCOMPLETED;
					else {
						printf("[Error] SSL_read failed\n");
						exit(EXIT_FAILURE);
					}
				}
				else if (status == SSLSTATUS_WANT_IO)
					return DELIVERY_INCOMPLETED;
			}
			offset += readbytes;
		} while (offset < BUF_SIZE);

		/* incomplete key block, save payload and offset to ssl_info map */
		if (offset < BUF_SIZE) {
			memcpy(si->payload + si->offset, l_payload + si->offset, offset - si->offset);
			si->offset = offset;
			return DELIVERY_INCOMPLETED;
		}

		/* now key block is completely received */
		assert(offset == BUF_SIZE);
		si->offset = 0;
		
		/* fill headers */
		getpeername(SSL_get_fd(si->ssl), (struct sockaddr *)&client_addr, &socketlen);
		l_hdr.iph.saddr = client_addr.sin_addr.s_addr;
		l_hdr.iph.daddr = *(uint32_t *)(l_payload + KEYBLOCK_SIZE);
		l_hdr.udph.source = *(uint16_t *)(l_payload + KEYBLOCK_SIZE + 4);
		l_hdr.udph.dest = *(uint16_t *)(l_payload + KEYBLOCK_SIZE + 6);
	#if UDP_CSUM
		/* 12B pseudo header for udp csum */
		l_psh = (struct pseudo_header) {
			.src = hdr.iph.saddr,
			.dst = hdr.iph.daddr,
			.padding = 0,
			.proto = IPPROTO_UDP,
			.udp_len = SEGMENT_SIZE
		};
		g_hdr.udph.check = WrapAroundAdd((uint16_t *)&l_psh, sizeof(l_psh));
	#endif
		do {
			sendbytes = sendmmsg(g_sd, l_msg, 1, 0);
		} while ((sendbytes == -1) && ((errno == EAGAIN) || (errno == EINTR)));
		if (sendbytes == -1) {
			fprintf(stderr, "[Error] sendmsg failed\n");
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
		/* counts key sent */
		g_key_cnt[si->worker_id]++;
		g_total_key_cnt[si->worker_id]++;
	}

	return DELIVERY_COMPLETED;
}
/*-----------------------------------------------------------------------------*/
void *
worker(void *arg)
{
	int worker_id = *(int *)arg;
	int epoll_fd, listen_fd, client_fd;
	int event_num;
	int optval = 1;
	int conn_cnt = 0;
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
	
	/* raw datagram header (we use tos as 0xff for key delivery) */
	l_hdr = (struct ether_frame) {
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
	l_msg_iov[0] = (struct iovec) {
		.iov_base = &l_hdr,
		.iov_len = sizeof(l_hdr)
	};
	l_msg_iov[1] = (struct iovec) {
		.iov_base = l_payload,
		.iov_len = KEYBLOCK_SIZE
	};
	l_msg[0].msg_hdr = (struct msghdr) {
		.msg_name = &g_server_addr,
		.msg_namelen = sizeof(g_server_addr),
		.msg_iov = l_msg_iov,
		.msg_iovlen = 2
	};

#if VERBOSE
	printf("worker id: %d, cpu id: %d\n", worker_id, sched_getcpu());
#endif
	ctx = g_ctx_arr[worker_id];

	/* initialize epoll events */
	events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * EPOLL_SIZE);
	if ((epoll_fd = epoll_create(EPOLL_SIZE)) == -1)
		return NULL;

	/* listening socket */
	if ((listen_fd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "Error: socket() failed\n");
		exit(EXIT_FAILURE);
	}
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) == -1) {
		fprintf(stderr, "Error: setsockopt() failed\n");
		exit(EXIT_FAILURE);
	}
	if (bind(listen_fd, (struct sockaddr *)&tls_server_addr, sizeof(tls_server_addr)) == -1) {
		perror("bind TCP listen socket");
		exit(EXIT_FAILURE);
	}
	if (listen(listen_fd, BACK_LOG) == -1) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	/* add listening socket fd into epoll target */
	listen_ev.events = EPOLLIN;
	listen_ev.data.fd = listen_fd;
	if ((epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &listen_ev)) == -1) {
		perror("epoll_ctl");
		close(epoll_fd);
		return NULL;
	}
	while (1) {
		event_num = epoll_wait(epoll_fd, events, EPOLL_SIZE, 0);
		if (event_num == -1) {
			perror("epoll_wait\n");
			continue;
		}
		for (int i = 0; i < event_num; i++) {

			/* listening socket */
			if (events[i].data.fd == listen_fd) {
				/* check epoll size is full */
				if (conn_cnt + 1 > EPOLL_SIZE) {
					fprintf(stderr, "polling connection is full, cannot accept\n");
					continue;
				}

				/* accept client */
				do {
					client_fd = accept(listen_fd, (struct sockaddr *)&tls_client_addr, &len);
				} while ((client_fd == -1) && (errno == EINTR));
				if (client_fd == -1) {
					perror("accept");
					exit(EXIT_FAILURE);
				};
				
				/* initialize ssl info */
				ssl_map[client_fd].worker_id = worker_id;
				ssl_map[client_fd].state = SSL_UNUSED;
				ssl_map[client_fd].offset = 0;
				
				/* set non-block */
				if (fcntl(client_fd, F_SETFL, O_NONBLOCK) == -1) {
					perror("fcntl");
					break;
				}

				/* add TCP accepted socket fd into epoll target */
				client_ev.events = EPOLLIN;
				client_ev.data.fd = client_fd;
				if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_ev) == -1) {
					perror("epoll_ctl");
					break;
				}
				conn_cnt++;
			}
			/* TCP accepted socket fd */
			else if (events[i].events & EPOLLIN) {
				/* thread safe check */
				assert(ssl_map[events[i].data.fd].worker_id == worker_id);

				/* start SSL handshake */
				if (ssl_map[events[i].data.fd].state == SSL_UNUSED) {
					/* get new SSL state with context */
					SSL *ssl = SSL_new(ctx);
					if (!ssl) {
						fprintf(stderr, "Error: ssl state create failed\n");
						exit(EXIT_FAILURE);
					}
					/* set connection socket to SSL state */
					if (SSL_set_fd(ssl, events[i].data.fd) == 0)
						perror("SSL_set_fd");
					/* SSL accept */
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
					int ret = DeliverKey(&ssl_map[events[i].data.fd]);
					if (ret == DELIVERY_SHUTDOWN) {
						SSL *ssl = ssl_map[events[i].data.fd].ssl;
						close(SSL_get_fd(ssl));
						SSL_shutdown(ssl);
						SSL_free(ssl); /* release SSL state */
						ssl_map[events[i].data.fd].state = SSL_UNUSED;
						/* counts finished connections */
						g_conn_cnt[worker_id]++;
						g_total_conn_cnt[worker_id]++;
					}
				}
			}
		}
	}
	printf("close!\n");
	close(epoll_fd);
	close(listen_fd);          /* close server socket */
	SSL_CTX_free(ctx);         /* release context */

	return NULL;
}
/*-----------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
	pthread_t p_thread[MAX_CPU];
	pthread_attr_t attr[MAX_CPU];
	int tid[MAX_CPU];
	cpu_set_t *cpusetp[MAX_CPU];
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
			else if (thread_num > MAX_CPU) {
				fprintf(stdout, "Usage: thread_num should be less than %d\n", MAX_CPU);
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
	if (setrlimit(RLIMIT_NOFILE, &rlp) == -1) {
		perror("setrlimit");
		exit(EXIT_FAILURE);
	}
	if (getrlimit(RLIMIT_NOFILE, &rlp_copy) == -1) {
		perror("getrlimit");
		exit(EXIT_FAILURE);
	}
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
	
	/* common low layer socketaddr */
	g_server_addr = (struct sockaddr_ll) {
		.sll_family = 0,
		.sll_protocol = ETH_P_IP,
		.sll_ifindex = if_nametoindex(INTERFACE),
		.sll_hatype = 0,
		.sll_pkttype = 0,
		.sll_halen = ETH_ALEN,
		.sll_addr = DST_MAC
	};

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
