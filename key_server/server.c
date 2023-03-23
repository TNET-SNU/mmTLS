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
#define IP_CSUM 1
#define UDP_CSUM 0

#define TLS_PORT 443
#define MAX_CPU 8
#define MAX_FD_NUM 10000
#define BACK_LOG 128

#define CLIENT_RANDOM_SIZE 32
#define _4TUPLE_SIZE 12
#define RECV_BUF_SIZE 65536 /* 256 * 64 */
#define PAYLOAD_SIZE 256
#define MAX_MSG (RECV_BUF_SIZE/PAYLOAD_SIZE)

#define SEGMENT_SIZE (sizeof(struct udphdr) + PAYLOAD_SIZE)
#define DGRAM_SIZE (sizeof(struct iphdr) + SEGMENT_SIZE)

#define RESET_BY_PEER 104

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
	uint16_t state;
	uint16_t offset;
	uint8_t payload[PAYLOAD_SIZE];
} ssl_map[MAX_CPU][MAX_FD_NUM];

/* raw socket to proxy */
int g_sd;
uint8_t g_src_mac[ETH_ALEN];
uint8_t g_dst_mac[ETH_ALEN] = {0xb8, 0xce, 0xf6, 0xd2, 0xca, 0x46};
struct sockaddr_ll g_server_addr;
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
DeliverKey(struct ssl_info *si, int worker_id) {
	int readbytes, remainder, recv_key_cnt, send_key_cnt, msg_cnt, status;
	int recv_offset = 0, send_offset = 0;
	uint16_t tls_version, cipher_suite, info_size;
	uint8_t payload[RECV_BUF_SIZE], *ptr;

	// ShowCerts(ssl);
	struct mmsghdr msg[MAX_MSG];
	/* [0] for common header, [1] for own payload */
	struct iovec msg_iov[MAX_MSG][2];
#if UDP_CSUM
	struct pseudo_header {
		uint32_t src;
		uint32_t dst;
		uint8_t padding;
		uint8_t proto;
		uint16_t udp_len;
	} psh;
#endif
	/* raw datagram header (we use udp w/ tos 0xff for key delivery) */
	struct ether_frame {
		struct ether_header ethh;
		struct iphdr iph;
		struct udphdr udph;
	} __attribute__ ((__packed__)) hdr = 
	{
		{
			.ether_type = htons(ETH_P_IP)
		},
		{
			.ihl = 0x5,
			.version = 0x4,
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
	memcpy(hdr.ethh.ether_dhost, g_dst_mac, ETH_ALEN);
	memcpy(hdr.ethh.ether_shost, g_src_mac, ETH_ALEN);
	
	/* fill payload */
	if (si->offset) {
		printf("[Info] Incomplete key block loaded: %d\n", si->offset);
		recv_offset = si->offset;
		memcpy(payload, si->payload, recv_offset);
		si->offset = 0;
	}
	if ((readbytes = SSL_read(si->ssl, payload + recv_offset, RECV_BUF_SIZE - recv_offset)) == 0) {
		printf("[Info] Graceful shutdown\n");
		return DELIVERY_SHUTDOWN;
	}
	if (readbytes < 0) {
		status = get_sslstatus(si->ssl, readbytes);
		if (status == SSLSTATUS_FAIL) {
			if (errno == RESET_BY_PEER) {
				printf("[Warning] Forced shutdown\n");
				return DELIVERY_SHUTDOWN;
			}
			else if (errno == EAGAIN) {
				printf("[Info] Nothing to read\n");
				return DELIVERY_INCOMPLETED;
			}
			else {
				printf("[Error] SSL_read failed\n");
				exit(EXIT_FAILURE);
			}
		}
		else if (status == SSLSTATUS_WANT_IO) {
			printf("[Info] Nothing to read\n");
			return DELIVERY_INCOMPLETED;
		}
	}
	recv_offset += readbytes;
	recv_key_cnt = recv_offset / PAYLOAD_SIZE;
	remainder = recv_offset % PAYLOAD_SIZE;
	printf("recv_offset: %d, recv_key_cnt: %d, remainder: %d\n", recv_offset, recv_key_cnt, remainder);

	/* incomplete key block, save payload and offset to ssl_info map */
	if (remainder) {
		printf("[Info] Incomplete key block saved\n");
		memcpy(si->payload, payload + recv_offset - remainder, remainder);
		si->offset = remainder;
		recv_offset -= remainder;
	}

	for (msg_cnt = 0; msg_cnt < recv_key_cnt; msg_cnt++) {
		/* parse recv packet */
		ptr = payload + send_offset + CLIENT_RANDOM_SIZE;
		tls_version = be16toh(*(uint16_t *)ptr);
		ptr += sizeof(uint16_t);
		cipher_suite = be16toh(*(uint16_t *)ptr);
		ptr += sizeof(uint16_t);
		info_size = be16toh(*(uint16_t *)ptr);
		ptr += sizeof(uint16_t);
		// printf("tls_version: %d, cipher_suite: %d, info_size: %d\n", tls_version, cipher_suite, info_size);
		(void)tls_version;
		(void)cipher_suite;
		/* fill headers (they are already network byte order) */
		ptr += info_size * 2;
		hdr.iph.saddr = *(uint32_t *)ptr;
		ptr += sizeof(uint32_t);
		hdr.iph.daddr = *(uint32_t *)ptr;
		ptr += sizeof(uint32_t);
		hdr.udph.source = *(uint16_t *)ptr;
		ptr += sizeof(uint16_t);
		hdr.udph.dest = *(uint16_t *)ptr;
#if IP_CSUM
		hdr.iph.check = ~WrapAroundAdd((uint16_t *)&hdr.iph, hdr.iph.ihl << 2);
#endif
#if UDP_CSUM
		/* 12B pseudo header for udp csum */
		psh = (struct pseudo_header) {
			.src = hdr.iph.saddr,
			.dst = hdr.iph.daddr,
			.padding = 0,
			.proto = IPPROTO_UDP,
			.udp_len = htons(SEGMENT_SIZE),
		};
		hdr.udph.check = WrapAroundAdd((uint16_t *)&psh, sizeof(psh));
		hdr.udph.check = WrapAroundAdd((uint16_t *)&hdr.udph, sizeof(hdr.udph));
		uint32_t temp = WrapAroundAdd((uint16_t *)(payload + send_offset), PAYLOAD_SIZE);
		temp += hdr.udph.check;
		hdr.udph.check = ~((temp & 0xffff) + (temp >> 16));
#endif
		msg_iov[msg_cnt][0] = (struct iovec) {
			.iov_base = &hdr,
			.iov_len = sizeof(hdr)
		};
		msg_iov[msg_cnt][1] = (struct iovec) {
			.iov_base = payload + send_offset,
			.iov_len = PAYLOAD_SIZE
		};
		msg[msg_cnt].msg_hdr = (struct msghdr) {
			.msg_name = &g_server_addr,
			.msg_namelen = sizeof(g_server_addr),
			.msg_iov = msg_iov[msg_cnt],
			.msg_iovlen = 2
		};
		send_offset += PAYLOAD_SIZE;
	}
	assert(msg_cnt == recv_key_cnt);
	assert(send_offset == recv_offset);

	do {
		send_key_cnt = sendmmsg(g_sd, msg, msg_cnt, 0);
	} while ((send_key_cnt == -1) && ((errno == EAGAIN) || (errno == EINTR)));
	if (send_key_cnt == -1) {
		fprintf(stderr, "[Error] sendmsg failed\n");
		exit(EXIT_FAILURE);
	}
	printf("sent key: %d\n", send_key_cnt);

#if VERBOSE
	printf("[core %d] %d bytes read, %d bytes sent\n"
			"[client] ip: %u, port: %u\n"
			"[server] ip: %u, port: %u\n",
			sched_getcpu(), readbytes, sendbytes, 
			ntohl(frame.iph.saddr), ntohs(frame.udph.source),
			ntohl(frame.iph.daddr), ntohs(frame.udph.dest));
#endif
	/* counts key sent */
	g_key_cnt[worker_id] += send_key_cnt;
	g_total_key_cnt[worker_id] += send_key_cnt;

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
				ssl_map[worker_id][client_fd].state = SSL_UNUSED;
				
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

				/* start SSL handshake */
				if (ssl_map[worker_id][events[i].data.fd].state == SSL_UNUSED) {
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
						ssl_map[worker_id][events[i].data.fd].state = SSL_UNUSED;
						continue;
					}

					/* add new ssl_info into ssl_map */
					ssl_map[worker_id][events[i].data.fd] = (struct ssl_info) {
						ssl,
						SSL_ACCEPT_INCOMPLETED,
						0,
						{0,}
					};
				}
				/* continue SSL handshake */
				else if (ssl_map[worker_id][events[i].data.fd].state == SSL_ACCEPT_INCOMPLETED) {
					static int accept_ret;
					SSL *ssl = ssl_map[worker_id][events[i].data.fd].ssl;
					if ((accept_ret = AcceptSSL(ssl)) < 0) {
						fprintf(stderr, "Error: can't SSL_accept\n");
						close(events[i].data.fd);
						SSL_free(ssl);
						ssl_map[worker_id][events[i].data.fd].state = SSL_UNUSED;
						continue;
					}
					/* initialize offset */
					if (accept_ret == SSL_ACCEPT_COMPLETED)
						ssl_map[worker_id][events[i].data.fd].offset = 0;
					ssl_map[worker_id][events[i].data.fd].state = accept_ret;
				}
				/* receive encrypted data
				 * reply and close the connection if exit command */
				else if (ssl_map[worker_id][events[i].data.fd].state == SSL_ACCEPT_COMPLETED) {
					int ret = DeliverKey(&ssl_map[worker_id][events[i].data.fd], worker_id);
					if (ret == DELIVERY_SHUTDOWN) {
						SSL *ssl = ssl_map[worker_id][events[i].data.fd].ssl;
						close(SSL_get_fd(ssl));
						SSL_shutdown(ssl);
						SSL_free(ssl); /* release SSL state */
						ssl_map[worker_id][events[i].data.fd].state = SSL_UNUSED;
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
	struct ifreq s = {0,};

	if (getuid()) {
		printf("This program must be run as root/sudo user!\n");
		exit(EXIT_SUCCESS);
	}

	/* parse options */
	while ((c = getopt(argc, argv, "c:i:")) != -1) {
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
		else if (c == 'i')
			memcpy(s.ifr_name, optarg, strlen(optarg));
		else
			Usage();
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

	/* get src MAC */
	if (!ioctl(g_sd, SIOCGIFHWADDR, &s)) {
		memcpy(g_src_mac, s.ifr_addr.sa_data, ETH_ALEN);
		// memcpy(g_dst_mac, g_src_mac, ETH_ALEN);
		// g_dst_mac[ETH_ALEN - 1] -= 4;
		printf("src_mac: %02x %02x %02x %02x %02x %02x\n"
			"dst_mac: %02x %02x %02x %02x %02x %02x\n",
			g_src_mac[0], g_src_mac[1], g_src_mac[2],
			g_src_mac[3], g_src_mac[4], g_src_mac[5],
			g_dst_mac[0], g_dst_mac[1], g_dst_mac[2],
			g_dst_mac[3], g_dst_mac[4], g_dst_mac[5]);
	}
	else {
		fprintf(stderr, "Error: ioctl() failed\n");
		exit(EXIT_FAILURE);
	}
	
	/* common low layer socketaddr */
	g_server_addr = (struct sockaddr_ll) {
		.sll_family = 0,
		.sll_protocol = ETH_P_IP,
		.sll_ifindex = if_nametoindex(s.ifr_name),
		.sll_hatype = 0,
		.sll_pkttype = 0,
		.sll_halen = ETH_ALEN
	};
	memcpy(g_server_addr.sll_addr, g_dst_mac, ETH_ALEN);

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
