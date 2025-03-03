//SSL-Client.c
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>
#include <endian.h>
#include <fcntl.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include "include/client.h"
#include "include/option.h"

/* It only handles TLS 1.2 or 1.3 */
#define USE_TLS_1_2 0

#define FAIL -1

FILE *fp;

char addr[MAX_ADDR_LEN + 1];
int port;
int thread_num;
int test_cnt;
char src_ip[MAX_ADDR_LEN + 1];
int s_port;
static char g_path[30] = "/home/junghan/";	// path for "key_log.txt"

struct timespec t1, t2, t3;

#if !USE_TLS_1_2
typedef struct __attribute__((__packed__)) {
	uint16_t length;
	uint8_t label_ctx[256];
} HkdfLabel;
#endif
/*-----------------------------------------------------------------------------*/
void
Usage()
{
	printf("Usage: ./ssl-client -a [ip address] -p [portnum] -k [key log path]\n");
	exit(0);
}
/*-----------------------------------------------------------------------------*/
void
ssl_ctx_new_keylog (const SSL *ssl, const char *line)
{
	const char new_line = '\n';

	KEY_M_PRINT("[%s] Get keylog of SSL %p!\n%s\n",
			__FUNCTION__, ssl, line);

	if (fwrite(line, sizeof(char), strlen(line), fp) == -1) {
		ERROR_PRINT("Error: write()\n");
		exit(-1);
	}
	if (fwrite(&new_line, sizeof(char), 1, fp) == -1) {
		ERROR_PRINT("Error: write()\n");
		exit(-1);
	}
	
}
/*-----------------------------------------------------------------------------*/
int
OpenConnection(const char *hostname, int port)
{
	int sd;
	static struct hostent *host;
	static struct sockaddr_in addr;
	int optval = 1;
	static int flag = 0;

	if (flag == 0) {
		flag = 1;
		if ( (host = gethostbyname(hostname)) == NULL ) {
			perror(hostname);
			abort();
		}
		bzero(&addr, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = *(long*)(host->h_addr);
		addr.sin_port = htons(port /* + rand() % thread_num */);
	}

	sd = socket(PF_INET, SOCK_STREAM, 0);
	setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

	if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		close(sd);
		perror(hostname);
		abort();
	}

	struct sockaddr_in client;
	socklen_t clientsz = sizeof(client);

	getsockname(sd, (struct sockaddr*)&client, &clientsz);
	memcpy(src_ip, (const char*)inet_ntoa(client.sin_addr), MAX_ADDR_LEN);
	src_ip[MAX_ADDR_LEN] = '\0';
	s_port = (int)ntohs(client.sin_port);

	return sd;
}
/*-----------------------------------------------------------------------------*/
SSL_CTX*
InitCTX(void)
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  static int flag = 0;

  if (flag == 0) {
  	  flag = 1;
  	  OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
  	  SSL_load_error_strings();   /* Bring in and register error messages */
  }

#if USE_TLS_1_2
  method = TLSv1_2_client_method();  /* note: deprecated. */
#else
  method = TLS_client_method();  /* Create new client-method instance */
#endif
  ctx = SSL_CTX_new(method);   /* Create new context */
  if (ctx == NULL) {
      ERR_print_errors_fp(stderr);
      abort();
  }
  SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
  SSL_CTX_set_keylog_callback(ctx, ssl_ctx_new_keylog);

  return ctx;
}
/*-----------------------------------------------------------------------------*/
void
ShowCerts(SSL* ssl)
{
  X509 *cert;
  /* char *line; */

  cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
  UNUSED(cert);

  /* if ( cert != NULL ) */
  /*   { */
  /*     /\* printf("Server certificates:\n"); *\/ */
  /*     line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0); */
  /*     /\* printf("Subject: %s\n", line); *\/ */
  /*     free(line);       /\* free the malloc'ed string *\/ */
  /*     line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0); */
  /*     /\* printf("Issuer: %s\n", line); *\/ */
  /*     free(line);       /\* free the malloc'ed string *\/ */
  /*     X509_free(cert);     /\* free the malloc'ed certificate copy *\/ */
  /*   } */

  /* else */
    /* printf("Info: No client certificates configured.\n"); */
}
/*-----------------------------------------------------------------------------*/
void *
worker(void *arg)
{
	UNUSED(arg);
	SSL_CTX *ctx;
	SSL *ssl;
#if USE_TLS_1_2
	SSL_SESSION *ssl_sess;
#endif
	char buf[1024];
	int bytes;
	int server;
	
	int cnt;
	uint64_t ret;
	char *msg = "Hello???";

	/* SSL_library_init(); */
	ctx = InitCTX();
	ret = SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
	UNUSED(ret);
	
	for(cnt = 0; cnt < test_cnt; cnt++) {
		server = OpenConnection(addr, port);

		ssl = SSL_new(ctx);      /* create new SSL connection state */
		SSL_set_fd(ssl, server);    /* attach the socket descriptor */
		if ( SSL_connect(ssl) == FAIL ) {   /* perform the connection */
			ERR_print_errors_fp(stderr);
		}
		else {
			ShowCerts(ssl);        /* get any certs */
			fclose(fp);
#if USE_TLS_1_2
			/* extract master secret, and calculate session key block */
			uint8_t client_random[128], server_random[128];
			uint8_t master_secret[128];
			size_t olen;
			int i;
			memset(client_random, 0, sizeof(client_random));
			memset(server_random, 0, sizeof(server_random));
			memset(master_secret, 0, sizeof(master_secret));

			/* client random */
			olen = SSL_get_client_random(ssl,
									   client_random, sizeof(client_random));
			KEY_M_PRINT("client_random of SSL %p (%lu B):\n", ssl, olen);
			for (i = 0; i < olen; i++) {
				KEY_M_PRINT("%02X", client_random[i]);
			}
			KEY_M_PRINT("\n");

			/* server random */
			olen = SSL_get_server_random(ssl,
									   server_random, sizeof(server_random));
			KEY_M_PRINT("server_random of SSL %p (%lu B):\n", ssl, olen);
			for (i = 0; i < olen; i++) {
				KEY_M_PRINT("%02X", server_random[i]);
			}
			KEY_M_PRINT("\n");

			ssl_sess = SSL_get_session(ssl);
			KEY_M_PRINT( "is ssl_sess %p resumable? %u\n",
					ssl_sess, SSL_SESSION_is_resumable(ssl_sess));
			olen = SSL_SESSION_get_master_key(ssl_sess,
									  master_secret, sizeof(master_secret));
			KEY_M_PRINT("master_secret of SSL_SESSION %p (%lu B):\n", ssl_sess, olen);
			for (i = 0; i < olen; i++) {
				KEY_M_PRINT("%02X", master_secret[i]);
			}
			KEY_M_PRINT("\n");
#endif	/* USE_TLS_1_2 */
			SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
			bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
			buf[bytes] = 0;
			// usleep(10000);
			/* release connection state */
			SSL_free(ssl);
		}
		
		close(server);         /* close socket */
	}
	
	SSL_CTX_free(ctx);        /* release context */
	return NULL;
}
/*-----------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
	pthread_t p_thread[MAX_THREAD_NUM];

	int i;
	char c;
	thread_num = 1;
	test_cnt = 1;
	port = 4888;

	/* parse arguments */
	while ((c = getopt(argc, argv, "a:p:k:t:n:")) != -1) {
		if (c == 'a') { 
			if (strlen(optarg) > MAX_ADDR_LEN) {
				ERROR_PRINT("error: invalid ip address\n");
			exit(-1);
			}
			memcpy(addr, optarg, strlen(optarg)); 
			addr[strlen(optarg)] = '\0';
		} else if (c == 'p') { 
			port = atoi(optarg); 
		} else if (c == 'k') { 
			strcpy(g_path, optarg);
		} else if (c == 't') { 
			thread_num = atoi(optarg);
			if (thread_num < 1) {
				ERROR_PRINT("Error: thread_num should be more than 0\n");
				exit(-1);
			}
		} else if (c == 'n') { 
			test_cnt = atoi(optarg); 
		} else {   
			Usage();
		}
	}
	
	/* extend limit of available file descriptor number */
	const struct rlimit rlp = {100000, 100000};
	struct rlimit rlp_copy;
	setrlimit(RLIMIT_NOFILE, &rlp);
	getrlimit(RLIMIT_NOFILE, &rlp_copy);

	SSL_library_init();

	strcat(g_path, "/key_log.txt");	// file name fixed
	if ((fp = fopen((const char*)g_path, "a+w")) < 0) {
		ERROR_PRINT("Error: open() failed");
		exit(-1);
	}

	for(i = 0; i < thread_num; i++) {
		if (pthread_create(&p_thread[i], NULL, worker, NULL) < 0) {
			ERROR_PRINT("Error: thread create failed\n");
			exit(-1);
		}
	}

	for(i = 0; i < thread_num; i++) {
		pthread_join(p_thread[i], NULL);
	}

	// fclose(fp);

	return 0;
}
