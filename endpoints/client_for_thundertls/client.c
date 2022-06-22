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
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "include/client.h"

/* It only handles TLS 1.2 or 1.3 */
#define USE_TLS_1_2 0

#define FAIL -1
#define MAX_ADDR_LEN 20

char addr[MAX_ADDR_LEN + 1];
int port;
int thread_num;
int test_cnt;
/*-----------------------------------------------------------------------------*/
void
Usage()
{
	printf("Usage: ./ssl-client -a [ip address] -p [portnum]\n");
	exit(0);
}
/*-----------------------------------------------------------------------------*/
#if !USE_TLS_1_2
void
ssl_ctx_new_keylog (const SSL *ssl, const char *line)
{
	fprintf(stderr, "[%s] Get keylog of SSL %p!\n%s\n",
			__FUNCTION__, ssl, line);
	
}
/*-----------------------------------------------------------------------------*/
int
ssl_sess_new_cb (SSL *ssl, SSL_SESSION *ssl_sess)
{
	/* uint8_t master_secret[128]; */
	/* size_t olen; */
	/* int i; */

	/* memset(master_secret, 0, sizeof(master_secret)); */

	/* fprintf(stderr, "[%s] ssl: %p, ssl_sess: %p\n", */
	/* 		__FUNCTION__, ssl, ssl_sess); */
	
	/* fprintf(stderr, "is ssl_sess %p resumable? %u\n", */
	/* 		ssl_sess, SSL_SESSION_is_resumable(ssl_sess)); */
	/* olen = SSL_SESSION_get_master_key(ssl_sess, */
	/* 								  master_secret, sizeof(master_secret)); */
	/* fprintf(stderr, "master_secret of SSL_SESSION %p (%lu B):\n", ssl_sess, olen); */
	/* for (i = 0; i < olen; i++) { */
	/* 	fprintf(stderr, "%02X", master_secret[i]); */
	/* } */
	/* fprintf(stderr, "\n"); */
	/* for (i = 0; i < 128; i++) { */
	/* 	fprintf(stderr, "%02X%c", master_secret[i], ((i&0xf) == 0xf) ? '\n' : ' '); */
	/* } */
	/* fprintf(stderr, "\n"); */
	return 0;
}
/*-----------------------------------------------------------------------------*/
void
ssl_sess_remove_cb (SSL_CTX *ctx, SSL_SESSION *ssl_sess)
{
	/* fprintf(stderr, "[%s] ctx: %p, ssl_sess: %p\n", */
	/* 		__FUNCTION__, ctx, ssl_sess); */
}
#endif	/* !USE_TLS_1_2 */
/*-----------------------------------------------------------------------------*/
int
OpenConnection(const char *hostname, int port)
{
  int sd;
  static struct hostent *host;
  static struct sockaddr_in addr;
  int optval = 1;
  static int flag = 0;

  if(flag == 0) {
	  flag = 1;
	  if ( (host = gethostbyname(hostname)) == NULL ) {
		  perror(hostname);
		  abort();
	  }
	  bzero(&addr, sizeof(addr));
	  addr.sin_family = AF_INET;
	  addr.sin_port = htons(port /* + rand() % thread_num */);
	  addr.sin_addr.s_addr = *(long*)(host->h_addr);
  }

  sd = socket(PF_INET, SOCK_STREAM, 0);
  setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

  if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
      close(sd);
      perror(hostname);
      abort();
  }
  return sd;
}
/*-----------------------------------------------------------------------------*/
SSL_CTX*
InitCTX(void)
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  static int flag = 0;

  if(flag == 0) {
  	  flag = 1;
  	  OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
  	  SSL_load_error_strings();   /* Bring in and register error messages */
  }

  /* OpenSSL_add_all_algorithms();  /\* Load cryptos, et.al. *\/ */
  /* SSL_load_error_strings();   /\* Bring in and register error messages *\/ */
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
	fprintf(stderr, "set session cache mode %lu\n", ret);
#if !USE_TLS_1_2
	SSL_CTX_sess_set_new_cb(ctx, ssl_sess_new_cb);
	/* SSL_CTX_sess_set_get_cb(ctx, ssl_sess_get_cb); */ /*for server*/
	SSL_CTX_sess_set_remove_cb(ctx, ssl_sess_remove_cb);
#endif	/* USE_TLS_1_2 */
	
	for(cnt = 0; cnt < test_cnt; cnt++) {
		server = OpenConnection(addr, port);

		ssl = SSL_new(ctx);      /* create new SSL connection state */
		SSL_set_fd(ssl, server);    /* attach the socket descriptor */

		/* printf("ssl_connect\n"); */
		if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
			ERR_print_errors_fp(stderr);
		else {
			/* printf("Connected with %s encryption\n", SSL_get_cipher(ssl)); */
			ShowCerts(ssl);        /* get any certs */

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
			fprintf(stderr, "client_random of SSL %p (%lu B):\n", ssl, olen);
			for (i = 0; i < olen; i++) {
				fprintf(stderr, "%02X", client_random[i]);
			}
			fprintf(stderr, "\n");

			/* server random */
			olen = SSL_get_server_random(ssl,
									   server_random, sizeof(server_random));
			fprintf(stderr, "server_random of SSL %p (%lu B):\n", ssl, olen);
			for (i = 0; i < olen; i++) {
				fprintf(stderr, "%02X", server_random[i]);
			}
			fprintf(stderr, "\n");

			ssl_sess = SSL_get_session(ssl);
			fprintf(stderr, "is ssl_sess %p resumable? %u\n",
					ssl_sess, SSL_SESSION_is_resumable(ssl_sess));
			olen = SSL_SESSION_get_master_key(ssl_sess,
									  master_secret, sizeof(master_secret));
			fprintf(stderr, "master_secret of SSL_SESSION %p (%lu B):\n", ssl_sess, olen);
			for (i = 0; i < olen; i++) {
				fprintf(stderr, "%02X", master_secret[i]);
			}
			fprintf(stderr, "\n");
#endif	/* USE_TLS_1_2 */
			
			SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
			bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
			buf[bytes] = 0;

			/* printf("Received: \"%s\"\n", buf); */
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
  /* SSL_CTX *ctx; */
  /* int server; */
  /* SSL *ssl; */
  /* char buf[1024]; */
  /* int bytes; */

  pthread_t p_thread[MAX_THREAD_NUM];
  /* pthread_attr_t attr[MAX_THREAD_NUM]; */
  /* int tid[MAX_THREAD_NUM]; */

  int i;
  char c;
  thread_num = 1;
  test_cnt = 1;
  port = 4888;

  /* parse arguments */
  while ((c = getopt(argc, argv, "a:p:t:n:")) != -1) {
	  if (c == 'a') { 
		  if (strlen(optarg) > MAX_ADDR_LEN) {
			  fprintf(stderr, "error: invalid ip address\n");
			  exit(0);
		  }
		  memcpy(addr, optarg, strlen(optarg)); 
		  addr[strlen(optarg)] = '\0';
	  } else if (c == 'p') { 
		  port = atoi(optarg); 
	  } else if (c == 't') { 
		  thread_num = atoi(optarg);
		  if(thread_num < 1) {
			  fprintf(stderr, "Error: thread_num should be more than 0\n");
			  exit(0);
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
  printf("file descriptor limit: %lu : %lu\n", rlp_copy.rlim_cur, rlp_copy.rlim_max);

  SSL_library_init();

  /* OpenSSL_add_all_algorithms();  /\* Load cryptos, et.al. *\/ */
  /* SSL_load_error_strings();   /\* Bring in and register error messages *\/ */
  /* ctx = InitCTX(); */

  for(i = 0; i < thread_num; i++) {
	  if(pthread_create(&p_thread[i], NULL, worker, NULL) < 0) {
		  fprintf(stderr, "Error: thread create failed\n");
		  exit(0);
	  }
  }

  /* int cnt; */
  /* char *msg = "Hello???"; */
  /* for(cnt = 0; cnt < test_cnt; cnt++) { */
  /*   server = OpenConnection(addr, port); */

  /*   ssl = SSL_new(ctx);      /\* create new SSL connection state *\/ */
  /*   SSL_set_fd(ssl, server);    /\* attach the socket descriptor *\/ */
  /*   if ( SSL_connect(ssl) == FAIL )   /\* perform the connection *\/ */
  /*     ERR_print_errors_fp(stderr); */
  /*   else { */
  /* 		/\* printf("Connected with %s encryption\n", SSL_get_cipher(ssl)); *\/ */
  /* 		ShowCerts(ssl);        /\* get any certs *\/ */
  /* 		SSL_write(ssl, msg, strlen(msg));   /\* encrypt & send message *\/ */
  /* 		bytes = SSL_read(ssl, buf, sizeof(buf)); /\* get reply & decrypt *\/ */
  /* 		buf[bytes] = 0; */
  /* 		/\* printf("Received: \"%s\"\n", buf); *\/ */
  /* 		SSL_free(ssl);        /\* release connection state *\/ */
  /* 	} */
  /*   close(server);         /\* close socket *\/ */
  /* } */

  /* SSL_CTX_free(ctx);        /\* release context *\/ */

  for(i = 0; i < thread_num; i++) {
	  pthread_join(p_thread[i], NULL);
  }

  return 0;
}
