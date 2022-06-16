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

#define FAIL    -1
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

  printf("test0.2\n");

  if(flag == 0) {
  	  flag = 1;
  	  OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
  	  SSL_load_error_strings();   /* Bring in and register error messages */
  }

  /* printf("test0.4\n"); */
  /* OpenSSL_add_all_algorithms();  /\* Load cryptos, et.al. *\/ */
  /* SSL_load_error_strings();   /\* Bring in and register error messages *\/ */
  method = TLS_client_method();  /* Create new client-method instance */
  ctx = SSL_CTX_new(method);   /* Create new context */
  if ( ctx == NULL )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
  printf("test0.5\n");
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
	char buf[1024];
	int bytes;
	int server;

	/* SSL_library_init(); */
	ctx = InitCTX();

	int cnt;
	char *msg = "Hello???";

	printf("test1\n");			/* debug by duckwoo */

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

			SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
			bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
			buf[bytes] = 0;

			/* printf("Received: \"%s\"\n", buf); */
			SSL_free(ssl);        /* release connection state */
		}
		close(server);         /* close socket */
	}
	
	printf("test2\n");			/* debug by duckwoo */
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
	  printf("test0\n");			/* debug by duckwoo */
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
	  printf("test3\n");			/* debug by duckwoo */
  }

  return 0;
}
