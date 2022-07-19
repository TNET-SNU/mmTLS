//SSL-KEY.c
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/inotify.h>
#include <resolv.h>
#include <netdb.h>
#include <endian.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include "include/option.h"
#include "include/client.h"

/*-----UDP Implementation-----*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PROXY_IP "143.248.129.126"
#define KEY_PORT 8888
/*----------------------------*/

#define MAX_DATA_LEN 	   512
#define AES256_KEY_LEN     32
#define CLIENT_RANDOM_LEN  64
#define TLS_1_3_IV_LEN     12
#define TRAFFIC_SECRET_LEN 48
#define EVENT_SIZE		   sizeof(struct inotify_event)
#define BUF_SIZE		   4096

static int ino_fd, ino_wd;		// inotify file descriptor

typedef struct __attribute__((__packed__)) {
	uint16_t length;
	uint8_t label_ctx[256];
} HkdfLabel;

typedef struct __attribute__((__packed__)){
	char src_ip[MAX_ADDR_LEN];
	int src_port;
	char dst_ip[MAX_ADDR_LEN];
	int dst_port;
	uint8_t client_write_key[AES256_KEY_LEN];
	uint8_t client_write_iv[TLS_1_3_IV_LEN];
	uint8_t server_write_key[AES256_KEY_LEN];
	uint8_t server_write_iv[TLS_1_3_IV_LEN];
	uint8_t client_random[CLIENT_RANDOM_LEN];
	uint8_t flag;
} session_info;

static int g_max_session_num;
static session_info **g_session;		// session array
static int g_session_num;				// # of connected sessions
static char g_path[1024];				// path for "key_log.txt"

/*-----------------------------------------------------------------------------*/
void
Usage(char *argv[])
{
	printf("Usage: %s -p [path] -s [max session number]\n", argv[0]);
}
/*-----------------------------------------------------------------------------*/
void 
sig_handler(int sig)
{	
	int i;

	printf("\n");
	if (inotify_rm_watch(ino_fd, ino_wd) < 0) {
		ERROR_PRINT("Error: inotify_rm_watch()\n");
		exit(0);
	}
	
	for (i = 0; i < g_session_num; i++) {
		free(g_session[i]);
	}
	close(ino_fd);

	exit(0);
}
/*-----------------------------------------------------------------------------*/
void 
reverse(char s[])
{
	int i, j;
	char c;

	for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}
/*-----------------------------------------------------------------------------*/
void 
itoa(int n, char s[])
	{
	int i = 0, sign;

	if ((sign = n) < 0)
		n = -n; 

	do {
		s[i++] = n % 10 + '0';
	} while ((n /= 10) > 0);

	if (sign < 0)
		s[i++] = '-';
	s[i] = '\0';

	reverse(s);
}
/*-----------------------------------------------------------------------------*/
void 
session_info_new(const char *src_ip, int src_port, 
				 const char *dst_ip, int dst_port,
				 const uint8_t *random)
{
	if (g_session_num == g_max_session_num) {
		ERROR_PRINT("Error: session number exceeds max session number\n");
		exit(0);
	}

	session_info *s_info = g_session[g_session_num];

	memcpy(s_info->src_ip, src_ip, MAX_ADDR_LEN);
	s_info->src_port = src_port;
	memcpy(s_info->dst_ip, dst_ip, MAX_ADDR_LEN);
	s_info->dst_port = dst_port;

	s_info->flag = 0;
	memcpy(s_info->client_random, random, CLIENT_RANDOM_LEN);
	g_session_num++;
}
/*-----------------------------------------------------------------------------*/
int 
find_session(const char *random)
{
	int i;
	
	for (i = 0; i < g_session_num; i++) {
		if (strncmp((char*)g_session[i]->client_random, random, CLIENT_RANDOM_LEN) == 0) {
			if (g_session[i]->flag == 0xf) {
				ERROR_PRINT("Error: session match error\n");
				exit(0);
			}
			return i;
		}
	}

	return - 1;
}
/*-----------------------------------------------------------------------------*/
static void 
read_hex(const char *hex, uint8_t *out, size_t outmax, size_t *outlen)
{
    size_t i;
	
    *outlen = 0;
    if (strlen(hex) > 2*outmax) {
		ERROR_PRINT("{%s} error, hex length exceeds outmax (%lu > %lu*2)\n",
				__FUNCTION__, strlen(hex), outmax*2);
		exit(1);
	}
	
    for (i = 0; hex[i] && hex[i+1]; i += 2) {
        unsigned int value = 0;

        if (!sscanf(hex + i, "%02x", &value)) {
			ERROR_PRINT("[%s] sscanf fail\n", __FUNCTION__);
			exit(1);
		}
        out[(*outlen)++] = value;
    }
}
/*-----------------------------------------------------------------------------*/
static unsigned char 
*HKDF_Expand(const EVP_MD *evp_md,
             const unsigned char *prk, size_t prk_len,
             HkdfLabel *label, size_t label_len,
             unsigned char *okm, size_t okm_len)
{
    HMAC_CTX *hmac;
    unsigned char *ret = NULL;
    unsigned int i;
    unsigned char prev[EVP_MAX_MD_SIZE] = {0};

    size_t done_len = 0, dig_len = EVP_MD_size(evp_md);
	
    size_t n = okm_len / dig_len;

    if (okm_len % dig_len)
        n++;

    if (n > 255 || okm == NULL)
        return NULL;

    if ((hmac = HMAC_CTX_new()) == NULL)
        return NULL;

    if (!HMAC_Init_ex(hmac, prk, prk_len, evp_md, NULL))
        goto err;
	
	unsigned char data[MAX_DATA_LEN];
	size_t len = 0;

	*(uint16_t*)(data+len) = htobe16(label->length);
	len += 2;
	*(data+len) = label_len;
	len += 1;
	memcpy(data + len, (const char*)(label->label_ctx), label_len);
	len += label_len;
	*(data+len) = '\0';
	len += 1;
	
    for (i = 1; i <= n; i++) {
        size_t copy_len;
		const unsigned char ctr = i;

        if (i > 1) {	
			ERROR_PRINT("[%s] Not implemented now\n", __FUNCTION__);
			goto err;
			
            if (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL))
                goto err;

			if (!HMAC_Update(hmac, prev, dig_len))
				goto err;
			
			data[len-1] = ctr;
        }
		else {
			data[len++] = ctr;
		}
		
        if (!HMAC_Update(hmac, (const unsigned char*)data, len))
            goto err;
		
        if (!HMAC_Final(hmac, prev, NULL))
            goto err;
		
        copy_len = (done_len + dig_len > okm_len) ?
                       okm_len - done_len :
                       dig_len;

        memcpy(okm + done_len, prev, copy_len);

        done_len += copy_len;
    }
    ret = okm;

 err:
    OPENSSL_cleanse(prev, sizeof(prev));
    HMAC_CTX_free(hmac);

    return ret;
}
/*-----------------------------------------------------------------------------*/
void
get_write_key_1_3(uint8_t *secret, uint8_t *key_out)
{
	HkdfLabel hkdf_label;
	const EVP_MD *evp_md;

	/* assume hash: SHA384 */
	evp_md = EVP_get_digestbyname("SHA384");

	hkdf_label.length = AES256_KEY_LEN;
	memcpy(hkdf_label.label_ctx, "tls13 key", strlen("tls13 key"));

	HKDF_Expand(evp_md, (const uint8_t*)secret, TRAFFIC_SECRET_LEN,
			     &hkdf_label, strlen("tls13 key"),
				key_out, AES256_KEY_LEN);

	return;
}
/*-----------------------------------------------------------------------------*/
void
get_write_iv_1_3(uint8_t *secret, uint8_t *iv_out)
{
	HkdfLabel hkdf_label;
	const EVP_MD *evp_md;
	
	/* assume hash: SHA384 */
	evp_md = EVP_get_digestbyname("SHA384");

	hkdf_label.length = TLS_1_3_IV_LEN;
	memcpy(hkdf_label.label_ctx, "tls13 iv", strlen("tls13 iv"));

	HKDF_Expand(evp_md, (const uint8_t*)secret, TRAFFIC_SECRET_LEN,
			    &hkdf_label, strlen("tls13 iv"),
				iv_out, TLS_1_3_IV_LEN);
				
	return;
}
/*-----------------------------------------------------------------------------*/
void 
UDP_send(session_info *s_info)
{
    int sd;
	struct sockaddr_in servaddr;
	int addrlen = sizeof(servaddr);
	char src_port[MAX_PORT_LEN+1];
	char dst_port[MAX_PORT_LEN+1];

    if ((sd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket fail");
        exit(0);
    }

    memset(&servaddr, 0, addrlen);
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(PROXY_IP);
    servaddr.sin_port = htons(KEY_PORT);

	/* client ip */
	if ((sendto(sd, (const char*)s_info->src_ip, MAX_ADDR_LEN, 0, (struct sockaddr *)&servaddr, addrlen)) < 0) {
      perror("sendto fail");
        exit(0);
    }

	/* client port */
	itoa(s_info->src_port, src_port);
	src_port[MAX_PORT_LEN] = '\0';
	if ((sendto(sd, (const char*)src_port, MAX_PORT_LEN, 0, (struct sockaddr *)&servaddr, addrlen)) < 0) {
        ERROR_PRINT("Error: sendto fail");
        exit(0);
    }

	/* server ip */
	if ((sendto(sd, (const char*)s_info->dst_ip, MAX_ADDR_LEN, 0, (struct sockaddr *)&servaddr, addrlen)) < 0) {
        ERROR_PRINT("Error: sendto fail");
        exit(0);
    }

	/* server port */
	itoa(s_info->dst_port, dst_port);
	src_port[MAX_PORT_LEN] = '\0';
	if ((sendto(sd, (const char*)dst_port, MAX_PORT_LEN, 0, (struct sockaddr *)&servaddr, addrlen)) < 0) {
        ERROR_PRINT("Error: sendto fail");
        exit(0);
    }

	/* client write key & IV */
    if ((sendto(sd, (const uint8_t*)s_info->client_write_key, AES256_KEY_LEN, 0, (struct sockaddr *)&servaddr, addrlen)) < 0) {
        ERROR_PRINT("Error: sendto fail");
        exit(0);
    }
	if ((sendto(sd, (const uint8_t*)s_info->client_write_iv, TLS_1_3_IV_LEN, 0, (struct sockaddr *)&servaddr, addrlen)) < 0) {
        ERROR_PRINT("Error: sendto fail");
        exit(0);
    }

	/* server write key & IV */
    if ((sendto(sd, (const uint8_t*)s_info->server_write_key, AES256_KEY_LEN, 0, (struct sockaddr *)&servaddr, addrlen)) < 0) {
        ERROR_PRINT("Error: sendto fail");
        exit(0);
    }
	if ((sendto(sd, (const uint8_t*)s_info->server_write_iv, TLS_1_3_IV_LEN, 0, (struct sockaddr *)&servaddr, addrlen)) < 0) {
        ERROR_PRINT("Error: sendto fail");
        exit(0);
    }
    
    close(sd);

    return;
}
/*-----------------------------------------------------------------------------*/
void 
ssl_keylog(const char *line)
{
	uint8_t random[CLIENT_RANDOM_LEN];
	char traffic_secret[1024];
	uint8_t secret[1024];
	char src_ip[MAX_ADDR_LEN];
	char dst_ip[MAX_ADDR_LEN];
	int src_port;
	int dst_port;

	char line_cpy[1024];
	size_t len;
	int i;

	memcpy(line_cpy, line, strlen(line)+1);

	if (sscanf(line_cpy, "CLIENT_TRAFFIC_SECRET_0 %s %s %s %s %d %d", random, traffic_secret, src_ip, dst_ip, &src_port, &dst_port)) {
		int num = find_session((const char*)random);
		if (num < 0) {
			session_info_new(src_ip, src_port, dst_ip, dst_port, random);
			num = g_session_num-1;
		}
		memcpy(secret, traffic_secret, TRAFFIC_SECRET_LEN);
		read_hex((const char*)traffic_secret, secret, 1024, &len);

		session_info* s_info = g_session[num];

		get_write_key_1_3(secret, s_info->client_write_key);
		get_write_iv_1_3(secret, s_info->client_write_iv);

		s_info->flag |= 0x3;

		if (s_info->flag == 0xf) {
			UDP_send(s_info);
		}

		KEY_M_PRINT("client write key[%d]:\n", num);
		for (i = 0; i < 32; i++) {
			KEY_M_PRINT("%02X", s_info->client_write_key[i]);
		}
		KEY_M_PRINT("\n");
		KEY_M_PRINT("client write iv[%d]:\n", num);
		for (i = 0; i < 12; i++) {
			KEY_M_PRINT("%02X", s_info->client_write_iv[i]);
		}
		KEY_M_PRINT("\n");

#if VERBOSE_EVAL
		FILE *fp1;	
		struct timespec t1;
		char line[128];
		const char new_line = '\n';

		if (session_num == 1) {
			fp1 = fopen("write.txt", "a+w");
		}
		
		clock_gettime(CLOCK_MONOTONIC, &t1);
			
		sprintf(line, "%lf", (double)t1.tv_nsec/1000 );
		if (fwrite(line, sizeof(char), strlen(line), fp1) == -1) {
			ERROR_PRINT("Error: write()\n");
			exit(0);
		}
		
		if (fwrite(&new_line, sizeof(char), 1, fp1) == -1) {
			ERROR_PRINT("Error: write()\n");
			exit(0);
		}
#endif
	}
	else if (sscanf(line_cpy, "SERVER_TRAFFIC_SECRET_0 %s %s %s %s %d %d", random, traffic_secret, src_ip, dst_ip, &src_port, &dst_port)) {
		int num = find_session((const char*)random);
		if (num < 0) {
			session_info_new(src_ip, src_port, dst_ip, dst_port, random);
			num = g_session_num-1;
		}
		memcpy(secret, traffic_secret, TRAFFIC_SECRET_LEN);
		read_hex((const char*)traffic_secret, secret, 1024, &len);

		session_info* s_info = g_session[num];

		get_write_key_1_3(secret, s_info->server_write_key);
		get_write_iv_1_3(secret, s_info->server_write_iv);

		s_info->flag |= 0xc;

		if (s_info->flag == 0xf) {
			UDP_send(s_info);
		}

		KEY_M_PRINT("server write key[%d]:\n", num);
		for (i = 0; i < 32; i++) {
			KEY_M_PRINT("%02X", s_info->server_write_key[i]);
		}
		KEY_M_PRINT("\n");
		KEY_M_PRINT("server write iv[%d]:\n",num);
		for (i = 0; i < 12; i++) {
			KEY_M_PRINT("%02X", s_info->server_write_iv[i]);
		}
		KEY_M_PRINT("\n");
	}
}
/*-----------------------------------------------------------------------------*/
void
read_log(FILE *fp)
{
	char buf[MAX_DATA_LEN];

	while (fgets(buf, MAX_DATA_LEN, fp) != NULL) {
		ssl_keylog((const char*)buf);
	}
}
/*-----------------------------------------------------------------------------*/
FILE*
open_log()
{
	FILE *fp;

	if (0 > (fp = fopen((const char*)g_path, "r"))) {
		ERROR_PRINT("\"key_log.txt\" file isn't created...continue...\n");
		return NULL;
	}
	else {
		read_log(fp);
		return fp;
	}
}
/*-----------------------------------------------------------------------------*/
void 
global_init()
{
	int i;

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		ERROR_PRINT("Error: could not use signal\n");
		abort();
	}
	printf("[Ctrl+C to quit]\n");

	g_session = (session_info **)calloc(g_max_session_num, sizeof(session_info*));
	if (g_session == NULL) {
		ERROR_PRINT("Error: calloc() failed\n");
		exit(1);
	}
	g_session_num = 0;
	
	for (i = 0; i < g_max_session_num; i++) {
		g_session[i] = (session_info*)calloc(1, sizeof(session_info));
		if (g_session[i] == NULL) {
			ERROR_PRINT("Error: calloc() failed\n");
			exit(1);
		}
	}
}
/*-----------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
	char c;
	
	if (argc < 2) {
		Usage(argv);
		exit(0);
	}

	while ((c = getopt(argc, argv, "p:s:")) != -1) {
		if (c == 'p') { 
			strcpy(g_path, optarg);
		}
		else if (c == 's') {
			g_max_session_num = atoi(optarg);
			if (g_max_session_num < 1) {
				ERROR_PRINT("Error: max session number should be more than 1\n");
				exit(0);
			}
		}
		else {   
			Usage(argv);
			exit(0);
		}
  	}

	global_init();

	if ((ino_fd = inotify_init()) < 0) {
		ERROR_PRINT("Error: inotify_init()\n");
		exit(0);
	}

	if ((ino_wd = inotify_add_watch(ino_fd, (const char*)g_path, IN_MODIFY|IN_CREATE)) < 0) {
		ERROR_PRINT("Error: inotify_add_watch()\n");
		exit(0);
	}

	strcat(g_path, "/key_log.txt");	// file name fixed

	FILE *fp = open_log();

	while (1) {
		int len;
		char buf[BUF_SIZE];
		const struct inotify_event *event;

		len = read(ino_fd, buf, BUF_SIZE);
		if (len < 0) {
			ERROR_PRINT("Error: read()\n");
			exit(0);
		}
		
		char *ptr;

		for (ptr = buf; ptr < buf + len; ptr += EVENT_SIZE + event->len) {
			event = (const struct inotify_event*)ptr;

			if (event->len) {
				if (event->mask & IN_CREATE) {
					fp = open_log();
					if (fp == NULL) {
						ERROR_PRINT("Error: fopen()\n");
						exit(0);
					}
				}
				else if (event->mask & IN_MODIFY) {
					read_log(fp);
				}
				else {
					ERROR_PRINT("Error: wrong inotify event\n");
				}
			}
		}
	}

	inotify_rm_watch(ino_fd, ino_wd);
	close(ino_fd);

    return 0;
}