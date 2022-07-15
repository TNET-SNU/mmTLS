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

#define MAX_DATA_LEN 	   512
#define AES256_KEY_LEN     32
#define CLIENT_RANDOM_LEN  64
#define TLS_1_3_IV_LEN     12
#define TRAFFIC_SECRET_LEN 48
#define EVENT_SIZE		   sizeof(struct inotify_event)
#define BUF_SIZE		   4096

int ino_fd, ino_wd;
FILE *fp1;

typedef struct __attribute__((__packed__)) {
	uint16_t length;
	uint8_t label_ctx[256];
} HkdfLabel;

typedef struct __attribute__((__packed__)){
	uint8_t client_write_key[AES256_KEY_LEN];
	uint8_t client_write_iv[TLS_1_3_IV_LEN];
	uint8_t server_write_key[AES256_KEY_LEN];
	uint8_t server_write_iv[TLS_1_3_IV_LEN];
	uint8_t *tuple[4];
	uint8_t client_random[CLIENT_RANDOM_LEN];
	uint8_t flag;
} session_info;

int max_session_num;
session_info **session;
int session_num;
char path[1024];

/*-----------------------------------------------------------------------------*/
void
Usage(char *argv[])
{
	printf("Usage: %s -p [path] -s [session number]\n", argv[0]);
}
/*-----------------------------------------------------------------------------*/
void sig_handler(int sig)
{	
	fprintf(stderr, "\n");
	inotify_rm_watch(ino_fd, ino_wd);
	int i;
	for (i = 0; i < session_num; i++) {
		free(session[i]);
	}
	close(ino_fd);
	exit(0);
}
/*-----------------------------------------------------------------------------*/
void session_info_new(const void *src_ip, const void *src_port, 
					  const void *dst_ip, const void *dst_port,
					  const char *random)
{
	session_info *s_info = session[session_num];
	// s_info->tuple[0] = src_ip;
	// s_info->tuple[1] = src_port;
	// s_info->tuple[2] = dst_ip;
	// s_info->tuple[3] = dst_port;
	s_info->flag = 0;
	memcpy((char*)s_info->client_random, random, CLIENT_RANDOM_LEN);
	session_num++;
	if (session_num == max_session_num) {
		exit(0);
	}
}
/*-----------------------------------------------------------------------------*/
int find_session(const char *random)
{
	int i;
	
	for (i = 0; i < session_num; i++) {
		if (strncmp((char*)session[i]->client_random, random, CLIENT_RANDOM_LEN) == 0) {
			if (session[i]->flag == 0xf) {
				ERROR_PRINT("Error: session match error\n");
				exit(0);
			}
			return i;
		}
	}
	session_info_new(NULL, NULL, NULL, NULL, random);
	return session_num-1;
}
/*-----------------------------------------------------------------------------*/
static void read_hex(const char *hex, uint8_t *out, size_t outmax, size_t *outlen)
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
static unsigned char *HKDF_Expand(const EVP_MD *evp_md,
                                  const unsigned char *prk, size_t prk_len,
                                  HkdfLabel *label, size_t label_len,
                                  unsigned char *okm, size_t okm_len)
{
    HMAC_CTX *hmac;
    unsigned char *ret = NULL;

    unsigned int i;

    unsigned char prev[EVP_MAX_MD_SIZE];
	memset(prev, 0, EVP_MAX_MD_SIZE);

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
	
	/* ToDo: handle multiple iterations */

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
get_write_key_1_3 (uint8_t *secret, uint8_t *key_out)
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
get_write_iv_1_3 (uint8_t *secret, uint8_t *iv_out)
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
ssl_keylog (const char *line)
{
	char *tok;
	uint8_t secret[1024];
	char line_cpy[1024];
	size_t len;

	memcpy(line_cpy, line, strlen(line)+1);
	tok = strtok(line_cpy, " ");

	if (strncmp(tok, "CLIENT_TRAFFIC_SECRET_0", strlen("CLIENT_TRAFFIC_SECRET_0")) == 0) {
		tok = strtok(NULL, " ");
		int num = find_session((const char*)tok);

		tok = strtok(NULL, " ");
		memcpy(secret, tok, 48);
		read_hex((const char *)tok, secret, 1024, &len);

		session_info* s_info = session[num];

		get_write_key_1_3(secret, s_info->client_write_key);
		get_write_iv_1_3(secret, s_info->client_write_iv);

		s_info->flag |= 0x3;
		int i;
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
		if (session_num == 1) {
			fp1 = fopen("write.txt", "a+w");
		}
		struct timespec t1;
		clock_gettime(CLOCK_MONOTONIC, &t1);
		
		char line[128];
		sprintf(line, "%lf", (double)t1.tv_nsec/1000 );
		if (fwrite(line, sizeof(char), strlen(line), fp1) == -1) {
			ERROR_PRINT("Error: write()\n");
			exit(0);
		}
		const char new_line = '\n';
		if (fwrite(&new_line, sizeof(char), 1, fp1) == -1) {
			ERROR_PRINT("Error: write()\n");
			exit(0);
		}
#endif

	}
	else if(strncmp(tok, "SERVER_TRAFFIC_SECRET_0", strlen("SERVER_TRAFFIC_SECRET_0")) == 0) {
		tok = strtok(NULL, " ");
		int num = find_session((const char*)tok);

		tok = strtok(NULL, " ");
		memcpy(secret, tok, 48);
		read_hex((const char *)tok, secret, 1024, &len);

		session_info* s_info = session[num];

		get_write_key_1_3(secret, s_info->server_write_key);
		get_write_iv_1_3(secret, s_info->server_write_iv);

		s_info->flag |= 0xc;
		int i;
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
long read_log(long size)
{
	FILE *fp;
	char *buf;
	if (0 > (fp = fopen((const char*)path, "r"))) {
		ERROR_PRINT("Error: fopen() failed\n");
		exit(0);
	}
	fseek(fp, size, SEEK_SET);

	size_t len = 0;
	while (0 < getline(&buf, &len, fp)) {
		ssl_keylog((const char*)buf);
	}
	free(buf);

	return ftell(fp);
}
/*-----------------------------------------------------------------------------*/
void global_init()
{
	signal(SIGINT, sig_handler);
	printf("[Ctrl+C to quit]\n");

	session = (session_info **)calloc(max_session_num, sizeof(session_info*));
	session_num = 0;
	
	int i;
	for (i = 0; i < max_session_num; i++) {
		session[i] = (session_info*)calloc(1, sizeof(session_info));
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
			strcpy(path, optarg);
		}
		else if (c == 's') {
			max_session_num = atoi(optarg);
			if (max_session_num < 1) {
				ERROR_PRINT("Error: session number should be more than 1\n");
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

	if ((ino_wd = inotify_add_watch(ino_fd, (const char*)path, IN_MODIFY|IN_CREATE)) < 0) {
		ERROR_PRINT("Error: inotify_add_watch()\n");
		exit(0);
	}

	long read_byte = 0;

	strcat(path, "/key_log.txt");	// file name fixed

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
					read_byte = read_log(read_byte);
				}
				else if (event->mask & IN_MODIFY) {
					read_byte = read_log(read_byte);
				}
				else {
					ERROR_PRINT("Error: wrong event\n");
				}
			}
		}
	}

	inotify_rm_watch(ino_fd, ino_wd);
	close(ino_fd);

    return 0;
}