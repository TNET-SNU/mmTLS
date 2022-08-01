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

#define PROXY_IP "10.0.40.6"		// wine6
#define KEY_PORT 6666
/*----------------------------*/

#define MAX_DATA_LEN 	   512
#define AES256_KEY_LEN     32
#define CLIENT_RANDOM_LEN  32
#define TLS_1_3_IV_LEN     12
#define TRAFFIC_SECRET_LEN 48
#define EVENT_SIZE		   sizeof(struct inotify_event)
#define BUF_SIZE		   4096

static int g_ino_fd, g_ino_wd;		// inotify file descriptor

typedef struct {
	uint16_t length;
	uint8_t label_ctx[256];
} HkdfLabel;

typedef struct {
	uint8_t client_write_key[AES256_KEY_LEN];
	uint8_t client_write_iv[TLS_1_3_IV_LEN];
	uint8_t server_write_key[AES256_KEY_LEN];
	uint8_t server_write_iv[TLS_1_3_IV_LEN];

	uint8_t client_random[CLIENT_RANDOM_LEN];
	uint8_t flag;
} session_info;

typedef struct { 						// sessions to send
	int send_cnt;
	session_info **session_to_send;
} session_send;

static int g_max_session_num;			// max session number
static session_info **g_session;		// session array
static int g_session_num;				// # of connected sessions
static session_send g_session_send;		// sessions to send
static char g_path[1024];				// path for "key_log.txt"

/*-----------------------------------------------------------------------------*/
static void
Usage(char *argv[])
{
	printf("Usage: %s -p [path] -s [max session number]\n", argv[0]);
}
/*-----------------------------------------------------------------------------*/
static void 
sig_handler(int sig)
{	
	int i;

	if (inotify_rm_watch(g_ino_fd, g_ino_wd) < 0) {
		ERROR_PRINT("Error: inotify_rm_watch()\n");
		exit(-1);
	}
	
	for (i = 0; i < g_session_num; i++) {
		free(g_session[i]);
	}
	free(g_session);
	free(g_session_send.session_to_send);
	close(g_ino_fd);

	exit(0);
}
/*-----------------------------------------------------------------------------*/
static session_info*
create_session(uint8_t *random)
{
	if (g_session_num == g_max_session_num) {
		ERROR_PRINT("Error: session number exceeds max session number\n");
		exit(-1);
	}

	session_info *s_info = g_session[g_session_num];
	
	s_info->flag = 0;
	memcpy(s_info->client_random, random, CLIENT_RANDOM_LEN);
	g_session_num++;

	return s_info;
}
/*-----------------------------------------------------------------------------*/
static session_info*
find_session(const uint8_t *random)
{
	int i;
	
	/* check if session is already created */
	for (i = 0; i < g_session_num; i++) {
		if (memcmp((char*)g_session[i]->client_random, random, CLIENT_RANDOM_LEN) == 0) {
			if (g_session[i]->flag == 0xf) {
				ERROR_PRINT("Warning: Session key log duplicated...continue...\n");
			}
			return g_session[i];
		}
	}

	return NULL;
}
/*-----------------------------------------------------------------------------*/
static void 
read_hex(const char *hex, uint8_t *out, size_t outmax, size_t *outlen)
{
    size_t i;
	
    *outlen = 0;
    if (strlen(hex) > 2*outmax) {
		ERROR_PRINT("Error: hex length exceeds outmax (%lu > %lu*2)\n", strlen(hex), outmax*2);
		exit(-1);
	}
	
    for (i = 0; hex[i] && hex[i+1]; i += 2) {
        unsigned int value = 0;

        if (!sscanf(hex + i, "%02x", &value)) {
			ERROR_PRINT("Error: [%s] sscanf fail\n", __FUNCTION__);
			exit(-1);
		}
        out[(*outlen)++] = value;
    }
}
/*-----------------------------------------------------------------------------*/
static unsigned char 
*HKDF_expand(const EVP_MD *evp_md,
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

    if (okm_len % dig_len) {
        n++;
	}

    if (n > 255 || okm == NULL) {
        return NULL;
	}

    if ((hmac = HMAC_CTX_new()) == NULL) {
        return NULL;
	}

    if (!HMAC_Init_ex(hmac, prk, prk_len, evp_md, NULL)) {
        goto err;
	}

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
			
            if (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL)) {
                goto err;
			}

			if (!HMAC_Update(hmac, prev, dig_len)) {
				goto err;
			}
			
			data[len-1] = ctr;
        }
		else {
			data[len++] = ctr;
		}
		
        if (!HMAC_Update(hmac, (const unsigned char*)data, len)) {
            goto err;
		}
		
        if (!HMAC_Final(hmac, prev, NULL)) {
            goto err;
		}
		
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
static void
get_write_key_1_3(uint8_t *secret, uint8_t *key_out)
{
	HkdfLabel hkdf_label;
	const EVP_MD *evp_md;

	/* assume hash: SHA384 */
	evp_md = EVP_get_digestbyname("SHA384");

	hkdf_label.length = AES256_KEY_LEN;
	memcpy(hkdf_label.label_ctx, "tls13 key", strlen("tls13 key"));

	HKDF_expand(evp_md, (const uint8_t*)secret, TRAFFIC_SECRET_LEN,
			     &hkdf_label, strlen("tls13 key"),
				key_out, AES256_KEY_LEN);

	return;
}
/*-----------------------------------------------------------------------------*/
static void
get_write_iv_1_3(uint8_t *secret, uint8_t *iv_out)
{
	HkdfLabel hkdf_label;
	const EVP_MD *evp_md;
	
	/* assume hash: SHA384 */
	evp_md = EVP_get_digestbyname("SHA384");

	hkdf_label.length = TLS_1_3_IV_LEN;
	memcpy(hkdf_label.label_ctx, "tls13 iv", strlen("tls13 iv"));

	HKDF_expand(evp_md, (const uint8_t*)secret, TRAFFIC_SECRET_LEN,
			    &hkdf_label, strlen("tls13 iv"),
				iv_out, TLS_1_3_IV_LEN);
				
	return;
}
/*-----------------------------------------------------------------------------*/
static void 
udp_send(session_info *s_info, int sd, struct sockaddr_in servaddr, int addrlen)
{
	uint8_t payload[BUF_SIZE];
	uint8_t *ptr;
	const int KEYBLOCK_SIZE = 124;

	/* cipher suite */
    ptr = payload;
	*(uint16_t*)ptr = htons(0x1302);	// AES_256_GCM_SHA384
	ptr += 2;
	
	/* key mask */
	*(uint16_t*)ptr = htons(0xffff);
	ptr += 2;

	/* key info */
	memcpy(ptr, s_info->client_write_key, AES256_KEY_LEN);
	ptr += AES256_KEY_LEN;
	memcpy(ptr, s_info->server_write_key, AES256_KEY_LEN);
	ptr += AES256_KEY_LEN;
	memcpy(ptr, s_info->client_write_iv, TLS_1_3_IV_LEN);
	ptr += TLS_1_3_IV_LEN;
	memcpy(ptr, s_info->server_write_iv, TLS_1_3_IV_LEN);
	ptr += TLS_1_3_IV_LEN;

	/* client random */
	memcpy(ptr, s_info->client_random, CLIENT_RANDOM_LEN);

	if ((sendto(sd, (const uint8_t*)payload, KEYBLOCK_SIZE, 0, (struct sockaddr *)&servaddr, addrlen)) !=  KEYBLOCK_SIZE) {
      	ERROR_PRINT("Error: sendto() failed\n");
        exit(-1);
    }

    return;
}
/*-----------------------------------------------------------------------------*/
static void
send_session_key(int sd, struct sockaddr_in servaddr, int addrlen) 
{
	int i;
	
	/* send session keys via UDP */
	for (i = 0; i < g_session_send.send_cnt; i++) {
		udp_send(g_session_send.session_to_send[i], sd, servaddr, addrlen);
	}
	g_session_send.send_cnt = 0;
}
/*-----------------------------------------------------------------------------*/
static void
print_key(uint8_t *client_random, session_info *s_info, int client_key)
{
	int i;

	fprintf(stderr, "[");
	for (i = 0; i < 32; i++) {
		fprintf(stderr, "%02X", client_random[i]);
	}
	fprintf(stderr, "]\n");
	fprintf(stderr,"%s write key: ", client_key ? "client" : "server");
	for (i = 0; i < 32; i++) {
		fprintf(stderr,"%02X", client_key ? s_info->client_write_key[i] : s_info->server_write_key[i]);
	}
	fprintf(stderr,"\n");
	fprintf(stderr,"%s write iv: ", client_key ? "client" : "server");
	for (i = 0; i < 12; i++) {
		fprintf(stderr,"%02X", client_key ? s_info->client_write_iv[i] : s_info->server_write_iv[i]);
	}
	fprintf(stderr,"\n");
}
/*-----------------------------------------------------------------------------*/
static void 
parse_keylog(const char *line) 
{
	char traffic_secret[BUF_SIZE], random[BUF_SIZE];
	uint8_t secret[BUF_SIZE], client_random[BUF_SIZE];
	size_t len, random_len;
	int res, client_key = TRUE;
	session_info* s_info;

	if ((res = sscanf(line, "CLIENT_TRAFFIC_SECRET_0 %s %s", random, traffic_secret)) > 0 )  {
	} 
	else if ((res = sscanf(line, "SERVER_TRAFFIC_SECRET_0 %s %s", random, traffic_secret)) > 0) {
		client_key = FALSE;
	} 
	else {
		/* irrelevant lines */
		return;
	}

	/* check the line format is correct */
	if (res != 2) {
		ERROR_PRINT("%s wrong line format, line = %s", 
				client_key ? "CLIENT_TRAFFIC_SECRET_0" : "SERVER_TRAFFIC_SECRET_0", line);
		exit(-1);
	}

	read_hex((const char*)random, client_random, BUF_SIZE, &random_len);
	
	/* get the session info */
	s_info = find_session(client_random);
	if (!s_info) {
		s_info = create_session(client_random);
	}

	read_hex((const char*)traffic_secret, secret, BUF_SIZE, &len);

	get_write_key_1_3(secret, client_key ? s_info->client_write_key: s_info->server_write_key);
	get_write_iv_1_3(secret, client_key ? s_info->client_write_iv: s_info->server_write_iv);
	s_info->flag = s_info->flag | (client_key ? 0x3: 0xc);
	if (s_info->flag == 0xf) {
		/* add sessions to send */
		g_session_send.session_to_send[g_session_send.send_cnt] = s_info;
		g_session_send.send_cnt++;
	}

	if (VERBOSE_KEY_M) {
		print_key(client_random, s_info, client_key);
	}
}
/*-----------------------------------------------------------------------------*/
static void
read_and_process_log(FILE *fp)
{
	char buf[MAX_DATA_LEN];

	/* read each line */
	while (fgets(buf, MAX_DATA_LEN, fp) != NULL) {
		if (strlen(buf) == MAX_DATA_LEN-1) {
			ERROR_PRINT("Error: file crashed\n");
			exit(-1);
		}
		parse_keylog((const char*)buf);
	}
}
/*-----------------------------------------------------------------------------*/
static FILE*
open_log()
{
	FILE *fp = fopen((const char*)g_path, "r");

	if (!fp) {
		fprintf(stderr, "\"key_log.txt\" file isn't created...continue...\n");

		return NULL;
	}
	else {
		setvbuf(fp, NULL, _IONBF, 0);

		return fp;
	}
}
/*-----------------------------------------------------------------------------*/
static void 
global_init()
{
	int i;

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		ERROR_PRINT("Error: could not use signal\n");
		abort();
	}
	printf("[Ctrl+C to quit]\n");

	/* g_session init */
	g_session = (session_info **)calloc(g_max_session_num, sizeof(session_info*));
	if (!g_session) {
		ERROR_PRINT("Error: calloc() failed\n");
		exit(-1);
	}
	g_session_num = 0;

	/* g_session_send init */
	g_session_send.session_to_send = (session_info **)calloc(g_max_session_num, sizeof(session_info*));
	if (!g_session_send.session_to_send) {
		ERROR_PRINT("Error: calloc() failed\n");
		exit(-1);
	}
	g_session_send.send_cnt = 0;

	for (i = 0; i < g_max_session_num; i++) {
		g_session[i] = (session_info*)calloc(1, sizeof(session_info));
		if (!g_session[i]) {
			ERROR_PRINT("Error: calloc() failed\n");
			exit(-1);
		}
	}
}
/*-----------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
	char c;
	int sd;						 // UDP socket descripter
	struct sockaddr_in servaddr;
	int addrlen = sizeof(servaddr);
	FILE *fp;
	
	if (argc < 4) {
		Usage(argv);
		exit(-1);
	}

	while ((c = getopt(argc, argv, "p:s:")) != -1) {
		if (c == 'p') { 
			strcpy(g_path, optarg);
		}
		else if (c == 's') {
			g_max_session_num = atoi(optarg);
			if (g_max_session_num < 1) {
				ERROR_PRINT("Error: max session number should be more than 1\n");
				exit(-1);
			}
		}
		else {   
			Usage(argv);
			exit(-1);
		}
  	}

	global_init();
	
	/* UDP socket */
	if ((sd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        ERROR_PRINT("Error: socket() failed\n");
        exit(-1);
    }

    memset(&servaddr, 0, addrlen);
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(PROXY_IP);
    servaddr.sin_port = htons(KEY_PORT);

	if ((g_ino_fd = inotify_init()) < 0) {
		ERROR_PRINT("Error: inotify_init()\n");
		exit(-1);
	}

	if ((g_ino_wd = inotify_add_watch(g_ino_fd, (const char*)g_path, IN_MODIFY|IN_CREATE)) < 0) {
		ERROR_PRINT("Error: inotify_add_watch()\n");
		exit(-1);
	}

	strcat(g_path, "/key_log.txt");	// file name fixed

	fp = open_log();
	if (fp) {
		read_and_process_log(fp);
		send_session_key(sd, servaddr, addrlen);
	}

	while (1) {
		int len;
		char buf[BUF_SIZE];
		const struct inotify_event *event;
		char *ptr;

		len = read(g_ino_fd, buf, BUF_SIZE);
		if (len < 0) {
			ERROR_PRINT("Error: read()\n");
			exit(-1);
		}

		for (ptr = buf; ptr < buf + len; ptr += EVENT_SIZE + event->len) {
			event = (const struct inotify_event*)ptr;
			if (event->len) {
				if (event->mask & IN_CREATE) {
					/* file created */
					fp = open_log();
					if (!fp) {
						ERROR_PRINT("Error: fopen()\n");
						exit(-1);
					}
					read_and_process_log(fp);
					send_session_key(sd, servaddr, addrlen);
				}
				else if (event->mask & IN_MODIFY) {
					/* file modified */
					read_and_process_log(fp);
					send_session_key(sd, servaddr, addrlen);
				}
				else {
					/* irrelevant event */
					ERROR_PRINT("Error: wrong inotify event\n");
				}
			}
		}
	}

	inotify_rm_watch(g_ino_fd, g_ino_wd);
	close(g_ino_fd);
	close(sd);
	fclose(fp);

    return 0;
}