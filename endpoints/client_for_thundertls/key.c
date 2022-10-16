// SSL-KEY.c
#define _GNU_SOURCE
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
#include <assert.h>
#include <sched.h>
#include <sys/queue.h>
#include "include/option.h"
#include "include/client.h"

/*-----UDP Implementation-----*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/*----------------------------*/

#define MAX_DATA_LEN 512
#define BUF_SIZE 128
#define NUM_BINS (65536)
#define MAX_FILE_NAME_LEN 50

#define AES256_KEY_LEN 32
#define CLIENT_RANDOM_LEN 32
#define TLS_1_3_IV_LEN 12
#define TRAFFIC_SECRET_LEN 48

#define EVENT_SIZE sizeof(struct inotify_event)
#define PROXY_PORT 443
#define PROXY_ADDR "10.1.90.10"
#define PROXY_ADDR_HEX 0x0a015a0a

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/* udp */
int g_udp_sd; // UDP socket descripter
int g_src_port = PROXY_PORT; // symmetric RSS

/* hash table */
struct hashtable *g_ht;
static int g_ino_fd, g_ino_wd; // inotify file descriptor

/* keylog file */
int g_keylog_env = 1;
static char g_keylog_filename[MAX_FILE_NAME_LEN];

typedef struct
{
	uint8_t client_write_key[AES256_KEY_LEN];
	uint8_t client_write_iv[TLS_1_3_IV_LEN];
	uint8_t server_write_key[AES256_KEY_LEN];
	uint8_t server_write_iv[TLS_1_3_IV_LEN];

	uint8_t client_random[CLIENT_RANDOM_LEN];
	uint8_t flag;
} session_info;

typedef struct
{
	uint16_t length;
	uint8_t label_ctx[256];
} HkdfLabel;

/* structures for hashtable with client random */
typedef TAILQ_HEAD(hash_bucket_head, ht_element) hash_bucket_head;

struct ht_element
{
	session_info *ht_si;
	TAILQ_ENTRY(ht_element)
	ht_link; /* hash table entry link */
};

struct hashtable
{
	uint32_t ht_count;
	hash_bucket_head ht_table[NUM_BINS];
};
/*----------------------------------------------------------------------------*/
static inline struct ht_element *
ht_search_int(struct hashtable *ht, uint8_t crandom[CLIENT_RANDOM_LEN])
{
	struct ht_element *walk;
	unsigned short idx = *(unsigned short *)crandom;
	hash_bucket_head *head = &ht->ht_table[idx];

	assert(head);
	TAILQ_FOREACH(walk, head, ht_link)
	{
		if (memcmp(walk->ht_si->client_random, crandom, CLIENT_RANDOM_LEN) == 0)
			return walk;
	}

	return NULL;
}
/*---------------------------------------------------------------------------*/
static inline struct hashtable *
ht_create(void)
{
	int i;
	struct hashtable *ht = (struct hashtable *)calloc(1, sizeof(struct hashtable));

	if (!ht)
	{
		fprintf(stderr, "Error: [%s] calloc() failed\n", __FUNCTION__);
		exit(-1);
	}

	/* init the tables */
	for (i = 0; i < NUM_BINS; i++)
		TAILQ_INIT(&ht->ht_table[i]);

	return ht;
}
/*----------------------------------------------------------------------------*/
static inline void
ht_destroy(struct hashtable *ht)
{
	free(ht);
}
/*----------------------------------------------------------------------------*/
static inline int
ht_insert(struct hashtable *ht, uint8_t crandom[CLIENT_RANDOM_LEN], session_info *si)
{
	unsigned short idx;
	struct ht_element *item;

	assert(ht);

	if (ht_search_int(ht, crandom))
	{
		fprintf(stderr, "Error: ct_insert() call with duplicate client random..\n");
		return 0;
	}

	if (!crandom)
	{
		fprintf(stderr, "Error: wrong Client Random value\n");
		exit(-1);
	}
	idx = *(unsigned short *)crandom;

	item = (struct ht_element *)calloc(1, sizeof(struct ht_element));
	if (!item)
	{
		fprintf(stderr, "Error: [%s] calloc() failed\n", __FUNCTION__);
		exit(-1);
	}
	item->ht_si = si;

	TAILQ_INSERT_TAIL(&ht->ht_table[idx], item, ht_link);
	ht->ht_count++;

	return 1;
}
/*----------------------------------------------------------------------------*/
static inline session_info *
ht_search(struct hashtable *ht, uint8_t crandom[CLIENT_RANDOM_LEN])
{
	struct ht_element *item = ht_search_int(ht, crandom);

	if (!item)
		return NULL;

	return item->ht_si;
}
/*----------------------------------------------------------------------------*/
static inline int
ht_remove(struct hashtable *ht, uint8_t crandom[CLIENT_RANDOM_LEN])
{
	hash_bucket_head *head;
	unsigned short idx;
	struct ht_element *item;

	item = ht_search_int(ht, crandom);
	if (!item)
		return 0;

	idx = *(unsigned short *)crandom;
	head = &ht->ht_table[idx];
	TAILQ_REMOVE(head, item, ht_link);
	ht->ht_count--;
	free(item);

	return 1;
}
/*-----------------------------------------------------------------------------*/
static void
Usage(char *argv[])
{
	printf("Usage: %s -k [path] -s [max session number]\n", argv[0]);
}
/*-----------------------------------------------------------------------------*/
static void
sig_handler(int sig)
{
	if (inotify_rm_watch(g_ino_fd, g_ino_wd) < 0)
	{
		ERROR_PRINT("Error: inotify_rm_watch()\n");
		exit(-1);
	}
	close(g_ino_fd);

	exit(0);
}
/*-----------------------------------------------------------------------------*/
static void
read_hex(const char *hex, uint8_t *out, size_t outmax, size_t *outlen)
{
	size_t i;

	*outlen = 0;
	if (strlen(hex) > 2 * outmax)
	{
		fprintf(stderr, "Error: hex length exceeds outmax (%lu > %lu*2)\n", strlen(hex), outmax * 2);
		exit(-1);
	}

	for (i = 0; hex[i] && hex[i + 1]; i += 2)
	{
		unsigned int value = 0;

		if (!sscanf(hex + i, "%02x", &value))
		{
			fprintf(stderr, "Error: [%s] sscanf fail\n", __FUNCTION__);
			exit(-1);
		}
		out[(*outlen)++] = value;
	}
}
/*-----------------------------------------------------------------------------*/
static unsigned char *
HKDF_expand(const EVP_MD *evp_md,
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

	*(uint16_t *)(data + len) = htobe16(label->length);
	len += 2;
	*(data + len) = label_len;
	len += 1;
	memcpy(data + len, (const char *)(label->label_ctx), label_len);
	len += label_len;
	*(data + len) = '\0';
	len += 1;

	for (i = 1; i <= n; i++)
	{
		size_t copy_len;
		const unsigned char ctr = i;

		if (i > 1)
		{
			ERROR_PRINT("[%s] Not implemented now\n", __FUNCTION__);
			goto err;

			if (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL))
			{
				goto err;
			}

			if (!HMAC_Update(hmac, prev, dig_len))
			{
				goto err;
			}

			data[len - 1] = ctr;
		}
		else
			data[len++] = ctr;

		if (!HMAC_Update(hmac, (const unsigned char *)data, len))
			goto err;

		if (!HMAC_Final(hmac, prev, NULL))
			goto err;

		copy_len = (done_len + dig_len > okm_len) ? okm_len - done_len : dig_len;
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

	HKDF_expand(evp_md, (const uint8_t *)secret, TRAFFIC_SECRET_LEN,
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

	HKDF_expand(evp_md, (const uint8_t *)secret, TRAFFIC_SECRET_LEN,
				&hkdf_label, strlen("tls13 iv"),
				iv_out, TLS_1_3_IV_LEN);

	return;
}
/*-----------------------------------------------------------------------------*/
static void
udp_send_key(session_info *si, in_port_t port, in_addr_t ip)
{
	uint8_t payload[BUF_SIZE];
	uint8_t *ptr = payload;
	struct sockaddr_in svraddr;
	const int KEYBLOCK_SIZE = 125;

	/* client random */
	memcpy(ptr, si->client_random, CLIENT_RANDOM_LEN);
	ptr += CLIENT_RANDOM_LEN;
	*ptr = '\n';
	ptr += 1;

	/* cipher suite */
	*(uint16_t *)ptr = htons(0x1302); // AES_256_GCM_SHA384
	ptr += 2;

	/* key mask */
	*(uint16_t *)ptr = htons(0xffff);
	ptr += 2;

	/* key info */
	memcpy(ptr, si->client_write_key, AES256_KEY_LEN);
	ptr += AES256_KEY_LEN;
	memcpy(ptr, si->server_write_key, AES256_KEY_LEN);
	ptr += AES256_KEY_LEN;
	memcpy(ptr, si->client_write_iv, TLS_1_3_IV_LEN);
	ptr += TLS_1_3_IV_LEN;
	memcpy(ptr, si->server_write_iv, TLS_1_3_IV_LEN);
	ptr += TLS_1_3_IV_LEN;

	memset(&svraddr, 0, sizeof(svraddr));
	svraddr.sin_family = AF_INET;
	svraddr.sin_addr.s_addr = ip;
	svraddr.sin_port = port;
	if (sendto(g_udp_sd, payload, KEYBLOCK_SIZE, 0,
				(struct sockaddr *)&svraddr, sizeof(svraddr)) != KEYBLOCK_SIZE)
	{
		fprintf(stderr, "sendto() failed\n");
		exit(-1);
	}
}
/*-----------------------------------------------------------------------------*/
static inline void
compute_and_send_key(const SSL *ssl, const char *line)
{
	int res, client_key = TRUE;
	char traffic_secret[BUF_SIZE], random[BUF_SIZE];
	uint8_t secret[BUF_SIZE], client_random[BUF_SIZE];
	size_t len, random_len;
	session_info *si;

	if ((res = sscanf(line, "CLIENT_TRAFFIC_SECRET_0 %s %s", random, traffic_secret)) > 0)
		;
	else if ((res = sscanf(line, "SERVER_TRAFFIC_SECRET_0 %s %s", random, traffic_secret)) > 0)
		client_key = FALSE;
	else /* irrelevant lines */
		return;

	if (res != 2)
	{
		fprintf(stderr, "%s wrong line format, line = %s",
				client_key ? "CLIENT_TRAFFIC_SECRET_0" : "SERVER_TRAFFIC_SECRET_0", line);
		exit(-1);
	}

	read_hex((const char *)random, client_random, BUF_SIZE, &random_len);
	read_hex((const char *)traffic_secret, secret, BUF_SIZE, &len);

	/* find session info*/
	si = ht_search(g_ht, client_random);
	if (!si)
	{
		si = (session_info *)calloc(1, sizeof(session_info));
		memcpy(si->client_random, client_random, CLIENT_RANDOM_LEN);
		if (!si)
			fprintf(stderr, "Error: [%s] calloc() failed\n", __FUNCTION__);
		if (ht_insert(g_ht, client_random, si) < 0)
			fprintf(stderr, "Error: ht_insert()\n");
	}
	get_write_key_1_3(secret, client_key ? si->client_write_key : si->server_write_key);
	get_write_iv_1_3(secret, client_key ? si->client_write_iv : si->server_write_iv);
	si->flag = si->flag | (client_key ? 0x3 : 0xc);
	if (si->flag == 0xf)
	{
#if 0 /* below is for client to send key by itself */
		struct sockaddr_in cliaddr, svraddr;
		socklen_t socketlen = sizeof(cliaddr);
		sd = SSL_get_fd(ssl);
		bzero(&cliaddr, socketlen);
		bzero(&svraddr, socketlen);
		getsockname(sd, (struct sockaddr*)&cliaddr, &socketlen);
		getpeername(sd, (struct sockaddr*)&svraddr, &socketlen);
		// fprintf(stderr, "ip: %s\n", inet_ntoa(svraddr.sin_addr));
		// fprintf(stderr, "TCP port : %u\n", ntohs(cliaddr.sin_port));
		udp_send_key(si, cliaddr.sin_port, svraddr.sin_addr.s_addr);
#else /* below is for agent to send key */
		udp_send_key(si, htons(PROXY_PORT), htonl(PROXY_ADDR_HEX));
#endif
		ht_remove(g_ht, client_random);
	}
}
/*-----------------------------------------------------------------------------*/
#if VERBOSE_KEY_M
static void
print_key(uint8_t *client_random, session_info *s_info, int client_key)
{
	int i;

	fprintf(stderr, "[");
	for (i = 0; i < 32; i++)
		fprintf(stderr, "%02X", client_random[i]);
	fprintf(stderr, "]\n%s write key: ", client_key ? "client" : "server");
	for (i = 0; i < 32; i++)
		fprintf(stderr, "%02X", client_key ? s_info->client_write_key[i] : s_info->server_write_key[i]);
	fprintf(stderr, "\n%s write iv: ", client_key ? "client" : "server");
	for (i = 0; i < 12; i++)
		fprintf(stderr, "%02X", client_key ? s_info->client_write_iv[i] : s_info->server_write_iv[i]);
	fprintf(stderr, "\n");
}
#endif
/*-----------------------------------------------------------------------------*/
static void
read_and_process_log(FILE *fp)
{
	char buf[MAX_DATA_LEN];

	/* read each line */
	while (fgets(buf, MAX_DATA_LEN, fp) != NULL)
	{
		if (strlen(buf) == MAX_DATA_LEN - 1)
		{
			ERROR_PRINT("Error: file crashed\n");
			exit(-1);
		}
		compute_and_send_key(NULL, (const char *)buf);
		memset(buf, 0, MAX_DATA_LEN);
	}
}
/*-----------------------------------------------------------------------------*/
static FILE *
open_log()
{
	FILE *fp = fopen((const char *)g_keylog_filename, "r");

	if (!fp)
	{
		fprintf(stderr, "\"key_log\" file isn't created...continue...\n");
		return NULL;
	}
	else
	{
		setvbuf(fp, NULL, _IOFBF, 0);
		return fp;
	}
}
/*-----------------------------------------------------------------------------*/
static void
global_init()
{
	if (signal(SIGINT, sig_handler) == SIG_ERR)
	{
		ERROR_PRINT("Error: could not use signal\n");
		abort();
	}
	printf("[Ctrl+C to quit]\n");
	g_ht = ht_create();
}
/*-----------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	FILE *fp;
	const struct inotify_event *event;
	struct sockaddr_in cliaddr;
	char c;
	int op = 1;
	int len;
	char *ptr;
	char buf[BUF_SIZE];

	while ((c = getopt(argc, argv, "k")) != -1)
	{
		if (c == 'k')
			g_keylog_env = 0;
		else
		{
			Usage(argv);
			exit(-1);
		}
	}
	global_init();

	/* set UDP socket */
	if ((g_udp_sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		fprintf(stderr, "Error: socket() failed\n");
		exit(-1);
	}
	if (setsockopt(g_udp_sd, SOL_SOCKET, SO_REUSEPORT, &op, sizeof(op)) < 0)
	{
		fprintf(stderr, "Error: setsockopt() failed\n");
		exit(-1);
	}
	memset(&cliaddr, 0, sizeof(cliaddr));
	cliaddr.sin_family = AF_INET;
	cliaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	cliaddr.sin_port = htons(g_src_port);
	if (bind(g_udp_sd, (struct sockaddr *)&cliaddr, sizeof(cliaddr)) < 0)
	{
		perror("bind");
		exit(-1);
	}

	/* set inotify fd from env variable */
	if ((g_ino_fd = inotify_init()) < 0)
	{
		ERROR_PRINT("Error: inotify_init()\n");
		exit(-1);
	}
	if ((g_ino_wd = inotify_add_watch(g_ino_fd,
						(const char *)getenv("SSLKEYLOGPATH"),
						IN_MODIFY | IN_CREATE)) < 0)
	{
		ERROR_PRINT("Error: inotify_add_watch()\n");
		exit(-1);
	}
	if (g_keylog_env)
		sprintf(g_keylog_filename, "%s%d", getenv("SSLKEYLOGFILE"), sched_getcpu());
	else
		sprintf(g_keylog_filename, "%s", getenv("SSLKEYLOGFILE"));
	fp = open_log();
#if 0
	if (fp)
	{
		read_and_process_log(fp);
		send_session_key(sd, servaddr, addrlen);
	}
#endif

	/* run main loop */
	while (1)
	{
		if ((len = read(g_ino_fd, buf, BUF_SIZE)) < 0)
		{
			ERROR_PRINT("Error: read()\n");
			exit(-1);
		}
		for (ptr = buf; ptr < buf + len; ptr += EVENT_SIZE + event->len)
		{
			event = (const struct inotify_event *)ptr;
			if (event->len)
			{
				if (event->mask & IN_CREATE) /* file created */
				{
					if (!(fp = open_log()))
					{
						ERROR_PRINT("Error: fopen()\n");
						exit(-1);
					}
					read_and_process_log(fp);
				}
				else if (event->mask & IN_MODIFY) /* file modified */
					read_and_process_log(fp);
				else /* irrelevant event */
					ERROR_PRINT("Error: wrong inotify event\n");
			}
		}
	}

	/* cleanup */
	inotify_rm_watch(g_ino_fd, g_ino_wd);
	close(g_ino_fd);
	close(g_udp_sd);
	fclose(fp);

	return 0;
}
