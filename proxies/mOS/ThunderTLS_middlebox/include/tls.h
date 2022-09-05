#ifndef __TLS_H__
#define __TLS_H__

#include <stdint.h>
#include <sys/queue.h>
#include <mos_api.h>

#define MAX_BUF_LEN 131072	  /* 128K */
#define MAX_RECORD_LEN 16384  /* 16K */
#define CLI_RECBUF_LEN 131072 /* 512K */
#define SVR_RECBUF_LEN 16384  /* 16K */
#define MAX_RECORD_NUM 16
#define MAX_RAW_PKT_NUM 20		/* 10 * MTU < 16K */
#define ETHERNET_FRAME_LEN 1514

#define TLS_HANDSHAKE_HEADER_LEN 4
#define TLS_RECORD_TYPE_LEN      1
#define TLS_1_0_VERSION 0x0301
#define TLS_1_2_VERSION 0x0303
#define TLS_1_3_CLIENT_RANDOM_LEN 32
#define TLS_CIPHER_AES_GCM_256_KEY_SIZE 32
#define TLS_CIPHER_AES_GCM_256_TAG_SIZE 16
#define TLS_CIPHER_AES_GCM_256_IV_SIZE 12
#define TLS_CIPHER_AES_GCM_256_AAD_SIZE 5
#define SHA384_HASH_LEN 48
#define HS_FINISHED_RECORD_LEN (TLS_HANDSHAKE_HEADER_LEN  +    \
								SHA384_HASH_LEN + 			   \
								TLS_CIPHER_AES_GCM_256_TAG_SIZE + \
								TLS_RECORD_TYPE_LEN) // 69
/* #define AES_256_KEY_LEN  32 */
/* #define AES_GCM_IV_LEN   12 */

#define LOWER_8BITS (0x000000FF)

#define PRINT (stderr)

#define VERBOSE_ERROR 1

#if VERBOSE_ERROR
#define ERROR_PRINT(fmt, args...) fprintf(PRINT, ANSI_COLOR_GREEN "" fmt "" ANSI_COLOR_RESET, ##args)
#else
#define ERROR_PRINT(fmt, args...) (void)0
#endif

/* Print message coloring */
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RESET "\x1b[0m"

enum tlshello
{
	CLIENT_HS = 0x01,
	SERVER_HS = 0x02,
};

enum tlsrecord
{
	CHANGE_CIPHER_SPEC = 0x14,
	ALERT = 0x15,
	HANDSHAKE = 0x16,
	APPLICATION_DATA = 0x17,
}; // tls_record_type

enum keymask
{
	CLI_KEY_MASK = 0x01,
	SRV_KEY_MASK = 0x02,
	CLI_IV_MASK = 0x04,
	SRV_IV_MASK = 0x08,
}; // tls_session_key_info_mask

enum tlsstate
{
	INITIAL_STATE,
	CLIENT_HELLO_RECV,
	SERVER_HELLO_RECV,
	SERVER_CYPHER_SUITE_RECV,
	CLIENT_CYPHER_SUITE_RECV,
	TLS_ESTABLISHED,
}; // tls_state_type

struct tls_crypto_info
{
	unsigned short version;
	unsigned short cipher_type;

	uint16_t key_mask;
	uint8_t key[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
	uint8_t iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
	/* union { */
	/* 	struct tls13_crypto_info_aes_gcm_256 key_block; */
	/* }; */
};

/* struct tls13_crypto_info_aes_gcm_256 { */
/*     unsigned char client_key[TLS_CIPHER_AES_GCM_256_KEY_SIZE]; */
/*     unsigned char client_iv[TLS_CIPHER_AES_GCM_256_IV_SIZE]; */
/*     unsigned char server_key[TLS_CIPHER_AES_GCM_256_KEY_SIZE]; */
/*     unsigned char server_iv[TLS_CIPHER_AES_GCM_256_IV_SIZE]; */
/* }; */

typedef struct tls_record
{
	uint8_t *tr_ciphertext;
	uint16_t tr_cipher_len;
} tls_record;

typedef struct raw_pkt
{
	uint8_t raw_pkt_buf[ETHERNET_FRAME_LEN];
	struct pkt_info raw_pkt_info;
} raw_pkt;

typedef struct tls_context
{
	uint8_t tc_buf[MAX_BUF_LEN]; /* TLS record buffer */
	uint32_t tc_buf_off;

	struct tls_crypto_info tc_key_info;
	uint16_t tc_version;
	uint32_t tc_unparse_tcp_seq;
	uint32_t tc_undecrypt_tcp_seq;
	uint16_t tc_current_record_len;
	uint64_t tc_current_tls_seq;
	/**< starting point to parse a new record */

	/* tls_record last_rec; */
	tls_record tc_records[MAX_RECORD_NUM];

	uint8_t *tc_plaintext;
	uint16_t tc_plain_len;
} tls_context;

typedef struct conn_info
{					  /* connection info */
	int ci_sock;	  /* socket ID */
	int ci_tls_state; /* TLS state */
	int ci_to_be_destroyed;
	uint8_t ci_client_random[TLS_1_3_CLIENT_RANDOM_LEN];

	tls_context ci_tls_ctx[2];
	
	raw_pkt tc_raw_buf[MAX_RAW_PKT_NUM]; /* raw packet buffer */
	int tc_raw_cnt;
} conn_info;

struct keytable
{ /* key pair <client_random, key> table */
	uint8_t kt_client_random[TLS_1_3_CLIENT_RANDOM_LEN];
	struct tls_crypto_info kt_key_info[2];
	int kt_valid;
};

#endif /* __TLS_H__ */
