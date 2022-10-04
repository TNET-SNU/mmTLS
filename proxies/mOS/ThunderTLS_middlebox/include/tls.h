#ifndef __TLS_H__
#define __TLS_H__

#include <stdint.h>
#include <sys/queue.h>
#include <mos_api.h>

// #define MAX_BUF_LEN 2097152 /* for IDS */
#define MAX_BUF_LEN 16800 /* > 16K */ // this one is better
#define MAX_BUF_LEN_SVR 8192 /* 8K */
#define MAX_RECORD_LEN 16385 /* 16K + 1 */
#define MAX_RAW_PKT_BUF_LEN 8192 /* 8K */
#define MAX_RAW_PKT_NUM 10

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
	SERVER_CIPHER_SUITE_RECV,
	CLIENT_CIPHER_SUITE_RECV,
	TLS_ESTABLISHED,
	TO_BE_DESTROYED,
}; // tls_state_type

typedef struct tls_buffer
{
	uint8_t *buf;
	uint32_t head;
	uint32_t tail;
} tls_buffer;

typedef struct pkt_vec
{
	uint8_t *data;
	uint16_t len;
} pkt_vec;

typedef struct tls_crypto_info
{
	uint16_t key_mask;
	uint8_t key[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
	uint8_t iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
} tls_crypto_info;

typedef struct tls_context
{
	tls_crypto_info tc_key_info;
	uint64_t tc_record_cnt; /* = tls_seq */
	uint64_t decrypt_len; /* for debugging */
	tls_buffer tc_cipher;
	tls_buffer tc_plain;
} tls_context;

typedef struct conn_info
{					  /* connection info */
	int ci_sock;	  /* socket ID */
	int ci_tls_state; /* TLS state */
	uint8_t ci_client_random[TLS_1_3_CLIENT_RANDOM_LEN];
	tls_context ci_tls_ctx[2];
	pkt_vec ci_raw_pkt[MAX_RAW_PKT_NUM]; /* raw packet buffer */
	uint32_t ci_raw_len;
	uint8_t ci_raw_cnt;
} conn_info;

typedef struct keytable
{ /* key pair <client_random, key> table */
	uint8_t kt_client_random[TLS_1_3_CLIENT_RANDOM_LEN];
	tls_crypto_info kt_key_info[2];
	int kt_valid;
} keytable;

#endif /* __TLS_H__ */
