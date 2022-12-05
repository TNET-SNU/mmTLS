#ifndef __TLS_H__
#define __TLS_H__

#include <stdint.h>
#include <sys/queue.h>
#include <mos_api.h>
#include <time.h>

// #define MAX_BUF_LEN 2097152 /* for IDS */
#define MAX_BUF_LEN 16800 /* > 16K */ // this one is better
#define MAX_BUF_LEN_SVR 1024 /* 1K */
#define MAX_RECORD_LEN 16385 /* 16K + 1 */
#define MAX_RAW_PKT_NUM 20

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
#define TLS_HS_FINISHED_DONE_LEN 69
/* #define AES_256_KEY_LEN  32 */
/* #define AES_GCM_IV_LEN   12 */
#define LOWER_8BITS (0x000000FF)

#define VERBOSE_INFO 1
#define VERBOSE_WARNING 1
#define VERBOSE_ERROR 1

/* Print message coloring */
#define PRINT (stderr)
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_RESET "\x1b[0m"

#if VERBOSE_INFO
#define INFO_PRINT(fmt, args...) \
	fprintf(stdout, ANSI_COLOR_GREEN "[Info] " fmt "\n" ANSI_COLOR_RESET, ##args)
#else
#define INFO_PRINT(fmt, args...) (void)0
#endif
#if VERBOSE_WARNING
#define WARNING_PRINT(fmt, args...) \
	fprintf(stdout, ANSI_COLOR_YELLOW "[Warning] " fmt "\n" ANSI_COLOR_RESET, ##args)
#else
#define WARNING_PRINT(fmt, args...) (void)0
#endif
#if VERBOSE_ERROR
#define ERROR_PRINT(fmt, args...) \
	fprintf(PRINT, ANSI_COLOR_RED "[Error] [%10s:%4d] errno: %u\n" \
			fmt "\n" ANSI_COLOR_RESET, \
			__FUNCTION__, __LINE__, errno, ##args);
#else
#define ERROR_PRINT(fmt, args...) (void)0
#endif

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

enum tlsstate
{
	INITIAL_STATE,
	TLS_ESTABLISHED,
	TO_BE_DESTROYED,
}; // tls_state_type

enum ercode
{
	DECRYPT_FINAL_ERR = -20,
	SET_EXPECTED_TAG_ERR,
	DECRYPT_ERR,
	SET_AAD_ERR,
	SET_KEY_IV_ERR,
	SET_IV_LEN_ERR,
	SET_CIPHER_ERR,
	ORPHAN_ERR,
	EARLY_FIN,
	MISSING_KEY = -1,
/*------------------------------------*/
	NO_KEY = 0,
}; // custom error code

enum need_decrypt
{
	NO_DECRYPT = 0,
	DO_DECRYPT,
};
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
	uint8_t key[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
	uint8_t iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
} tls_crypto_info;

typedef struct tls_context
{
	tls_crypto_info tc_key_info;
	uint64_t tc_tls_seq; /* = tls_seq */
	uint64_t decrypt_len; /* for debugging */
	uint64_t peek_len; /* for debugging */
	tls_buffer tc_cipher;
	tls_buffer tc_plain;
} tls_context;

typedef struct conn_info
{					  /* connection info */
	int ci_sock;	  /* socket ID */
	int ci_tls_state; /* TLS state */
	int ci_has_key;
	uint8_t ci_client_random[TLS_1_3_CLIENT_RANDOM_LEN];
	tls_context ci_tls_ctx[2];
	pkt_vec ci_raw_pkt[MAX_RAW_PKT_NUM]; /* raw packet buffer */
	uint32_t ci_raw_len;
	uint8_t ci_raw_cnt;
	clock_t ci_clock_stall;
	clock_t ci_clock_resend;
	clock_t ci_key_delay;
} conn_info;

typedef struct keytable
{ /* key pair <client_random, key> table */
	uint8_t kt_client_random[TLS_1_3_CLIENT_RANDOM_LEN];
	tls_crypto_info kt_key_info[2];
	int kt_valid;
} keytable;

#endif /* __TLS_H__ */
