#ifndef __TLS_H__
#define __TLS_H__

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <sys/queue.h>
#include <mos_api.h>
#include <time.h>

#define MAX_BUF_LEN 16800 /* > 16K */ /* 2097152 */
#define MAX_BUF_LEN_SVR 1024 /* 1K */
#define MAX_RECORD_LEN 8192 /* 16K + 1 */
#define MAX_RAW_PKT_NUM 10
#define MAX_FILE_NAME_LEN	64

#define TLS_HANDSHAKE_HEADER_LEN 4
#define TLS_RECORD_TYPE_LEN      1
#define TLS_1_2_VERSION 0x0303
#define TLS_1_3_VERSION 0x0304
#define TLS_CLIENT_RANDOM_LEN 32
#define TLS_SERVER_RANDOM_LEN 32
#define TLS_MAX_SNI_LEN 64
#define NUM_MMTLS_CALLBACK 8

#define MAX_KEY_INFO_SIZE (EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH + EVP_MAX_MD_SIZE)
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
#define EXIT_WITH_ERROR(fmt, args...) { \
	ERROR_PRINT(fmt, ##args); \
	exit(EXIT_FAILURE); \
}
struct mmtls_context {
	int cpu;
};
typedef struct mmtls_context *mmtls_t;
typedef void (*mmtls_cb)(mmtls_t mmctx, int cid, int side);
struct mmtls_manager {
	mctx_t mctx;
	mmtls_t mmctx;
	mmtls_cb cb[NUM_MMTLS_CALLBACK];
};

/*---------------------------------------------------------------------------*/
/** Definition of monitor side */
enum {MMTLS_SIDE_CLI=0, MMTLS_SIDE_SVR, MMTLS_SIDE_BOTH};

/** events provided by mmTLS */
enum mmtls_event_type
{
	ON_TLS_SESSION_START,
	ON_TLS_SESSION_END,
	ON_TLS_HANDSHAKE_START,
	ON_TLS_HANDSHAKE_END,
	ON_TLS_NEW_RECORD,
	ON_TLS_ABNORMAL,
	ON_TLS_STALL,
	ON_TLS_RECV_KEY,
};

enum tls_cipher_suite
{
	TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
	TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DH_anon_WITH_AES_128_CBC_SHA256,
    TLS_DH_anon_WITH_AES_256_CBC_SHA256,
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
    TLS_DH_anon_WITH_AES_128_GCM_SHA256,
    TLS_DH_anon_WITH_AES_256_GCM_SHA384,
    TLS_PSK_WITH_AES_128_GCM_SHA256,
    TLS_PSK_WITH_AES_256_GCM_SHA384,
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
    TLS_PSK_WITH_AES_128_CBC_SHA256,
    TLS_PSK_WITH_AES_256_CBC_SHA384,
	/* tls1.3 start */
	TLS_AES_128_GCM_SHA256 = 0x1301,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_AES_128_CCM_SHA256,
	TLS_AES_128_CCM_8_SHA256,
	/* tls1.3 end */
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // 0xc030
	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
};

enum monlevel
{
	NO_DECRYPT,
	DO_DECRYPT,
};

enum tlshello
{
	CLIENT_HS = 0x01,
	SERVER_HS = 0x02,
	SERVER_HS_FINISHED = 0x14,
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
	RECV_CH,
	RECV_SH,
	TLS_ESTABLISHED,
	TO_BE_DESTROYED,
}; // tls_state_type

enum ercode
{
	INTEGRITY_ERR = -20,
	DECRYPT_ERR,
	ORPHAN_ERR,
	EARLY_FIN,
	NOT_SUPPORTED,
	MISSING_KEY = -1,
/*------------------------------------*/
	NO_KEY = 0,
}; // custom error code

typedef struct tls_buffer
{
	uint8_t *buf;
	uint32_t chead;
	uint32_t ctail;
	uint32_t phead;
	uint32_t ptail;
} tls_buffer;

typedef struct pkt_vec
{
	uint8_t *data;
	uint16_t len;
} pkt_vec;

typedef struct tls_crypto_info
{
	uint8_t data[MAX_KEY_INFO_SIZE];
} tls_crypto_info;

typedef struct tls_context
{
	uint8_t tc_key_info[MAX_KEY_INFO_SIZE];
	uint64_t tc_tls_seq; /* = tls_seq */
	tls_buffer tc_cipher;
	// tls_buffer tc_plain;
} tls_context;

typedef struct conn_info
{
	void *ci_uctx;
	int ci_mon_state[2];
	int ci_tls_state; /* TLS state */
	int ci_has_key;
	int ci_err_code;
	uint8_t ci_client_random[TLS_CLIENT_RANDOM_LEN];
	uint8_t ci_server_random[TLS_SERVER_RANDOM_LEN];
	uint16_t ci_tls_version;
	uint16_t ci_cipher_suite;
	uint8_t ci_sni_type;
	uint8_t ci_sni[TLS_MAX_SNI_LEN];
	const EVP_CIPHER *ci_evp_cipher;
	const EVP_MD *ci_evp_md;
	tls_context ci_tls_ctx[2];

	/* below are for packet stall */
	pkt_vec ci_raw_pkt[MAX_RAW_PKT_NUM]; /* raw packet buffer */
	uint32_t ci_raw_len;
	uint8_t ci_raw_cnt;
} conn_info;

typedef struct keytable
{
	/* key pair <client_random, key> table */
	uint8_t kt_client_random[TLS_CLIENT_RANDOM_LEN];
	tls_crypto_info kt_key_info[2];
	int kt_valid;
} keytable;

/*---------------------------------------------------------------------------*/
int mmtls_init(const char *fname, int num_cpus);
/*---------------------------------------------------------------------------*/
void mmtls_app_join(mmtls_t mmctx);
/*---------------------------------------------------------------------------*/
int mmtls_destroy();
/*---------------------------------------------------------------------------*/
mmtls_t mmtls_create_context(int cpu);
/*---------------------------------------------------------------------------*/
int mmtls_register_callback(mmtls_t mmctx, event_t event, mmtls_cb cb);
/*---------------------------------------------------------------------------*/
int mmtls_deregister_callback(mmtls_t mmctx, event_t event);
/*---------------------------------------------------------------------------*/
int mmtls_get_record(mmtls_t mmctx, int cid, int side, uint8_t *buf, int *len);
/*---------------------------------------------------------------------------*/
void mmtls_drop_packet(mmtls_t mmctx, int cid, int side);
/*---------------------------------------------------------------------------*/
void mmtls_reset_conn(mmtls_t mmctx, int cid, int side);
/*---------------------------------------------------------------------------*/
int mmtls_get_err(mmtls_t mmctx, int cid, int side);
/*---------------------------------------------------------------------------*/
uint8_t *mmtls_get_random(mmtls_t mmctx, int cid, int side);
/*---------------------------------------------------------------------------*/
uint16_t mmtls_get_version(mmtls_t mmctx, int cid, int side);
/*---------------------------------------------------------------------------*/
uint16_t mmtls_get_cipher(mmtls_t mmctx, int cid, int side);
/*---------------------------------------------------------------------------*/
int mmtls_get_monopt(mmtls_t mmctx, int cid, int side);
/*---------------------------------------------------------------------------*/
int mmtls_set_monopt(mmtls_t mmctx, int cid, int side, int optval);
/*---------------------------------------------------------------------------*/
int mmtls_get_stallcnt(mmtls_t mmctx, int cid, int side);
/*---------------------------------------------------------------------------*/
void mmtls_set_uctx(mmtls_t mmctx, int cid, void *uctx);
/*---------------------------------------------------------------------------*/
void *mmtls_get_uctx(mmtls_t mmctx, int cid);
/*---------------------------------------------------------------------------*/

#endif /* __TLS_H__ */