#ifndef __TLS_H__
#define __TLS_H__

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <sys/queue.h>
#include <mos_api.h>
#include <time.h>
#include <errno.h>
#include <rte_mempool.h>

#define ZERO_COPY

#define MMTLS_SIDE_CLI MOS_SIDE_CLI
#define MMTLS_SIDE_SVR MOS_SIDE_SVR
#define MMTLS_SIDE_BOTH MOS_SIDE_BOTH

#define MAX_RECORD_LEN 16448
#define MAX_BUF_LEN 16512 /* align64(16K + TLS_HEADER_LEN) */
#define MAX_RAW_PKT_NUM 10
#define MAX_POOL_NAME_LEN 20
#define MAX_FILE_NAME_LEN 64

#define TLS_HANDSHAKE_HEADER_LEN 4
#define TLS_RECORD_TYPE_LEN 1
#define TLS_PORT_NUM 443
#define TLS_1_2_VERSION 0x0303
#define TLS_1_3_VERSION 0x0304
#define TLS_CLIENT_RANDOM_LEN 32
#define TLS_SERVER_RANDOM_LEN 32
#define TLS_MAX_SNI_LEN 64

#define MAX_KEY_INFO_SIZE (EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH + EVP_MAX_MD_SIZE)
#define LOWER_8BITS (0x000000FF)

#define VERBOSE_INFO 1
#define VERBOSE_WARNING 1
#define VERBOSE_ERROR 1

#define OFFLOAD_BYPASS 0x04
#define OFFLOAD_DROP 0x05
#define ONLOAD 0x06

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
#define ERROR_PRINT(fmt, args...)                                                             \
	fprintf(PRINT, ANSI_COLOR_RED "[Error] [%10s:%4d] errno: %u\n" fmt "\n" ANSI_COLOR_RESET, \
			__FUNCTION__, __LINE__, errno, ##args);
#else
#define ERROR_PRINT(fmt, args...) (void)0
#endif
#define EXIT_WITH_ERROR(fmt, args...) \
	{                                 \
		ERROR_PRINT(fmt, ##args);     \
		exit(EXIT_FAILURE);           \
	}
struct mmtls_context
{
	int cpu;
};
typedef struct mmtls_context *mmctx_t;
typedef void (*mmtls_cb)(mmctx_t mmctx, int cid, int side);
typedef int (*crypto_cb)(EVP_CIPHER_CTX *evp_ctx,
						 const EVP_CIPHER *evp_cipher,
						 const EVP_MD *evp_md,
						 uint8_t *data,
						 uint8_t *plain,
						 uint8_t *key_info,
						 uint64_t tls_seq,
						 uint16_t cipher_len);

/*---------------------------------------------------------------------------*/
/** events provided by mmTLS */
enum mmtls_event_type
{
	ON_TLS_SESSION_START,
	ON_TLS_SESSION_END,
	ON_TLS_HANDSHAKE_START,
	ON_TLS_HANDSHAKE_END,
	ON_TLS_NEW_RECORD,
	ON_TLS_ERROR,
	/*------------------------------------*/
	/* below are for inner-usage */
	ON_TLS_STALL,
	ON_TLS_RECV_KEY,
	NUM_MMTLS_CALLBACK,
};

struct mmtls_manager
{
	mctx_t mctx;
	mmctx_t mmctx;
	/* OpenSSL context to find IANA standard name */
	SSL_CTX *ssl_ctx;
	/* OpenSSL instance to use SSL utils */
	SSL *ssl;
	/* EVP Cipher context for decryption */
	EVP_CIPHER_CTX *evp_ctx;
	/* move callback to each session one day */
	mmtls_cb cb[NUM_MMTLS_CALLBACK];
	struct rte_mempool *ci_pool;
	struct rte_mempool *rawpkt_pool;
#ifndef ZERO_COPY
	struct rte_mempool *cli_buffer_pool;
	struct rte_mempool *svr_buffer_pool;
#endif
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
}; // IANA name format

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
	INVALID_VERSION,
	INVALID_CIPHER_SUITE,
	INVALID_RECORD_LEN,
	WRONG_USAGE,
	MISSING_KEY = -1,
	/*------------------------------------*/
	/* 
	 * below are not error,
	 * but NO_KEY might raise MISSING_KEY
	 * when NO_KEY raised many times
	 */
	NO_KEY = 0,
}; // custom error code

typedef struct pkt_vec
{
	uint8_t *data;
	uint16_t len;
} pkt_vec;

typedef struct session_ctx
{
	uint8_t key_info[MAX_KEY_INFO_SIZE];
	uint64_t tls_seq;
	uint8_t *buf;
#ifndef ZERO_COPY
	uint32_t head;
	uint32_t tail;
	uint8_t record_type;
#endif
	uint16_t record_len; /* TLS header not included */
} session_ctx;

typedef struct session_info
{
	/* cipher */
	uint16_t version;
	uint16_t cipher_suite;
	uint16_t group;
	/* sockaddr */
	int sock;
	uint32_t cli_ip;
	uint32_t svr_ip;
	uint16_t cli_port;
	uint16_t svr_port;
	/* randoms */
	uint8_t client_random[TLS_CLIENT_RANDOM_LEN];
	uint8_t server_random[TLS_SERVER_RANDOM_LEN];
	/* server name indicator */
	uint8_t sni_len;
	uint8_t sni_type;
	uint8_t sni[TLS_MAX_SNI_LEN];
	/* something related to cert, not implemented yet */
	void *certificate;
} session_info;

enum info_mask
{
	VERSION = 1,
	CIPHER_SUITE = 1 << 1,
	SOCK_ADDR = 1 << 2,
	SNI = 1 << 3,
	CLIENT_RANDOM = 1 << 4,
	SERVER_RANDOM = 1 << 5,
	// not implemented yet, need to modify structures
	CLIENT_KEY = 1 << 6,
	SERVER_KEY = 1 << 7,
	CLIENT_IV = 1 << 8,
	SERVER_IV = 1 << 9,
	CLIENT_MAC_KEY = 1 << 10,
	SERVER_MAC_KEY = 1 << 11,
	// not implemented yet, need to decrypt handshake record
	CERTIFICATE = 1 << 12,
};

typedef struct session
{
	void *uctx;
	uint8_t has_key : 1;
	uint8_t drop : 1;
	uint8_t bypass : 1;

	/* below two fields are for session state tracking */
	uint8_t svr_done : 2;
	uint8_t tls_state : 3; /* TLS state */
	int err_code;

	session_info sess_info;
	session_ctx sess_ctx[MMTLS_SIDE_BOTH];

	void *offload_flow;
	int stop_len[MMTLS_SIDE_BOTH];
	const EVP_CIPHER *evp_cipher;
	const EVP_MD *evp_md;

	/* below are for packet stall */
	pkt_vec raw_pkt[MAX_RAW_PKT_NUM]; /* raw packet buffer */
	uint32_t raw_len;
	uint8_t raw_cnt;
} session;

/*---------------------------------------------------------------------------*/
int mmtls_init(const char *fname, int num_cpus);
/*---------------------------------------------------------------------------*/
void mmtls_app_join(mmctx_t mmctx);
/*---------------------------------------------------------------------------*/
int mmtls_destroy();
/*---------------------------------------------------------------------------*/
mmctx_t mmtls_create_context(int cpu);
/*---------------------------------------------------------------------------*/
int mmtls_register_callback(mmctx_t mmctx, event_t event, mmtls_cb cb);
/*---------------------------------------------------------------------------*/
int mmtls_deregister_callback(mmctx_t mmctx, event_t event);
/*---------------------------------------------------------------------------*/
int mmtls_pause_monitor(mmctx_t mmctx, int cid, int side, int len);
/*---------------------------------------------------------------------------*/
int mmtls_resume_monitor(mmctx_t mmctx, int cid, int side);
/*---------------------------------------------------------------------------*/
int mmtls_get_record(mmctx_t mmctx, int cid, int side,
					 char *buf, int *len, uint8_t *type);
/*---------------------------------------------------------------------------*/
int mmtls_set_uctx(mmctx_t mmctx, int cid, void *uctx);
/*---------------------------------------------------------------------------*/
void *mmtls_get_uctx(mmctx_t mmctx, int cid);
/*---------------------------------------------------------------------------*/
int mmtls_reset_conn(mmctx_t mmctx, int cid);
/*---------------------------------------------------------------------------*/
int mmtls_get_error(mmctx_t mmctx, int cid);
/*---------------------------------------------------------------------------*/
int mmtls_get_tls_info(mmctx_t mmctx, int cid,
					   session_info *info, uint16_t bitmask);
/*---------------------------------------------------------------------------*/
/* in development */
int mmtls_offload_ctl(mmctx_t mmctx, int cid, int side, int cmd);
/*---------------------------------------------------------------------------*/
/* only for inner usage */
int mmtls_get_stallcnt(mmctx_t mmctx, int cid);
/*---------------------------------------------------------------------------*/

#endif /* __TLS_H__ */