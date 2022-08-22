#ifndef __TLS_H__
#define __TLS_H__

#include <stdint.h>
#include <sys/queue.h>

#define MAX_BUF_LEN      16384      /* 16K */
#define MAX_RECORD_LEN   16384      /* 16K */
#define CLI_RECBUF_LEN   524288	    /* 512K */
#define SVR_RECBUF_LEN   16384	    /* 16K */
#define MAX_RECORD_NUM   16

#define TLS_1_3_CLIENT_RANDOM_LEN 32
#define TLS_CIPHER_AES_GCM_256_KEY_SIZE 32
#define TLS_CIPHER_AES_GCM_256_TAG_SIZE 16
#define TLS_CIPHER_AES_GCM_256_IV_SIZE 12
#define TLS_CIPHER_AES_GCM_256_AAD_SIZE 5
/* #define AES_256_KEY_LEN  32 */
/* #define AES_GCM_IV_LEN   12 */

#define PRINT (stderr)  

#define VERBOSE_ERROR   1

#if VERBOSE_ERROR
#define ERROR_PRINT(fmt, args...) fprintf(PRINT, ANSI_COLOR_GREEN \
                                    ""fmt""ANSI_COLOR_RESET, ##args)
#else
#define ERROR_PRINT(fmt, args...) (void)0
#endif

/* Print message coloring */
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_RESET   "\x1b[0m"

enum {
    CHANGE_CIPHER_SPEC  = 0x14,
    ALERT               = 0x15,
    HANDSHAKE           = 0x16,
    APPLICATION_DATA    = 0x17,
}; 	// tls_record_type

enum {
    CLI_KEY_MASK = 0x1,
	SRV_KEY_MASK = 0x2,
	CLI_IV_MASK  = 0x4,
	SRV_IV_MASK  = 0x8,
}; 	// tls_session_key_info_mask

struct tls_crypto_info {
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

// typedef struct tls_record {
// 	uint8_t tr_type;
// 	uint32_t tr_tcp_seq;

// 	uint8_t tr_ciphertext[MAX_RECORD_LEN];
// 	uint16_t tr_cipher_len;
// } tls_record;

typedef struct tls_context {
	uint8_t tc_buf[MAX_BUF_LEN];			/* TLS record buffer */
	uint32_t tc_seq_head;
	uint32_t tc_seq_tail;

	struct tls_crypto_info tc_key_info;
	uint16_t tc_version;
	uint32_t tc_unparse_tcp_seq;
	uint32_t tc_undecrypt_tcp_seq;
	/**< starting point to parse a new record */

	/* tls_record last_rec; */
	// tls_record tc_records[MAX_RECORD_NUM];
	
	uint8_t *tc_plaintext;
	uint16_t tc_plain_len;
} tls_context;

typedef struct conn_info {					/* connection info */
    int ci_sock;                    	    /* socket ID */
    int ci_cli_state;              	  	    /* TCP state of the client */
    int ci_svr_state;                 		/* TCP state of the server */
	uint8_t ci_client_random[TLS_1_3_CLIENT_RANDOM_LEN];

	tls_context ci_tls_ctx[2];
} conn_info;


#endif /* __TLS_H__ */
