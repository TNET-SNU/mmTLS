#ifndef __TLS_H__
#define __TLS_H__

#include <stdint.h>
#include <sys/queue.h>

#define MAX_BUF_LEN      1048576    /* 1M */
#define MAX_RECORD_LEN   16384		/* 16K */
#define MAX_RECORD_NUM   128
#define MAX_KEY_SIZE     128
#define MAX_IV_SIZE      16

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
    unsigned char client_key[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
    unsigned char client_iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
    unsigned char server_key[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
    unsigned char server_iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];

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

typedef struct tls_record {
	uint8_t tr_type;
	uint32_t tr_tcp_seq;
	uint64_t tr_rec_seq;

	uint8_t tr_plaintext[MAX_RECORD_LEN];
	uint8_t tr_ciphertext[MAX_RECORD_LEN];
	uint16_t tr_plain_len;
	uint16_t tr_cipher_len;
} tls_record;

typedef struct tls_context {
	uint16_t tc_version;
	// uint8_t tc_client_random[TLS_1_3_CLIENT_RANDOM_LEN];
	struct tls_crypto_info tc_key_info;
	uint64_t tc_last_rec_seq[2];
	uint32_t tc_unparse_tcp_seq[2];
	/**< starting point to parse a new record */

	/* tls_record last_rec[2]; */
	tls_record tc_records[2][MAX_RECORD_NUM];
	uint32_t tc_record_head[2];
	uint32_t tc_record_tail[2];
	uint32_t tc_record_cnt[2];
	uint32_t tc_decrypt_record_idx[2];
} tls_context;

struct ct_hash_elements {
	struct ct_hash_bucket_head *he_mybucket;
	TAILQ_ENTRY(ct_element) he_link;		/* hash table entry link */
};

struct st_hash_elements {
	struct st_hash_bucket_head *he_mybucket;
	TAILQ_ENTRY(st_element) he_link;		/* hash table entry link */
};

typedef struct conn_info {					/* connection info */
    // int ci_sock;                    	    /* socket ID */
    int ci_cli_state;              	  	    /* TCP state of the client */
    int ci_svr_state;                 		/* TCP state of the server */

	uint8_t ci_buf[2][MAX_BUF_LEN];			/* TLS record buffer */
	uint32_t ci_seq_head[2];
	uint32_t ci_seq_tail[2];

	tls_context ci_tls_ctx;

	struct ct_hash_elements ci_ct_he;
	struct st_hash_elements ci_st_he;
    // TAILQ_ENTRY(conn_info) ci_link;         /* link to next context in this core */
} conn_info;


#endif /* __TLS_H__ */
