#ifndef __TLS_H__
#define __TLS_H__

#define MAX_RECORD_LEN   16384		/* 16K */
#define MAX_RECORD_NUM   128
#define MAX_KEY_SIZE     128
#define MAX_IV_SIZE      16
	
#define TLS_CIPHER_AES_GCM_256_KEY_SIZE 32
#define TLS_CIPHER_AES_GCM_256_TAG_SIZE 16
#define TLS_CIPHER_AES_GCM_256_IV_SIZE 12
#define TLS_CIPHER_AES_GCM_256_AAD_SIZE 5
/* #define AES_256_KEY_LEN  32 */
/* #define AES_GCM_IV_LEN   12 */

#define PRINT (stderr)  

#define VERBOSE_DEBUG   0
#define VERBOSE_ERROR   1

#if VERBOSE_ERROR
#define ERROR_PRINT(fmt, args...) fprintf(PRINT, ANSI_COLOR_GREEN \
                                    ""fmt""ANSI_COLOR_RESET, ##args)
#else
#define ERROR_PRINT(fmt, args...) (void)0
#endif

#if VERBOSE_DEBUG
#define DECRYPT_PRINT(fmt, args...) fprintf(PRINT, ""fmt"", ##args)
#else
#define DECRYPT_PRINT(fmt, args...) (void)0
#endif

/* Print message coloring */
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_RESET   "\x1b[0m"

enum {
    CHANGE_CIPHER_SPEC  = 0x14,
    ALERT               = 0x15,
    HANDSHAKE           = 0x16,
    APPLICATION_DATA    = 0x17,
} tls_record_type;

enum {
    CLI_KEY_MASK = 0x1,
	SRV_KEY_MASK = 0x2,
	CLI_IV_MASK  = 0x4,
	SRV_IV_MASK  = 0x8,
} tls_session_key_info_mask;

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
	uint8_t type;
	uint32_t tcp_seq;
	uint64_t rec_seq;

	uint8_t plaintext[MAX_RECORD_LEN];
	uint8_t ciphertext[MAX_RECORD_LEN];
	uint16_t plain_len;
	uint16_t cipher_len;
} tls_record;

typedef struct tls_context {
	uint16_t version;

	struct tls_crypto_info key_info;

	uint64_t last_rec_seq[2];
	
	uint32_t unparse_tcp_seq[2];
	/**< starting point to parse a new record */

	/* tls_record last_rec[2]; */
	tls_record records[2][MAX_RECORD_NUM];
	uint32_t record_head[2];
	uint32_t record_tail[2];
	uint32_t record_cnt[2];
	uint32_t decrypt_record_idx[2];
} tls_context;

#endif /* __TLS_H__ */
