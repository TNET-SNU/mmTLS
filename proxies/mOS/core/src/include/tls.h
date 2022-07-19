#ifndef __TLS_H_
#define __TLS_H_

/* #include "tcp_stream.h" */
#include "mos_api.h"
#include "mtcp.h"

#define MAX_KEYBLOCK_SIZE 1024

#define TLS_CIPHER_AES_GCM_256_KEY_SIZE 32
#define TLS_CIPHER_AES_GCM_256_IV_SIZE 12

struct tls_crypto_info {
    unsigned short version;
    unsigned short cipher_type;

    uint16_t key_mask;
    unsigned char client_key[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
    unsigned char client_iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
    unsigned char server_key[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
    unsigned char server_iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
};

#endif
