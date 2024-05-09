#include "keysend.h"
/*---------------------------------------------------------------------------*/
static inline void hexdump(const char *title, uint8_t *buf, size_t len) {
  if (title)
    fprintf(stdout, "%s\n", title);
  for (size_t i = 0; i < len; i++)
    fprintf(stdout, "%02X%c", buf[i], ((i + 1) % 16 ? ' ' : '\n'));
  fprintf(stdout, "\n");
}
/*---------------------------------------------------------------------------*/
static inline int read_hex(uint8_t *dst, const char *src, int max) {
  int len = 0;
  for (int i = 0; src[i] && src[i + 1]; i += 2) {
    if (!sscanf(src + i, "%2hhx", (char *)dst + len++)) {
      fprintf(stderr, "Error: [%s] sscanf fail\n", __FUNCTION__);
      exit(EXIT_FAILURE);
    }
    if (len > max) {
      fprintf(stderr, "Error: read_hex fail (%d > %d)\n", len, max);
      exit(EXIT_FAILURE);
    }
  }
  return len;
}
/*---------------------------------------------------------------------------*/
static void select_cipher(const SSL *ssl, const EVP_CIPHER **evp_cipher,
                          const EVP_MD **evp_md) {
  const SSL_CIPHER *ssl_cipher;
  const char *IANA_cipher_name;

  if (!(ssl_cipher = SSL_get_current_cipher(ssl))) {
    fprintf(stderr, "SSL_get_current_cipher failed");
    exit(EXIT_FAILURE);
  }
  IANA_cipher_name = SSL_CIPHER_standard_name(ssl_cipher);
  if (strstr(IANA_cipher_name, "_GCM_")) {
    if (strstr(IANA_cipher_name, "AES_256")) {
      *evp_cipher = EVP_aes_256_gcm();
      *evp_md = EVP_sha384();
    } else if (strstr(IANA_cipher_name, "AES_128")) {
      *evp_cipher = EVP_aes_128_gcm();
      *evp_md = EVP_sha256();
    } else {
      fprintf(stderr, "Not supported cipher suite: %s\n", IANA_cipher_name);
      exit(EXIT_FAILURE);
    }
  } else if (strstr(IANA_cipher_name, "_CHACHA20_")) {
    *evp_cipher = EVP_chacha20_poly1305();
    *evp_md = EVP_sha256();
  } else if (strstr(IANA_cipher_name, "_CBC_")) {
    if (strstr(IANA_cipher_name, "AES_256"))
      *evp_cipher = EVP_aes_256_cbc();
    else if (strstr(IANA_cipher_name, "AES_128"))
      *evp_cipher = EVP_aes_128_cbc();
    else {
      fprintf(stderr, "Not supported cipher suite: %s\n", IANA_cipher_name);
      exit(EXIT_FAILURE);
    }
    if (strstr(IANA_cipher_name, "SHA256"))
      *evp_md = EVP_sha256();
    else if (strstr(IANA_cipher_name, "SHA384"))
      *evp_md = EVP_sha384();
    else if (strstr(IANA_cipher_name, "SHA"))
      *evp_md = EVP_sha1();
    else {
      fprintf(stderr, "Not supported cipher suite: %s\n", IANA_cipher_name);
      exit(EXIT_FAILURE);
    }
  } else if (strstr(IANA_cipher_name, "_CCM_")) {
    if (strstr(IANA_cipher_name, "AES_256"))
      *evp_cipher = EVP_aes_256_ccm();
    else if (strstr(IANA_cipher_name, "AES_128"))
      *evp_cipher = EVP_aes_128_ccm();
    else {
      fprintf(stderr, "Not supported cipher suite: %s\n", IANA_cipher_name);
      exit(EXIT_FAILURE);
    }
    if (strstr(IANA_cipher_name, "SHA256"))
      *evp_md = EVP_sha256();
    else if (strstr(IANA_cipher_name, "SHA384"))
      *evp_md = EVP_sha384();
    else if (strstr(IANA_cipher_name, "SHA"))
      *evp_md = EVP_sha1();
    else {
      fprintf(stderr, "Not supported cipher suite: %s\n", IANA_cipher_name);
      exit(EXIT_FAILURE);
    }
  } else {
    fprintf(stderr, "Not supported mode: %s\n", IANA_cipher_name);
    exit(EXIT_FAILURE);
  }
  printf("IANA_cipher_name: %s\n", IANA_cipher_name);
}
/*---------------------------------------------------------------------------*/
static inline unsigned char *HKDF_expand(const EVP_MD *evp_md,
                                         const unsigned char *prk,
                                         size_t prk_len, const char *label,
                                         unsigned char *okm, size_t okm_len) {
  HMAC_CTX *hmac = HMAC_CTX_new();
  unsigned int i;
  unsigned char *ret = NULL, ctr;
  unsigned char prev[EVP_MAX_MD_SIZE] = {0}, data[MAX_DATA_LEN];
  size_t label_len = strlen(label), done_len = 0, md_len = EVP_MD_size(evp_md);
  size_t len = 0, N = (okm_len - 1) / md_len + 1, copy_len;

  if (N > 255 || okm == NULL || prk == NULL || hmac == NULL)
    return NULL;
  if (!HMAC_Init(hmac, prk, prk_len, evp_md))
    goto err;

  *(uint16_t *)data = htobe16(okm_len);
  len += sizeof(uint16_t);
  *(data + len) = label_len;
  len += sizeof(uint8_t);
  memcpy(data + len, label, label_len);
  len += label_len;
  *(data + len) = '\0';
  len += sizeof(uint8_t);

  for (i = 1; i <= N; i++) {
    ctr = i;
    if (i > 1) {
      fprintf(stderr, "[%s] Not implemented now\n", __FUNCTION__);
      goto err;
      // if (!HMAC_Init(hmac, NULL, 0, NULL))
      //   goto err;
      // if (!HMAC_Update(hmac, prev, md_len))
      //   goto err;
      // data[len - 1] = ctr;
    } else
      data[len++] = ctr;
    if (!HMAC_Update(hmac, (const unsigned char *)data, len))
      goto err;
    if (!HMAC_Final(hmac, prev, NULL))
      goto err;
    copy_len = (md_len > okm_len - done_len) ? okm_len - done_len : md_len;
    memcpy(okm + done_len, prev, copy_len);
    done_len += copy_len;
  }
  ret = okm;

err:
  OPENSSL_cleanse(prev, sizeof(prev));
  HMAC_CTX_free(hmac);

  return ret;
}
/*---------------------------------------------------------------------------*/
static inline void get_write_key_iv_13(const EVP_CIPHER *evp_cipher,
                                       const EVP_MD *evp_md, uint8_t *secret,
                                       int secret_len, uint8_t *key_out,
                                       uint8_t *iv_out) {
  HKDF_expand(evp_md, (const uint8_t *)secret, secret_len, "tls13 key", key_out,
              EVP_CIPHER_key_length(evp_cipher));
  HKDF_expand(evp_md, (const uint8_t *)secret, secret_len, "tls13 iv", iv_out,
              EVP_CIPHER_iv_length(evp_cipher));
}
/*---------------------------------------------------------------------------*/
/* ToDo, make below function pretty one day */
static inline void
get_write_key_iv_12_aead(const EVP_CIPHER *evp_cipher, const EVP_MD *evp_md,
                         uint8_t *crand, uint8_t *srand, int random_len,
                         uint8_t *msecret, int secret_len, uint8_t *c_key,
                         uint8_t *s_key, uint8_t *c_iv, uint8_t *s_iv) {
  int key_len = EVP_CIPHER_key_length(evp_cipher);
  int iv_len = EVP_CIPHER_iv_length(evp_cipher);
  int md_len = EVP_MD_size(evp_md);
  uint8_t p[BUF_SIZE], seed[BUF_SIZE];
  uint8_t a1[BUF_SIZE], a2[BUF_SIZE];
  int seed_len = strlen("key expansion") + 2 * random_len;

  memcpy(seed, "key expansion", strlen("key expansion"));
  memcpy(seed + strlen("key expansion"), srand, random_len);
  memcpy(seed + strlen("key expansion") + random_len, crand, random_len);

  HMAC(evp_md, msecret, secret_len, seed, seed_len, a1, NULL);
  HMAC(evp_md, msecret, secret_len, a1, md_len, a2, NULL);

  memcpy(a1 + md_len, seed, seed_len);
  HMAC(evp_md, msecret, secret_len, a1, seed_len + md_len, p, NULL);

  memcpy(a2 + md_len, seed, seed_len);
  HMAC(evp_md, msecret, secret_len, a2, seed_len + md_len, p + md_len, NULL);

  memcpy(c_key, p, key_len);
  memcpy(s_key, p + key_len, key_len);
  memcpy(c_iv, p + key_len + key_len, EVP_GCM_TLS_FIXED_IV_LEN);
  memcpy(s_iv, p + key_len + key_len + EVP_GCM_TLS_FIXED_IV_LEN,
         EVP_GCM_TLS_FIXED_IV_LEN);
}
/*---------------------------------------------------------------------------*/
static inline void get_write_key_iv_12_cbc(const EVP_CIPHER *evp_cipher,
                                           const EVP_MD *evp_md, uint8_t *crand,
                                           uint8_t *srand, int random_len,
                                           uint8_t *msecret, int secret_len,
                                           uint8_t *c_mac, uint8_t *s_mac,
                                           uint8_t *c_key, uint8_t *s_key,
                                           uint8_t *c_iv, uint8_t *s_iv) {
  int key_len = EVP_CIPHER_key_length(evp_cipher);
  int iv_len = EVP_CIPHER_iv_length(evp_cipher);
  int md_len = EVP_MD_size(evp_md);
  uint8_t p[BUF_SIZE], seed[BUF_SIZE];
  uint8_t a1[BUF_SIZE], a2[BUF_SIZE], a3[BUF_SIZE], a4[BUF_SIZE], a5[BUF_SIZE];
  int seed_len = strlen("key expansion") + 2 * random_len;

  memcpy(seed, "key expansion", strlen("key expansion"));
  memcpy(seed + strlen("key expansion"), srand, random_len);
  memcpy(seed + strlen("key expansion") + random_len, crand, random_len);

  HMAC(evp_md, msecret, secret_len, seed, seed_len, a1, NULL);
  HMAC(evp_md, msecret, secret_len, a1, md_len, a2, NULL);
  HMAC(evp_md, msecret, secret_len, a2, md_len, a3, NULL);
  HMAC(evp_md, msecret, secret_len, a3, md_len, a4, NULL);
  HMAC(evp_md, msecret, secret_len, a4, md_len, a5, NULL);

  memcpy(a1 + md_len, seed, seed_len);
  HMAC(evp_md, msecret, secret_len, a1, seed_len + md_len, p, NULL);

  memcpy(a2 + md_len, seed, seed_len);
  HMAC(evp_md, msecret, secret_len, a2, seed_len + md_len, p + md_len, NULL);

  memcpy(a3 + md_len, seed, seed_len);
  HMAC(evp_md, msecret, secret_len, a3, seed_len + md_len, p + md_len + md_len,
       NULL);

  memcpy(a4 + md_len, seed, seed_len);
  HMAC(evp_md, msecret, secret_len, a4, seed_len + md_len,
       p + md_len + md_len + md_len, NULL);

  memcpy(a5 + md_len, seed, seed_len);
  HMAC(evp_md, msecret, secret_len, a5, seed_len + md_len,
       p + md_len + md_len + md_len + md_len, NULL);

  memcpy(c_mac, p, md_len);
  memcpy(s_mac, p + md_len, md_len);
  memcpy(c_key, p + md_len + md_len, key_len);
  memcpy(s_key, p + md_len + md_len + key_len, key_len);
  memcpy(c_iv, p + md_len + md_len + key_len + key_len, iv_len);
  memcpy(s_iv, p + md_len + md_len + key_len + key_len + iv_len, iv_len);
}
/*---------------------------------------------------------------------------*/
int SSL_set_sockaddr(SSL *ssl, struct sockaddr_in *sock) {
  return SSL_set_ex_data(ssl, CUSTOM_APP_INDEX + 1, sock);
}
/*---------------------------------------------------------------------------*/
void destroy_key_channel(SSL_CTX *ssl_ctx) {
  int key_chan_sd;
  SSL_CTX *key_ctx;
  SSL *key_ssl;
  struct key_chan *channel = (struct key_chan *)SSL_CTX_get_app_data(ssl_ctx);
  if (!channel)
    return;
  key_ctx = SSL_get_SSL_CTX(channel->key_ssl[0]);
  if (!key_ctx)
    return;
  for (int i = 0; i < channel->num_chan; i++) {
    pthread_mutex_destroy(&channel->mutex[i]);
    key_ssl = channel->key_ssl[i];
    if (!key_ssl)
      continue;
    key_chan_sd = SSL_get_fd(key_ssl);
    SSL_shutdown(key_ssl);
    SSL_free(key_ssl);
    if (key_chan_sd > 0)
      close(key_chan_sd);
  }
  SSL_CTX_free(key_ctx);
}
/*---------------------------------------------------------------------------*/
static inline struct key_chan *alloc_key_channel(int nthread) {
  struct key_chan *channel;
  if (!(channel = (struct key_chan *)calloc(1, sizeof(struct key_chan)))) {
    perror("calloc");
    return NULL;
  }
  channel->num_chan = nthread;
  channel->cnt = (int *)calloc(nthread, sizeof(int));
  channel->key_ssl = (SSL **)calloc(nthread, sizeof(SSL *));
  channel->mutex = (pthread_mutex_t *)calloc(nthread, sizeof(pthread_mutex_t));

  return channel;
}
/*---------------------------------------------------------------------------*/
int init_key_channel(SSL_CTX *ssl_ctx, int nthread) {
  int key_chan_sd;
  struct key_chan *channel = NULL;
  SSL_CTX *key_ctx = NULL;
  struct sockaddr_in svraddr;

  /* get key server address */
  char *key_server_addr = getenv("KEYSERVERADDR");
  if (!key_server_addr) {
    perror("KEYSERVERADDR not set");
    return -1;
  }
  /* Load cryptos, et.al. */
  if (OpenSSL_add_all_algorithms() < 0) {
    perror("OpenSSL_add_all_algorithms");
    return -1;
  }
  /* Bring in and register error messages */
  if (SSL_load_error_strings() < 0) {
    perror("SSL_load_error_strings");
    return -1;
  }
  if (!(channel = alloc_key_channel(nthread))) {
    perror("alloc_key_channel");
    return -1;
  }
  if (!(key_ctx = SSL_CTX_new(TLS_client_method()))) {
    ERR_print_errors_fp(stderr);
    goto err;
  }
  if (!(SSL_CTX_set_options(key_ctx, SSL_OP_NO_TICKET) & SSL_OP_NO_TICKET)) {
    perror("SSL_CTX_set_options");
    goto err;
  }
  SSL_CTX_set_session_cache_mode(key_ctx, SSL_SESS_CACHE_OFF);

  for (int i = 0; i < nthread; i++) {
    /* initialize mutex */
    if (pthread_mutex_init(&channel->mutex[i], NULL) < 0) {
      perror("pthread_mutex_init");
      goto err;
    }
    if (!(channel->key_ssl[i] = SSL_new(key_ctx))) {
      ERR_print_errors_fp(stderr);
      goto err;
    }
    /* TCP connection */
    int optval = 1;
    if ((key_chan_sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
      perror("socket");
      goto err;
    }
    if (setsockopt(key_chan_sd, SOL_SOCKET, SO_REUSEPORT, &optval,
                   sizeof(optval)) < 0) {
      perror("setsockopt");
      goto err;
    }
    bzero(&svraddr, sizeof(svraddr));
    svraddr.sin_family = AF_INET;
    svraddr.sin_addr.s_addr = inet_addr(key_server_addr);
    svraddr.sin_port = htons(TLS_PORT);
    if (connect(key_chan_sd, (struct sockaddr *)&svraddr, sizeof(svraddr)) <
        0) {
      perror("connect");
      goto err;
    }
    if (SSL_set_fd(channel->key_ssl[i], key_chan_sd) < 0) {
      ERR_print_errors_fp(stderr);
      goto err;
    }
    if (SSL_connect(channel->key_ssl[i]) < 0) {
      ERR_print_errors_fp(stderr);
      goto err;
    }
    printf("connected!\n");
  }
  if (SSL_CTX_set_app_data(ssl_ctx, channel) < 0) {
    ERR_print_errors_fp(stderr);
    goto err;
  }

  return 0;

err:
  destroy_key_channel(ssl_ctx);
  return -1;
}
/*---------------------------------------------------------------------------*/
void keysend_callback(const SSL *ssl, const char *line) {
  /*
   * we had called keylog_callback in keysend_callback
   * to decrypt and see the captured packets, but not necessary now
   */
  // keylog_callback(ssl, line);
  SSL_CTX *ssl_ctx;
  struct key_chan *channel;
  int random_len, secret_len, res, bytes, sd, channel_id, offset = 0;
  struct sockaddr_in cliaddr, svraddr;
  socklen_t socketlen = sizeof(struct sockaddr_in);
  uint8_t *ptr;
  uint8_t payload[BUF_SIZE];

  /* line parsing */
  uint8_t flag;
  enum { CLIENT_SIDE = 1, SERVER_SIDE = 2, TLS12 = 3 };
  struct pair_secret {
    uint8_t traffic_secret[MAX_SECRET_LEN];
    uint8_t flag;
  } *ps;
  char secret_buf[BUF_SIZE], crandom_buf[BUF_SIZE];
  uint8_t crandom[MAX_RANDOM_LEN], srandom[MAX_RANDOM_LEN],
      secret[MAX_SECRET_LEN];

  /* TLS parameter */
  const SSL_CIPHER *ssl_cipher;
  const char *IANA_cipher_name;
  const EVP_MD *evp_md;
  const EVP_CIPHER *evp_cipher;
  int aead, key_len, iv_len, mac_key_len = 0;

  /* key and iv */
  uint8_t client_write_key[EVP_MAX_KEY_LENGTH];
  uint8_t client_write_iv[EVP_MAX_IV_LENGTH];
  uint8_t client_mac_key[EVP_MAX_MD_SIZE];
  uint8_t server_write_key[EVP_MAX_KEY_LENGTH];
  uint8_t server_write_iv[EVP_MAX_IV_LENGTH];
  uint8_t server_mac_key[EVP_MAX_MD_SIZE];

  /* line parsing start */
  if ((res = sscanf(line, "CLIENT_TRAFFIC_SECRET_0 %s %s", crandom_buf,
                    secret_buf)) > 0)
    flag = CLIENT_SIDE; /* tls1.3 */
  else if ((res = sscanf(line, "SERVER_TRAFFIC_SECRET_0 %s %s", crandom_buf,
                         secret_buf)) > 0)
    flag = SERVER_SIDE; /* tls1.3 */
  else if ((res = sscanf(line, "CLIENT_RANDOM %s %s", crandom_buf,
                         secret_buf)) > 0)
    flag = TLS12; /* tls1.2 */
  else
    return; /* irrelevant lines */
  if (res != 2) {
    fprintf(stderr, "wrong line format, line = %s\n", line);
    exit(EXIT_FAILURE);
  }
  random_len = read_hex(crandom, (const char *)crandom_buf, BUF_SIZE);
  secret_len = read_hex(secret, (const char *)secret_buf, BUF_SIZE);

  /* if TLS13, find pair */
  // if (flag != TLS12 && !(ps = (struct pair_secret *)SSL_get_app_data(ssl))) {
  if (flag != TLS12 &&
      !(ps = (struct pair_secret *)SSL_get_ex_data(ssl, CUSTOM_APP_INDEX))) {
    /* not found, insert */
    if (!(ps = (struct pair_secret *)calloc(1, sizeof(struct pair_secret))))
      fprintf(stderr, "Error: [%s] calloc() failed\n", __FUNCTION__);

    // SSL_set_app_data((SSL *)ssl, ps);
    SSL_set_ex_data((SSL *)ssl, CUSTOM_APP_INDEX, ps);
    memcpy(ps->traffic_secret, secret, secret_len);
    ps->flag = flag;
    return;
  }

  /* get parameters */
  select_cipher(ssl, &evp_cipher, &evp_md);

  aead = EVP_CIPHER_get_flags(evp_cipher) & EVP_CIPH_FLAG_AEAD_CIPHER;
  key_len = EVP_CIPHER_key_length(evp_cipher);
  iv_len = EVP_CIPHER_iv_length(evp_cipher);
  mac_key_len = aead ? 0 : EVP_MD_size(evp_md);

  /* get key and iv */
  if (flag != TLS12) {
    /* TLSv1.3 cipher suites are all AEAD */
    get_write_key_iv_13(
        evp_cipher, evp_md, secret, secret_len,
        (flag == CLIENT_SIDE) ? client_write_key : server_write_key,
        (flag == CLIENT_SIDE) ? client_write_iv : server_write_iv);
    get_write_key_iv_13(
        evp_cipher, evp_md, ps->traffic_secret, secret_len,
        (ps->flag == CLIENT_SIDE) ? client_write_key : server_write_key,
        (ps->flag == CLIENT_SIDE) ? client_write_iv : server_write_iv);
    free(ps);
  } else {
    SSL_get_server_random(ssl, srandom, random_len);
    if (aead)
      get_write_key_iv_12_aead(
          evp_cipher, evp_md, crandom, srandom, random_len, secret, secret_len,
          client_write_key, server_write_key, client_write_iv, server_write_iv);
    else
      /* !! cbc only supported among non-AEAD ciphers !! */
      get_write_key_iv_12_cbc(
          evp_cipher, evp_md, crandom, srandom, random_len, secret, secret_len,
          client_mac_key, server_mac_key, client_write_key, server_write_key,
          client_write_iv, server_write_iv);
  }

  /* get 4-tuple */
  bzero(&cliaddr, sizeof(cliaddr));
  bzero(&svraddr, sizeof(svraddr));
  if ((sd = SSL_get_fd(ssl)) < 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  if (getsockname(sd, (struct sockaddr *)&cliaddr, &socketlen) < 0) {
    perror("getsockname");
    exit(EXIT_FAILURE);
  }
  if (getpeername(sd, (struct sockaddr *)&svraddr, &socketlen) < 0) {
    perror("getpeername");
    exit(EXIT_FAILURE);
  }

  /* make key msg */
  ptr = payload;
  /* clientrandom | TLSversion | ciphersuite | infosize | keyinfo | 4-tuple */
  memcpy(ptr, crandom, random_len);
  ptr += random_len;
  *(uint16_t *)ptr = htobe16(SSL_version(ssl));
  ptr += sizeof(uint16_t);
  *(uint16_t *)ptr =
      htobe16(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(ssl)));
  ptr += sizeof(uint16_t);
  *(uint16_t *)ptr = htobe16(key_len + iv_len + mac_key_len);
  ptr += sizeof(uint16_t);
  memcpy(ptr, client_write_key, key_len);
  ptr += key_len;
  memcpy(ptr, client_write_iv, iv_len);
  ptr += iv_len;
  memcpy(ptr, client_mac_key, mac_key_len);
  ptr += mac_key_len;
  memcpy(ptr, server_write_key, key_len);
  ptr += key_len;
  memcpy(ptr, server_write_iv, iv_len);
  ptr += iv_len;
  memcpy(ptr, server_mac_key, mac_key_len);
  ptr += mac_key_len;
  memcpy(ptr, &cliaddr.sin_addr.s_addr, sizeof(uint32_t)); /* src ip */
  ptr += sizeof(uint32_t);
  memcpy(ptr, &svraddr.sin_addr.s_addr, sizeof(uint32_t)); /* dst ip */
  ptr += sizeof(uint32_t);
  memcpy(ptr, &cliaddr.sin_port, sizeof(uint16_t)); /* src port */
  ptr += sizeof(uint16_t);
  memcpy(ptr, &svraddr.sin_port, sizeof(uint16_t)); /* dst port */
  ptr += sizeof(uint16_t);

  /* for debugging, currently not used */
  // printf("key_len: %d, iv_len: %d, mac_key_len: %d\n",
  //        key_len, iv_len, mac_key_len);
  // hexdump("client key", client_write_key, key_len);
  // hexdump("client iv", client_write_iv, iv_len);
  // hexdump("client mac key", client_mac_key, mac_key_len);
  // hexdump("server key", server_write_key, key_len);
  // hexdump("server iv", server_write_iv, iv_len);
  // hexdump("server mac key", server_mac_key, mac_key_len);
  // printf("cliaddr.sin_port: %d\n", ntohs(cliaddr.sin_port));

  /* send */
  /* use channels evenly */
  channel_id = sched_getcpu() % channel->num_chan;
  ssl_ctx = SSL_get_SSL_CTX(ssl);
  if (!ssl_ctx) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  channel = (struct key_chan *)SSL_CTX_get_app_data(ssl_ctx);
  if (!channel) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  /* guarantee atomicity for each channel */
  pthread_mutex_lock(&channel->mutex[channel_id]);
  do {
    bytes = SSL_write(channel->key_ssl[channel_id], payload + offset,
                      BUF_SIZE - offset);
    if (bytes <= 0)
      continue;
    offset += bytes;
  } while (offset < BUF_SIZE);
  pthread_mutex_unlock(&channel->mutex[channel_id]);
  if (offset > BUF_SIZE) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  /* leave a log */
  channel->cnt[channel_id]++;
  int total_cnt = 0;
  for (int i = 0; i < channel->num_chan; i++)
    total_cnt += channel->cnt[i];
  printf("sent key! %d\n", total_cnt);
}
