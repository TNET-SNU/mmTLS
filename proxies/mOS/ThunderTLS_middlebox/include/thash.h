#ifndef __THASH_H__
#define __THASH_H__

#include "tls.h"

#define NUM_BINS 		(65536)
#define LOWER_16BITS 	(0x0000FFFF)

/* hashtable structure */
struct ct_hashtable;
struct st_hashtable;

/* functions for connection info table with client random */
struct ct_hashtable *ct_create(void);
void ct_destroy(struct ct_hashtable *ht);

int ct_insert(struct ct_hashtable *ht, uint8_t crandom[TLS_1_3_CLIENT_RANDOM_LEN], conn_info *c);
int ct_remove(struct ct_hashtable *ht, uint8_t crandom[TLS_1_3_CLIENT_RANDOM_LEN]);
conn_info* ct_search(struct ct_hashtable *ht, uint8_t crandom[TLS_1_3_CLIENT_RANDOM_LEN]);

/* functions for connection info table with socket descriptor */
struct st_hashtable *st_create(void);
void st_destroy(struct st_hashtable *ht);

int st_insert(struct st_hashtable *ht, int sock, conn_info *c);
int st_remove(struct st_hashtable *ht, int sock);
conn_info* st_search(struct st_hashtable *ht, int sock);

#endif /* __THASH_H__ */
