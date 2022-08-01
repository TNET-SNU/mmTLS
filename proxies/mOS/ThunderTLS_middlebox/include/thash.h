#ifndef __HASH_H__
#define __HASH_H__

#include "tls.h"

#define NUM_BINS (65536)
#define AR_CNT (3)

/* hashtable structure */
struct hashtable;

/* functions for connection info table */
struct hashtable *ct_create(void);
void ct_destroy(struct hashtable *ht);

int ct_insert(struct hashtable *ht, conn_info *item);
void* ct_remove(struct hashtable *ht, conn_info *item);
conn_info* ct_search(struct hashtable *ht, uint8_t *hash);

#endif /* __HASH_H__ */
