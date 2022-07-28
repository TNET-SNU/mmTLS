#ifndef __HASH_H__
#define __HASH_H__

#include <sys/queue.h>

#include "tls.h"

#define NUM_BINS (131072)     /* 132 K */
#define AR_CNT (3)

typedef struct hash_bucket_head {
	connection *tqh_first;
	connection **tqh_last;
} hash_bucket_head;

/* hashtable structure */
struct hashtable {
	uint8_t ht_count ;                    // count for # entry

	hash_bucket_head ht_table[NUM_BINS];
};

/*functions for hashtable*/
struct hashtable *Create_Hashtable(void);
void Destroy_Hashtable(struct hashtable *ht);


int HT_Insert(struct hashtable *ht, connection *item, uint8_t *hash);
void* HT_Remove(struct hashtable *ht, connection *item);
connection* HT_Search(struct hashtable *ht, uint8_t *hash);

#endif /* __HASH_H__ */
