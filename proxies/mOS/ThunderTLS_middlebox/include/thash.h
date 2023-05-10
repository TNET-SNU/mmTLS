#ifndef __THASH_H__
#define __THASH_H__

#include "mmtls.h"
#include "../../core/src/include/memory_mgt.h"

#define NUM_BINS 		(65536)
#define LOWER_16BITS 	(0x0000FFFF)

/* structures for hashtable with client random */
typedef TAILQ_HEAD(ct_hash_bucket_head, ct_element) ct_hash_bucket_head;

typedef struct ct_element {
	session *ct_sess;
	TAILQ_ENTRY(ct_element) ct_link;		/* hash table entry link */
} ct_element;

typedef struct ct_hashtable {
	uint32_t ht_count;
	ct_hash_bucket_head ht_table[NUM_BINS];
} ct_hashtable;

/* structures for hashtable with socket */
typedef TAILQ_HEAD(st_hash_bucket_head, st_element) st_hash_bucket_head;

typedef struct st_element {
	session *st_sess;
	TAILQ_ENTRY(st_element) st_link;		/* hash table entry link */
} st_element;

typedef struct st_hashtable {
	uint32_t ht_count;
	st_hash_bucket_head ht_table[NUM_BINS];
} st_hashtable;

/* functions for connection info table with client random */
ct_hashtable *ct_create(void);
void ct_destroy(ct_hashtable *ht);

int ct_insert(ct_hashtable *ht, uint8_t *crandom, session *c, mem_pool_t pool);
int ct_remove(ct_hashtable *ht, uint8_t *crandom, mem_pool_t pool);
session* ct_search(ct_hashtable *ht, uint8_t *crandom);

/* functions for connection info table with socket descriptor */
st_hashtable *st_create(void);
void st_destroy(st_hashtable *ht);

int st_insert(st_hashtable *ht, int sock, session *c, mem_pool_t pool);
int st_remove(st_hashtable *ht, int sock, mem_pool_t pool);
session* st_search(st_hashtable *ht, int sock);

#endif /* __THASH_H__ */
