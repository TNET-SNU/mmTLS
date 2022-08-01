#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#include "include/thash.h"

typedef struct hash_bucket_head {
	conn_info *tqh_first;
	conn_info **tqh_last;
} hash_bucket_head;

struct hashtable {
	uint8_t ht_count ;                    // count for # entry
	hash_bucket_head ht_table[NUM_BINS];
};

/*---------------------------------------------------------------------------*/
struct hashtable*
ct_create(void)
{
	int i;
	struct hashtable* ht = calloc(1, sizeof(struct hashtable));

	if (!ht) {
		ERROR_PRINT("Error: CreateHashtable()\n");
		exit(-1);
	}

	/* init the tables */
	for (i = 0; i < NUM_BINS; i++) {
		TAILQ_INIT(&ht->ht_table[i]);
	}

	return ht;
}
/*----------------------------------------------------------------------------*/
void
ct_destroy(struct hashtable *ht)
{
	free(ht);	
}
/*----------------------------------------------------------------------------*/
int 
ct_insert(struct hashtable *ht, conn_info *item)
{
	/* create an entry*/ 
	unsigned short idx;

	assert(ht);

	if (!item->ci_tls_ctx.tc_client_random) {
		ERROR_PRINT("Error: wrong Client Random value\n");
        exit(0);
    }

	idx = (unsigned short)*item->ci_tls_ctx.tc_client_random;
	assert(idx >=0 && idx < NUM_BINS);

	TAILQ_INSERT_TAIL(&ht->ht_table[idx], item, ci_he->he_link);
	item->ci_he->he_mybucket = &ht->ht_table[idx];
	item->ci_ht_idx = AR_CNT;
	ht->ht_count++;
	
	return 0;
}
/*----------------------------------------------------------------------------*/
void*
ct_remove(struct hashtable *ht, conn_info *item)
{
	/* remove an entry */
	hash_bucket_head *head;

    head = item->ci_he->he_mybucket;
    assert(head);
    TAILQ_REMOVE(head, item, ci_he->he_link);	

	ht->ht_count--;

	return (item);
}	
/*----------------------------------------------------------------------------*/
conn_info* 
ct_search(struct hashtable *ht, uint8_t *hash)
{
	conn_info *walk;
	hash_bucket_head *head;
	unsigned short idx;

	if (!hash) {
		ERROR_PRINT("Error: wrong hash value\n");
        exit(-1);
    }

	idx = (unsigned short)*hash;
	head = &ht->ht_table[idx];

	TAILQ_FOREACH(walk, head, ci_he->he_link) {
		if (memcmp(walk->ci_tls_ctx.tc_client_random, hash, TLS_1_3_CLIENT_RANDOM_LEN) == 0) {
            return walk;
        }
	}

	return NULL;
}
/*----------------------------------------------------------------------------*/
