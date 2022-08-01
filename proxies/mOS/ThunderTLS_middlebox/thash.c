#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#include "include/thash.h"

/*---------------------------------------------------------------------------*/
struct hashtable*
Create_Hashtable(void)            // equality
{
	int i;
	struct hashtable* ht = calloc(1, sizeof(struct hashtable));

	if (!ht){
		ERROR_PRINT("Error: CreateHashtable()\n");
		return 0;
	}

	/* init the tables */
	for (i = 0; i < NUM_BINS; i++)
		TAILQ_INIT(&ht->ht_table[i]);
	return ht;
}
/*----------------------------------------------------------------------------*/
void
Destroy_Hashtable(struct hashtable *ht)
{
	free(ht);	
}
/*----------------------------------------------------------------------------*/
int 
HT_Insert(struct hashtable *ht, connection *item, uint8_t *hash)
{
	/* create an entry*/ 
	int idx;

	assert(ht);
	assert(ht->ht_count <= 65535); // uint16_t ht_count 

	if (hash) {
		idx = (int)*hash;
    }
	else {
		ERROR_PRINT("Error: wrong Client Random value\n");
        exit(0);
    }

	assert(idx >=0 && idx < NUM_BINS);

	TAILQ_INSERT_TAIL(&ht->ht_table[idx], item, he->he_link);
	item->he->he_mybucket = &ht->ht_table[idx];
	item->ht_idx = AR_CNT;
	ht->ht_count++;
	
	return 0;
}
/*----------------------------------------------------------------------------*/
void*
HT_Remove(struct hashtable *ht, connection *item)
{
	hash_bucket_head *head;

    head = item->he->he_mybucket;
    assert(head);
    TAILQ_REMOVE(head, item, he->he_link);	

	ht->ht_count--;
	return (item);
}	
/*----------------------------------------------------------------------------*/
connection* 
HT_Search(struct hashtable *ht, uint8_t *hash)
{
	connection *walk;
	hash_bucket_head *head;
	int idx;

	if (hash) {
		idx = (int)*hash;
    }
	else {
		ERROR_PRINT("Error: wrong Client Random value\n");
        exit(0);
    }

	head = &ht->ht_table[idx];

	TAILQ_FOREACH(walk, head, he->he_link) {
		if (memcmp(walk->tls_ctx.client_random, hash, TLS_1_3_CLIENT_RANDOM_LEN) == 0) {
            return walk;
        }
	}

	return NULL;
}
/*----------------------------------------------------------------------------*/
