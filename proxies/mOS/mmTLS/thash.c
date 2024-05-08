#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/queue.h>

#include "include/thash.h"

#ifdef LEADER_FOLLOWER
/* Below are deprecated..
 * mmtls no longer uses its own hash table */
/*---------------------------------------------------------------------------*/
ct_hashtable *
ct_create(void)
{
	ct_hashtable *ht;
	if (!(ht = calloc(1, sizeof(ct_hashtable))))
		return NULL;
	/* init the tables */
	for (int i = 0; i < NUM_BINS; i++)
		TAILQ_INIT(&ht->ht_table[i]);

	return ht;
}
/*----------------------------------------------------------------------------*/
void
ct_destroy(ct_hashtable *ht)
{
	free(ht);
}
/*----------------------------------------------------------------------------*/
static inline ct_element * 
ct_search_int(ct_hashtable *ht, uint8_t *crandom)
{
	ct_element *walk;
	ct_hash_bucket_head *head = &ht->ht_table[*(unsigned short *)crandom];

	TAILQ_FOREACH(walk, head, ct_link) {
		if (memcmp(walk->ct_sess->sess_info.client_random,
					crandom, TLS_1_3_CLIENT_RANDOM_LEN) == 0) 
			return walk;
	}

	return NULL;
}
/*----------------------------------------------------------------------------*/
int 
ct_insert(ct_hashtable *ht, uint8_t *crandom, mmtls *c, mem_pool_t pool)
{
	ct_element *item;

	if ((item = ct_search_int(ht, crandom))) 
		return -1;

	if (!(item = (ct_element *)MPAllocateChunk(pool)))
		return -1;

	/* MPAlloc needs memset */
	memset(item, 0, sizeof(ct_element));
	item->ct_sess = c;

	TAILQ_INSERT_TAIL(&ht->ht_table[*(unsigned short *)crandom], item, ct_link);
	ht->ht_count++;
	
	return 1;
}
/*----------------------------------------------------------------------------*/
session *
ct_search(ct_hashtable *ht, uint8_t *crandom)
{
	ct_element *item;

	if (!(item = ct_search_int(ht, crandom)))
		return NULL;

	return item->ct_sess;
}
/*----------------------------------------------------------------------------*/
int
ct_remove(ct_hashtable *ht, uint8_t *crandom, mem_pool_t pool)
{
	ct_hash_bucket_head *head;
	ct_element *item;

	if (!(item = ct_search_int(ht, crandom))) 
		return -1;

    head = &ht->ht_table[*(unsigned short *)crandom];
    TAILQ_REMOVE(head, item, ct_link);
	ht->ht_count--;
	MPFreeChunk(pool, item);

	return 1;
}
#endif
/*----------------------------------------------------------------------------*/
st_hashtable *
st_create(void)
{
	st_hashtable *ht;

	if (!(ht = calloc(1, sizeof(st_hashtable))))
		return NULL;
	/* init the tables */
	for (int i = 0; i < NUM_BINS; i++)
		TAILQ_INIT(&ht->ht_table[i]);

	return ht;
}
/*----------------------------------------------------------------------------*/
void
st_destroy(st_hashtable *ht)
{
	free(ht);
}
/*----------------------------------------------------------------------------*/
static inline st_element *
st_search_int(st_hashtable *ht, int sock)
{
	st_element *walk;
	st_hash_bucket_head *head = &ht->ht_table[sock & LOWER_16BITS];

	TAILQ_FOREACH(walk, head, st_link) {
		if (walk->st_sess->sess_info.sock == sock) 
			return walk;
	}

	return NULL;
}
/*----------------------------------------------------------------------------*/
int 
st_insert(st_hashtable *ht, int sock, session *c, mem_pool_t pool)
{
	st_element *item;

	if (!(item = (st_element *)MPAllocateChunk(pool)))
		return -1;
	/* MPAlloc needs memset */
	memset(item, 0, sizeof(st_element));
	item->st_sess = c;

	TAILQ_INSERT_TAIL(&ht->ht_table[sock & LOWER_16BITS], item, st_link);
	ht->ht_count++;
	
	return 1;
}
/*----------------------------------------------------------------------------*/
session * 
st_search(st_hashtable *ht, int sock)
{
	st_element *item;

	if (!(item = st_search_int(ht, sock)))
		return NULL;

	return item->st_sess;
}
/*----------------------------------------------------------------------------*/
int
st_remove(st_hashtable *ht, int sock, mem_pool_t pool)
{
	st_hash_bucket_head *head;
	st_element *item;

	if (!(item = st_search_int(ht, sock)))
		return -1;

	head = &ht->ht_table[sock & LOWER_16BITS];
    TAILQ_REMOVE(head, item, st_link);
	ht->ht_count--;
	MPFreeChunk(pool, item);

	return 1;
}
/*----------------------------------------------------------------------------*/