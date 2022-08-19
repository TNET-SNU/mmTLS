#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/queue.h>

#include "include/thash.h"

#define NUM_BINS 		(65536)
#define LOWER_16BITS 	(0x0000FFFF)

/* ToDo: remove client random and sock number from conn_info */

/* structures for hashtable with client random */
typedef TAILQ_HEAD(ct_hash_bucket_head, ct_element) ct_hash_bucket_head;

struct ct_element {
	conn_info *ct_ci;
	TAILQ_ENTRY(ct_element) ct_link;		/* hash table entry link */
};

struct ct_hashtable {
	uint32_t ht_count;
	ct_hash_bucket_head ht_table[NUM_BINS];
};

/* structures for hashtable with socket */
typedef TAILQ_HEAD(st_hash_bucket_head, st_element) st_hash_bucket_head;

struct st_element {
	conn_info *st_ci;
	TAILQ_ENTRY(st_element) st_link;		/* hash table entry link */
};

struct st_hashtable {
	uint32_t ht_count;
	st_hash_bucket_head ht_table[NUM_BINS];
};

static struct ct_element* ct_search_int(struct ct_hashtable *ht, uint8_t crandom[TLS_1_3_CLIENT_RANDOM_LEN]);
static struct st_element* st_search_int(struct st_hashtable *ht, int sock);
/*---------------------------------------------------------------------------*/
struct ct_hashtable*
ct_create(void)
{
	int i;
	struct ct_hashtable* ht = calloc(1, sizeof(struct ct_hashtable));

	if (!ht) {
		ERROR_PRINT("Error: [%s] calloc() failed\n", __FUNCTION__);
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
ct_destroy(struct ct_hashtable *ht)
{
	free(ht);
}
/*----------------------------------------------------------------------------*/
int 
ct_insert(struct ct_hashtable *ht, conn_info *c, uint8_t crandom[TLS_1_3_CLIENT_RANDOM_LEN])
{
	unsigned short idx;
	struct ct_element *item;

	assert(ht);

	if (ct_search_int(ht, crandom)) {
		/* packet retransmission or other errors */
		ERROR_PRINT("Error: ct_insert() call with duplicate client random..\n");
		return 0;
	}

	if (!crandom) {
		ERROR_PRINT("Error: wrong Client Random value\n");
        exit(-1);
    }
	idx = *(unsigned short*)crandom;

	item = (struct ct_element*)calloc(1, sizeof(struct ct_element));
	if (!item) {
		ERROR_PRINT("Error: [%s] calloc() failed\n", __FUNCTION__);
		exit(-1);
	}
	item->ct_ci = c;

	TAILQ_INSERT_TAIL(&ht->ht_table[idx], item, ct_link);
	ht->ht_count++;
	
	return 1;
}
/*----------------------------------------------------------------------------*/
static struct ct_element* 
ct_search_int(struct ct_hashtable *ht, uint8_t crandom[TLS_1_3_CLIENT_RANDOM_LEN])
{
	struct ct_element *walk;
	unsigned short idx = *(unsigned short*)crandom;
	ct_hash_bucket_head *head = &ht->ht_table[idx];

	assert(head);
	TAILQ_FOREACH(walk, head, ct_link) {
		if (memcmp(walk->ct_ci->ci_client_random, crandom, TLS_1_3_CLIENT_RANDOM_LEN) == 0) 
			return walk;
	}

	return NULL;
}
/*----------------------------------------------------------------------------*/
conn_info*
ct_search(struct ct_hashtable *ht, uint8_t crandom[TLS_1_3_CLIENT_RANDOM_LEN])
{
	struct ct_element* item = ct_search_int(ht, crandom);

	if (!item) {
		return NULL;
	}

	return item->ct_ci;
}
/*----------------------------------------------------------------------------*/
int
ct_remove(struct ct_hashtable *ht, uint8_t crandom[TLS_1_3_CLIENT_RANDOM_LEN])
{
	ct_hash_bucket_head *head;
	unsigned short idx;
	struct ct_element* item;

	item = ct_search_int(ht, crandom);
	if (!item) 
		return 0;

	idx = *(unsigned short*)crandom;
    head = &ht->ht_table[idx];
    TAILQ_REMOVE(head, item, ct_link);
	ht->ht_count--;
	free(item);

	return 1;
}
/*----------------------------------------------------------------------------*/
struct st_hashtable*
st_create(void)
{
	int i;
	struct st_hashtable* ht = calloc(1, sizeof(struct st_hashtable));

	if (!ht) {
		ERROR_PRINT("Error: [%s] calloc() failed\n", __FUNCTION__);
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
st_destroy(struct st_hashtable *ht)
{
	free(ht);
}
/*----------------------------------------------------------------------------*/
int 
st_insert(struct st_hashtable *ht, conn_info *c, int sock)
{
	unsigned short idx;
	struct st_element *item;

	assert(ht);

	if (st_search_int(ht, sock)) {
		/* packet retransmission or other errors */
		ERROR_PRINT("Error: st_insert() call with duplicate socket..\n");
		return 0;
	}

	if (!sock) {
		ERROR_PRINT("Error: wrong sock descriptor\n");
        exit(-1);
    }
	idx = sock & LOWER_16BITS;

	item = (struct st_element*)calloc(1, sizeof(struct st_element));
	if (!item) {
		ERROR_PRINT("Error: [%s] calloc() failed\n", __FUNCTION__);
		exit(-1);
	}
	item->st_ci = c;

	TAILQ_INSERT_TAIL(&ht->ht_table[idx], item, st_link);
	ht->ht_count++;
	
	return 1;
}
/*----------------------------------------------------------------------------*/
static struct st_element*
st_search_int(struct st_hashtable *ht, int sock)
{
	struct st_element *walk;
	unsigned short idx = sock & LOWER_16BITS;
	st_hash_bucket_head *head = &ht->ht_table[idx];

	head = &ht->ht_table[idx];
	assert(head);
	TAILQ_FOREACH(walk, head, st_link) {
		if (walk->st_ci->ci_sock == sock) 
			return walk;
	}

	return NULL;
}
/*----------------------------------------------------------------------------*/
conn_info* 
st_search(struct st_hashtable *ht, int sock)
{
	struct st_element* item = st_search_int(ht, sock);

	if (!item) {
		return NULL;
	}

	return item->st_ci;
}
/*----------------------------------------------------------------------------*/
int
st_remove(struct st_hashtable *ht, int sock)
{
	st_hash_bucket_head *head;
	unsigned short idx;
	struct st_element* item;

	item = st_search_int(ht, sock);
	if (!item) 
		return 0;

	idx = sock & LOWER_16BITS;
	head = &ht->ht_table[idx];
    TAILQ_REMOVE(head, item, st_link);
	ht->ht_count--;
	free(item);

	return 1;
}
/*----------------------------------------------------------------------------*/
