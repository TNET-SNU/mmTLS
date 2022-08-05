#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/queue.h>

#include "include/thash.h"

#define NUM_BINS (65536)

/* ToDo: remove client random and sock number from conn_info */

/* structures for hashtable with client random */
typedef TAILQ_HEAD(ct_hash_bucket_head, ct_element) ct_hash_bucket_head;

struct ct_element {
	uint8_t ct_client_random[TLS_1_3_CLIENT_RANDOM_LEN];
	conn_info *ct_ci;
};

struct ct_hashtable {
	uint16_t ht_count;
	ct_hash_bucket_head ht_table[NUM_BINS];
};

/* structures for hashtable with socket */
typedef TAILQ_HEAD(st_hash_bucket_head, st_element) st_hash_bucket_head;

struct st_element {
	int st_sock;
	conn_info *st_ci;
};

struct st_hashtable {
	uint16_t ht_count;
	st_hash_bucket_head ht_table[NUM_BINS];
};

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

	if (ct_search(ht, crandom)) {
		/* packet retransmission or other errors */
		ERROR_PRINT("Error: ct_insert() call with duplicate client random..\n");
		return 0;
	}

	if (!crandom) {
		ERROR_PRINT("Error: wrong Client Random value\n");
        exit(-1);
    }
	idx = *(unsigned short*)crandom;
	assert(idx >=0 && idx < NUM_BINS);

	item = (struct ct_element*)calloc(1, sizeof(struct ct_element));
	if (!item) {
		ERROR_PRINT("Error: [%s] calloc() failed\n", __FUNCTION__);
		exit(-1);
	}
	item->ct_ci = c;
	memcpy(item->ct_client_random, crandom, TLS_1_3_CLIENT_RANDOM_LEN);

	TAILQ_INSERT_TAIL(&ht->ht_table[idx], item, ct_ci->ci_ct_he.he_link);
	item->ct_ci->ci_ct_he.he_mybucket = &ht->ht_table[idx];
	ht->ht_count++;
	
	return 0;
}
/*----------------------------------------------------------------------------*/
void*
ct_remove(struct ct_hashtable *ht, conn_info *c)
{
	ct_hash_bucket_head *head;
	struct ct_hash_elements he = c->ci_ct_he;

    head = he.he_mybucket;
    assert(head);

	free(*he.he_link.tqe_prev); 	// free() an element to remove
    // TAILQ_REMOVE(head, c, ct_ci->ci_ct_he.he_link);
	if (he.he_link.tqe_next) {
		he.he_link.tqe_next->ct_ci->ci_ct_he.he_link.tqe_prev = he.he_link.tqe_prev;
	}
	else {
		head->tqh_last = he.he_link.tqe_prev;
	}
	*he.he_link.tqe_prev = he.he_link.tqe_next;

	ht->ht_count--;

	return (c);
}
/*----------------------------------------------------------------------------*/
conn_info* 
ct_search(struct ct_hashtable *ht, uint8_t crandom[TLS_1_3_CLIENT_RANDOM_LEN])
{
	struct ct_element *walk;
	ct_hash_bucket_head *head;
	unsigned short idx;

	if (!crandom) {
		ERROR_PRINT("Error: wrong hash value\n");
        exit(-1);
    }

	idx = *(unsigned short*)crandom;
	head = &ht->ht_table[idx];
	/* ToDo: change */
	//TAILQ_FOREACH(walk, head, ci_he.he_link) {
	for (walk = head->tqh_first; walk; walk = walk->ct_ci->ci_ct_he.he_link.tqe_next)	{
		if (memcmp(walk->ct_client_random, crandom, TLS_1_3_CLIENT_RANDOM_LEN) == 0) {
            return walk->ct_ci;
        }
	}

	return NULL;
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

	if (st_search(ht, sock)) {
		/* packet retransmission or other errors */
		ERROR_PRINT("Error: st_insert() call with duplicate socket..\n");
		return 0;
	}

	if (!sock) {
		ERROR_PRINT("Error: wrong sock descriptor\n");
        exit(-1);
    }
	idx = (unsigned short)sock;
	assert(idx >=0 && idx < NUM_BINS);

	item = (struct st_element*)calloc(1, sizeof(struct st_element));
	if (!item) {
		ERROR_PRINT("Error: [%s] calloc() failed\n", __FUNCTION__);
		exit(-1);
	}
	item->st_sock = sock;
	item->st_ci   = c;

	TAILQ_INSERT_TAIL(&ht->ht_table[idx], item, st_ci->ci_st_he.he_link);
	item->st_ci->ci_st_he.he_mybucket = &ht->ht_table[idx];
	ht->ht_count++;
	
	return 0;
}
/*----------------------------------------------------------------------------*/
void*
st_remove(struct st_hashtable *ht, conn_info *c)
{
	st_hash_bucket_head *head;
	struct st_hash_elements he = c->ci_st_he;

    head = he.he_mybucket;
    assert(head);

	free(*he.he_link.tqe_prev); 	// free() an element to remove
    //TAILQ_REMOVE(head, c, ci_he.he_link);
	if (he.he_link.tqe_next) {
		he.he_link.tqe_next->st_ci->ci_st_he.he_link.tqe_prev = he.he_link.tqe_prev;
	}
	else {
		head->tqh_last = he.he_link.tqe_prev;
	}
	*he.he_link.tqe_prev = he.he_link.tqe_next;

	ht->ht_count--;

	return (c);
}
/*----------------------------------------------------------------------------*/
conn_info* 
st_search(struct st_hashtable *ht, int sock)
{
	struct st_element *walk;
	st_hash_bucket_head *head;
	unsigned short idx;

	if (!sock) {
		ERROR_PRINT("Error: wrong hash value\n");
        exit(-1);
    }

	idx = (unsigned short)sock;
	head = &ht->ht_table[idx];
	/* ToDo: change */
	//TAILQ_FOREACH(walk, head, ci_he.he_link) {
	for (walk = head->tqh_first; walk; walk = walk->st_ci->ci_st_he.he_link.tqe_next)	{
		if (walk->st_sock == sock) {
            return walk->st_ci;
        }
	}

	return NULL;
}
/*----------------------------------------------------------------------------*/
