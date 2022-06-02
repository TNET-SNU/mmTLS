#include <stdio.h>

#include "fhash.h"

/*---------------------------------------------------------------------------*/
static inline unsigned int
calculate_hash(struct tcp_session *sess)
{
    int hash, i;
    char *key = (char *)&sess->src_ip;

    for (hash = 0, i = 0; i < 12; i++) {
	    hash += key[i];
	    hash += (hash << 10);
	    hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash & (NUM_BINS - 1);
}
/*----------------------------------------------------------------------------*/
struct hashtable *
create_ht(int bins) // no of bins
{
    int i;
    struct hashtable* ht = calloc(1, sizeof(struct hashtable));
    if (!ht){
	fprintf(stderr, "calloc: create_ht");
	return 0;
    }

    ht->bins = bins;

    /* creating bins */
    ht->ht_table = calloc(bins, sizeof(hash_bucket_head));
    if (!ht->ht_table) {
	fprintf(stderr, "calloc: create_ht bins!\n");
	free(ht);
	return 0;
    }
    /* init the tables */
    for (i = 0; i < bins; i++)
	TAILQ_INIT(&ht->ht_table[i]);

    return ht;
}
/*----------------------------------------------------------------------------*/
void
destroy_ht(struct hashtable *ht)
{
    free(ht->ht_table);
    free(ht);
}
/*----------------------------------------------------------------------------*/
int
ht_insert(struct hashtable *ht, struct tcp_session *item)
{
    /* create an entry*/
    int idx;

    assert(ht);

    idx = calculate_hash(item);
    assert(idx >=0 && idx < NUM_BINS);

    TAILQ_INSERT_TAIL(&ht->ht_table[idx], item, active_session_link);

    return 0;
}
/*----------------------------------------------------------------------------*/
void*
ht_remove(struct hashtable *ht, struct tcp_session *item)
{
    hash_bucket_head *head;
    int idx = calculate_hash(item);

    head = &ht->ht_table[idx];
    TAILQ_REMOVE(head, item, active_session_link);

    return (item);
}
/*----------------------------------------------------------------------------*/ 
void *                    
ht_search(struct hashtable *ht, uint32_t src_ip, uint16_t src_port,
	  uint32_t dst_ip, uint16_t dst_port)
{
    struct tcp_session *walk;
    hash_bucket_head *head;

    struct tcp_session target;
    target.src_ip = src_ip;
    target.src_port = src_port;
    target.dst_ip = dst_ip;
    target.dst_port = dst_port;

    head = &ht->ht_table[calculate_hash(&target)];
    TAILQ_FOREACH(walk, head, active_session_link) {
		assert(walk->state != TCP_SESSION_IDLE);

		if ((walk->src_ip == src_ip) &&
			(walk->src_port == src_port) &&
			(walk->dst_ip == dst_ip) &&
			(walk->dst_port == dst_port))
			return walk;
    }

    return NULL;
}
/*----------------------------------------------------------------------------*/
