#ifndef __FHASH_H_
#define __FHASH_H_

#include <sys/queue.h>
#include "tcp_stream.h"

#define NUM_BINS (131072)     /* 128 K entries per thread*/
#define TCP_AR_CNT (3)

#define STATIC_TABLE FALSE
#define INVALID_HASH (NUM_BINS + 1)

typedef struct hash_bucket_head {
	tcp_stream *tqh_first;
	tcp_stream **tqh_last;
} hash_bucket_head;

/* hashtable structure */
struct hashtable {
	uint16_t ht_count; // count for # entry

#if STATIC_TABLE
	tcp_stream* ht_array[NUM_BINS][TCP_AR_CNT];
#endif
	hash_bucket_head ht_table[NUM_BINS];
};

/*functions for hashtable*/
struct hashtable *CreateHashtable(void);
void DestroyHashtable(struct hashtable *ht);


inline int HTInsert(struct hashtable *ht, tcp_stream *, uint32_t rss_hash);
inline void *HTRemove(struct hashtable *ht, tcp_stream *, uint32_t rss_hash);
inline tcp_stream *HTSearch(struct hashtable *ht, const tcp_stream *, uint32_t rss_hash);

#endif /* __FHASH_H_ */
