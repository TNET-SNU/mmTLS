#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include <hs/hs.h>
#ifdef HUGETABLE
#include <hugetlbfs.h>
#endif
//#define SYS_MALLOC

#define MAX_CPUS 16
#define MAX_WORD_LENGTH 1024 // Maximum word length, adjust as needed
#define MAX_STREAMS_PER_CORE 8192

struct dpi_ctx {
    int cpu;
    hs_scratch_t *scratch;
    hs_stream_t *stream;
    // int stop_dpi;
};

typedef struct tag_mem_chunk
{
	int mc_free_chunks;
	struct tag_mem_chunk *mc_next;
} mem_chunk;

typedef mem_chunk *mem_chunk_t;

#ifdef HUGETABLE
typedef enum { MEM_NORMAL, MEM_HUGEPAGE};
#endif

typedef struct mem_pool
{
	u_char *mp_startptr;      /* start pointer */
	mem_chunk_t mp_freeptr;   /* pointer to the start memory chunk */
	int mp_free_chunks;       /* number of total free chunks */
	int mp_total_chunks;       /* number of total free chunks */
	int mp_chunk_size;        /* chunk size in bytes */
	int mp_type;

} mem_pool;

typedef struct mem_pool* mem_pool_t;
typedef struct dpi_ctx *dctx_t;
/*---------------------------------------------------------------------------*/
/*
 * First, we attempt to compile the pattern provided on the command line.
 * We assume 'DOTALL' semantics, meaning that the '.' meta-character will
 * match newline characters. The compiler will analyse the given pattern and
 * either return a compiled Hyperscan database, or an error message
 * explaining why the pattern didn't compile.
 */
int init_DPI(const char *filename, int num_cores, int mode);
/*---------------------------------------------------------------------------*/
void deinit_DPI();
/*---------------------------------------------------------------------------*/
dctx_t open_DPI_context(int cpu);
/*---------------------------------------------------------------------------*/
void close_DPI_context(dctx_t dctx);
/*---------------------------------------------------------------------------*/
int DPI(dctx_t dctx, char *buf, size_t len);
/*---------------------------------------------------------------------------*/
/* this is for test */
int blockDPI(int cpu, char *buf, size_t len);