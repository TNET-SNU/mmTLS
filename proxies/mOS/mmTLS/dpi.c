#include "include/dpi.h"

static hs_database_t *g_database;
static hs_scratch_t **g_scratch = {NULL};
static unsigned int *g_flags;
static char **g_patterns = NULL;
static int g_numPatterns;
static int g_num_cores;
static int g_dpi_mode;
static mem_pool_t *g_dctx_pool = {NULL};
/*---------------------------------------------------------------------------*/
static inline mem_pool * 
MPCreate(int chunk_size, size_t total_size, int is_hugepage)
{
	mem_pool_t mp;

	if (chunk_size < sizeof(mem_chunk))
		return NULL;
	if (chunk_size % 4 != 0)
		return NULL;

	//assert(chunk_size <= 2*1024*1024);

	if ((mp = calloc(1, sizeof(mem_pool))) == NULL) {
		perror("calloc failed");
		exit(0);
	}
	mp->mp_type = is_hugepage;
	mp->mp_chunk_size = chunk_size;
	mp->mp_free_chunks = ((total_size + (chunk_size -1))/chunk_size);
	mp->mp_total_chunks = mp->mp_free_chunks;
	total_size = chunk_size * ((size_t)mp->mp_free_chunks);

#ifndef SYS_MALLOC

	/* allocate the big memory chunk */
#ifdef HUGETABLE
	if (is_hugepage == MEM_HUGEPAGE) {
		mp->mp_startptr = get_huge_pages(total_size, NULL);
		if (!mp->mp_startptr) {
			assert(0);
			free(mp);
			return (NULL);
		}
	} else {
#endif
		int res = posix_memalign((void **)&mp->mp_startptr, getpagesize(), total_size);
		if (res != 0) {
			assert(0);
			free(mp);
			return (NULL);
		}
#ifdef HUGETABLE
	}
#endif

	/* try mlock only for superuser */
	if (geteuid() == 0) {
		if (mlock(mp->mp_startptr, total_size) < 0) 
			return (NULL);
	}

	mp->mp_freeptr = (mem_chunk_t)mp->mp_startptr;
	mp->mp_freeptr->mc_free_chunks = mp->mp_free_chunks;
	mp->mp_freeptr->mc_next = NULL;

#endif // SYS_MALLOC

	return mp;
}
/*---------------------------------------------------------------------------*/
static inline void *
MPAllocateChunk(mem_pool_t mp)
{

#ifdef SYS_MALLOC
	return malloc(mp->mp_chunk_size);
#else
	mem_chunk_t p = mp->mp_freeptr;

	if (mp->mp_free_chunks == 0)
		return (NULL);
	assert((p->mc_free_chunks > 0) && (p->mc_free_chunks <= p->mc_free_chunks));

	p->mc_free_chunks--;
	mp->mp_free_chunks--;
	if (p->mc_free_chunks) {
		/* move right by one chunk */
		mp->mp_freeptr = (mem_chunk_t)((u_char *)p + mp->mp_chunk_size);
		mp->mp_freeptr->mc_free_chunks = p->mc_free_chunks;
		mp->mp_freeptr->mc_next = p->mc_next;
	}
	else {
		mp->mp_freeptr = p->mc_next;
	}

	return p;
#endif
}
/*---------------------------------------------------------------------------*/
static inline void
MPFreeChunk(mem_pool_t mp, void *p)
{
#ifdef SYS_MALLOC
	return free(p);
#else
	mem_chunk_t mcp = (mem_chunk_t)p;

	//	assert((u_char*)p >= mp->mp_startptr && 
	//		   (u_char *)p < mp->mp_startptr + mp->mp_total_size);
	assert(((u_char *)p - mp->mp_startptr) % mp->mp_chunk_size == 0);
	//	assert(*((u_char *)p + (mp->mp_chunk_size-1)) == 'a');
	//	*((u_char *)p + (mp->mp_chunk_size-1)) = 'f';

	mcp->mc_free_chunks = 1;
	mcp->mc_next = mp->mp_freeptr;
	mp->mp_freeptr = mcp;
	mp->mp_free_chunks++;
#endif
}
/*---------------------------------------------------------------------------*/
static inline void
MPDestroy(mem_pool_t mp)
{
#ifdef HUGETABLE
	if(mp->mp_type == MEM_HUGEPAGE) {
		free_huge_pages(mp->mp_startptr);
	} else {
#endif
		free(mp->mp_startptr);
#ifdef HUGETABLE
	}
#endif
	free(mp);
}
/*---------------------------------------------------------------------------*/
static inline int
MPGetFreeChunks(mem_pool_t mp)
{
	return mp->mp_free_chunks;
}
/*---------------------------------------------------------------------------*/
static inline uint32_t 
MPIsDanger(mem_pool_t mp)
{
#define DANGER_THREASHOLD 0.95
#define SAFE_THREASHOLD 0.90
	uint32_t danger_num = mp->mp_total_chunks * DANGER_THREASHOLD;
	uint32_t safe_num = mp->mp_total_chunks * SAFE_THREASHOLD;
	if (danger_num < mp->mp_total_chunks - mp->mp_free_chunks) {
		return mp->mp_total_chunks - mp->mp_free_chunks - safe_num;
	}
	return 0;
}
/*---------------------------------------------------------------------------*/
static inline uint32_t
MPIsOverSafeline(mem_pool_t mp)
{
#define SAFELINE 0.90
	uint32_t safe_num = mp->mp_total_chunks * SAFELINE;
	if (safe_num < mp->mp_total_chunks - mp->mp_free_chunks) {
		return 1;
	}
	return 0;
}
/*---------------------------------------------------------------------------*/

// Callback function called when a match is found
int onMatch(unsigned int id, unsigned long long from,
            unsigned long long to, unsigned int flags, void* context) {
    printf("Match found for pattern ID %u at position %llu to %llu\n",
           id, from, to);
    return 0;
}
/*---------------------------------------------------------------------------*/
static inline int
parsePatternList(const char *filename, int *len)
{
    int cnt = 0;    // Number of words read
    char line[MAX_WORD_LENGTH];
    FILE* file = fopen(filename, "r");

    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }

    // Read the file line by line
    while (fgets(line, sizeof(line), file) != NULL) {
        // Remove trailing newline character
        size_t lineLength = strlen(line);
        if (lineLength > 0 && line[lineLength - 1] == '\n') {
            line[lineLength - 1] = '\0';
        }

        // Allocate memory for the new word and copy it
        char *word = strdup(line);
        if (word == NULL) {
            perror("Memory allocation error");
            break;
        }

        // Resize the array to store the new word
        g_patterns = (char**)realloc(g_patterns, (cnt + 1) * sizeof(char*));
        if (!g_patterns) {
            perror("Memory allocation error");
            free(word);
            break;
        }

        // Store the word in the array
        g_patterns[cnt] = word;
        cnt++;
    }

    // Close the file
    fclose(file);

	if (!g_patterns) {
        *len = 0;
        return -1;
    }
	*len = cnt;

    return 0;
}
/*---------------------------------------------------------------------------*/
/*
 * First, we attempt to compile the pattern provided on the command line.
 * We assume 'DOTALL' semantics, meaning that the '.' meta-character will
 * match newline characters. The compiler will analyse the given pattern and
 * either return a compiled Hyperscan database, or an error message
 * explaining why the pattern didn't compile.
 */
int init_DPI(const char *filename, int num_cores, int mode)
{
    int i;
    hs_compile_error_t *err;

	if (parsePatternList(filename, &g_numPatterns) < 0)
        return -1;

	g_flags = calloc(g_numPatterns, sizeof(int));
	if (!g_flags)
        return -1;

	for (i = 0; i < g_numPatterns; i++)
		g_flags[i] = HS_FLAG_CASELESS;

    if (hs_compile_multi((const char *const *)g_patterns, (const unsigned int *)g_flags,
						NULL, g_numPatterns,
						mode, NULL, &g_database,
						&err) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to compile: %s\n", err->message);
        hs_free_compile_error(err);
        return -1;
    }
    g_num_cores = num_cores;
    g_dpi_mode = mode;
    g_dctx_pool = (mem_pool_t *)calloc(num_cores, sizeof(mem_pool_t));
    g_scratch = (hs_scratch_t **)calloc(num_cores, sizeof(hs_scratch_t *));

    for (i = 0; i < num_cores; i++) {
        g_dctx_pool[i] = MPCreate(sizeof(struct dpi_ctx),
                                  sizeof(struct dpi_ctx) * 
                                  MAX_STREAMS_PER_CORE, 0);
		if (!g_dctx_pool[i]) {
            fprintf(stderr, "ERROR: Unable to create DPI context pool. Exiting.\n");
            return -1;
        }

        if (hs_alloc_scratch(g_database, &g_scratch[i]) != HS_SUCCESS) {
            fprintf(stderr, "ERROR: Unable to allocate scratch space. Exiting.\n");
            hs_free_database(g_database);
            return -1;
        }
    }

    return 0;
}
/*---------------------------------------------------------------------------*/
void deinit_DPI()
{
    int i;
    hs_free_database(g_database);

    /* free patterns */
    for (i = 0; i < g_numPatterns; i++) {
        // printf("Word %zu: %s\n", i + 1, g_patterns[i]);
        free(g_patterns[i]); // Free memory for each word
    }

    /* free scratches */
    for (i = 0; i < g_num_cores; i++) {
        if (g_scratch[i])
            hs_free_scratch(g_scratch[i]);
		MPDestroy(g_dctx_pool[i]);
    }
    free(g_dctx_pool);
    free(g_scratch);
    free(g_patterns);
    free(g_flags);
}
/*---------------------------------------------------------------------------*/
dctx_t open_DPI_context(int cpu)
{
    hs_error_t err;
    dctx_t dctx;

    dctx = MPAllocateChunk(g_dctx_pool[cpu]);
	if (!dctx) {
        fprintf(stderr, "ERROR: Unable to allocate DPI context. Exiting.\n");
        return NULL;
    }
    /* mempool requires initializing */
    memset(dctx, 0, sizeof(struct dpi_ctx));

    if (g_dpi_mode == HS_MODE_STREAM) {
        err = hs_open_stream(g_database, 0, &dctx->stream);
        if (err != HS_SUCCESS) {
            fprintf(stderr, "ERROR: Unable to open stream. Exiting.\n");
            exit(EXIT_FAILURE);
        }
    }

    dctx->cpu = cpu;
    dctx->scratch = g_scratch[cpu];
    
    return dctx;
}
/*---------------------------------------------------------------------------*/
void close_DPI_context(dctx_t dctx)
{
    hs_error_t err;
    /* if STREAM MODE */
    if (dctx->stream) {
        err = hs_close_stream(dctx->stream, dctx->scratch, NULL, NULL);
        if (err != HS_SUCCESS) {
            fprintf(stderr, "ERROR: Unable to close stream. Exiting.\n");
            exit(EXIT_FAILURE);
        }
    }

	MPFreeChunk(g_dctx_pool[dctx->cpu], dctx);
}
/*---------------------------------------------------------------------------*/
int DPI(dctx_t dctx, char *buf, size_t len)
{
    hs_error_t err;
    /* if STREAM MODE */
    if (dctx->stream) {
        err = hs_scan_stream(dctx->stream, (const char *)buf, len, 0,
                             dctx->scratch, NULL, NULL);
        if (err != HS_SUCCESS) {
            fprintf(stderr, "ERROR: Unable to scan input buffer: err: %d\n", err);
            hs_free_scratch(dctx->scratch);
            hs_free_database(g_database);
            return -1;
        }
    }
    else {
        if (hs_scan(g_database, (const char *)buf, len, 0, dctx->scratch,
                    NULL, NULL) != HS_SUCCESS) {
            fprintf(stderr, "ERROR: Unable to scan input buffer. Exiting.\n");
            hs_free_scratch(dctx->scratch);
            hs_free_database(g_database);
            return -1;
        }
    }
    
    return 0;
}
/*---------------------------------------------------------------------------*/
int blockDPI(int cpu, char *buf, size_t len)
{
    hs_error_t err;
    err = hs_scan(g_database, (const char *)buf, len, 0, g_scratch[cpu],
                  NULL, NULL);
    if (err != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to scan input buffer. Exiting.\n");
        hs_free_scratch(g_scratch[cpu]);
        hs_free_database(g_database);
        return -1;
    }
    
    return 0;
}