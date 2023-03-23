#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <endian.h>
#include "include/mmtls.h"
#include "cpu.h"
#include "memory_mgt.h"

#define MAX_CPUS 16
#define MAX_PATH_LEN	32
#define FILE_PATH	"outputs/"
#define MAX_FILE_NAME_LEN	64

/* Default path to mmTLS configuration file */
#define MMTLS_CONFIG_FILE "config/mos.conf"
typedef struct uctx
{
	FILE *fp[2];

	/* below are for debugging, remove when eval */
	uint64_t payload_len[2];
	uint64_t monitor_len[2];

	/* below are for delay eval */
	clock_t clock_stall;
	clock_t clock_resend;
	clock_t key_delay;
} uctx;
/*---------------------------------------------------------------------------*/
struct debug_cnt {
	int ins;
	int del;
	int shash;
	int chash;
	int key;
	int cr;
} g_cnt[MAX_CPUS] = {{0}};
int g_measure_delay = 0;
int g_write_all = 0;
int g_cnt_conn = 0;
FILE *g_delay_fp;
char g_path[MAX_PATH_LEN] = FILE_PATH;
mmtls_t g_mmctx[MAX_CPUS];
mem_pool_t g_uctx_pool[MAX_CPUS] = {NULL};
/*---------------------------------------------------------------------------*/
static inline void
print_conn_stat(mmtls_t mmctx, uctx *c)
{
	if (g_measure_delay)
		fprintf(g_delay_fp,
			// "%lf "
			// "%lf "
			"%lf\n",
			// (double)c->clock_stall / CLOCKS_PER_SEC,
			// (double)c->clock_resend / CLOCKS_PER_SEC,
			(double)c->key_delay / CLOCKS_PER_SEC);
	if (!g_cnt_conn)
		return;
	struct debug_cnt sum = {0,};
	for (int i = 0; i < MAX_CPUS; i++) {
		sum.ins += g_cnt[i].ins;
		sum.del += g_cnt[i].del;
		sum.key += g_cnt[i].key;
	}
	fprintf(stdout,
			"\n--------------------------------------------------\n"
			"[CORE: %d]\n"
			"CLIENT: %lu B\n"
			"CLIENT peek: %lu B\n"
			"SERVER: %lu B\n"
			"SERVER peek: %lu B\n"
			"Insert conn cnt: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n"
			"Total insert conn: %d\n"
			"Remove conn cnt: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n"
			"Total remove conn: %d\n"
			"key cnt: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n"
			"Total key: %d\n",
			mmctx->cpu,
			c->payload_len[MOS_SIDE_CLI],
			c->monitor_len[MOS_SIDE_CLI],
			c->payload_len[MOS_SIDE_SVR],
			c->monitor_len[MOS_SIDE_SVR],
			/* master core: num of keys */
			g_cnt[0].ins, g_cnt[1].ins, g_cnt[2].ins, g_cnt[3].ins,
			g_cnt[4].ins, g_cnt[5].ins, g_cnt[6].ins, g_cnt[7].ins,
			g_cnt[8].ins, g_cnt[9].ins, g_cnt[10].ins, g_cnt[11].ins,
			g_cnt[12].ins, g_cnt[13].ins, g_cnt[14].ins, g_cnt[15].ins,
			sum.ins,
			g_cnt[0].del, g_cnt[1].del, g_cnt[2].del, g_cnt[3].del,
			g_cnt[4].del, g_cnt[5].del, g_cnt[6].del, g_cnt[7].del,
			g_cnt[8].del, g_cnt[9].del, g_cnt[10].del, g_cnt[11].del,
			g_cnt[12].del, g_cnt[13].del, g_cnt[14].del, g_cnt[15].del,
			sum.del,
			g_cnt[0].key, g_cnt[1].key, g_cnt[2].key, g_cnt[3].key,
			g_cnt[4].key, g_cnt[5].key, g_cnt[6].key, g_cnt[7].key,
			g_cnt[8].key, g_cnt[9].key, g_cnt[10].key, g_cnt[11].key,
			g_cnt[12].key, g_cnt[13].key, g_cnt[14].key, g_cnt[15].key,
			sum.key);
}
/*---------------------------------------------------------------------------*/
static void
cb_session_start(mmtls_t mmctx, int cid, int side)
{
	char destfile[MAX_FILE_NAME_LEN];
	uctx *c;
	if (side != MMTLS_SIDE_CLI)
		return;
    if ((c = mmtls_get_uctx(mmctx, cid)))
		/* already inserted session, might be caused by duplicated SYN */
		return;
	if (!(c = MPAllocateChunk(g_uctx_pool[mmctx->cpu])))
		EXIT_WITH_ERROR("uctx pool alloc failed");
	if (g_write_all) {
		sprintf(destfile, "%score%dconn%dside%d", g_path, mmctx->cpu, cid, side);
		if ((c->fp[side] = fopen(destfile, "a+w")) < 0)
			EXIT_WITH_ERROR("fopen() failed");
	}
    mmtls_set_uctx(mmctx, cid, c);
	/* turn on decrypt to detect HTTP request */
	if (mmtls_set_monopt(mmctx, cid, MMTLS_SIDE_SVR, DO_DECRYPT) == -1)
		EXIT_WITH_ERROR("mmtls_set_monopt() failed");
	if (!g_cnt_conn)
		return;
	g_cnt[mmctx->cpu].ins++;
}
/*---------------------------------------------------------------------------*/
static void
cb_session_end(mmtls_t mmctx, int cid, int side)
{
	uctx *c;
	if (side != MMTLS_SIDE_CLI) 
		return;
    if (!(c = mmtls_get_uctx(mmctx, cid)))
		/* already removed session */
		return;
	if (g_write_all)
		if (c->fp[side]) {
			if (fclose(c->fp[side]) < 0)
				EXIT_WITH_ERROR("fclose() failed");
		}
	print_conn_stat(mmctx, c);
	MPFreeChunk(g_uctx_pool[mmctx->cpu], c);
	if (!g_cnt_conn)
		return;
	g_cnt[mmctx->cpu].del++;
}
/*---------------------------------------------------------------------------*/
static void
cb_handshake_end(mmtls_t mmctx, int cid, int side)
{
	uctx *c;
	uint16_t cipher_suite;
	uint16_t version;
	uint8_t *random;
	if (side != MMTLS_SIDE_CLI) 
		return;
    if (!(c = mmtls_get_uctx(mmctx, cid)))
		/* already removed session */
		return;
	random = mmtls_get_random(mmctx, cid, side);
	version = mmtls_get_version(mmctx, cid, side);
	cipher_suite = mmtls_get_cipher(mmctx, cid, side);
	printf("version: %d\n"
			"cipher_suite: %d\n"
			"random: %p\n",
			version,
			cipher_suite,
			random);
}
/*---------------------------------------------------------------------------*/
static void
cb_stall(mmtls_t mmctx, int cid, int side)
{
	uctx *c;
    if (!(c = mmtls_get_uctx(mmctx, cid)))
		/* already removed session */
		return;
	if (g_measure_delay && (c->clock_stall == 0))
		c->clock_stall = clock();
}
/*---------------------------------------------------------------------------*/
static void
cb_recv_key(mmtls_t mmctx, int cid, int side)
{
	uctx *c;
	int cnt;
    if (!(c = mmtls_get_uctx(mmctx, cid)))
		/* already removed session */
		return;
	if (g_measure_delay && (c->clock_stall)) {
		c->clock_resend = clock();
		c->key_delay = c->clock_resend - c->clock_stall;
	}
	if (!g_cnt_conn)
		return;
	cnt = mmtls_get_stallcnt(mmctx, cid, side);
	printf("\n--------------------------------------------------\n"
			"[%s] core: %d, cid: %u\nsent %d stalled pkts\n",
			__FUNCTION__, mmctx->cpu, cid, cnt);
	g_cnt[mmctx->cpu].key++;
	printf("key found: %d\n",
			g_cnt[0].key + g_cnt[1].key + g_cnt[2].key + g_cnt[3].key + 
			g_cnt[4].key + g_cnt[5].key + g_cnt[6].key + g_cnt[7].key + 
			g_cnt[8].key + g_cnt[9].key + g_cnt[10].key + g_cnt[11].key + 
			g_cnt[12].key + g_cnt[13].key + g_cnt[14].key + g_cnt[15].key);
}
/*---------------------------------------------------------------------------*/
static void
cb_new_record(mmtls_t mmctx, int cid, int side)
{
	uctx *c;
	uint8_t buf[MAX_BUF_LEN];
	int len = MAX_BUF_LEN;
	if (side == MMTLS_SIDE_SVR) {
		/* client request */
		if (mmtls_get_record(mmctx, cid, side, buf, &len) == -1)
			EXIT_WITH_ERROR("mmtls_get_record failed");
		if (!len)
			return;
		/* if new request detected, turn on decrypt for the following response */
		if (strstr((char *)buf, "GET "))
			mmtls_set_monopt(mmctx, cid, MMTLS_SIDE_CLI, DO_DECRYPT);
		return;
	}
	if (mmtls_get_record(mmctx, cid, side, buf, &len) == -1)
		EXIT_WITH_ERROR("mmtls_get_record failed");
	if (!len)
		return;
    if (!(c = mmtls_get_uctx(mmctx, cid)))
		EXIT_WITH_ERROR("uctx_search() failed");
	c->payload_len[side] += len; // for debugging
	if (strstr((char *)buf, "HTTP/")) {
		c->monitor_len[side] = len;
		goto Log;
	}
	c->monitor_len[side] += len;
	if (c->monitor_len[side] > 1000000)
		/* decrypt only 1MB for each response */
		mmtls_set_monopt(mmctx, cid, MMTLS_SIDE_CLI, NO_DECRYPT);
Log:
	if (g_write_all)
		if (fwrite((const void *)buf, 1, len, c->fp[side]) == -1)
			EXIT_WITH_ERROR("fwrite failed");
}
/*---------------------------------------------------------------------------*/
static void
cb_abnormal(mmtls_t mmctx, int cid, int side)
{
    WARNING_PRINT("Warning! err code: %d", mmtls_get_err(mmctx, cid, side));
	mmtls_drop_packet(mmctx, cid, side);
	mmtls_reset_conn(mmctx, cid, side);
}
/*---------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
	int i;
	char *fname = MMTLS_CONFIG_FILE; /* path to the default mos config file */
	int opt, rc;

	/* get the total # of cpu cores */
	int core_num = GetNumCPUs();

	while ((opt = getopt(argc, argv, "c:def:")) != -1)
		switch (opt) {
		case 'c':
			if ((rc = atoi(optarg)) > core_num)
				EXIT_WITH_ERROR("failed to set core number\n"
							"request %u, but only %u available",
							rc, core_num);
			core_num = rc;
			break;
		case 'd':
			g_measure_delay = 1;
			break;
		case 'e':
			g_cnt_conn = 1;
			break;
		case 'f':
			g_write_all = 1;
			break;
		default:
			printf("Usage: %s [-c num of cores]\n", argv[0]);
			return 0;
		}
	
	if (mmtls_init(fname, core_num) == -1)
		EXIT_WITH_ERROR("mmtls_init failed");

	/* Run mmTLS for each core */
	for (i = 0; i < core_num; i++) {
		if (!(g_uctx_pool[i] = MPCreate(sizeof(uctx), sizeof(uctx) * 1000, 0)))
			EXIT_WITH_ERROR("MPCreate failed");
		if (!(g_mmctx[i] = mmtls_create_context(i)))
			EXIT_WITH_ERROR("mmtls_create_context failed");
		if (mmtls_register_callback(g_mmctx[i], ON_TLS_SESSION_START, cb_session_start))
			EXIT_WITH_ERROR("mmtls_register_callback failed");
		if (mmtls_register_callback(g_mmctx[i], ON_TLS_SESSION_END, cb_session_end))
			EXIT_WITH_ERROR("mmtls_register_callback failed");
		if (mmtls_register_callback(g_mmctx[i], ON_TLS_HANDSHAKE_END, cb_handshake_end))
			EXIT_WITH_ERROR("mmtls_register_callback failed");
		if (mmtls_register_callback(g_mmctx[i], ON_TLS_NEW_RECORD, cb_new_record))
			EXIT_WITH_ERROR("mmtls_register_callback failed");
		if (mmtls_register_callback(g_mmctx[i], ON_TLS_STALL, cb_stall))
			EXIT_WITH_ERROR("mmtls_register_callback failed");
		if (mmtls_register_callback(g_mmctx[i], ON_TLS_RECV_KEY, cb_recv_key))
			EXIT_WITH_ERROR("mmtls_register_callback failed");
		if (mmtls_register_callback(g_mmctx[i], ON_TLS_ABNORMAL, cb_abnormal))
			EXIT_WITH_ERROR("mmtls_register_callback failed");
		INFO_PRINT("[core %d] thread created and callback registered", i);
	}

	/* wait until all threads finish */
	for (i = 0; i < core_num; i++)
		mmtls_app_join(g_mmctx[i]);

	/* destroy mempool */
	for (i = 0; i < core_num; i++)
		MPDestroy(g_uctx_pool[i]);

	if (mmtls_destroy() == -1)
		EXIT_WITH_ERROR("mmtls_destroy failed");

	return EXIT_SUCCESS;
}
/*---------------------------------------------------------------------------*/
