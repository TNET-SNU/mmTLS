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
#include "../core/src/include/memory_mgt.h"

#define MAX_CPUS 16
#define MAX_PATH_LEN	32
#define FILE_PATH	"outputs/"
#define MAX_FILE_NAME_LEN	64

/* Default path to mmTLS configuration file */
#define MMTLS_CONFIG_FILE "config/mos.conf"
typedef struct uctx
{
	FILE *fp[2];
	uint64_t monitor_len[2];

	/* below are for delay eval */
	clock_t clock_stall;
	clock_t clock_resend;
	clock_t key_delay;

	clock_t session_start;
	clock_t page_load_time;

	/* below are for debugging, remove when eval */
	uint64_t payload_len[2];
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
mmctx_t g_mmctx[MAX_CPUS];
mem_pool_t g_uctx_pool[MAX_CPUS] = {NULL};
/*---------------------------------------------------------------------------*/
static inline void
print_conn_stat(mmctx_t mmctx, uctx *c)
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
			c->monitor_len[MOS_SIDE_CLI],
			c->payload_len[MOS_SIDE_CLI],
			c->monitor_len[MOS_SIDE_SVR],
			c->payload_len[MOS_SIDE_SVR],
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
	printf("page load time: %lf\n",
			(double)(c->page_load_time - c->session_start) / CLOCKS_PER_SEC);
}
/*---------------------------------------------------------------------------*/
static void
cb_session_start(mmctx_t mmctx, int cid, int side)
{
	char destfile[MAX_FILE_NAME_LEN];
	uctx *c;
    if ((c = mmtls_get_uctx(mmctx, cid)))
		/* already inserted session, might be caused by duplicated SYN */
		return;
	if (!(c = MPAllocateChunk(g_uctx_pool[mmctx->cpu])))
		EXIT_WITH_ERROR("uctx pool alloc failed");
	memset(c, 0, sizeof(uctx));
	if (g_write_all) {
		sprintf(destfile, "%score%dconn%d", g_path, mmctx->cpu, cid);
		if ((c->fp[MOS_SIDE_CLI] = fopen(destfile, "a+w")) < 0)
			EXIT_WITH_ERROR("fopen() failed");
	}
	c->session_start = clock();
    if (mmtls_set_uctx(mmctx, cid, c) == -1)
		EXIT_WITH_ERROR("mmtls_set_uctx failed");
	if (!g_cnt_conn)
		return;
	g_cnt[mmctx->cpu].ins++;
}
/*---------------------------------------------------------------------------*/
static void
cb_session_end(mmctx_t mmctx, int cid, int side)
{
	uctx *c;
    if (!(c = mmtls_get_uctx(mmctx, cid)))
		/* already removed session */
		return;
	if (g_write_all) {
		if (fclose(c->fp[MOS_SIDE_CLI]) < 0)
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
cb_handshake_end(mmctx_t mmctx, int cid, int side)
{
	uctx *c;
	session_info info;
	if (side != MMTLS_SIDE_CLI) 
		return;
    if (!(c = mmtls_get_uctx(mmctx, cid)))
		/* already removed session */
		return;
	if (mmtls_get_tls_info(mmctx, cid, &info, VERSION | CIPHER_SUITE) == -1)
		EXIT_WITH_ERROR("mmtls_get_info failed");
	printf("TLS %02X%02X, %02X%02X\n",
		*((uint8_t *)&info.version + 1),
		*(uint8_t *)&info.version,
		*((uint8_t *)&info.cipher_suite + 1),
		*(uint8_t *)&info.cipher_suite);
}
/*---------------------------------------------------------------------------*/
static void
cb_stall(mmctx_t mmctx, int cid, int side)
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
cb_recv_key(mmctx_t mmctx, int cid, int side)
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
	if ((cnt = mmtls_get_stallcnt(mmctx, cid)) == -1)
		EXIT_WITH_ERROR("mmtls_get_stallcnt failed");
	printf("\n--------------------------------------------------\n"
			"[%s] core: %d, cid: %u, stall_cnt: %d\n",
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
cb_new_record(mmctx_t mmctx, int cid, int side)
{
	uctx *c;
	char buf[MAX_BUF_LEN];
	int len;
	int err;
    if (!(c = mmtls_get_uctx(mmctx, cid)))
		EXIT_WITH_ERROR("uctx_search() failed");

	// if (mmtls_offload_ctl(mmctx, cid, side, OFFLOAD_BYPASS) < 0)
	// 	printf("offload failed!\n");
	// printf("[CORE: %d]\nCLIENT: %lu\n", mmctx->cpu, c->monitor_len[side]);
	// return;

	/* decrypt only 10KB for each response */
	if ((side == MMTLS_SIDE_CLI) &&
		(c->monitor_len[side] > 10000)) {
		// mmtls_offload_ctl(mmctx, cid, side, OFFLOAD_BYPASS);
		// printf("[CORE: %d]\nCLIENT: %lu\n", mmctx->cpu, c->monitor_len[side]);
		mmtls_pause_monitor(mmctx, cid, side, 64000);
		printf("paused!\n");
	}

	/* get plaintext */
	if (mmtls_get_record(mmctx, cid, side, buf, &len, NULL) == -1) {
		err = mmtls_get_error(mmctx, cid);
		printf("err: %d\n", err);
		if (err == INTEGRITY_ERR) {
			if (mmtls_reset_conn(mmctx, cid) == -1)
				EXIT_WITH_ERROR("mmtls_reset_conn failed");
			cb_session_end(mmctx, cid, side);
		}
		return;
	}
	c->monitor_len[side] += len;

	if (side == MMTLS_SIDE_SVR) {
		/* if new request from client detected, reset */
		if (strstr(buf, "GET ")) {
			// mmtls_offload_ctl(mmctx, cid, side, ONLOAD);
			c->monitor_len[MMTLS_SIDE_CLI] = 0;
			mmtls_resume_monitor(mmctx, cid, MMTLS_SIDE_CLI);
			printf("resumed!\n");
		}
		return;
	}
	if (g_write_all) {
		if (fwrite((const void *)buf, 1, len, c->fp[MOS_SIDE_CLI]) == -1)
			EXIT_WITH_ERROR("fwrite failed");
	}
	c->page_load_time = clock();
}
/*---------------------------------------------------------------------------*/
static void
cb_abnormal(mmctx_t mmctx, int cid, int side)
{
	int err = mmtls_get_error(mmctx, cid);
    WARNING_PRINT("Warning! err code: %d", err);
	if ((err == INVALID_VERSION) ||
		(err == INVALID_CIPHER_SUITE) ||
		(err == INVALID_RECORD_LEN) ||
		(err == MISSING_KEY)) {
		if (mmtls_reset_conn(mmctx, cid) == -1)
			EXIT_WITH_ERROR("mmtls_reset_conn failed");
		cb_session_end(mmctx, cid, side);
		// if (mmtls_offload_ctl(mmctx, cid, side, OFFLOAD_BYPASS) == -1)
		// 	EXIT_WITH_ERROR("mmtls_offload_flow failed");
		// if (mmtls_offload_ctl(mmctx, cid, side, OFFLOAD_DROP) == -1)
		// 	EXIT_WITH_ERROR("mmtls_offload_flow failed");
	}
}
/*---------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
	int i;
	char *fname = MMTLS_CONFIG_FILE; /* path to the default mos config file */
	int opt, rc;

	/* get the total # of cpu cores */
	int core_num = GetNumCPUs();

	while ((opt = getopt(argc, argv, "c:def")) != -1)
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
		if (!(g_uctx_pool[i] = MPCreate(sizeof(uctx), sizeof(uctx) * 8000, 0)))
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
		if (mmtls_register_callback(g_mmctx[i], ON_TLS_ERROR, cb_abnormal))
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
