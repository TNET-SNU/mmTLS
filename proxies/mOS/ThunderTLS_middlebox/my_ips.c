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

#define MAX_CPUS 16
#define MAX_PATH_LEN	32
#define FILE_PATH	"outputs/"

/* Default path to mOS configuration file */
#define MOS_CONFIG_FILE "config/mos.conf"

int g_max_cores;
char g_path[MAX_PATH_LEN] = FILE_PATH;
mmtls_t g_mmtls[MAX_CPUS];
/*---------------------------------------------------------------------------*/
static void
cb_session_start(int cpu, int cid, int side)
{
	/* used conn_info and mtcp_get_uctx for convenience,
	   but it should be search on app layer */
	// char destfile[MAX_FILE_NAME_LEN];
	// conn_info *c;
	// if (side != MOS_SIDE_CLI)
	// 	return;
	// sprintf(destfile, "%score%dconn%dside%d", g_path, cpu, cid, side);
	// c = mtcp_get_uctx(g_mctx[cpu], cid);
	// if ((c->ci_tls_ctx[side].tc_fp = fopen(destfile, "a+w")) < 0)
	// 	EXIT_WITH_ERROR("fopen() failed");
}
/*---------------------------------------------------------------------------*/
static void
cb_session_end(int cpu, int cid, int side)
{
	/* used conn_info and mtcp_get_uctx for convenience,
	   but it should be search on app layer */
	// conn_info *c;
	// if (side != MOS_SIDE_CLI)
	// 	return;
	// c = mtcp_get_uctx(g_mctx[cpu], cid);
	// if (fclose(c->ci_tls_ctx[side].tc_fp) < 0)
	// 	EXIT_WITH_ERROR("fclose() failed");
}
/*---------------------------------------------------------------------------*/
static void
cb_new_record(int cpu, int cid, int side)
{
	/* used conn_info and mtcp_get_uctx for convenience,
	   but it should be search on app layer */
	// conn_info *c;
	uint8_t plaintext[16384];
	int len;
	// if (side != MOS_SIDE_CLI) 
	// 	return;
	len = mmtls_get_record(g_mmtls[cpu], cid, side, plaintext);
    (void)len;
	// c = mtcp_get_uctx(g_mctx[cpu], cid);
	// if (fwrite((const void *)plaintext, 1, len, c->ci_tls_ctx[side].tc_fp) == -1)
	// 	EXIT_WITH_ERROR("fwrite failed");
}
/*---------------------------------------------------------------------------*/
static void
cb_malicious(int cpu, int cid, int side)
{
	/* used conn_info and mtcp_get_uctx for convenience,
	   but it should be search on app layer */
	mmtls_drop_packet(g_mmtls[cpu], cid, side);
	mmtls_reset_conn(g_mmtls[cpu], cid, side);
}
/*---------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
	int i;
	char *fname = MOS_CONFIG_FILE; /* path to the default mos config file */
	int opt, rc;

	/* get the total # of cpu cores */
	g_max_cores = GetNumCPUs();

	while ((opt = getopt(argc, argv, "c:f:d")) != -1)
		switch (opt) {
		case 'c':
			if ((rc = atoi(optarg)) > g_max_cores)
				EXIT_WITH_ERROR("failed to set core number\n"
							"request %u, but only %u available",
							rc, g_max_cores);
			g_max_cores = rc;
			break;
		default:
			printf("Usage: %s [-c num of cores]\n", argv[0]);
			return 0;
		}
	
	if (mmtls_init(fname, g_max_cores) == -1)
		EXIT_WITH_ERROR("mmtls_init failed");

	/* Run mmTLS for each core */
	for (i = 0; i < g_max_cores; i++) {
		if (!(g_mmtls[i] = mmtls_create_context(i)))
			EXIT_WITH_ERROR("mmtls_create_context failed");
		INFO_PRINT("[core %d] thread created", i);
	}

	for (i = 0; i < g_max_cores; i++) {
		if (mmtls_register_callback(g_mmtls[i], ON_TLS_SESSION_START, cb_session_start))
			EXIT_WITH_ERROR("mmtls_register_callback failed");
		if (mmtls_register_callback(g_mmtls[i], ON_TLS_SESSION_END, cb_session_end))
			EXIT_WITH_ERROR("mmtls_register_callback failed");
		if (mmtls_register_callback(g_mmtls[i], ON_NEW_TLS_RECORD, cb_new_record))
			EXIT_WITH_ERROR("mmtls_register_callback failed");
		if (mmtls_register_callback(g_mmtls[i], ON_MALICIOUS, cb_malicious))
			EXIT_WITH_ERROR("mmtls_register_callback failed");
		(void)cb_session_start;
		(void)cb_session_end;
		(void)cb_new_record;
		(void)cb_malicious;
		INFO_PRINT("[core %d] callback attached", i);
	}

	/* wait until all threads finish */
	for (i = 0; i < g_max_cores; i++)
		mmtls_app_join(i);

	if (mmtls_destroy() == -1)
		EXIT_WITH_ERROR("mmtls_destroy failed");

	return EXIT_SUCCESS;
}
/*---------------------------------------------------------------------------*/
