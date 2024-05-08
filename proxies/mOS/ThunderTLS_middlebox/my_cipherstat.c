#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "include/mmtls.h"
/* Default path to mmTLS configuration file */
#define MMTLS_CONFIG_FILE "config/mos.conf"
#define MAX_CPUS 16
/*---------------------------------------------------------------------------*/
char g_filename[20] = "cipherstat";
FILE *g_cipher_fp;
mmctx_t g_mmctx[MAX_CPUS];
/*---------------------------------------------------------------------------*/
static void
cb_handshake_end(mmctx_t mmctx, int cid, int side)
{
	session_info info;
	if (mmtls_get_tls_info(mmctx, cid, &info, VERSION | CIPHER_SUITE | SNI) == -1)
		EXIT_WITH_ERROR("mmtls_get_info failed");
    fprintf(g_cipher_fp, "%d %d %s\n", info.version, info.cipher_suite, info.sni);
    // mmtls_pause_monitor(mmctx, cid, MMTLS_SIDE_BOTH, -1);
}
/*---------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
	int i;
	char *fname = MMTLS_CONFIG_FILE; /* path to the default mos config file */
	int opt, rc;
	int core_num = MAX_CPUS;
	while ((opt = getopt(argc, argv, "c:f:")) != -1)
		switch (opt) {
		case 'c':
			if ((rc = atoi(optarg)) > core_num)
				EXIT_WITH_ERROR("failed to set core number\n");
			core_num = rc;
			break;
		case 'f':
			strcpy(g_filename, optarg);
			break;
		default:
			printf("Usage: %s [-c num of cores]\n", argv[0]);
			return 0;
		}
    if ((g_cipher_fp = fopen(g_filename, "a+w")) < 0)
        EXIT_WITH_ERROR("fopen() failed");
	if (mmtls_init(fname, core_num) == -1)
		EXIT_WITH_ERROR("mmtls_init failed");
	/* Run mmTLS for each core */
	for (i = 0; i < core_num; i++) {
		if (!(g_mmctx[i] = mmtls_create_context(i)))
			EXIT_WITH_ERROR("mmtls_create_context failed");
		if (mmtls_register_callback(g_mmctx[i], ON_TLS_HANDSHAKE_END, cb_handshake_end))
			EXIT_WITH_ERROR("mmtls_register_callback failed");
	}
	/* wait until all threads finish */
	for (i = 0; i < core_num; i++)
		mmtls_app_join(g_mmctx[i]);
	if (mmtls_destroy() == -1)
		EXIT_WITH_ERROR("mmtls_destroy failed");
    fclose(g_cipher_fp);

	return EXIT_SUCCESS;
}