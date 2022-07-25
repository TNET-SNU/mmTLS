#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAXLINE    1023
#define FILENAME "key.txt"

static void 
read_hex(const char *hex, uint8_t *out, size_t outmax, size_t *outlen)
{
    size_t i;
	
    *outlen = 0;
    if (strlen(hex) > 2*outmax) {
		printf("{%s} error, hex length exceeds outmax (%lu > %lu*2)\n",
				__FUNCTION__, strlen(hex), outmax*2);
		exit(1);
	}
	
    for (i = 0; hex[i] && hex[i+1]; i += 2) {
        unsigned int value = 0;

        if (!sscanf(hex + i, "%02x", &value)) {
			printf("[%s] sscanf fail\n", __FUNCTION__);
			exit(1);
		}
        out[(*outlen)++] = value;
    }
}

int main(int argc, char *argv[]) {

    char c;
    int session;

    while ((c = getopt(argc, argv, "s:")) != -1) {
		if (c == 's') {
			session = atoi(optarg);
		}
        else {
            printf("./udp-server -s [session number]\n");
            exit(0);
        }
  	}

    struct sockaddr_in servaddr, cliaddr;
    int s, nbyte, addrlen = sizeof(struct sockaddr);
    
    if((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket fail");
        exit(0);
    }
    
    memset(&cliaddr, 0, addrlen);
    memset(&servaddr, 0, addrlen);
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(8888);

    if(bind(s, (struct sockaddr *)&servaddr, addrlen) < 0) {
        perror("bind fail");
        exit(0);
    }

    for (;session>0;session--) {
        int i;
        for (i = 0; i<8; i++)
        {   
            uint8_t buf[MAXLINE+1] = {0};
            nbyte = recvfrom(s, buf, MAXLINE , 0, (struct sockaddr *)&cliaddr, &addrlen);
            if (nbyte < 0) {
                perror("recvfrom fail");
                exit(1);
            }
            buf[nbyte] = 0;

            int j;

            if (i>3) {
                for (j = 0; j < nbyte; j++) {
                    printf("%02X", buf[j]);
                }
                printf(" ");
            }
            else {
                printf("%s ", buf);
            }
        }
        printf("\n");
    }
    close(s);
	return 0;
}