/* 
 * From https://www.cs.cmu.edu/afs/cs/academic/class/15213-f99/www/class26/udpclient.c
 *
 * udpclient.c - A simple UDP client
 * usage: udpclient <host> <port>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define FILE_NAME "example_keyinfo"
#define BUFSIZE 1024

/* 
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

int main(int argc, char **argv) {
    int sockfd, portno, n;
    socklen_t serverlen;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    char buf[BUFSIZE];
	int fd;

    /* check command line arguments */
    if (argc != 3) {
       fprintf(stderr,"usage: %s <hostname> <port>\n", argv[0]);
       exit(0);
    }
    hostname = argv[1];
    portno = atoi(argv[2]);

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        exit(0);
    }

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);

    /* get a message from the user */
    bzero(buf, BUFSIZE);
	fd = open(FILE_NAME, O_RDONLY | O_CREAT);
	if (fd < 0) {
		fprintf(stderr, "error!\n");
		exit(-1);
	}
	read(fd, buf, BUFSIZE);

	int i;
    for (i = 0; i < 104; i++) {
        fprintf(stderr, "%02x%c", buf[i],
                ((i+1)%16) ? ' ':'\n');

    }

    /* send the message to the server */
    serverlen = sizeof(serveraddr);
    n = sendto(sockfd, buf, 104, 0, (struct sockaddr *)&serveraddr, serverlen);
    if (n < 0) 
      error("ERROR in sendto");
    
    /* print the server's reply */
    n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&serveraddr, &serverlen);
    if (n < 0) 
      error("ERROR in recvfrom");
    printf("Echo from server: %s", buf);
    return 0;
}
