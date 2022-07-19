#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>

#define FILE_NAME "example_keyinfo"

int
main(int argc, char *argv[])
{
	char data[1024];
	int fd;
	char *ptr;

	fd = open(FILE_NAME, O_WRONLY | O_CREAT);
	if (fd < 0) {
		perror("open failed");
		exit(-1);
	}

	ptr = data;
	*(uint16_t*)ptr = htons(0x1234);
	ptr += 2;
		
	*((uint16_t*)ptr) = htons(0xffff);
	ptr += 2;

	memset(ptr, 1, 32);
	ptr += 32;
	memset(ptr, 2, 32);
	ptr += 32;
	memset(ptr, 3, 12);
	ptr += 12;
	memset(ptr, 4, 12);
	ptr += 12;

	*(uint32_t*)ptr = htonl(0xa002d03);
	ptr += 4;
	*(uint32_t*)ptr = htonl(0xa002d02);
	ptr += 4;
	*(uint16_t*)ptr = htons(atoi(argv[1]));
	ptr += 2;
	*(uint16_t*)ptr = htons(6666);
	ptr += 2;

	int i;
	for (i = 0; i < 104; i++) {
		fprintf(stderr, "%02x%c", data[i],
				((i+1)%16) ? ' ':'\n');
		
	}
	
	write(fd, data, 104);

	close(fd);

	return 0;
}
