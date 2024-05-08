CC=$gcc
CNF_CFLAGS=-pthread -m64 -Wa,--noexecstack
CFLAGS=-Wall -O3
BIN_CFLAGS=$(CNF_CFLAGS) $(CFLAGS)
CNF_EX_LIBS=-ldl -pthread
BIN_EX_LIBS=$(CNF_EX_LIBS)


all: tag.c ../libcrypto.a
	$${LDCMD:-$(CC)} $(BIN_CFLAGS) -DGHASH_ASM -DAES_ASM -DGHASH_ASM_X86_OR_64 \
		tag.c \
		-o tag \
		../libcrypto.a $(BIN_EX_LIBS)

clean:
	rm tag
