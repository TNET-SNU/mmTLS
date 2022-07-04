all: test_digest

test_digest: test_digest.c
	gcc test_digest.c -o test_digest -lcrypto -lssl

clean:
	rm test_digest *~
