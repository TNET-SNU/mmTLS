all: gcm-encrypt aes_256_gcm_encrypt aes_256_gcm_decrypt

gcm-encrypt: evp-gcm-encrypt.c
	gcc evp-gcm-encrypt.c -o gcm-encrypt -lcrypto -lssl

aes_256_gcm_encrypt: aes_256_gcm_encrypt.c
	gcc aes_256_gcm_encrypt.c -o aes_256_gcm_encrypt -lcrypto -lssl

aes_256_gcm_decrypt: aes_256_gcm_decrypt.c
	gcc aes_256_gcm_decrypt.c -o aes_256_gcm_decrypt -lcrypto -lssl

clean:
	rm gcm-encrypt aes_256_gcm_encrypt aes_256_gcm_decrypt *~

