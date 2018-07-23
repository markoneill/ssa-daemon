TARGET=https_client
	
normal:
	gcc -o ssl_early_data ssl_early_data.c -I ../../openssl/include/ -L ../../openssl/lib -lssl -lcrypto
	gcc -o $(TARGET) https_client.c

clean:
	rm $(TARGET)
	rm ssl_early_data


