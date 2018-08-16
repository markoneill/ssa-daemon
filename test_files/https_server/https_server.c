#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../in_tls.h"

#define CERT_FILE_A	"test_files/certificate_a.pem"
#define KEY_FILE_A	"test_files/key_a.pem"
#define CERT_FILE_B	"test_files/certificate_b.pem"
#define KEY_FILE_B	"test_files/key_b.pem"
#define BUFFER_SIZE	2048

void handle_req(char* req, char* resp);

int main() {
	char servername[255];
	int servername_len = sizeof(servername);
	char request[BUFFER_SIZE];
	char response[BUFFER_SIZE];
	memset(request, 0, BUFFER_SIZE);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	addr.sin_port = htons(8080);

	int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TLS);
	bind(fd, (struct sockaddr*)&addr, sizeof(addr));
	if (setsockopt(fd, IPPROTO_TLS, SO_CERTIFICATE_CHAIN, CERT_FILE_A, sizeof(CERT_FILE_A)) == -1) {
		perror("cert a");
	}
	if (setsockopt(fd, IPPROTO_TLS, SO_PRIVATE_KEY, KEY_FILE_A, sizeof(KEY_FILE_A)) == -1) {
		perror("key a");
	}
	if (setsockopt(fd, IPPROTO_TLS, SO_CERTIFICATE_CHAIN, CERT_FILE_B, sizeof(CERT_FILE_B)) == -1) {
		perror("cert b");
	}
	if (setsockopt(fd, IPPROTO_TLS, SO_PRIVATE_KEY, KEY_FILE_B, sizeof(KEY_FILE_B)) == -1) {
		perror("key b");
	}
	int ret;
	ret = listen(fd, SOMAXCONN);

	while (1) {	
		struct sockaddr_storage addr;
		socklen_t addr_len = sizeof(addr);
		int c_fd = accept(fd, (struct sockaddr*)&addr, &addr_len);
		if (getsockopt(c_fd, IPPROTO_TLS, SO_HOSTNAME, servername, &servername_len) == -1) {
			perror("getsockopt: SO_HOSTNAME");
			exit(EXIT_FAILURE);
		}
		printf("Client requested host %d %s\n", servername_len,  servername);
		int length = recv(c_fd, request, BUFFER_SIZE, 0);
		handle_req(request, response);
		send(c_fd, response, length, 0);
		close(c_fd);
	}
	return 0;
}

void handle_req(char* req, char* resp) {
	memcpy(resp, req, BUFFER_SIZE);
	return;
}
