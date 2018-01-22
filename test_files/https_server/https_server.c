#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../extras/in_tls.h"

#define CERT_FILE	"path"
#define KEY_FILE	"path"
#define BUFFER_SIZE	2048

void handle_req(char* req, char* resp);

int main() {
	char request[BUFFER_SIZE];
	char response[BUFFER_SIZE];
	memset(request, 0, BUFFER_SIZE);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	addr.sin_port = htons(443);

	int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TLS);
	bind(fd, (struct sockaddr*)&addr, sizeof(addr));
	setsockopt(fd, IPPROTO_TLS, SO_CERTIFICATE_CHAIN, CERT_FILE, sizeof(CERT_FILE));
	setsockopt(fd, IPPROTO_TLS, SO_PRIVATE_KEY, KEY_FILE, sizeof(KEY_FILE));
	listen(fd, SOMAXCONN);

	while (1) {	
		struct sockaddr_storage addr;
		socklen_t addr_len = sizeof(addr);
		int c_fd = accept(fd, (struct sockaddr*)&addr, &addr_len);
		recv(c_fd, request, BUFFER_SIZE, 0);
		handle_req(request, response);
		send(c_fd, response, BUFFER_SIZE, 0);
		close(c_fd);
	}
	return 0;
}

void handle_req(char* req, char* resp) {
	memcpy(resp, req, BUFFER_SIZE);
	return;
}
