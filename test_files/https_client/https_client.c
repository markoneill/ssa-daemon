#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../in_tls.h"

int main() {
	struct sockaddr_host addr;
	addr.sin_family = AF_HOSTNAME;
	strcpy((char*)addr.sin_addr.name, "www.google.com");
	addr.sin_port = htons(443);

	int sock_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TLS);
	connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr));

	char http_request[] = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
	char http_response[2048];
	memset(http_response, 0, 2048);
	printf("sending\n");
	send(sock_fd, http_request, sizeof(http_request)-1, 0);
	printf("recving\n");
	recv(sock_fd, http_response, 2047, 0);
	printf("closing\n");
	close(sock_fd);
	printf("Received:\n%s", http_response);
	return 0;
}

