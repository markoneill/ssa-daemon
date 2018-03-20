#include <stdio.h>

#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

#include "../../in_tls.h"

#define ADDR	"localhost"
#define PORT	8080

#define CERT_PATH	"../certificate_personal.pem"
#define KEY_PATH	"../key_personal.pem"

#define MSG	"Hey from the client!\n"

int main(int argc, char* argv[]) {
	struct sockaddr_host addr;
	addr.sin_family = AF_HOSTNAME;
	int sock_fd;
	int err_val;

	strcpy((char*)addr.sin_addr.name, "localhost");
	addr.sin_port = htons(443);

	sock_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TLS);
	if (sock_fd == -1) {
		printf("socket error\n");
		return -1;
	}

	// set our client cert
	err_val = setsockopt(sock_fd, IPPROTO_TLS, SO_CERTIFICATE_CHAIN, CERT_PATH, sizeof(CERT_PATH));
	if (err_val) {
		printf("setsockopt cert_chain error: %d\n", err_val);
		return -1;
	}

	err_val = setsockopt(sock_fd, IPPROTO_TLS, SO_PRIVATE_KEY, KEY_PATH, sizeof(KEY_PATH));
	if (err_val) {
		printf("setsockopt key error: %d\n", err_val);
		return -1;
	}

	err_val = connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr));
	if (err_val) {
		print("connect error: %d\n\n", err_val);
		return -1;
	}
	
	send(sock_fd, MSG, sizeof(MSG)-1, 0);

	printf("\n[Finished]\n");
	getchar();

	close(sock_fd);
	printf("Done\n");

	return 0;
}
