#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../in_tls.h"

#define MAX_REQUEST_SIZE 2048
#define MAX_RESPONSE_SIZE 2048

void print_identity(int fd);

int main(int argc, char* argv[]) {
	int sock_fd;
	int ret;
	char http_request[MAX_REQUEST_SIZE];
	char http_response[MAX_RESPONSE_SIZE];
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	if (argc < 3) {
		printf("USAGE: %s <host name> <port>\n", argv[0]);
		return 0;
	}

    char* host = argv[1];
    char* port = argv[2]; //use port given to allow for more flexibility while testing

    //set up the connection
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	ret = getaddrinfo(host, port, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

    //connect to the port
	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock_fd = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (sock_fd == -1) {
			perror("socket");
			continue;
		}

        //set the correct hostname for correct handshake
        if (setsockopt(sock_fd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("setsockopt: TLS_REMOTE_HOSTNAME");
			close(sock_fd);
			continue;
		}

        //connect to the socket
		if (connect(sock_fd, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect");
			close(sock_fd);
			continue;
		}

		print_identity(sock_fd);
		break;
	}

	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "failed to find a suitable address for connection\n");
		exit(EXIT_FAILURE);
	}

    //put the HTTP request into the buf
	sprintf(http_request,"GET / HTTP/1.1\r\nhost: %s\r\n\r\n", argv[1]);
	memset(http_response, 0, 2048);
    
    //send encrypted request
    int request_size = strlen(http_request);
    int tot_bytes_sent = 0;
    while(tot_bytes_sent < request_size) {
        int bytes_sent = send(sock_fd, http_request + tot_bytes_sent, request_size - tot_bytes_sent, 0);
        tot_bytes_sent += bytes_sent;
    }

    // receive decrypted response
    // in general, more robust reading will be required
	recv(sock_fd, http_response, MAX_RESPONSE_SIZE, 0);
	printf("Received:\n%s\n", http_response);
	close(sock_fd);
	return 0;
}


void print_identity(int fd) {
	char data[4096];
	socklen_t data_len = sizeof(data);
	if (getsockopt(fd, IPPROTO_TLS, TLS_PEER_CERTIFICATE_CHAIN, data, &data_len) == -1) {
		perror("TLS_PEER_CERTIFICATE_CHAIN");
	}
	printf("Peer certificate:\n%s\n", data);
	if (getsockopt(fd, IPPROTO_TLS, TLS_PEER_IDENTITY, data, &data_len) == -1) {
		perror("TLS_PEER_IDENTITY");
	}

	printf("Peer identity:\n%s\n", data);
	return;
}

