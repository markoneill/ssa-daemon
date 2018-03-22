#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../in_tls.h"

#define DEFAULT_ADDR    "localhost"
#define DEFAULT_PORT    "8080"
#define CERT_PATH       "../certificate_personal.pem"
#define KEY_PATH        "../key_personal.pem"

int NO_CLIENT_AUTH = 0;

void usage(char* name);
int send_request(char* host, char* port, char* cert_path, char* key_path);
int connect_to_host(char* host, char* service, char* cert_path, char* key_path);
void print_identity(int fd);

int main(int argc, char* argv[]) {
	char* port = NULL;
	char* host = NULL;
	char* cert_path = NULL;
	char* key_path = NULL;	

	port = DEFAULT_PORT;
	host = DEFAULT_ADDR;
	cert_path = CERT_PATH;
	key_path = KEY_PATH;

	int c;
	while ((c = getopt(argc, argv, "np:h:c:k:")) != -1) {
		switch (c) {
			case 'p':
				port = optarg;
				break;
			case 'h':
				host = optarg;
				break;
			case 'c':
				cert_path = optarg;
				break;
			case 'k':
				key_path = optarg;
				break;
			case 'n':
				NO_CLIENT_AUTH = 1;
				break;				
			case '?':
				if (optopt == 'p' || optopt == 'h' || optopt == 'c' || optopt == 'k' ) {
					fprintf(stderr, "Option -%c requires an argument\n", optopt);
					usage(argv[0]);
					exit(EXIT_FAILURE);
				}
			default:
				fprintf(stderr, "Unknown option encountered\n");
				usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}
	send_request(host,port,cert_path,key_path);
	return 0;
}

void usage(char* name) {
	printf("Usage: %s [-p port] [-h host] [-k key path] [-c cert path] [-n] No client auth\n", name);
	printf("Example:\n");
        printf("\t%s -h www.google.com -p 443 \n", name);
	return;
}


int send_request(char* host, char* port, char* cert_path, char* key_path) {
	int sock_fd;
	char* http_request;
	char http_response[2048];
	int msg_size;
	printf("Connect\n");
	sock_fd = connect_to_host(host, port,cert_path, key_path);
	memset(http_response, 0, 2048);
	msg_size = asprintf(&http_request, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host);
	if (msg_size < 0) {
		printf("Unable to allocate emessage\n");
		return -1;
	}
	printf("Send\n");
	if (send(sock_fd, http_request, msg_size, 0) < 0) {
		perror("send");
		return -1;
	}
	printf("Recv\n");
	if (recv(sock_fd, http_response, 750, 0) < 0) {
		perror("recv");
		return -1;
	}
	printf("Received:\n%s", http_response);
	free(http_request);
	close(sock_fd);
	
}


int connect_to_host(char* host, char* service, char* cert_path, char* key_path) {
	int sock;
	int ret;
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	ret = getaddrinfo(host, service, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {

		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (sock == -1) {
			perror("socket");
			continue;
		}

	    if (setsockopt(sock, IPPROTO_TLS, SO_REMOTE_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("setsockopt: SO_REMOTE_HOSTNAME");
			close(sock);
			continue;
		}

		if (setsockopt(sock, IPPROTO_TLS, SO_CERTIFICATE_CHAIN, cert_path, sizeof(CERT_PATH)) == -1) {
			printf("setsockopt: SO_CERTIFICATE_CHAIN");
			continue;
		}

		if (setsockopt(sock, IPPROTO_TLS, SO_PRIVATE_KEY, key_path, sizeof(KEY_PATH)) == -1) {
			printf("setsockopt: SO_PRIVATE_KEY");
			continue;
		}
		
		if (connect(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect");
			close(sock);
			continue;
		}

		//print_identity(sock);
		break;
	}
	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "failed to find a suitable address for connection\n");
		exit(EXIT_FAILURE);
	}
	return sock;
}

void print_identity(int fd) {
	char data[2048];
	socklen_t data_len = sizeof(data);
	if (getsockopt(fd, IPPROTO_TLS, SO_PEER_CERTIFICATE, data, &data_len) == -1) {
		perror("SO_PEER_CERTIFICATE");
	}
	printf("Peer certificate:\n%s\n", data);
	if (getsockopt(fd, IPPROTO_TLS, SO_PEER_IDENTITY, data, &data_len) == -1) {
		perror("SO_PEER_IDENTITY");
	}
	printf("Peer identity:\n%s\n", data);
	return;
}
