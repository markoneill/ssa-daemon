#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"
#include "../../in_tls.h"

#define MIN(a, b) a < b ? a : b

int connect_to_host(char* host, char* service) {
	int fd;
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
		return -1;
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		fd = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (fd == -1) {
			perror("connect_to_host: socket");
			continue;
		}
	        if (setsockopt(fd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("connect_to_host: setsockopt TLS_REMOTE_HOSTNAME");
			close(fd);
			continue;
		}

		if (connect(fd, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect_to_host: connect");
			close(fd);
			continue;
		}

		break;
	}
	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "failed to find a suitable address for connection\n");
		return -1;
	}
	return fd;
}

int bind_listen(uint16_t port, char* hostname) {
	struct sockaddr_in in_addr;
	socklen_t addr_len = sizeof(in_addr);
	int fd;

	in_addr.sin_family = AF_INET;
	in_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	in_addr.sin_port = htons(port);
	if ((fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TLS)) == -1) {
		perror("bind_listen socket");
		return fd;
	}
	if (bind(fd, (struct sockaddr*)&in_addr, addr_len) == -1) {
		perror("bind_listen bind");
		if (close(fd) == -1) {
			perror("close connect_test_server");
		}
		return -1;
	}
	if (setsockopt(	fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN,
			CERT_FILE_A, sizeof(CERT_FILE_A)) == -1)
	{ perror("cert A"); }
	if (setsockopt( fd, IPPROTO_TLS, TLS_PRIVATE_KEY,
			KEY_FILE_A, sizeof(KEY_FILE_A)) == -1)
	{ perror("key A"); }
	if (setsockopt( fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN,
			CERT_FILE_B, sizeof(CERT_FILE_B)) == -1)
	{ perror("cert B"); }
	if ( setsockopt( fd, IPPROTO_TLS, TLS_PRIVATE_KEY,
			KEY_FILE_B, sizeof(KEY_FILE_B)) == -1)
	{ perror("key B"); }
	if (listen(fd, SOMAXCONN) == -1) {
		perror("bind_listen listen");
		if (close(fd) == -1) {
			perror("close connect_test_server");
		}
		return -1;
	}
	return fd;
}

int echo_recv(int fd, char* buff, size_t buff_len) {
	char request[LARGE_BUFFER];
	int request_len;
	int err = 0;
	struct timeval tv = { 5, 0 };

	memset(request, 0, LARGE_BUFFER);
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
		perror("setsockopt SO_RCVTIMEO");
	}
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
		perror("setsockopt SO_RCVTIMEO");
	}
	if ((request_len = recv(fd, request, LARGE_BUFFER, 0)) == -1) {
		err = request_len;
		perror("echo_recv: recv");
	}
	else if ((err = send(fd, request, request_len, 0)) == -1) {
		perror("echo_recv: send");
	}
	if (!err && buff) {
		memcpy(buff, request, MIN(request_len, buff_len));
		return MIN(request_len, buff_len);
	}
	return err;
}

/*
int timed_accept(int listen_fd, struct sockaddr* addr, socklen_t* addr_len, int timeout) {
	int accept_fd;
	int errno_save;

	alarm(timeout);
	accept_fd = accept(listen_fd, addr, addr_len);
	errno_save = errno;
	alarm(0);
	if (-1 == accept_fd) {
		if (EINTR == errno_save) {
			return 0;
		}
		return -1;
	}
	return accept_fd;
}
*/

/*
void shmem_test(void) {
	ctx->server_funct = connect_test_client;
	ctx->funct_ret = 5;
	ctx->test_status = 6;
	if ((server_pid = fork()) == 0) {
		printf("Child read: funct %p, ret %d, stat %d\n",
			ctx->server_funct, ctx->funct_ret, ctx->test_status);
		ctx->server_funct = connect_test_server;
		ctx->funct_ret = 7;
		ctx->test_status = 2;
		printf("Child wrote: funct %p, ret %d, stat %d\n",
			ctx->server_funct, ctx->funct_ret, ctx->test_status);

	
	} else {
		printf("Parent read:funct %p, ret %d, stat %d\n",
			ctx->server_funct, ctx->funct_ret, ctx->test_status);
;
		sleep(1);
		printf("After 1s, parent read: funct %p, ret %d, stat %d\n",
			ctx->server_funct, ctx->funct_ret, ctx->test_status);

	}
}
*/
