#define _GNU_SOURCE

#include <dlfcn.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include "../in_tls.h"

#define PORT_LENGTH	32
char* custom_itoa(int num, char* buf, int len);

/* This POC is IPv4 only but can easily be extended to do IPv6 */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	typeof(connect) *real_connect;
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;
	struct sockaddr_host* host_addr;
	char* hostname;
	char service[PORT_LENGTH];
	int ret;
	int type;
	int type_len;

	printf("Connect overriden\n");

	/* Determine location of original connect call */
	real_connect = dlsym(RTLD_NEXT, "connect");
	if (addr->sa_family != AF_HOSTNAME) {
		return (*real_connect)(sockfd, addr, addrlen);
	}

	/* Determine socket type */
	type_len = sizeof(type);
	if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &type_len) == -1) {
		errno = EPROTOTYPE;
		return -1;
	}


	/* Set hostname (only works on TLS sockets, so we check retval) */
	host_addr = (struct sockaddr_host*)addr;
	hostname = host_addr->sin_addr.name;
	setsockopt(sockfd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, hostname, strlen(hostname)+1);

	/* Resolve hostname */
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = type;
	hints.ai_family = AF_INET; /* Set AF_UNSPEC for IPv6 and IPv4 */
	custom_itoa(ntohs(host_addr->sin_port), service, PORT_LENGTH);
	ret = getaddrinfo(hostname, service, &hints, &addr_list);
	if (ret != 0) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		if ((*real_connect)(sockfd, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == 0) {
			return 0; /* Success */
		}
	}
	freeaddrinfo(addr_list);
	errno = EAFNOSUPPORT;
	return -1;
}


char* custom_itoa(int num, char* buf, int len) {
	if (buf == NULL) {
		return NULL;
	}
	snprintf(buf, len, "%d", num);
	return buf;
}

