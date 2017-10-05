#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <openssl/bio.h>

#define TLS_PROTO	(715 % 255)
#define SO_HOSTNAME	85
#define INVALID_SOCKET	(-1)

union bio_addr_st {
    struct sockaddr sa;
# ifdef AF_INET6
    struct sockaddr_in6 s_in6;
# endif
    struct sockaddr_in s_in;
# ifdef AF_UNIX
    struct sockaddr_un s_un;
# endif
};

socklen_t get_sockadrr_size(const BIO_ADDR *ap);

int BIO_socket(int domain, int socktype, int protocol, int options){
	int sock_fd;
	printf("************* BIO_socket called");
	sock_fd = -1;

	sock_fd = socket(domain, socktype, TLS_PROTO);
	if (sock_fd == -1){
		return INVALID_SOCKET;
	}

	const char hostname[] = "www.google.com";
	if (setsockopt(sock_fd, IPPROTO_IP, SO_HOSTNAME, hostname, sizeof(hostname)) == -1) {
		perror("setsockopt: SO_HOSTNAME");
		return -1;
	} 

	return sock_fd;
}

int BIO_connect(int sock, const BIO_ADDR *addr, int options){
	int sockaddr_size;

	printf("******** BIO_connect called\n");
	
	if (connect(sock, &(addr->sa), get_sockadrr_size(addr)) == -1){
		return 0;	// connect failed
	}

	return 1;	// connect succeeded
}

socklen_t get_sockadrr_size(const BIO_ADDR *ap){
    if (ap->sa.sa_family == AF_INET)
		return sizeof(ap->s_in);
#ifdef AF_INET6
	if (ap->sa.sa_family == AF_INET6)
		return sizeof(ap->s_in6);
#endif
#ifdef AF_UNIX
	if (ap->sa.sa_family == AF_UNIX)
		return sizeof(ap->s_un);
#endif
	return sizeof(*ap);
}

/*
int *SSL_write(SSL *s, const void *buf, size_t len, size_t *written){
	printf("******** SSL_write called\n");
	return 0;
}

int *SSL_read(SSL *s, void *buf, size_t len, size_t *readbytes){
	printf("******** SSL_read called\n");	
	return 0;
}

*/
/*

	if (ap->sa.sa_family == AF_INET){
		sockaddr_size = sizeof(ap->s_in);
	}
#ifdef AF_INET6
	if (ap->sa.sa_family == AF_INET6){
		sockaddr_size = sizeof(ap->s_in6);
	}
#endif

#ifdef AF_UNIX
	if (ap->sa.sa_family == AF_UNIX){
		sockaddr_size = sizeof(ap->s_un);
	}
#endif

	sockaddr_size = sizeof(*ap);

*/
