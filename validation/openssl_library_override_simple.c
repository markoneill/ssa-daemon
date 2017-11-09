#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <openssl/ossl_typ.h>
#include <openssl/bio.h>
//#include "ssl_st_def.h"

#define TLS_PROTO	(715 % 255)
#define SO_HOSTNAME	85
#define INVALID_SOCKET	(-1)
#define MAX_HOSTNAME	255

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

int g_sock_fd;

typedef struct SSL ssl_st;
socklen_t get_sockadrr_size(const BIO_ADDR *ap);

int BIO_socket(int domain, int socktype, int protocol, int options){
	int sock_fd;
	printf("************* BIO_socket called\n");
	sock_fd = -1;

	sock_fd = socket(domain, socktype, TLS_PROTO);
	if (sock_fd == -1){
		return INVALID_SOCKET;
	}
	printf("%i\n", sock_fd);

	const char hostname[] = "google.com";
	if (setsockopt(sock_fd, IPPROTO_IP, SO_HOSTNAME, hostname, sizeof(hostname)) == -1) {
		perror("setsockopt: SO_HOSTNAME");
		return -1;
	} 

	return sock_fd;
}

int BIO_connect(int sock, const BIO_ADDR *addr, int options){
	int sockaddr_size;

	printf("******** BIO_connect called\n");
	g_sock_fd = sock;
	
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


int SSL_write(SSL *s, const void *buf, int len){
	int ret;
	char hostname_retrieved[MAX_HOSTNAME];
	int hostname_length = MAX_HOSTNAME;
	printf("******** SSL_write called: %i\n", len);
	
	getsockopt(g_sock_fd, IPPROTO_IP, SO_HOSTNAME, hostname_retrieved, &hostname_length);
	printf("Hostname Get: %s\n", hostname_retrieved);

	printf("Length to write: %i\n", len);

	ret = send(g_sock_fd, buf, len, 0);
	if (ret < 0){
		perror("Send");
	}
	printf("Bytes Sent: %i\n", ret);

	return ret;
}

int SSL_read(SSL *s, void *buf, int num){
	int ret;
	printf("******** SSL_read called\n");	

	ret = recv(g_sock_fd, buf, num, 0);
	if (ret < 0){
		perror("Recieve");
	}
	printf("Buf output: %s\n", ((char *)buf));

	return ret;
}


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
