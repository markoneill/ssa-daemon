#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

/* OpenSSL includes */
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define BUFFER_MAX	200

static int connect_to_host(char* host, char* port, int protocol);
static SSL* openssl_connect_to_host(int sock, char* hostname);
static int new_session_cb(SSL* tls, SSL_SESSION* session);
static void rm_session_cb(SSL_CTX* tls_ctx, SSL_SESSION* session);
int resume_session(SSL* tls, const unsigned char* id, int idlen, int* copy);
SSL_SESSION* cached_session;

int main() {
	int i;
	int sock;
	SSL* tls;
	char query[2048];
	char response[2048];
	int query_len;
	char hostname[] = "www.google.com";

	/* Connect one time */	
	sock = connect_to_host(hostname, "443", SOCK_STREAM);
	tls = openssl_connect_to_host(sock, hostname);
	sprintf(query ,"GET / HTTP/1.1\r\nHost: %s\r\n\r\n", hostname);
	query_len = strlen(query);
	SSL_write(tls, query, query_len);
	SSL_read(tls, response, sizeof(response));
	printf("Connected once and received data\n");
	SSL_shutdown(tls);
	SSL_free(tls);
	close(sock);

	/* Connect again */
	sock = connect_to_host(hostname, "443", SOCK_STREAM);
	tls = openssl_connect_to_host(sock, hostname);
	SSL_shutdown(tls);
	SSL_free(tls);
	close(sock);
	return 0;
}

SSL* openssl_connect_to_host(int sock, char* hostname) {
	SSL_CTX* tls_ctx;
	SSL* tls;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	tls_ctx = SSL_CTX_new(TLS_client_method());
	if (tls_ctx == NULL) {
		fprintf(stderr, "Could not create SSL_CTX\n");
		exit(EXIT_FAILURE);
	}
	SSL_CTX_sess_set_new_cb(tls_ctx, new_session_cb);
	SSL_CTX_set_session_cache_mode(tls_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
	SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_NONE, NULL);

	tls = SSL_new(tls_ctx);
	SSL_CTX_free(tls_ctx); /* lower reference count now in case we need to early return */
	if (tls == NULL) {
		fprintf(stderr, "SSL_new from tls_ctx failed\n");
		exit(EXIT_FAILURE);
	}

	/* set server name indication for client hello */
	SSL_set_tlsext_host_name(tls, hostname);

	resume_session(tls, (const unsigned char*)hostname, strlen(hostname), NULL);

	/* Associate socket with TLS context */
	SSL_set_fd(tls, sock);

	if (SSL_connect(tls) != 1) {
		fprintf(stderr, "Failed in SSL_connect\n");
		exit(EXIT_FAILURE);
	}

	if (SSL_session_reused(tls)) {
		printf("Resumed a session!\n");
	}
	else {
		printf("Did NOT resume session!\n");
	}


	return tls;
}

int connect_to_host(char* host, char* service, int protocol) {
	int sock;
	int ret;
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = protocol;
	hints.ai_family = AF_UNSPEC; // IP4 or IP6, we don't care
	ret = getaddrinfo(host, service, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
		if (sock == -1) {
			perror("socket");
			continue;
		}
		if (connect(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect");
			close(sock);
			continue;
		}
		break;
	}
	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "Failed to find a suitable address for connection\n");
		exit(EXIT_FAILURE);
	}
	return sock;
}

int new_session_cb(SSL* tls, SSL_SESSION* session) {
	cached_session = session;
	printf("Session saved\n");
	return 1;
}

void rm_session_cb(SSL_CTX* tls_ctx, SSL_SESSION* session) {
	cached_session = NULL;
	printf("Session removed\n");
	return;
}

int resume_session(SSL* tls, const unsigned char* id, int idlen, int* copy) {
	/* Here is where you would use hostname and port to look up */
	if (cached_session == NULL) {
		return 0;
	}
	
	SSL_set_session(tls, cached_session);

	return 1;
}

