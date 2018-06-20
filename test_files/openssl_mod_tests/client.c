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
#define CLIENT_CERT	"../certificate_personal.pem"
#define CLIENT_KEY	"../key_personal.pem"

int connect_to_host(char* host, char* port, int protocol);
SSL* openssl_connect_to_host(int sock, char* hostname, char* client_pub_file);
int client_auth_callback(SSL *s, void* hdata, size_t hdata_len, int sigalg_nid, unsigned char** o_sig, size_t* o_siglen);
int client_cert_callback(SSL *s, X509** cert, EVP_PKEY** key);
EVP_PKEY* get_private_key_from_file(char* filename);
X509* get_cert_from_file(char* filename);

int main() {
	int sock;
	SSL* tls;
	char* query;
	int query_len;
	char response[2048];
	/*char* query_again;
	int query_again_len;*/
	char hostname[] = "openrebellion.com";

	printf("Connecting to %s\n", hostname);
	memset(response, 0, 2048);
	
	sock = connect_to_host(hostname, "443", SOCK_STREAM);
	tls = openssl_connect_to_host(sock, hostname, CLIENT_CERT);

	query = "GET /account/index.php HTTP/1.1\r\nHost: openrebellion.com\r\n\r\n";
	query_len = strlen(query);
	/*query_again = "GET / HTTP/1.1\r\nHost: openrebellion.com\r\n\r\n";
	query_again_len = strlen(query_again);*/
	while (SSL_write(tls, query, query_len) <= 0) {}
	//SSL_read(tls, NULL, 0);
	while (SSL_read(tls, response, sizeof(response)) <= 0) {}
	printf("Received:\n%s", response);

	/*SSL_write(tls, query_again, query_again_len);
	SSL_read(tls, response, sizeof(response));
	printf("Received:\n%s", response);*/


	close(sock);
	SSL_shutdown(tls);
	SSL_free(tls);
	return 0;
}

SSL* openssl_connect_to_host(int sock, char* hostname, char* client_pub_file) {
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
	SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_client_cert_cb(tls_ctx, client_cert_callback);

	if (client_pub_file != NULL) {
		/*printf("Using client certificate chain at %s\n", client_pub_file);
		if (SSL_CTX_use_certificate_chain_file(tls_ctx, client_pub_file) != 1) {
			fprintf(stderr, "Could not use file at %s\n", client_pub_file);
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}*/

		// For Sanity check, uncomment below to add the private key to the ctx
		/*if (SSL_CTX_use_PrivateKey_file(tls_ctx, CLIENT_KEY, SSL_FILETYPE_PEM) != 1) {
			fprintf(stderr, "Could not use file at %s\n", CLIENT_KEY);
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}*/
	}

	tls = SSL_new(tls_ctx);
	SSL_force_post_handshake_auth(tls);

	if (client_pub_file != NULL) {
		// set the client auth callback
		//SSL_set_client_auth_cb(tls, client_auth_callback);
	}

	SSL_CTX_free(tls_ctx); /* lower reference count now in case we need to early return */
	if (tls == NULL) {
		fprintf(stderr, "SSL_new from tls_ctx failed\n");
		exit(EXIT_FAILURE);
	}

	/* set server name indication for client hello */
	SSL_set_tlsext_host_name(tls, hostname);

	/* Associate socket with TLS context */
	SSL_set_fd(tls, sock);

	if (SSL_connect(tls) != 1) {
		fprintf(stderr, "Failed in SSL_connect\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
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

	struct timeval timeout;      
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
		printf("setsockopt failed\n");
		exit(EXIT_FAILURE);
	}
	
	if (setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
		printf("setsockopt failed\n");
		exit(EXIT_FAILURE);
	}

	return sock;
}

int client_auth_callback(SSL *s, void* hdata, size_t hdata_len, int sigalg_nid, unsigned char** o_sig, size_t* o_siglen) {
        EVP_PKEY* pkey = NULL;
        const EVP_MD *md = NULL;
        EVP_MD_CTX *mctx = NULL;
        EVP_PKEY_CTX *pctx = NULL;
        size_t siglen;
        unsigned char* sig;

        printf("Signing hash\n");
        pkey = get_private_key_from_file(CLIENT_KEY);
        if (pkey == NULL) {
                return 0;
        }
        mctx = EVP_MD_CTX_new();
        if (mctx == NULL) {
                EVP_PKEY_free(pkey);
                return 0;
        }

        siglen = EVP_PKEY_size(pkey);
        sig = (unsigned char*)malloc(siglen);
        if (sig == NULL) {
                EVP_PKEY_free(pkey);
                EVP_MD_CTX_free(mctx);
                return 0;
        }
        
        md = EVP_get_digestbynid(sigalg_nid);
        if (md == NULL) {
                EVP_PKEY_free(pkey);
                EVP_MD_CTX_free(mctx);
                free(sig);
                return 0;
        }

        if (EVP_DigestSignInit(mctx, &pctx, md, NULL, pkey) <= 0) {
                EVP_PKEY_free(pkey);
                EVP_MD_CTX_free(mctx);
                free(sig);
                return 0;
        }
	EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
	EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);

        if (EVP_DigestSign(mctx, sig, &siglen, hdata, hdata_len) <= 0) {
                EVP_PKEY_free(pkey);
                EVP_MD_CTX_free(mctx);
                free(sig);
                return 0;
        }

        *o_sig = sig;
        *o_siglen = siglen;

        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mctx);
        /* sig is freed by caller */
        
        return 1;
}


EVP_PKEY* get_private_key_from_file(char* filename) {
	EVP_PKEY* key;
	FILE* key_file;
	key_file = fopen(filename, "r");
	if (key_file == NULL) {
		return NULL;
	}

	key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
	if (key == NULL) {
		fclose(key_file);
		return NULL;
	}
	fclose(key_file);
	return key;
}

X509* get_cert_from_file(char* filename) {
	X509* cert;
	FILE* cert_file;
	cert_file = fopen(filename, "r");
	if (cert_file == NULL) {
		return NULL;
	}

	cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
	if (cert == NULL) {
		fclose(cert_file);
		return NULL;
	}
	fclose(cert_file);
	return cert;
}

int client_cert_callback(SSL *s, X509** cert, EVP_PKEY** key) {
	printf("Setting certificate\n");
	*cert = get_cert_from_file(CLIENT_CERT);
	*key = NULL;
	//*key = get_private_key_from_file(CLIENT_KEY);
	SSL_set_client_auth_cb(s, client_auth_callback);
	return 1;
}
