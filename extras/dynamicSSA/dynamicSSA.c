#define _GNU_SOURCE
#define MAP_BUCKETS             10

#define LOG_FILE "/tmp/sslLog.txt"
#define SOCKET_PATH "\0tls_upgrade"

#include <dlfcn.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <netinet/tcp.h> 
#include <fcntl.h> 

#include "../../in_tls.h"
#include "hashmap.h"


typedef struct conn_stat {
    int upgraded;
    int keys;
} conn_stat_t;


typedef SSL *(*orig_SSL_new_f_type)(SSL_CTX *ctx);
typedef void (*orig_SSL_free_f_type)(SSL *ssl);

int logSSL(char* msg);
int upgrade_check(SSL *ssl);
X509* PEM_str_to_X509(char* pem_str);
int dup_socket_TLS(int fd, const char * ssl_hostname);

hmap_t* connection_map = NULL;


int logSSL(char* msg)
{
    FILE * fd = fopen(LOG_FILE,"a");
    fputs(msg,fd);
    fclose(fd);
}


SSL *SSL_new(SSL_CTX *ctx)
{

    if(!connection_map) {
        connection_map = hashmap_create(MAP_BUCKETS);
    }

    SSL * ssl_obj;

    orig_SSL_new_f_type orig_SSL_new;
    orig_SSL_new = (orig_SSL_new_f_type)dlsym(RTLD_NEXT,"SSL_new");

    ssl_obj = orig_SSL_new(ctx);

    int conn_stat_len = sizeof(conn_stat_t);
    conn_stat_t * connection_stat = malloc(conn_stat_len);
    memset(connection_stat,0,conn_stat_len);
    hashmap_add(connection_map, (unsigned long) ssl_obj, connection_stat);

    // char * message;
    // asprintf(&message,"New SSL %p\n", ssl_obj);
    // logSSL(message);
    // free(message);


    return ssl_obj;
}


int SSL_connect(SSL *s)
{
    // Lie that we have connected.
    return 1;
}

int upgrade_check(SSL *ssl)
{
    int dup_fd;
    struct tcp_info info;
    char * hostname = NULL;
    char * message = NULL; 
    conn_stat_t * con = NULL;
    int fd = SSL_get_fd(ssl);
    int infoLen = sizeof(info);
    int is_accepting = SSL_in_accept_init(ssl) ? 1 : 0;
    socklen_t optlen;

    if (connection_map) {

        con = (conn_stat_t *) hashmap_get(connection_map,(unsigned long)ssl);
        if (!con) {
            perror("Connection not in hashmap\n");
        }

        if ( !con->upgraded ) {
            memset(&info,0,infoLen);
            getsockopt(fd, SOL_TCP, TCP_INFO, (void *)&info, (socklen_t *)&infoLen);

            // Access hostname from SSL structure. Also one in the session part of SSL object?
            hostname = (char *) SSL_get_servername(ssl,TLSEXT_NAMETYPE_host_name);

            // What states do we want to upgrade and which ones do we want to leave alone?
            if (info.tcpi_state != 0) { //== TCP_ESTABLISHED) {
		if (is_accepting == 0 && hostname != NULL) {
			optlen = strlen(hostname)+1;
		}
		else {
			optlen = 0;
		}
                if (setsockopt(fd, IPPROTO_TCP, TCP_UPGRADE_TLS, hostname, optlen) == -1) {
                      perror("setsockopt: TCP_UPGRADE_TLS");
                      close(fd);
               }
            }

            //Not connected duplicate connection
            else if(info.tcpi_state == 0)
            {
                dup_fd = dup_socket_TLS(fd,hostname);
                dup2(dup_fd,fd);
            }
            else
            {
                asprintf(&message,"Unaccounted state %u\n", info.tcpi_state);
                logSSL(message);
                free(message);
                perror("Unaccounted connection state");
            }
            
            con->upgraded = 1;
        }
    }
}

int SSL_write(SSL *ssl, const void *buf, int num)
{
    int wfd, ret;

    upgrade_check(ssl);
    logSSL("Writing to socket\n");
    wfd = SSL_get_wfd(ssl);
    return send(wfd, buf, num, 0);

}

int SSL_read(SSL *ssl, void *buf, int num)
{
    int rfd, ret;

    upgrade_check(ssl);
    logSSL("Reading from socket\n");
    rfd = SSL_get_rfd(ssl);
    return recv(rfd, buf, num, 0);

}

int SSL_peek(SSL *ssl, void *buf, int num)
{
    int rfd, ret;

    upgrade_check(ssl);
    // logSSL("Peek from socket\n");
    rfd = SSL_get_rfd(ssl);
    return recv(rfd, buf, num, MSG_PEEK);

}

// Lie that we have finished
int SSL_is_init_finished(SSL *s)
{
    return 1;
}

// SSL_ERROR_WANT_READ Lie to litt
int SSL_get_error(const SSL *ssl, int ret)
{
    // Lie for error
    return SSL_ERROR_WANT_READ;
}


X509 *SSL_get_peer_certificate(const SSL *s)
{
    int ssl_fd = SSL_get_rfd(s);
    int cert_len = 1024*4;
    char cert[1024*4];
    
    // SSL *ssl, void *buf, int num
    upgrade_check((SSL *)s);

    // SSL_write((SSL*)s,"GET / HTTP/1.1\r\nhost: google.com\r\n\r\n",1);

    if (getsockopt(ssl_fd, IPPROTO_TLS, SO_PEER_CERTIFICATE, cert, &cert_len) == -1) {
        perror("getsockopt: SO_PEER_CERTIFICATE:");
    }

    /* Cert conversion to an X509 OpenSSL Object */
    X509* cert_openssl = PEM_str_to_X509(cert);

    return cert_openssl;
}


X509* PEM_str_to_X509(char* pem_str) {
    X509* cert;
    BIO* bio;

    if (pem_str == NULL) {
        return NULL;
    }

    bio = BIO_new_mem_buf(pem_str, strlen(pem_str));
    if (bio == NULL) {
        return NULL;
    }
    
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (cert == NULL) {
        return NULL;
    }

    BIO_free(bio);
    return cert;
}

void SSL_free(SSL *ssl)
{
    char * message;

    orig_SSL_free_f_type orig_SSL_free;
    orig_SSL_free = (orig_SSL_free_f_type)dlsym(RTLD_NEXT,"SSL_free");

    conn_stat_t * con;
    con = (conn_stat_t *) hashmap_get(connection_map,(unsigned long)ssl);
    free(con);
    int del_ret = hashmap_del(connection_map, (unsigned long)ssl);

    
    // asprintf(&message,"SSL_FREE %d sslObj %p\n", del_ret,ssl);
    // logSSL(message);
    // free(message);
    orig_SSL_free(ssl);
}
