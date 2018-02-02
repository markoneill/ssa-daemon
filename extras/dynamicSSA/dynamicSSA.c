#define _GNU_SOURCE
#define SO_HOSTNAME             85
#define IPPROTO_TLS             (715 % 255)
#define SO_PEER_CERTIFICATE     86
#define SSA_PORT                8443
#define SSA_ADDR                "127.0.0.1"
#define MAP_BUCKETS             10

#define LOG_FILE "/tmp/sslLog.txt"
#define SOCKET_PATH "\0tls_upgrade"
#define SO_ID   89

#include <dlfcn.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <netinet/tcp.h> 
#include <fcntl.h> 

#include "hashmap.h"


typedef struct conn_stat {
    int upgraded;
    int hostname;
    int ipaddress;
    int keys;
} conn_stat_t;

typedef int (*orig_socket_f_type)(int domain, int type, int protocol);
typedef int (*orig_SSL_set_fd_f_type)(SSL *s, int fd);
typedef SSL *(*orig_SSL_new_f_type)(SSL_CTX *ctx);

int SSA_create_socket();
int dup_socket_TLS(int fd, const char * ssl_hostname);
// int SSA_send_fd(int fd);
ssize_t write_fd(int fd, void* iobuf, size_t nbytes, int sendfd);
conn_stat_t * print_connection(SSL *s);
int upgrade_check(SSL *ssl);
//int dup_socket_TLS(int fd, const char * ssl_hostname);
int connect_to_host(char* host, char* service);
X509* PEM_str_to_X509(char* pem_str);
int logSSL(char* msg);

int upgrade_sock(int fd, SSL *ssl); 
int SSA_send_fd(int fd, unsigned long id, int is_accepting);
ssize_t send_fd_to(int fd, void* iobuf, size_t nbytes, int sendfd, struct sockaddr_un* addr, int addr_len);


int ssl_map_setup = 0;
hmap_t* connection_map;



// TCP_ESTABLISHED = 1,
// TCP_SYN_SENT,
// TCP_SYN_RECV,
// TCP_FIN_WAIT1,
// TCP_FIN_WAIT2,
// TCP_TIME_WAIT,
// TCP_CLOSE,
// TCP_CLOSE_WAIT,
// TCP_LAST_ACK,
// TCP_LISTEN,
// TCP_CLOSING,   /* now a valid state */
// CP_MAX_STATES /* Leave at the end! */
//  };

int logSSL(char* msg)
{
    FILE * fd = fopen(LOG_FILE,"a");
    fputs(msg,fd);
    fclose(fd);
}


SSL *SSL_new(SSL_CTX *ctx)
{

    if(!ssl_map_setup) {
        ssl_map_setup = 1;
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
    // connection_stat->hostname = 0;
    // connection_stat->ipaddress = 0;
    // connection_stat->keys = 0;


    return ssl_obj;
}


int SSL_connect(SSL *s)
{
    int fd = SSL_get_fd(s);
    

    conn_stat_t * connection_stat;

    // Not an exisiting SSL object?
    // connection_stat = print_connection(s);

    // const char * hostname = SSL_get_servername(s,TLSEXT_NAMETYPE_host_name);

    //printf("HOSTNAME %s\n", hostname);
    
    // if (setsockopt(fd, IPPROTO_IP, SO_HOSTNAME, hostname, strlen(hostname)+1) == -1){
    //        perror("setsockopt: SO_HOSTNAME");
    //        close(fd);
    // }
    

    //int new_fd = dup_socket_TLS(old_fd,hostname);
    //dup2(new_fd,old_fd);
    //printf("HOSTNAME %s\n", hostname);
    // logSSL("Called SSL_connect\n");
    //SSL_set_fd(s,new_fd);

    // Old code for duplication TLS Sockets.
    // int old_fd = SSL_get_fd(s);
    // int new_fd = dup_socket_TLS(old_fd,s->tlsext_hostname);
    // dup2(new_fd,old_fd);

    return 1;
}

conn_stat_t * print_connection(SSL *s)
{
    conn_stat_t * con;

    if (ssl_map_setup) {

        con = (conn_stat_t *) hashmap_get(connection_map,(unsigned long)s);
        if (con) {
            // printf("--------------\n"
            //         "upgraded:%d\nHostname:%d\nipaddress:%d\nkeys:%d\n"
            //         "--------------\n",con->upgraded,con->hostname,con->ipaddress,con->keys);
            return con;
        }
        else {
            perror("Connection not in hashmap\n");
        }
    }
    return 0;
}

int upgrade_check(SSL *ssl)
{
    int dup_fd;
    int fd = SSL_get_fd(ssl);
    struct tcp_info info;
    int infoLen = sizeof(info);
    const char * hostname = NULL;

    char * message = NULL; 

    conn_stat_t * con = print_connection(ssl);
    if ( !con->upgraded ) {

        memset(&info,0,infoLen);
        getsockopt(fd, SOL_TCP, TCP_INFO, (void *)&info, (socklen_t *)&infoLen);

        if ( con->hostname ) {
            hostname = SSL_get_servername(ssl,TLSEXT_NAMETYPE_host_name);
        }

        // What states do we want to upgrade and which ones do we want to leave alone?
        if (info.tcpi_state == TCP_ESTABLISHED) {
            upgrade_sock(SSL_get_fd(ssl),ssl);
            /* code */
            if (hostname)
            {
                if (setsockopt(fd, IPPROTO_IP, SO_HOSTNAME, hostname, strlen(hostname)+1) == -1){
                   perror("setsockopt: SO_HOSTNAME");
                   close(fd);
                }
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
            asprintf(&message,"Unaccounted state? %u\n", info.tcpi_state);
            logSSL(message);
            free(message);
        }
        
        con->upgraded = 1;
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

    logSSL("Peek from socket\n");

    rfd = SSL_get_rfd(ssl);

    return recv(rfd, buf, num, MSG_PEEK);

}

int SSL_is_init_finished(SSL *s)
{
    return 1;
}

int SSL_get_error(const SSL *ssl, int ret)
{

    return 2;
}


X509 *SSL_get_peer_certificate(const SSL *s)
{
    int ssl_fd = SSL_get_rfd(s);

    int cert_len = 1024*4;
    char cert[1024*4];

    upgrade_check((SSL *)s);


    struct tcp_info info;
    int infoLen = sizeof(info);
    memset(&info,0,infoLen);
    getsockopt(ssl_fd, SOL_TCP, TCP_INFO, (void *)&info, (socklen_t *)&infoLen);

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

int upgrade_sock(int fd, SSL *ssl) {
    unsigned long id;
    int id_len = sizeof(id);
    int is_accepting;
    int file_flags;

    /* This is the address of the SSA daemon */
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(8443),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };
    int new_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (getsockopt(new_fd, IPPROTO_TLS, SO_ID, &id, &id_len) == -1) {
        perror("getsockopt: SO_ID");
        exit(EXIT_FAILURE);
    }
    //printf("socket ID is %lu\n", id);

    is_accepting = SSL_in_accept_init(ssl) ? 1 : 0;

    file_flags = fcntl(fd, F_GETFL, 0);
    if (file_flags == -1) {
        perror("fcntl get flags");
    }
    
    file_flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, file_flags) == -1)
    {
        perror("fcntl set non blocking");
    }

    SSA_send_fd(fd, id, is_accepting);
    if(connect(new_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("connect SSA FD");
    }
    dup2(new_fd, fd);
    logSSL("Upgraded new socket\n");
    return 0;
}

int SSA_send_fd(int fd, unsigned long id, int is_accepting)
{
    struct sockaddr_un addr;
    struct sockaddr_un self;
    int addrlen;
    int ret;
    char buffer[1024];
    int bytes_to_send;
    int con = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (con == -1) {
        perror("Socket error\n");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, SOCKET_PATH, sizeof(SOCKET_PATH));
    addrlen = sizeof(SOCKET_PATH) + sizeof(sa_family_t);

    /*if (connect(con, (struct sockaddr*)&addr, addrlen)) {
        perror("Connect error\n");
        return -1;
    }*/
    self.sun_family = AF_UNIX;

    bytes_to_send = sprintf(buffer, "%d:%lu", is_accepting, id);
    if (bind(con, (struct sockaddr*)&self, sizeof(sa_family_t)) == -1) {
        perror("bind");
    }
    ret = send_fd_to(con, buffer, bytes_to_send + 1, fd, &addr, addrlen);
    /* Wait for a confirmation to prevent race condition */
    recv(con, buffer, 1024, 0);
    close(con);
    
    return ret;
}

ssize_t send_fd_to(int fd, void* iobuf, size_t nbytes, int sendfd,
            struct sockaddr_un* addr, int addr_len) {
    struct msghdr msg = {0};
    struct iovec iov[1];

    // should have an ifdef here to be thurough, check for HAVE_MSGHDR_MSG_CONTROL
    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr* cmptr;

    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);

    cmptr = CMSG_FIRSTHDR(&msg);
    cmptr->cmsg_len = CMSG_LEN(sizeof(int));
    cmptr->cmsg_level = SOL_SOCKET;
    cmptr->cmsg_type = SCM_RIGHTS;

    *((int*) CMSG_DATA(cmptr)) = sendfd;

    msg.msg_name = addr;
    msg.msg_namelen = addr_len;

    iov[0].iov_base = iobuf;
    iov[0].iov_len = nbytes;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    return sendmsg(fd, &msg, 0);
}


int dup_socket_TLS(int sock_fd, const char * ssl_hostname)
{
   
    int type;
    int type_length = sizeof( int );
    int new_socket;
    char clientip[20];
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);

    
    int err = getpeername(sock_fd, (struct sockaddr *)&addr, &addr_size);
    if (err != 0) {
       // error
    }
    
    strcpy(clientip, inet_ntoa(addr.sin_addr));

    getsockopt( sock_fd, SOL_SOCKET, SO_TYPE, &type, &type_length );

    new_socket = socket(addr.sin_family, type, IPPROTO_TLS);
    if (new_socket == -1) {
            perror("socket");
    }

    
    if (ssl_hostname != NULL){

        if (setsockopt(new_socket, IPPROTO_IP, SO_HOSTNAME, ssl_hostname, strlen(ssl_hostname)+1) == -1){
           perror("setsockopt: SO_HOSTNAME");
           close(sock_fd);
        }
    }
    else{
        perror("No host specified within SSL context\n");
    }

    if (connect(new_socket, (struct sockaddr *) &addr,sizeof(addr)) == -1) {
            perror("connect");
            close(sock_fd);
    }
    
    return new_socket;

}


// int SSL_set_fd (SSL *s, int fd)
// {


//     // struct tcp_info info;
//     // int infoLen = sizeof(info);
//     // getsockopt(fd, SOL_TCP, TCP_INFO, (void *)&info, (socklen_t *)&infoLen);
//     // fprintf(stderr,"\nSET_FD:%u\n", info.tcpi_state); 

//     //SSA_send_fd(fd);

//     // int ssa_fd = SSA_create_socket();

//     // dup2(ssa_fd,fd);

//     orig_SSL_set_fd_f_type orig_SSL_set_fd;
//     orig_SSL_set_fd = (orig_SSL_set_fd_f_type)dlsym(RTLD_NEXT,"SSL_set_fd");
//     return orig_SSL_set_fd(s,fd);
//     // orig_SSL_set_fd_f_type
// }