#define _GNU_SOURCE
#define SO_HOSTNAME             85
#define IPPROTO_TLS             (715 % 255)
#define SO_PEER_CERTIFICATE     86
#define SSA_PORT                8443
#define SSA_ADDR                "127.0.0.1"

#define LOG_FILE "/tmp/sslLog.txt"
#define SEND_MSG "\1\0www.google.com\0"
#define SOCKET_PATH "\0tls_upgrade"

#include <dlfcn.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>


typedef int (*orig_socket_f_type)(int domain, int type, int protocol);
typedef int (*orig_SSL_set_fd_f_type)(SSL *s, int fd);

int SSA_create_socket();
int SSA_send_fd(int fd);
ssize_t write_fd(int fd, void* iobuf, size_t nbytes, int sendfd);
int dup_socket_TLS(int fd, const char * ssl_hostname);
int connect_to_host(char* host, char* service);
X509* PEM_str_to_X509(char* pem_str);
int logSSL(char* msg);


int logSSL(char* msg)
{
    FILE * fd = fopen(LOG_FILE,"a");
    fputs(msg,fd);
    fclose(fd);
}


int SSL_connect(SSL *s)
{
    int fd = SSL_get_fd(s);
    const char * hostname = SSL_get_servername(s,TLSEXT_NAMETYPE_host_name);
    
    // if (setsockopt(fd, IPPROTO_IP, SO_HOSTNAME, hostname, strlen(hostname)+1) == -1){
    //        perror("setsockopt: SO_HOSTNAME");
    //        close(fd);
    // }
    //

    //int new_fd = dup_socket_TLS(old_fd,hostname);
    //dup2(new_fd,old_fd);
    //printf("HOSTNAME %s\n", hostname);
    // logSSL("Called SSL_connect\n");
    //SSL_set_fd(s,new_fd);

    return 1;
}

int SSL_write(SSL *ssl, const void *buf, int num)
{
    int wfd, ret;

    wfd = SSL_get_wfd(ssl);

    return send(wfd, buf, num, 0);

}

int SSL_read(SSL *ssl, void *buf, int num)
{
    int rfd, ret;

    rfd = SSL_get_rfd(ssl);

    return recv(rfd, buf, num, 0);

}

int SSL_peek(SSL *ssl, void *buf, int num)
{
    int rfd, ret;

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

int socket(int domain, int type, int protocol)
{
    int fd;
    orig_socket_f_type orig_socket;
    orig_socket = (orig_socket_f_type)dlsym(RTLD_NEXT,"socket");
    if (type == SOCK_STREAM)
    {
        fd = orig_socket(domain,type,IPPROTO_TLS);
        // if (setsockopt(fd, IPPROTO_IP, SO_HOSTNAME, "www.google.com", strlen("www.google.com")+1) == -1){
        //    perror("setsockopt: SO_HOSTNAME");
        //    close(fd);
        // }
    }
    else
    {
        fd = orig_socket(domain,type,protocol);
    }

    //printf("Domain:%d Type:%d PROTO:%d FD:%d\n",domain,type,protocol,fd);



    return fd;
}

X509 *SSL_get_peer_certificate(const SSL *s)
{
    int ssl_fd = SSL_get_rfd(s);

    int cert_len = 1024*4;
    char cert[1024*4];

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


int SSL_set_fd (SSL *s, int fd)
{

    // SSA_send_fd(fd);

    // int ssa_fd = SSA_create_socket();

    // dup2(ssa_fd,fd);

    orig_SSL_set_fd_f_type orig_SSL_set_fd;
    orig_SSL_set_fd = (orig_SSL_set_fd_f_type)dlsym(RTLD_NEXT,"SSL_set_fd");
    return orig_SSL_set_fd(s,fd);
    // orig_SSL_set_fd_f_type
}

int SSA_create_socket()
{
    struct sockaddr_in sa;
    int sd;
    char * addr = SSA_ADDR;
    int portno = SSA_PORT;

    memset(&sa, 0, sizeof(sa));

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(addr);
    sa.sin_port = htons(portno);

    sd = socket(AF_INET, SOCK_STREAM, 0);
    connect(sd, (struct sockaddr *)&sa, sizeof(sa));
}

int SSA_send_fd(int fd)
{
    struct sockaddr_un addr;
    int addrlen;
    int ret;
    int con = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (con == -1) {
        perror("Socket error\n");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, SOCKET_PATH, sizeof(SOCKET_PATH));
    addrlen = sizeof(SOCKET_PATH) + sizeof(sa_family_t);

    if (connect(con, (struct sockaddr*)&addr, addrlen)) {
        perror("Connect error\n");
        return -1;
    }

    ret = write_fd(con,SEND_MSG,sizeof(SEND_MSG),fd);

    close(con);
    
    return ret;
}

ssize_t write_fd(int fd, void* iobuf, size_t nbytes, int sendfd) {
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

    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    iov[0].iov_base = iobuf;
    iov[0].iov_len = nbytes;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    return sendmsg(fd, &msg, 0);
}
