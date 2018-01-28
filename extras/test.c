#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define IPPROTO_TLS	205
#define SO_ID	89
#define SOCKET_PATH "\0tls_upgrade"

int upgrade_sock(int fd); 
int SSA_send_fd(int fd, unsigned long id, int is_accepting);
ssize_t send_fd_to(int fd, void* iobuf, size_t nbytes, int sendfd, struct sockaddr_un* addr, int addr_len);

int main() {
	int fd = socket(PF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(8080),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};
	connect(fd, (struct sockaddr*)&addr, sizeof(addr));

	/* Some chochface calls SSL_set_fd(ssl, fd) or something */

	/* Oh noes! Upgrade to use TLS via SSA! */
	upgrade_sock(fd);
	send(fd, "It worked!\n", sizeof("It worked!\n"), 0);
	return 0;
}


int upgrade_sock(int fd) {
	unsigned long id;
	int id_len = sizeof(id);

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
	printf("socket ID is %lu\n", id);
	SSA_send_fd(fd, id, 0);
	connect(new_fd, (struct sockaddr*)&addr, sizeof(addr));
	dup2(new_fd, fd);
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
