#ifndef SENDER_H
#define SENDER_H

#define _GNU_SOURCE  

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <ctype.h>
#include <unistd.h>
#include <linux/limits.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "unix_helper.h"
#include "../../in_tls.h" 
#include "../../hashmap.h"
#include "../../ipc.h"

typedef int (*orig_socket_type)(int domain, int type, int protocol);
typedef int (*orig_connect_type)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
typedef int (*orgi_setsockopt_type)(int sockfd, int level, int optname,
                      const void *optval, socklen_t optlen);
typedef int (*orgi_getsockopt_type)(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen);
typedef int (*orgi_close_type)(int fd);
typedef int (*orgi_listen_type)(int sockfd, int backlog); 
typedef int (*orgi_accept_type)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
typedef int (*orgi_bind_type)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

#define SNAME "/mysem"

int send_socket_message(unsigned long daemon_id);
int send_connect_message(int sockfd, unsigned long daemon_id, struct sockaddr* internal_address, struct sockaddr *addr);
int send_setsockopt_message(unsigned long daemon_id, int level, int optname, char* optval);
int send_getsockopt_message(unsigned long daemon_id, int level, int optname, char* optval, socklen_t *optlen);
int send_close_message(unsigned long daemon_id);
int send_accept_message(unsigned long new_daemon_id, struct sockaddr_in peer_address);
int send_listen_message(unsigned long daemon_id, struct sockaddr* internal_address, struct sockaddr* external_address);
int send_bind_message(unsigned long daemon_id, struct sockaddr* internal_address, struct sockaddr* external_address);

#endif