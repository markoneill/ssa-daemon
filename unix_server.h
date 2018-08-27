#ifndef UNIXSERVER_H
#define UNIXSERVER_H

#include "ipc.h"
#include "daemon.h"

void chopString(char *str, size_t n);
char* get_addr_string(struct sockaddr *addr);
int create_unix_socket();
int close_unix_socket(int fd);
void unix_recv(evutil_socket_t fd, short events, void *arg);
void unix_notify_kernel(tls_daemon_ctx_t* ctx, unsigned long id, int response);
void unix_send_and_notify_kernel(tls_daemon_ctx_t* ctx, unsigned long id, char* data, unsigned int len);
void unix_handshake_notify_kernel(tls_daemon_ctx_t* ctx, unsigned long id, int response);

#endif