#ifndef UNIXSERVER_H
#define UNIXSERVER_H

#include "ipc.h"
#include "daemon.h"

void chopString(char *str, size_t n);
int create_unix_socket();
int unix_recv(evutil_socket_t fd, short events, void *arg);
void netlink_notify_kernel(tls_daemon_ctx_t* ctx, unsigned long id, int response);
void netlink_send_and_notify_kernel(tls_daemon_ctx_t* ctx, unsigned long id, char* data, unsigned int len);

#endif