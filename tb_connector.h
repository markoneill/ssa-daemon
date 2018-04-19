#ifndef NATIVE_NETLINK_H
#define NATIVE_NETLINK_H

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "tb_communications.h"

int trustbase_connect(void);
int trustbase_disconnect(void);
int send_query_openssl(uint64_t id, char* host, int port, STACK_OF(X509)* chain);
int send_query(uint64_t id, char* host, int port, unsigned char* chain, int length);
int recv_response(void);
#endif
