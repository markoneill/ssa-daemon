#ifndef CSR_DAEMON_H
#define CSR_DAEMON_H

#include <netinet/in.h>

#include <event2/event.h>
#include <event2/util.h>

#include <openssl/ssl.h>

#include "hashmap.h"
#include "queue.h"



int csr_server_create(int port);

#endif /*CSR_DAEMON_H*/
