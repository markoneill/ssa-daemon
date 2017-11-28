/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "daemon.h"
#include "hashmap.h"
#include "tls_wrapper.h"
#include "netlink.h"
#include "log.h"

#define SO_HOSTNAME		85
#define MAX_HOSTNAME		255
#define HASHMAP_NUM_BUCKETS	10

typedef struct sock_ctx {
	unsigned long id;
	evutil_socket_t fd;
	int has_bound; /* Nonzero if we've called bind locally */
	struct sockaddr int_addr;
	int int_addrlen;
	struct sockaddr ext_addr;
	int ext_addrlen;
	struct sockaddr rem_addr;
	int rem_addrlen;
	char hostname[MAX_HOSTNAME];
} sock_ctx_t;

void signal_handler(int signum);

/* SSA client functions */
static void accept_error_cb(struct evconnlistener *listener, void *ctx);
static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *ctx);
static void signal_cb(evutil_socket_t fd, short event, void* arg);
static evutil_socket_t create_server_socket(ev_uint16_t port, int protocol);

/* SSA server functions */
static void server_accept_error_cb(struct evconnlistener *listener, void *ctx);
static void server_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg);
static int add_listener_to_ctx(tls_daemon_ctx_t* ctx, listener_ctx_t* lctx);
static void free_listeners(tls_daemon_ctx_t* ctx);

struct event_base* g_ev_base;

int server_create() {
	evutil_socket_t server_sock;
	struct evconnlistener* listener;
        const char* ev_version = event_get_version();
	struct event_base* ev_base = event_base_new();
	struct event* sev_pipe;
	struct event* nl_ev;
	struct nl_sock* netlink_sock;
	if (ev_base == NULL) {
                perror("event_base_new");
                return 1;
        }

	g_ev_base = ev_base;

       	log_printf(LOG_INFO, "Using libevent version %s with %s behind the scenes\n", ev_version, event_base_get_method(ev_base));
	
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	sev_pipe = evsignal_new(ev_base, SIGPIPE, signal_cb, NULL);
	if (sev_pipe == NULL) {
		log_printf(LOG_ERROR, "Couldn't create signal handler event");
		return 1;
	}
	evsignal_add(sev_pipe, NULL);

	tls_daemon_ctx_t daemon_ctx = {
		.ev_base = ev_base,
		.sev_pipe = sev_pipe,
		.netlink_sock = NULL,
		.listeners = NULL,
		.sock_map = hashmap_create(HASHMAP_NUM_BUCKETS),
		.sock_map_port = hashmap_create(HASHMAP_NUM_BUCKETS),
	};

	/* Start setting up server socket and event base */
	server_sock = create_server_socket(8443, SOCK_STREAM);
	listener = evconnlistener_new(ev_base, accept_cb, &daemon_ctx, 
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, SOMAXCONN, server_sock);
	if (listener == NULL) {
		log_printf(LOG_ERROR, "Couldn't create evconnlistener");
		return 1;
	}

	/* Signal handler registration */
	netlink_sock = netlink_connect(&daemon_ctx);
	if (netlink_sock == NULL) {
		log_printf(LOG_ERROR, "Couldn't create Netlink socket");
		return 1;
	}
	nl_ev = event_new(ev_base, nl_socket_get_fd(netlink_sock), EV_READ | EV_PERSIST, netlink_recv, netlink_sock);
	if (event_add(nl_ev, NULL) == -1) {
		log_printf(LOG_ERROR, "Couldn't add Netlink event");
		return 1;
	}
	
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigaction(SIGINT, &sa, NULL);


	evconnlistener_set_error_cb(listener, accept_error_cb);
	event_base_dispatch(ev_base);

	log_printf(LOG_INFO, "Main event loop terminated\n");
	netlink_disconnect(netlink_sock);

	/* Cleanup */
	evconnlistener_free(listener); /* This also closes the socket due to our listener creation flags */
	free_listeners(&daemon_ctx);
	hashmap_free(daemon_ctx.sock_map);
	hashmap_free(daemon_ctx.sock_map_port);
	event_free(nl_ev);
	event_free(sev_pipe);
        event_base_free(ev_base);
        /* This function hushes the wails of memory leak
         * testing utilities, but was not introduced until
         * libevent 2.1
         */
        #if LIBEVENT_VERSION_NUMBER >= 0x02010000
        libevent_global_shutdown();
        #endif

	/* Standard OpenSSL cleanup functions */
	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	OPENSSL_cleanup();
	#else
	FIPS_mode_set(0);
	ENGINE_cleanup();
	CONF_modules_unload(1);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	SSL_COMP_free_compression_methods();
	#endif
        return 0;
}

/* Creates a listening socket that binds to local IPv4 and IPv6 interfaces.
 * It also makes the socket nonblocking (since this software uses libevent)
 * @param port numeric port for listening
 * @param type SOCK_STREAM or SOCK_DGRAM
 */
evutil_socket_t create_server_socket(ev_uint16_t port, int type) {
	evutil_socket_t sock;
	char port_buf[6];
	int ret;
	int optval = 1;

	struct evutil_addrinfo hints;
	struct evutil_addrinfo* addr_ptr;
	struct evutil_addrinfo* addr_list;

	/* Convert port to string for getaddrinfo */
	evutil_snprintf(port_buf, sizeof(port_buf), "%d", (int)port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; /* Both IPv4 and IPv6 */
	hints.ai_socktype = type;
	/* AI_PASSIVE for filtering out addresses on which we
	 * can't use for servers
	 *
	 * AI_ADDRCONFIG to filter out address types the system
	 * does not support
	 *
	 * AI_NUMERICSERV to indicate port parameter is a number
	 * and not a string
	 *
	 * */
	hints.ai_flags = EVUTIL_AI_PASSIVE | EVUTIL_AI_ADDRCONFIG | EVUTIL_AI_NUMERICSERV;
	/*
	 *  On Linux binding to :: also binds to 0.0.0.0
	 *  Null is fine for TCP, but UDP needs both
	 *  See https://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
	 */
	ret = evutil_getaddrinfo(type == SOCK_DGRAM ? "::" : NULL, port_buf, &hints, &addr_list);
	if (ret != 0) {
		log_printf(LOG_ERROR, "Failed in evutil_getaddrinfo: %s\n", evutil_gai_strerror(ret));
		exit(EXIT_FAILURE);
	}
	
	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
		if (sock == -1) {
			log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
			continue;
		}

		ret = evutil_make_listen_socket_reuseable(sock);
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}

		ret = evutil_make_socket_nonblocking(sock);
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}

		ret = bind(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen);
		if (ret == -1) {
			log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}
		break;
	}
	evutil_freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		log_printf(LOG_ERROR, "Failed to find a suitable address for binding\n");
		exit(EXIT_FAILURE);
	}

	return sock;
}

void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg) {
	log_printf(LOG_INFO, "Received connection!\n");

	int port;
	sock_ctx_t* sock_ctx;
	tls_daemon_ctx_t* ctx = arg;

	port = (int)ntohs(((struct sockaddr_in*)address)->sin_port);
	sock_ctx = hashmap_get(ctx->sock_map_port, port);
	if (sock_ctx == NULL) {
		log_printf(LOG_ERROR, "Got an unauthorized connection on port %d\n", port);
		EVUTIL_CLOSESOCKET(fd);
		return;
	}
	log_printf_addr(&sock_ctx->rem_addr);

	if (evutil_make_socket_nonblocking(fd) == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(fd);
		return;
	}
	log_printf(LOG_INFO, "Hostname: %s (%p)\n", sock_ctx->hostname, sock_ctx->hostname);
	hashmap_del(ctx->sock_map_port, port);
	hashmap_del(ctx->sock_map, sock_ctx->id);
	tls_client_wrapper_setup(fd, sock_ctx->fd, ctx->ev_base, address, socklen, 
			&sock_ctx->rem_addr, &sock_ctx->rem_addrlen, sock_ctx->hostname);
	free(sock_ctx); /* Can probably do this later when closing, or
				merge with another struct */
	return;
}

void accept_error_cb(struct evconnlistener *listener, void *ctx) {
        struct event_base *base = evconnlistener_get_base(listener);
        int err = EVUTIL_SOCKET_ERROR();
        log_printf(LOG_ERROR, "Got an error %d (%s) on the listener\n", 
				err, evutil_socket_error_to_string(err));
        event_base_loopexit(base, NULL);
	return;
}

void server_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg) {
	listener_ctx_t* lctx = (listener_ctx_t*)arg;
        struct event_base *base = evconnlistener_get_base(listener);
	log_printf(LOG_INFO, "Got a connection on a vicarious listener\n");
	log_printf_addr(&lctx->int_addr);
	if (evutil_make_socket_nonblocking(fd) == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(fd);
		return;
	}
	tls_server_wrapper_setup(fd, base, lctx->tls_ctx, address, socklen, &lctx->int_addr, lctx->int_addrlen);
	return;
}

void server_accept_error_cb(struct evconnlistener *listener, void *ctx) {
        struct event_base *base = evconnlistener_get_base(listener);
        int err = EVUTIL_SOCKET_ERROR();
        log_printf(LOG_ERROR, "Got an error %d (%s) on a server listener\n", 
				err, evutil_socket_error_to_string(err));
        event_base_loopexit(base, NULL);
	return;
}

void signal_cb(evutil_socket_t fd, short event, void* arg) {
	int signum = fd; /* why is this fd? */
	switch (signum) {
		case SIGPIPE:
			log_printf(LOG_DEBUG, "Caught SIGPIPE and ignored it\n");
			break;
		default:
			break;
	}
	return;
}

int add_listener_to_ctx(tls_daemon_ctx_t* ctx, listener_ctx_t* lctx) {
	listener_ctx_t* cur = ctx->listeners;
	if (cur == NULL) {
		ctx->listeners = lctx;
		return 0;
	}
	while (cur->next != NULL) {
		cur = cur->next;
	}
	cur->next = lctx;
	return 0;
}

void free_listeners(tls_daemon_ctx_t* ctx) {
	listener_ctx_t* cur = ctx->listeners;
	listener_ctx_t* tmp = NULL;
	while (cur != NULL) {
		tmp = cur->next;
		/* This also closes the socket due to our listener creation flags */
		evconnlistener_free(cur->listener);
		SSL_CTX_free(cur->tls_ctx);
		free(cur);
		cur = tmp;
	}
	return;
}

void signal_handler(int signum) {
	if (signum == SIGINT) {
		event_base_loopbreak(g_ev_base);
	}
	return;
}


void socket_cb(tls_daemon_ctx_t* ctx, unsigned long id) {
	sock_ctx_t* sock_ctx;
	evutil_socket_t fd;
	int response = 0;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		response = errno;
	}
	else {
		sock_ctx = (sock_ctx_t*)calloc(1, sizeof(sock_ctx_t));
		if (sock_ctx == NULL) {
			response = -ENOMEM;
		}
		else {
			sock_ctx->id = id;
			sock_ctx->fd = fd;
			hashmap_add(ctx->sock_map, id, (void*)sock_ctx);
		}
	}
	netlink_notify_kernel(ctx, id, response);
	return;
}

void setsockopt_cb(tls_daemon_ctx_t* ctx, unsigned long id, int option,
		void* value, socklen_t len) {
	int ret;
	sock_ctx_t* sock_ctx;
	int response = 0;

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
		netlink_notify_kernel(ctx, id, response);
		return;
	}
	switch (option) {
		case SO_HOSTNAME:
			/* The kernel validated this data for us */
			memcpy(sock_ctx->hostname, value, len);
			break;
		default:
			break;
	}
	netlink_notify_kernel(ctx, id, response);
	return;
}

void bind_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr, 
	int int_addrlen, struct sockaddr* ext_addr, int ext_addrlen) {

	int ret;
	sock_ctx_t* sock_ctx;
	int response = 0;

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
	}
	else {
		ret = bind(sock_ctx->fd, ext_addr, ext_addrlen);
		if (ret == -1) {
			response = errno;
		}
		else {
			sock_ctx->has_bound = 1;
			sock_ctx->int_addr = *int_addr;
			sock_ctx->int_addrlen = int_addrlen;
			sock_ctx->ext_addr = *ext_addr;
			sock_ctx->ext_addrlen = ext_addrlen;
		}
	}
	netlink_notify_kernel(ctx, id, response);
	return;
}

void connect_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr, 
	int int_addrlen, struct sockaddr* rem_addr, int rem_addrlen) {
	
	int ret;
	sock_ctx_t* sock_ctx;
	int response = 0;
	int port;
	port = (int)ntohs(((struct sockaddr_in*)int_addr)->sin_port);

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
	}
	else {
		ret = connect(sock_ctx->fd, rem_addr, rem_addrlen);
		if (ret == -1) {
			response = errno;
		}
		else {
			if (sock_ctx->has_bound == 0) {
				sock_ctx->int_addr = *int_addr;
				sock_ctx->int_addrlen = int_addrlen;
			}
			log_printf(LOG_INFO, "Placing sock_ctx for port %d\n", port);
			hashmap_add(ctx->sock_map_port, port, sock_ctx);
			sock_ctx->rem_addr = *rem_addr;
			sock_ctx->rem_addrlen = rem_addrlen;
		}
	}
	netlink_notify_kernel(ctx, id, response);
	return;
}

void listen_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr,
	int int_addrlen, struct sockaddr* ext_addr, int ext_addrlen) {

	int ret;
	sock_ctx_t* sock_ctx;
	int response = 0;
	
	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
	}
	else {
		ret = listen(sock_ctx->fd, SOMAXCONN);
		if (ret == -1) {
			response = errno;
		}
	}
	netlink_notify_kernel(ctx, id, response);
	if (response != 0) {
		return;
	}
	
	/* We're done gathering info, let's set up a server */
	ret = evutil_make_listen_socket_reuseable(sock_ctx->fd);
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
		return;
	}

	ret = evutil_make_socket_nonblocking(sock_ctx->fd);
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
		return;
	}

	listener_ctx_t* lctx = malloc(sizeof(listener_ctx_t));
	if (lctx == NULL) {
		log_printf(LOG_ERROR, "Failed to malloc listener context\n");
		return;
	}

	/* XXX If the application never called bind, ext_addr will be empty. 
	 * This may not matter (I'm not sure we actually use it)  */

	lctx->socket = sock_ctx->fd;
	lctx->int_addr = *int_addr;
	lctx->int_addrlen = int_addrlen;
	lctx->ext_addr = *ext_addr;
	lctx->ext_addrlen = ext_addrlen;
	lctx->tls_ctx = tls_server_ctx_create();
	lctx->next = NULL;
	lctx->listener = evconnlistener_new(ctx->ev_base, server_accept_cb, lctx, 
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, 0, sock_ctx->fd);

	evconnlistener_set_error_cb(lctx->listener, server_accept_error_cb);
	hashmap_del(ctx->sock_map, id);
	free(sock_ctx); /* We can do this later somehow, or merge this struct with lctx */
	add_listener_to_ctx(ctx, lctx);
	return;
}

