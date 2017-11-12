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
#include "tls_wrapper.h"
#include "netlink.h"
#include "log.h"

#define MAX_HOSTNAME	255

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
static evutil_socket_t create_listen_socket(struct sockaddr* addr, int addrlen, int type, int protocol);
static int add_listener_to_ctx(tls_daemon_ctx_t* ctx, listener_ctx_t* lctx);
static void free_listeners(tls_daemon_ctx_t* ctx);

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
       	log_printf(LOG_INFO, "Using libevent version %s with %s behind the scenes\n", ev_version, event_base_get_method(ev_base));
	log_printf(LOG_DEBUG, "ev_base address is %p\n", ev_base);
	
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
		.listeners = NULL
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
	

	evconnlistener_set_error_cb(listener, accept_error_cb);
	event_base_dispatch(ev_base);

	log_printf(LOG_INFO, "Main event loop terminated\n");
	netlink_disconnect(netlink_sock);

	/* Cleanup */
	evconnlistener_free(listener); /* This also closes the socket due to our listener creation flags */
	free_listeners(&daemon_ctx);
        event_base_free(ev_base);
        /* This function hushes the wails of memory leak
         * testing utilities, but was not introduced until
         * libevent 2.1
         */
        #if LIBEVENT_VERSION_NUMBER >= 0x02010000
        libevent_global_shutdown();
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

evutil_socket_t create_listen_socket(struct sockaddr* addr, int addrlen, int type, int protocol) {
	int sock;
	int ret;
	sock = socket(addr->sa_family, type, protocol);
	if (sock == -1) {
		log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
		return 0;
	}

	ret = evutil_make_listen_socket_reuseable(sock);
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(sock);
		return 0;
	}

	ret = evutil_make_socket_nonblocking(sock);
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(sock);
		return 0;
	}

	ret = bind(sock, addr, addrlen);
	if (ret == -1) {
		log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
		EVUTIL_CLOSESOCKET(sock);
		return 0;
	}
	return sock;
}

void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg) {
	log_printf(LOG_INFO, "Received connection!\n");

	tls_daemon_ctx_t* ctx = arg;

	struct sockaddr_host orig_addr; /* sockaddr_host is bigger than the other */
	int orig_addrlen = sizeof(struct sockaddr_host);
	char hostname[MAX_HOSTNAME];
	int hostname_len = MAX_HOSTNAME;

	if (getsockopt(fd, IPPROTO_IP, 86, &orig_addr, &orig_addrlen) == -1) {
		log_printf(LOG_ERROR, "getsockopt: %s\n", strerror(errno));
	}
	log_printf_addr(&orig_addr);
	if (orig_addr.sin_family == AF_HOSTNAME) {
		log_printf(LOG_DEBUG, "Detected sockaddr_host usage\n");
		strcpy(hostname, orig_addr.sin_addr.name);
	}
	else {
		if (getsockopt(fd, IPPROTO_IP, 85, hostname, &hostname_len) == -1) {
			log_printf(LOG_ERROR, "getsockopt: %s\n", strerror(errno));
		}
	}
	log_printf(LOG_INFO, "Hostname: %s (%p)\n", hostname, hostname);
	tls_client_wrapper_setup(fd, ctx->ev_base, address, socklen, &orig_addr, orig_addrlen, hostname);
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

void listen_cb(tls_daemon_ctx_t* ctx, struct sockaddr* internal_addr, int internal_addr_len,
			 struct sockaddr* external_addr, int external_addr_len) {
	log_printf(LOG_INFO, "internal address is\n");
	log_printf_addr(internal_addr);
	log_printf(LOG_INFO, "external address is\n");
	log_printf_addr(external_addr);
	log_printf(LOG_DEBUG, "ev_base address in listen_cb is %p\n", ctx->ev_base);

	evutil_socket_t socket = create_listen_socket(external_addr, external_addr_len, 
							SOCK_STREAM, IPPROTO_TCP);
	listener_ctx_t* lctx = malloc(sizeof(listener_ctx_t));
	if (lctx == NULL) {
		log_printf(LOG_ERROR, "Failed to malloc listener context\n");
		return;
	}
	lctx->socket = socket;
	lctx->int_addr = *internal_addr;
	lctx->int_addrlen = internal_addr_len;
	lctx->ext_addr = *external_addr;
	lctx->ext_addrlen = external_addr_len;
	lctx->tls_ctx = tls_server_ctx_create();
	lctx->next = NULL;
	lctx->listener = evconnlistener_new(ctx->ev_base, server_accept_cb, lctx, 
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, SOMAXCONN, socket);

	evconnlistener_set_error_cb(lctx->listener, server_accept_error_cb);
	add_listener_to_ctx(ctx, lctx);
	return;
}

void server_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg) {
	listener_ctx_t* lctx = (listener_ctx_t*)arg;
        struct event_base *base = evconnlistener_get_base(listener);
	log_printf(LOG_INFO, "Got a connection on a vicarious listener\n");
	log_printf(LOG_INFO, "The remote client is\n");
	log_printf_addr(address);
	log_printf(LOG_INFO, "We are\n");
	log_printf_addr(&lctx->ext_addr);
	log_printf(LOG_INFO, "Application is\n");
	log_printf_addr(&lctx->int_addr);
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
		free(cur);
		cur = tmp;
	}
	return;
}

