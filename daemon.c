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
#include <sys/un.h>
#include <netdb.h>
#include <assert.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "in_tls.h"
#include "daemon.h"
#include "hashmap.h"
#include "tls_wrapper.h"
#include "netlink.h"
#include "log.h"
#include "session_manager.h"

#define MAX_UPGRADE_SOCKET  18
#define HASHMAP_NUM_BUCKETS	100

#ifdef CLIENT_AUTH
int auth_info_index;
#endif

typedef struct sock_ctx {
	unsigned long id;
	evutil_socket_t fd;
	int has_bound; /* Nonzero if we've called bind locally */
	struct sockaddr int_addr;
	int int_addrlen;
	union {
		struct sockaddr ext_addr;
		struct sockaddr rem_addr;
	};
	union {
		int ext_addrlen;
		int rem_addrlen;
	};
	int is_connected;
	int is_accepting; /* acting as a TLS server or client? */
	struct evconnlistener* listener;
	tls_opts_t* tls_opts;
	char rem_hostname[MAX_HOSTNAME];
	tls_conn_ctx_t* tls_conn;
	tls_daemon_ctx_t* daemon;
} sock_ctx_t;


void free_sock_ctx(sock_ctx_t* sock_ctx);

/* SSA direct functions */
static void accept_error_cb(struct evconnlistener *listener, void *ctx);
static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *ctx);
static void signal_cb(evutil_socket_t fd, short event, void* arg);
static evutil_socket_t create_server_socket(ev_uint16_t port, int family, int protocol);

/* SSA listener functions */
static void listener_accept_error_cb(struct evconnlistener *listener, void *ctx);
static void listener_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg);

/* special */
static evutil_socket_t create_upgrade_socket(int port);
static void upgrade_recv(evutil_socket_t fd, short events, void *arg);
ssize_t recv_fd_from(int fd, void *ptr, size_t nbytes, int *recvfd, struct sockaddr_un* addr, int addr_len);




int server_create(int port) {
	int ret;
	evutil_socket_t server_sock;
	evutil_socket_t upgrade_sock;
	struct evconnlistener* listener;

        const char* ev_version = event_get_version();
	struct event_base* ev_base = event_base_new();
	struct event* sev_pipe;
	struct event* sev_int;
	struct event* nl_ev;
	struct event* upgrade_ev;
	struct nl_sock* netlink_sock;
	if (ev_base == NULL) {
                perror("event_base_new");
                return 1;
        }

       	log_printf(LOG_INFO, "Using libevent version %s with %s behind the scenes\n", ev_version, event_base_get_method(ev_base));
	
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	#ifdef CLIENT_AUTH
	auth_info_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	#endif

	/* Signal handler registration */
	sev_pipe = evsignal_new(ev_base, SIGPIPE, signal_cb, NULL);
	if (sev_pipe == NULL) {
		log_printf(LOG_ERROR, "Couldn't create SIGPIPE handler event\n");
		return 1;
	}
	sev_int = evsignal_new(ev_base, SIGINT, signal_cb, ev_base);
	if (sev_int == NULL) {
		log_printf(LOG_ERROR, "Couldn't create SIGINT handler event\n");
		return 1;
	}
	evsignal_add(sev_pipe, NULL);
	evsignal_add(sev_int, NULL);

	//signal(SIGPIPE, SIG_IGN);

	tls_daemon_ctx_t daemon_ctx = {
		.ev_base = ev_base,
		.netlink_sock = NULL,
		.port = port,
		.sock_map = hashmap_create(HASHMAP_NUM_BUCKETS),
		.sock_map_port = hashmap_create(HASHMAP_NUM_BUCKETS),
	};

	/* Set up server socket with event base */
	server_sock = create_server_socket(port, PF_INET, SOCK_STREAM);
	listener = evconnlistener_new(ev_base, accept_cb, &daemon_ctx, 
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, SOMAXCONN, server_sock);
	if (listener == NULL) {
		log_printf(LOG_ERROR, "Couldn't create evconnlistener\n");
		return 1;
	}
	evconnlistener_set_error_cb(listener, accept_error_cb);

	/* Set up netlink socket with event base */
	netlink_sock = netlink_connect(&daemon_ctx);
	if (netlink_sock == NULL) {
		log_printf(LOG_ERROR, "Couldn't create Netlink socket\n");
		return 1;
	}
	ret = evutil_make_socket_nonblocking(nl_socket_get_fd(netlink_sock));
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
	}
	nl_ev = event_new(ev_base, nl_socket_get_fd(netlink_sock), EV_READ | EV_PERSIST, netlink_recv, netlink_sock);
	if (event_add(nl_ev, NULL) == -1) {
		log_printf(LOG_ERROR, "Couldn't add Netlink event\n");
		return 1;
	}

	/* Set up upgrade notification socket with event base */
	upgrade_sock = create_upgrade_socket(port);
	upgrade_ev = event_new(ev_base, upgrade_sock, EV_READ | EV_PERSIST, upgrade_recv, &daemon_ctx);
	if (event_add(upgrade_ev, NULL) == -1) {
		log_printf(LOG_ERROR, "Couldn't add upgrade event\n");
		return 1;
	}

	/* Main event loop */	
	event_base_dispatch(ev_base);

	log_printf(LOG_INFO, "Main event loop terminated\n");
	netlink_disconnect(netlink_sock);

	/* Cleanup */
	evconnlistener_free(listener); /* This also closes the socket due to our listener creation flags */
	hashmap_free(daemon_ctx.sock_map_port);
	hashmap_deep_free(daemon_ctx.sock_map, (void (*)(void*))free_sock_ctx);
	event_free(nl_ev);

	event_free(upgrade_ev);
	event_free(sev_pipe);
	event_free(sev_int);
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

evutil_socket_t create_upgrade_socket(int port) {
	evutil_socket_t sock;
	int ret;
	struct sockaddr_un addr;
	int addrlen;
	char name[MAX_UPGRADE_SOCKET];
	int namelen = snprintf(name, MAX_UPGRADE_SOCKET, "%ctls_upgrade%d", '\0', port);
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, name, namelen);
	addrlen = namelen + sizeof(sa_family_t);

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock == -1) {
		log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	ret = evutil_make_socket_nonblocking(sock);
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(sock);
		exit(EXIT_FAILURE);
	}

	ret = bind(sock, (struct sockaddr*)&addr, addrlen);
	if (ret == -1) {
		log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
		EVUTIL_CLOSESOCKET(sock);
		exit(EXIT_FAILURE);
	}
	return sock;
}

/* Creates a listening socket that binds to local IPv4 and IPv6 interfaces.
 * It also makes the socket nonblocking (since this software uses libevent)
 * @param port numeric port for listening
 * @param type SOCK_STREAM or SOCK_DGRAM
 */
evutil_socket_t create_server_socket(ev_uint16_t port, int family, int type) {
	evutil_socket_t sock;
	char port_buf[6];
	int ret;
	int optval = 1;

	struct evutil_addrinfo hints;
	struct evutil_addrinfo* addr_ptr;
	struct evutil_addrinfo* addr_list;
	struct sockaddr_un bind_addr = {
		.sun_family = AF_UNIX,
	};

	/* Convert port to string for getaddrinfo */
	evutil_snprintf(port_buf, sizeof(port_buf), "%d", (int)port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = type;

	if (family == PF_UNIX) {
		sock = socket(AF_UNIX, type, 0);
		if (sock == -1) {
			log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		ret = evutil_make_listen_socket_reuseable(sock);
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}

		ret = evutil_make_socket_nonblocking(sock);
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}

		strcpy(bind_addr.sun_path+1, port_buf);
		ret = bind(sock, (struct sockaddr*)&bind_addr, sizeof(sa_family_t) + 1 + strlen(port_buf));
		if (ret == -1) {
			log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}
		return sock;
	}

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

	if (address->sa_family == AF_UNIX) {
		port = strtol(((struct sockaddr_un*)address)->sun_path+1, NULL, 16);
		log_printf(LOG_INFO, "unix port is %05x", port);
	}
	else {
		port = (int)ntohs(((struct sockaddr_in*)address)->sin_port);
	}
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
	hashmap_del(ctx->sock_map_port, port);
	//sock_ctx->tls_conn = tls_client_wrapper_setup(sock_ctx->fd, ctx, 
	//			sock_ctx->rem_hostname, sock_ctx->is_accepting, sock_ctx->tls_opts);

	associate_fd(sock_ctx->tls_conn, fd);
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

void listener_accept_cb(struct evconnlistener *listener, evutil_socket_t efd,
	struct sockaddr *address, int socklen, void *arg) {
	struct sockaddr_in int_addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};
	int intaddr_len = sizeof(int_addr);
	sock_ctx_t* sock_ctx = (sock_ctx_t*)arg;
	evutil_socket_t ifd;
	int port;
	sock_ctx_t* new_sock_ctx;
        struct event_base *base = evconnlistener_get_base(listener);

	//log_printf(LOG_DEBUG, "Got a connection on a vicarious listener\n");
	//log_printf_addr(&sock_ctx->int_addr);
	if (evutil_make_socket_nonblocking(efd) == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(efd);
		return;
	}

	new_sock_ctx = (sock_ctx_t*)calloc(1, sizeof(sock_ctx_t));
	if (new_sock_ctx == NULL) {
		return;
	}
	new_sock_ctx->fd = efd;
	//new_sock_ctx->daemon = sock_ctx->daemon;
	//new_sock_ctx->tls_opts = sock_ctx->tls_opts;
	//new_sock_ctx->int_addr = sock_ctx->int_addr;
	//new_sock_ctx->int_addrlen = sock_ctx->int_addrlen;

	ifd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ifd == -1) {
		return;
	}

	if (bind(ifd, (struct sockaddr*)&int_addr, sizeof(int_addr)) == -1) {
		perror("bind");
		EVUTIL_CLOSESOCKET(ifd);
		return;
	}

	if (getsockname(ifd, (struct sockaddr*)&int_addr, &intaddr_len) == -1) {
		perror("getsockname");
		EVUTIL_CLOSESOCKET(ifd);
		return;
	}

	if (evutil_make_socket_nonblocking(ifd) == -1) {
		log_printf(LOG_ERROR, "Failed in ifd evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(ifd);
		return;
	}

	port = (int)ntohs((&int_addr)->sin_port);
	hashmap_add(sock_ctx->daemon->sock_map_port, port, (void*)new_sock_ctx);
	
	new_sock_ctx->tls_conn = tls_server_wrapper_setup(efd, ifd, sock_ctx->daemon,
			sock_ctx->tls_opts, &sock_ctx->int_addr, sock_ctx->int_addrlen);
	return;
}

void listener_accept_error_cb(struct evconnlistener *listener, void *ctx) {
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
		case SIGINT:
			log_printf(LOG_DEBUG, "Caught SIGINT\n");
			event_base_loopbreak(arg);
			break;
		default:
			break;
	}
	return;
}

void socket_cb(tls_daemon_ctx_t* ctx, unsigned long id, char* comm) {
	sock_ctx_t* sock_ctx;
	evutil_socket_t fd;
	int response = 0;

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx != NULL) {
		log_printf(LOG_ERROR, "We have created a socket with this ID already: %lu\n", id);
		netlink_notify_kernel(ctx, id, response);
		return;
	}

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		response = -errno;
	}
	else {
		sock_ctx = (sock_ctx_t*)calloc(1, sizeof(sock_ctx_t));
		if (sock_ctx == NULL) {
			response = -ENOMEM;
		}
		else {
			sock_ctx->id = id;
			sock_ctx->fd = fd;
			sock_ctx->tls_opts = tls_opts_create(comm);
			hashmap_add(ctx->sock_map, id, (void*)sock_ctx);
		}
	}
	log_printf(LOG_INFO, "Socket created on behalf of application %s\n", comm);
	netlink_notify_kernel(ctx, id, response);
	return;
}

void setsockopt_cb(tls_daemon_ctx_t* ctx, unsigned long id, int level, 
		int option, void* value, socklen_t len) {
	sock_ctx_t* sock_ctx;
	int response = 0; /* Default is success */

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
		netlink_notify_kernel(ctx, id, response);
		return;
	}

	switch (option) {
	case SO_REMOTE_HOSTNAME:
		/* The kernel validated this data for us */
		memcpy(sock_ctx->rem_hostname, value, len);
		log_printf(LOG_INFO, "Assigning %s to socket %lu\n", sock_ctx->rem_hostname, id);
		if (set_remote_hostname(sock_ctx->tls_opts, sock_ctx->tls_conn, value) == 0) {
			response = -EINVAL;
		}
		break;
	case SO_HOSTNAME:
		response = -ENOPROTOOPT; /* get only */
		break;
	case SO_TRUSTED_PEER_CERTIFICATES:
		if (set_trusted_peer_certificates(sock_ctx->tls_opts, sock_ctx->tls_conn, value, len) == 0) {
			response = -EINVAL;
		}
		break;
	case SO_CERTIFICATE_CHAIN:

		if (set_certificate_chain(sock_ctx->tls_opts, sock_ctx->tls_conn, value) == 0) {
			response = -EINVAL;
		}
		break;
	case SO_PRIVATE_KEY:
		if (set_private_key(sock_ctx->tls_opts, sock_ctx->tls_conn, value) == 0) {
			response = -EINVAL;
		}
		break;
	case SO_ALPN:
		if (set_alpn_protos(sock_ctx->tls_opts, sock_ctx->tls_conn, value) == 0) {
			response = -EINVAL;
		}
		break;
	case SO_SESSION_TTL:
		if (set_session_ttl(sock_ctx->tls_opts, sock_ctx->tls_conn, value) == 0) {
			response = -EINVAL;
		}
		break;
	case SO_DISABLE_CIPHER:
		if (set_disbled_cipher(sock_ctx->tls_opts, sock_ctx->tls_conn, value) == 0) {
			response = -EINVAL;
		}
		break;
	case SO_PEER_IDENTITY:
		response = -ENOPROTOOPT; /* get only */
		break;
	case SO_PEER_CERTIFICATE:
		response = -ENOPROTOOPT; /* get only */
		break;
	case SO_ID:
		response = -ENOPROTOOPT; /* get only */
		break;
	default:
		if (setsockopt(sock_ctx->fd, level, option, value, len) == -1) {
			response = -errno;
		}
		break;
	}
	netlink_notify_kernel(ctx, id, response);
	return;
}

void getsockopt_cb(tls_daemon_ctx_t* ctx, unsigned long id, int level, int option) {
	sock_ctx_t* sock_ctx;
	long value;
	int ret;
	int response = 0;
	char* data = NULL;
	unsigned int len = 0;
	int need_free = 0;

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		netlink_notify_kernel(ctx, id, -EBADF);
		return;
	}
	switch (option) {
	case SO_REMOTE_HOSTNAME:
		if (sock_ctx->rem_hostname != NULL) {
			netlink_send_and_notify_kernel(ctx, id, sock_ctx->rem_hostname, strlen(sock_ctx->rem_hostname)+1);
			return;
		}
		if (get_remote_hostname(sock_ctx->tls_opts, sock_ctx->tls_conn, &data, &len) == 0) {
			response = -EINVAL;
		}
		break;
	case SO_HOSTNAME:
		if(get_hostname(sock_ctx->tls_opts, sock_ctx->tls_conn, &data, &len) == 0) {
			response = -EINVAL;
		}
		break;
	case SO_TRUSTED_PEER_CERTIFICATES:
		response = -ENOPROTOOPT; /* set only */
		break;
	case SO_CERTIFICATE_CHAIN:
		if (get_certificate_chain(sock_ctx->tls_opts, sock_ctx->tls_conn, &data, &len) == 0) {
			response = -EINVAL;
		}
		break;
	case SO_PRIVATE_KEY:
		response = -ENOPROTOOPT; /* set only */
		break;
	case SO_ALPN:
		if (get_alpn_proto(sock_ctx->tls_opts, sock_ctx->tls_conn, &data, &len) == 0) {
			response = -EINVAL;
		}
		break;
	case SO_SESSION_TTL:
		value = get_session_ttl(sock_ctx->tls_opts, sock_ctx->tls_conn);
		if (value < 0) {
			response = EINVAL;
		}
		data = &value;
		len = sizeof(value);
		break;
	case SO_DISABLE_CIPHER:
		response = -ENOPROTOOPT; /* set only */
		break;
	case SO_PEER_IDENTITY:
		if (get_peer_identity(sock_ctx->tls_opts, sock_ctx->tls_conn, &data, &len) == 0) {
			response = -ENOTCONN;
		}
		else {
			need_free = 1;
		}
		break;
	case SO_PEER_CERTIFICATE:
		if (get_peer_certificate(sock_ctx->tls_opts, sock_ctx->tls_conn, &data, &len) == 0) {
			response = -ENOTCONN;
		}
		need_free = 1;
		break;
	case SO_ID:
		/* This case is handled directly by the kernel.
		 * If we want to change that, uncomment the lines below */
		/* data = &id;
		len = sizeof(id);
		break; */
	default:
		log_printf(LOG_ERROR, "Default case for getsockopt hit: should never happen\n");
		response = -EBADF;
		break;
	}
	if (response != 0) {
		netlink_notify_kernel(ctx, id, response);
		return;
	}
	netlink_send_and_notify_kernel(ctx, id, data, len);
	if (need_free == 1) {
		free(data);
	}
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
			perror("bind");
			response = -errno;
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
	int int_addrlen, struct sockaddr* rem_addr, int rem_addrlen, int blocking) {
	
	int ret;
	sock_ctx_t* sock_ctx;
	int response = 0;
	int port;

	if (int_addr->sa_family == AF_UNIX) {
		port = strtol(((struct sockaddr_un*)int_addr)->sun_path+1, NULL, 16);
		log_printf(LOG_INFO, "unix port is %05x", port);
	}
	else {
		port = (int)ntohs(((struct sockaddr_in*)int_addr)->sin_port);
	}

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
	}
	else {
		/* only connect if we're not already.
		 * we might already be connected due to a
		 * socket upgrade */
		if (sock_ctx->is_connected == 0) {
			ret = connect(sock_ctx->fd, rem_addr, rem_addrlen);
		}
		else {
			ret = 0;
		}
		if (ret == -1) {
			response = -errno;
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
			sock_ctx->is_connected = 1;
			tls_opts_client_setup(sock_ctx->tls_opts);
		}
	}
	ret = evutil_make_socket_nonblocking(sock_ctx->fd);
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
	}
	sock_ctx->tls_conn = tls_client_wrapper_setup(sock_ctx->fd, ctx, 
				sock_ctx->rem_hostname, sock_ctx->is_accepting, sock_ctx->tls_opts);
	set_netlink_cb_params(sock_ctx->tls_conn, ctx, sock_ctx->id);
	if (blocking == 0) {
		log_printf(LOG_INFO, "Nonblocking connect requested\n");
		netlink_notify_kernel(ctx, id, -EINPROGRESS);
	}
	return;
}



void connect_and_send_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr, 
	int int_addrlen, struct sockaddr* rem_addr, int rem_addrlen, int blocking, char *msg, size_t size) {
	
	int ret;
	sock_ctx_t* sock_ctx;
	int response = 0;
	int port;

	if (int_addr->sa_family == AF_UNIX) {
		port = strtol(((struct sockaddr_un*)int_addr)->sun_path+1, NULL, 16);
		log_printf(LOG_INFO, "unix port is %05x", port);
	}
	else {
		port = (int)ntohs(((struct sockaddr_in*)int_addr)->sin_port);
	}

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
	}
	else {
		/* only connect if we're not already.
		 * we might already be connected due to a
		 * socket upgrade */
		if (sock_ctx->is_connected == 0) {
			ret = connect(sock_ctx->fd, rem_addr, rem_addrlen);
		}
		else {
			ret = 0;
		}
		if (ret == -1) {
			response = -errno;
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
			sock_ctx->is_connected = 1;
			tls_opts_client_setup(sock_ctx->tls_opts);
		}
	}
	ret = evutil_make_socket_nonblocking(sock_ctx->fd);
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
	}
	sock_ctx->tls_conn = tls_client_wrapper_setup(sock_ctx->fd, ctx, 
				sock_ctx->rem_hostname, sock_ctx->is_accepting, sock_ctx->tls_opts);
	set_netlink_cb_params(sock_ctx->tls_conn, ctx, sock_ctx->id);
	if (blocking == 0) {
		log_printf(LOG_INFO, "Nonblocking connect requested\n");
		netlink_notify_kernel(ctx, id, -EINPROGRESS);
	}
	tls_early_data(sock_ctx->tls_conn,msg,size);
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
			response = -errno;
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

	tls_opts_server_setup(sock_ctx->tls_opts);
	sock_ctx->daemon = ctx; /* XXX I don't want this here */
	sock_ctx->listener = evconnlistener_new(ctx->ev_base, listener_accept_cb, sock_ctx,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, 0, sock_ctx->fd);

	evconnlistener_set_error_cb(sock_ctx->listener, listener_accept_error_cb);
	return;
}

void associate_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr, int int_addrlen) {
	sock_ctx_t* sock_ctx;
	int response = 0;
	int port;

	if (int_addr->sa_family == AF_UNIX) {
		port = strtol(((struct sockaddr_un*)int_addr)->sun_path+1, NULL, 16);
		log_printf(LOG_INFO, "unix port is %05x", port);
	}
	else {
		port = (int)ntohs(((struct sockaddr_in*)int_addr)->sin_port);
	}
	sock_ctx = hashmap_get(ctx->sock_map_port, port);
	hashmap_del(ctx->sock_map_port, port);
	if (sock_ctx == NULL) {
		log_printf(LOG_ERROR, "port provided in associate_cb not found");
		response = -EBADF;
		netlink_notify_kernel(ctx, id, response);
		return;
	}

	sock_ctx->id = id;
	sock_ctx->is_connected = 1;
	hashmap_add(ctx->sock_map, id, (void*)sock_ctx);
	
	set_netlink_cb_params(sock_ctx->tls_conn, ctx, id);
	//log_printf(LOG_INFO, "Socket %lu accepted\n", id);
	netlink_notify_kernel(ctx, id, response);
	return;
}

void close_cb(tls_daemon_ctx_t* ctx, unsigned long id) {
	int ret;
	sock_ctx_t* sock_ctx;

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		return;
	}
	/* close things here */
	if (sock_ctx->is_accepting == 1) {
		/* This is an ophan server connection.
		 * We don't host its corresponding listen socket
		 * But we were given control of the remote peer
		 * connection */
		hashmap_del(ctx->sock_map, id);
		tls_opts_free(sock_ctx->tls_opts);
		free_tls_conn_ctx(sock_ctx->tls_conn);
		free(sock_ctx);
		return;
	}
	if (sock_ctx->is_connected == 1) {
		/* connections under the control of the tls_wrapper code
		 * clean up themselves as a result of the close event
		 * received from one of the endpoints. In this case we
		 * only need to clean up the sock_ctx */
		//netlink_notify_kernel(ctx, id, 0);
		hashmap_del(ctx->sock_map, id);
		tls_opts_free(sock_ctx->tls_opts);
		free_tls_conn_ctx(sock_ctx->tls_conn);
		free(sock_ctx);
		return;
	}
	if (sock_ctx->listener != NULL) {
		hashmap_del(ctx->sock_map, id);
		evconnlistener_free(sock_ctx->listener);
		tls_opts_free(sock_ctx->tls_opts);
		free(sock_ctx);
		//netlink_notify_kernel(ctx, id, 0);
		return;
	}
	hashmap_del(ctx->sock_map, id);
	EVUTIL_CLOSESOCKET(sock_ctx->fd);
	free(sock_ctx);
	//netlink_notify_kernel(ctx, id, 0);
	return;
}

void upgrade_cb(tls_daemon_ctx_t* ctx, unsigned long id, 
		struct sockaddr* int_addr, int int_addrlen) {
	/* This was implemented in the kernel directly. */
	return;
}

/* This function is provided to the hashmap implementation
 * so that it can correctly free all held data */
void free_sock_ctx(sock_ctx_t* sock_ctx) {
	if (sock_ctx->listener != NULL) {
		evconnlistener_free(sock_ctx->listener);
	}
	else if (sock_ctx->is_connected == 1) {
		/* connections under the control of the tls_wrapper code
		 * clean up themselves as a result of the close event
		 * received from one of the endpoints. In this case we
		 * only need to clean up the sock_ctx */
	}
	else {
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
	}
	tls_opts_free(sock_ctx->tls_opts);
	if (sock_ctx->tls_conn != NULL) {
		free_tls_conn_ctx(sock_ctx->tls_conn);
	}
	free(sock_ctx);
	return;
}

void upgrade_recv(evutil_socket_t fd, short events, void *arg) {
	sock_ctx_t* sock_ctx;
	tls_daemon_ctx_t* ctx = (tls_daemon_ctx_t*)arg;
	char msg_buffer[256];
	int new_fd;
	int bytes_read;
	unsigned long id;
	int is_accepting;
	struct sockaddr_un addr = {};
	/* Why the 5? Because that's what linux uses for autobinds*/
	/* Why the 1? Because of the null byte in front of abstract names */
	int addr_len = sizeof(sa_family_t) + 5 + 1;
	log_printf(LOG_INFO, "Someone wants an upgrade!\n");
	memset(msg_buffer, 0, 256);
	bytes_read = recv_fd_from(fd, msg_buffer, 255, &new_fd, &addr, addr_len);
	if (bytes_read == -1) {
		log_printf(LOG_ERROR, "recv_fd: %s\n", strerror(errno));
		return;
	}

	sscanf(msg_buffer, "%d:%lu", &is_accepting, &id);
	log_printf(LOG_INFO, "Got a new %s descriptor %d, to be associated with %lu from addr %s\n",
		       	is_accepting == 1 ? "accepting" : "connecting", new_fd, id, addr.sun_path+1, addr_len);
	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		return;
	}
	EVUTIL_CLOSESOCKET(sock_ctx->fd);
	sock_ctx->fd = new_fd;
	sock_ctx->is_connected = 1;
	sock_ctx->tls_opts = tls_opts_create(NULL); 

	if (is_accepting == 1) {
		tls_opts_server_setup(sock_ctx->tls_opts);
		sock_ctx->is_accepting = 1;
	}
	else {
		tls_opts_client_setup(sock_ctx->tls_opts);
		sock_ctx->is_accepting = 0;
	}

	//sock_ctx->tls_conn = tls_client_wrapper_setup(sock_ctx->fd, ctx, 
	//			sock_ctx->rem_hostname, sock_ctx->is_accepting, sock_ctx->tls_opts);
	//set_netlink_cb_params(sock_ctx->tls_conn, ctx, sock_ctx->id);

	if (sendto(fd, "GOT IT", sizeof("GOT IT"), 0, &addr, addr_len) == -1) {
		perror("sendto");
	}
	return;
}

/* Modified read_fd taken from various online sources. Found without copyright or
 * attribution. Examples also in manpages so we could use that if needed */
ssize_t recv_fd_from(int fd, void *ptr, size_t nbytes, int *recvfd, struct sockaddr_un* addr, int addr_len) {
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t	n;
	int newfd;

	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr* cmptr;

	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);
	msg.msg_name = addr;
	msg.msg_namelen = addr_len;

	iov[0].iov_base = ptr;
	iov[0].iov_len = nbytes;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if ((n = recvmsg(fd, &msg, 0)) <= 0) {
		return n;
	}

	if ((cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
	    cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
		if (cmptr->cmsg_level != SOL_SOCKET) {
			log_printf(LOG_ERROR, "control level != SOL_SOCKET\n");
			return -1;
		}
		if (cmptr->cmsg_type != SCM_RIGHTS) {
			log_printf(LOG_ERROR, "control type != SCM_RIGHTS\n");
			return -1;
		}
		*recvfd = *((int *) CMSG_DATA(cmptr));
	}
	else {
		*recvfd = -1; /* descriptor was not passed */
	}
	return n;
}

