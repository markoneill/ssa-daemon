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
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#include "tls_wrapper.h"
#include "openssl_compat.h"
#include "log.h"
#include "config.h"

#define MAX_BUFFER	1024*1024*10
#define IPPROTO_TLS 	(715 % 255)

static SSL* tls_server_setup(SSL_CTX* tls_ctx);
static SSL* tls_client_setup(SSL_CTX* tls_ctx, char* hostname);
static void tls_bev_write_cb(struct bufferevent *bev, void *arg);
static void tls_bev_read_cb(struct bufferevent *bev, void *arg);
static void tls_bev_event_cb(struct bufferevent *bev, short events, void *arg);
static int server_name_cb(SSL* tls, int* ad, void* arg);
static int server_alpn_cb(SSL *s, const unsigned char **out, unsigned char *outlen,
	       	const unsigned char *in, unsigned int inlen, void *arg);
static SSL_CTX* get_tls_ctx_from_name(tls_opts_t* tls_opts, char* hostname);

static tls_conn_ctx_t* new_tls_conn_ctx();
static void shutdown_tls_conn_ctx(tls_conn_ctx_t* ctx); 
static int read_rand_seed(char **buf, char* seed_path, int size);


tls_conn_ctx_t* tls_client_wrapper_setup(evutil_socket_t efd, tls_daemon_ctx_t* daemon_ctx,
	char* hostname, int is_accepting, tls_opts_t* tls_opts) {
	
	tls_conn_ctx_t* ctx = new_tls_conn_ctx();
	if (ctx == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate tls_conn_ctx_t: %s\n", strerror(errno));
		return NULL;
	}
	ctx->tls = tls_client_setup(tls_opts->tls_ctx, hostname);

	if (ctx->tls == NULL) {
		log_printf(LOG_ERROR, "Failed to set up TLS (SSL*) context\n");
		free_tls_conn_ctx(ctx);
		return NULL;
	}
	/* socket set to -1 because we set it later */
	ctx->plain.bev = bufferevent_socket_new(daemon_ctx->ev_base, -1,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	//ctx->plain.connected = 1;
	if (ctx->plain.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up client facing bufferevent [direct mode]\n");
		/* Need to close socket because it won't be closed on free since bev creation failed */
		free_tls_conn_ctx(ctx);
		return NULL;
	}


	if (is_accepting == 1) { /* TLS server role */
		ctx->secure.bev = bufferevent_openssl_socket_new(daemon_ctx->ev_base, efd, ctx->tls,
			BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	}
	else { /* TLS client role */
		ctx->secure.bev = bufferevent_openssl_socket_new(daemon_ctx->ev_base, efd, ctx->tls,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	}

	if (ctx->secure.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up server facing bufferevent [direct mode]\n");
		free_tls_conn_ctx(ctx);
		return NULL;
	}

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	/* Comment out this line if you need to do better debugging of OpenSSL behavior */
	bufferevent_openssl_set_allow_dirty_shutdown(ctx->secure.bev, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */


	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(ctx->secure.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, ctx);
	bufferevent_enable(ctx->secure.bev, EV_READ | EV_WRITE);
	bufferevent_setcb(ctx->plain.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, ctx);
	//log_printf(LOG_INFO, "secure bev enabled\n");
	//bufferevent_enable(ctx->plain.bev, EV_READ | EV_WRITE);

	/* Connect server facing socket */
	/*if (bufferevent_socket_connect(ctx->secure.bev, (struct sockaddr*)server_addr, server_addrlen) < 0) {
		log_printf(LOG_ERROR, "bufferevent_socket_connect [direct mode]: %s\n", strerror(errno));
		free_tls_conn_ctx(ctx);
		return;
	}*/
	//SSL_connect(ctx->tls);
	return ctx;
}

void associate_fd(tls_conn_ctx_t* conn, evutil_socket_t ifd) {
	bufferevent_setfd(conn->plain.bev, ifd);
	bufferevent_enable(conn->plain.bev, EV_READ | EV_WRITE);

	//log_printf(LOG_INFO, "plain bev enabled\n");
	return;
}


tls_conn_ctx_t* tls_server_wrapper_setup(evutil_socket_t efd, evutil_socket_t ifd, tls_daemon_ctx_t* daemon_ctx,
	tls_opts_t* tls_opts, struct sockaddr* internal_addr, int internal_addrlen) {

	tls_conn_ctx_t* ctx = new_tls_conn_ctx();
	if (ctx == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate server tls_conn_ctx_t: %s\n", strerror(errno));
		return NULL;
	}
	
	/* We're sending just the first tls_ctx here because our SNI callbacks will fix it if needed */
	ctx->tls = tls_server_setup(tls_opts->tls_ctx);
	ctx->secure.bev = bufferevent_openssl_socket_new(daemon_ctx->ev_base, efd, ctx->tls,
			BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	ctx->secure.connected = 1;
	if (ctx->secure.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up client facing bufferevent [listener mode]\n");
		EVUTIL_CLOSESOCKET(efd);
		free_tls_conn_ctx(ctx);
		return NULL;
	}
	
	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	/* Comment out this line if you need to do better debugging of OpenSSL behavior */
	bufferevent_openssl_set_allow_dirty_shutdown(ctx->secure.bev, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	ctx->plain.bev = bufferevent_socket_new(daemon_ctx->ev_base, ifd,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (ctx->plain.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up server facing bufferevent [listener mode]\n");
		EVUTIL_CLOSESOCKET(ifd);
		free_tls_conn_ctx(ctx);
		return NULL;
	}

	ctx->addr = internal_addr;
	ctx->addrlen = internal_addrlen;
	
	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(ctx->plain.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, ctx);
	//bufferevent_enable(ctx->plain.bev, EV_READ | EV_WRITE);
	bufferevent_setcb(ctx->secure.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, ctx);
	bufferevent_enable(ctx->secure.bev, EV_READ | EV_WRITE);
	
	/* Connect to local application server */
	/*if (bufferevent_socket_connect(ctx->plain.bev, internal_addr, internal_addrlen) < 0) {
		log_printf(LOG_ERROR, "bufferevent_socket_connect [listener mode]: %s\n", strerror(errno));
		free_tls_conn_ctx(ctx);
		return;
	}*/
	return ctx;
}

static int read_rand_seed(char **buf, char* seed_path, int size) {
	int fd;
	int data_len = 0;
	int ret;

	if ((seed_path == NULL) || ( size < 0)) {
		return 0;
	}

	fd = open(seed_path,O_RDONLY);
	if (fd == -1) {
		return 0;
	}

	*buf = malloc(size);
	if (*buf == NULL) {
		return 0;
	}

	while (data_len < size)
    {
    	ret = read(fd, *buf + data_len, size-data_len);
        if (ret < 0)
        {
            free(*buf);
            close(fd);
			*buf = NULL;
			return 0;
        }
        data_len += ret;
    }

    close(fd);
	return 1;
}

tls_opts_t* tls_opts_create(char* path) {
	tls_opts_t* opts;
	SSL_CTX* tls_ctx;
	ssa_config_t* ssa_config;
	struct stat stat_store;
	char* store_dir = NULL;
	char* store_file = NULL;
	unsigned char* rand_buf;

	opts = (tls_opts_t*)calloc(1, sizeof(tls_opts_t));
	if (opts == NULL) {
		return NULL;
	}

	/* Configure default settings for connections based on
	 * admin preferences */
	tls_ctx = SSL_CTX_new(SSLv23_method());

	ssa_config = get_app_config(path);

	if (ssa_config) {
		if (SSL_CTX_set_min_proto_version(tls_ctx, ssa_config->min_version) == 0) {
			log_printf(LOG_ERROR, "Unable to set min protocol version for %s\n",path);
		}
		if (SSL_CTX_set_max_proto_version(tls_ctx, ssa_config->max_version) == 0) {
			log_printf(LOG_ERROR, "Unable to set max protocol version for %s\n",path);
		}
		if (SSL_CTX_set_cipher_list(tls_ctx, ssa_config->cipher_list) == 0) {
			log_printf(LOG_ERROR, "Unable to set cipher list for %s\n",path);
		}

		stat(ssa_config->trust_store, &stat_store);
		if (S_ISDIR(stat_store.st_mode)) {
			store_dir = ssa_config->trust_store;
		}
		else {
			store_file = ssa_config->trust_store;
		}

		if (SSL_CTX_load_verify_locations(tls_ctx, store_file, store_file) == 0) {
			log_printf(LOG_ERROR, "Unable set truststore %s\n",ssa_config->trust_store);
		}

		if ( read_rand_seed(&rand_buf,ssa_config->randseed_path,ssa_config->randseed_size) == 1 )
		{
			RAND_seed(rand_buf,ssa_config->randseed_size);
			free(rand_buf);
		}
		else {
			log_printf(LOG_ERROR, "Unable to read set random seed from %s\n",ssa_config->randseed_path);
		}

		//SessionCacheLocation
		SSL_CTX_set_timeout(tls_ctx, ssa_config->cache_timeout);
		opts->custom_validation = ssa_config->custom_validation;
		
	}
	else {
		log_printf(LOG_ERROR, "Unable to find ssa configuration\n");
	}

	opts->tls_ctx = tls_ctx;
	opts->app_path = NULL;
	if (path) {
		opts->app_path = strdup(path);
	}
	return opts;
}

void tls_opts_free(tls_opts_t* opts) {
	tls_opts_t* cur_opts;
	tls_opts_t* tmp_opts;
	/* opts can be NULL (e.g., accepted sockets
	 * have no opts because they adopt the
	 * listening socket's opts upon accept */
	cur_opts = opts;
	while (cur_opts != NULL) {
		tmp_opts = cur_opts->next;
		SSL_CTX_free(cur_opts->tls_ctx);
		if (cur_opts->app_path) {
			free(cur_opts->app_path);
		}
		free(cur_opts);
		cur_opts = tmp_opts;
	}
	return;
}

int tls_opts_server_setup(tls_opts_t* tls_opts) {
	SSL_CTX* tls_ctx = tls_opts->tls_ctx;
	
	tls_opts->is_server = 1;
	
	SSL_CTX_set_options(tls_ctx, SSL_OP_ALL);
	/* There's a billion options we can/should set here by admin config XXX
 	 * See SSL_CTX_set_options and SSL_CTX_set_cipher_list for details */

	/* XXX We can do all sorts of caching modes and define our own callbacks
	 * if desired */
	SSL_CTX_set_session_cache_mode(tls_ctx, SSL_SESS_CACHE_SERVER);

	/* SNI configuration */
	SSL_CTX_set_tlsext_servername_callback(tls_ctx, server_name_cb);
	SSL_CTX_set_tlsext_servername_arg(tls_ctx, (void*)tls_opts);

	SSL_CTX_use_certificate_chain_file(tls_ctx, "test_files/certificate_a.pem");
	SSL_CTX_use_PrivateKey_file(tls_ctx, "test_files/key_a.pem", SSL_FILETYPE_PEM);

	return 1;
}

int tls_opts_client_setup(tls_opts_t* tls_opts) {
	SSL_CTX* tls_ctx = tls_opts->tls_ctx;

	tls_opts->is_server = 0;

	SSL_CTX_set_options(tls_ctx, SSL_OP_ALL);

	/* We're going to commit the cardinal sin for a bit. Hook up TrustBase here XXX */
	SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_NONE, NULL);

	/* There's a billion options we can/should set here by admin config XXX
 	 * See SSL_CTX_set_options and SSL_CTX_set_cipher_list for details */

	/* For client auth portion of the SSA utilize 
	 * SSL_CTX_set_default_passwd_cb */

	return 1;
}


int set_trusted_peer_certificates(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char* value, int len) {
	SSL_CTX* tls_ctx = tls_opts->tls_ctx;
	/* XXX update this to take in-memory PEM chains as well as file names */
	STACK_OF(X509_NAME)* cert_names;

	if (tls_opts->custom_validation) {
		return 1;
	}

	if (conn_ctx != NULL) {
		/* These options not supported after connection (for now) */
		return 0;
	}
	if (SSL_CTX_load_verify_locations(tls_ctx, value, NULL) == 0) {
		return 0;
	}
	
	SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER, NULL);


	/* Really we should only do this if we're the server */
	cert_names = SSL_load_client_CA_file(value);
	if (cert_names == NULL) {
		return 0;
	}

	SSL_CTX_set_client_CA_list(tls_ctx, cert_names);
	return 1;
}

int set_alpn_protos(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char* protos) {
	char* next;
	char* proto;
	int proto_len;
	//char alpn_string[256];
	char* alpn_string;
	int alpn_len;
	char* alpn_str_ptr;
	tls_opts_t* cur_opts;

	if (conn_ctx != NULL) {
		/* Already connected */
		return 0;
	}
	alpn_string = tls_opts->alpn_string;
	proto = protos;
	alpn_str_ptr = alpn_string;
	SSL_CTX* tls_ctx = tls_opts->tls_ctx;
	log_printf(LOG_INFO, "ALPN Setting: %s\n", protos);
	memset(alpn_string, 0, sizeof(alpn_string));
	while ((next = strchr(proto, ',')) != NULL) {
		*next = '\0';
		proto_len = strlen(proto);
		alpn_str_ptr[0] = proto_len;
		alpn_str_ptr++;
		memcpy(alpn_str_ptr, proto, proto_len);
		alpn_str_ptr += proto_len;
		proto = next + 1; /* +1 to skip delimeter */
	}
	proto_len = strlen(proto);
	alpn_str_ptr[0] = proto_len;
	alpn_str_ptr++;
	memcpy(alpn_str_ptr, proto, proto_len);

	alpn_len = strlen(alpn_string);

	/* We need to apply the callback to all relevant SSL_CTXs */
	cur_opts = tls_opts;
	while (cur_opts != NULL) {
		SSL_CTX_set_alpn_select_cb(cur_opts->tls_ctx, server_alpn_cb, (void*)tls_opts);
		cur_opts = cur_opts->next;
	}
	
	if (SSL_CTX_set_alpn_protos(tls_ctx, alpn_string, alpn_len) == 1) {
		return 0;
	}
	

	return 1;
}

int set_disbled_cipher(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char* cipher) {
	SSL_CTX* tls_ctx = tls_opts->tls_ctx;
	ssa_config_t* ssa_config;
	char* cipher_list;

	ssa_config = get_app_config(tls_opts->app_path);

	if (asprintf(&cipher_list, "%s:!%s",ssa_config->cipher_list ,cipher) > 0) {
		log_printf(LOG_ERROR, "Unable to disable cipher %s\n",cipher);
		return 0;
	}

	if (SSL_CTX_set_cipher_list(tls_ctx, ssa_config->cipher_list) == 0) {
		free(cipher_list);
		log_printf(LOG_ERROR, "Unable to disable cipher %s\n",cipher);
		return 0;
	}

	free(ssa_config->cipher_list);
	ssa_config->cipher_list = cipher_list;


	//char* cur_cipher;
	// XXX to make this function less than 500 lines we need access to the
	// config string for this app.
	// There is no function in OpenSSL to get back a cipher string and append
	// the desired !cipher to it. All ways to do it are endlessly hairy.
	//SSL_CTX_set_cipher_list
	//SSL_set_cipher_list
	return 1;
}

int set_session_ttl(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char* ttl) {
	SSL_CTX* tls_ctx;
	long timeout;
	memcpy(&timeout, ttl, sizeof(timeout));
	if (conn_ctx != NULL) {
		return SSL_SESSION_set_timeout(SSL_get0_session(conn_ctx->tls), timeout);
	}

	if (tls_opts != NULL) {
		tls_ctx = tls_opts->tls_ctx;
		SSL_CTX_set_timeout(tls_ctx, timeout);
	}
	return 1;
}

/* XXX update this to take in-memory PEM chains as well as file names */
int set_certificate_chain(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char* filepath) {
	tls_opts_t* cur_opts;
	tls_opts_t* new_opts;

	/* If a connection already exists, set the certs on the existing connection*/
	if (conn_ctx != NULL) {
		#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		if (SSL_use_certificate_chain_file(conn_ctx->tls, filepath) != 1) {
		#else
		if (compat_SSL_use_certificate_chain_file(conn_ctx->tls, filepath) != 1) {
		#endif
			/* Get ready for renegotiation */
			return 0;
		}
		return 1;
	}

	/* If no connection exists, set the certs on the options */
	if (tls_opts == NULL) {
		return 0;
	}
	cur_opts = tls_opts;
	/* There is no cert set yet on the first SSL_CTX so we'll use that */
	if (SSL_CTX_get0_certificate(cur_opts->tls_ctx) == NULL) {
		if (SSL_CTX_use_certificate_chain_file(cur_opts->tls_ctx, filepath) != 1) {
			log_printf(LOG_ERROR, "Unable to assign certificate chain\n");
			return 0;
		}
		log_printf(LOG_INFO, "Using cert located at %s\n", filepath);
		return 1;
	}

	/* Otherwise create a new options struct and use that */
	while (cur_opts->next != NULL) {
		cur_opts = cur_opts->next;
	}

	new_opts = tls_opts_create(NULL);
	if (new_opts == NULL) {
		return 0;
	}
	
	if (SSL_CTX_use_certificate_chain_file(new_opts->tls_ctx, filepath) != 1) {
		log_printf(LOG_ERROR, "Unable to assign certificate chain\n");
		return 0;
	}
	log_printf(LOG_INFO, "Using cert located at %s\n", filepath);
	/* Add new opts to option list */
	cur_opts->next = new_opts;
	return 1;
}

/* XXX update this to take in-memory PEM keys as well as file names */
int set_private_key(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char* filepath) {
	tls_opts_t* cur_opts;

	/* If an active connection exists, just set the key for that session */
	if (conn_ctx != NULL) {
		if (SSL_use_PrivateKey_file(conn_ctx->tls, filepath, SSL_FILETYPE_PEM) == 1) {
			/* Renegotiate now? */
			return 0;
		}
		log_printf(LOG_INFO, "Using key located at %s\n", filepath);
		return 1;
	}

	/* Otherwise set the key to the first SSL_CTX that doesn't currently have one */
	cur_opts = tls_opts;
	while (cur_opts != NULL) {
		if (SSL_CTX_get0_privatekey(cur_opts->tls_ctx) == NULL) {
			if (SSL_CTX_use_PrivateKey_file(cur_opts->tls_ctx, filepath, SSL_FILETYPE_PEM) != 1) {
				return 0;
			}
			log_printf(LOG_INFO, "Using key located at %s\n", filepath);
			return 1;
		}
		cur_opts = cur_opts->next;
	}

	/* XXX Should call these as appropriate in this func */
	//SSL_CTX_check_private_key
	//SSL_check_private_key
	return 0;
}

int set_remote_hostname(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char* hostname) {
	SSL_CTX* tls_ctx = tls_opts->tls_ctx;
	if (conn_ctx == NULL) {
		/* We don't fail here because this will be set when the
		 * connection is actually created by tls_client_setup */
		return 1;
	}
	SSL_set_tlsext_host_name(conn_ctx->tls, hostname);
	return 1;
}

int get_peer_certificate(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char** data, unsigned int* len) {
	X509* cert;
	BIO* bio;
	char* bio_data;
	char* pem_data;
	unsigned int cert_len;

	if (conn_ctx->tls == NULL) {
		return 0;
	}
	cert = SSL_get_peer_certificate(conn_ctx->tls);
	if (cert == NULL) {
		return 0;
	}
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		X509_free(cert);
		return 0;
	}
	if (PEM_write_bio_X509(bio, cert) == 0) {
		X509_free(cert);
		BIO_free(bio);
		return 0;
	}

	cert_len = BIO_get_mem_data(bio, &bio_data);
	pem_data = malloc(cert_len + 1); /* +1 for null terminator */
	if (pem_data == NULL) {
		X509_free(cert);
		BIO_free(bio);
		return 0;
	}

	memcpy(pem_data, bio_data, cert_len);
	pem_data[cert_len] = '\0';
	X509_free(cert);
	BIO_free(bio);

	*data = pem_data;
	*len = cert_len;
	return 1;
}

int get_peer_identity(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char** data, unsigned int* len) {
	X509* cert;
	X509_NAME* subject_name;
	char* identity;
	if (conn_ctx->tls == NULL) {
		return 0;
	}
	cert = SSL_get_peer_certificate(conn_ctx->tls);
	if (cert == NULL) {
		return 0;
	}
	subject_name = X509_get_subject_name(cert);
	identity = X509_NAME_oneline(subject_name, NULL, 0);
	*data = identity;
	*len = strlen(identity)+1;
	return 1;
}

int get_remote_hostname(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char** data, unsigned int* len) {
	/* XXX hostname is a bit of a misnomer for the client auth case, as it's actually client identity
	 * instead of hostname. Perhaps rename this option or make an alias for it */
	return 1;
}

int get_hostname(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char** data, unsigned int* len) {
	char* hostname;
	char* hostname_copy;
	if (conn_ctx == NULL) {
		return 0;
	}
	hostname = SSL_get_servername(conn_ctx->tls, TLSEXT_NAMETYPE_host_name);
	*data = hostname;
	if (hostname == NULL) {
		*len = 0;
		return 1;
	}
	*len = strlen(hostname)+1;
	return 1;
}

int get_certificate_chain(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char** data, unsigned int* len) {
	/* XXX stub */
	return 1;
}

int get_alpn_proto(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx, char** data, unsigned int* len) {
	SSL_get0_alpn_selected(conn_ctx->tls, data, len);
	return 1;
}

long get_session_ttl(tls_opts_t* tls_opts, tls_conn_ctx_t* conn_ctx) {
	long timeout;
	SSL_CTX* tls_ctx;
	if (conn_ctx != NULL) {
		timeout = SSL_SESSION_get_timeout(SSL_get0_session(conn_ctx->tls));
		return timeout;
	}
	if (tls_opts != NULL) {
		tls_ctx = tls_opts->tls_ctx;
		timeout = SSL_CTX_get_timeout(tls_ctx);
	}
	return timeout;
}

SSL_CTX* get_tls_ctx_from_name(tls_opts_t* tls_opts, char* hostname) {
	X509* cert;
	tls_opts_t* cur_opts;
	if (tls_opts == NULL) {
		return NULL;
	}
	cur_opts = tls_opts;
	while (cur_opts != NULL) {
		cert = SSL_CTX_get0_certificate(cur_opts->tls_ctx);
		if (cert == NULL) {
			break;
		}
		#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		if (X509_check_host(hostname, 0, 0, NULL) == 1) {
		#else
		if (validate_hostname(hostname, cert) == MatchFound) {
		#endif
			return cur_opts->tls_ctx;
		}
		cur_opts = cur_opts->next;
	}
	return NULL;
}

int server_name_cb(SSL* tls, int* ad, void* arg) {
	SSL_CTX* tls_ctx;
	SSL_CTX* old_ctx;
	old_ctx = SSL_get_SSL_CTX(tls);

	const char* hostname = SSL_get_servername(tls, TLSEXT_NAMETYPE_host_name);
	if (hostname == NULL) {
		return SSL_TLSEXT_ERR_NOACK;
	}
	log_printf(LOG_INFO, "SNI from client is %s\n", hostname);
	tls_ctx = get_tls_ctx_from_name((tls_opts_t*)arg, hostname);
	if (tls_ctx != NULL) {
		log_printf(LOG_INFO, "Server SSL_CTX matching SNI was found\n");
		SSL_set_SSL_CTX(tls, tls_ctx);
		SSL_set_verify(tls, SSL_CTX_get_verify_mode(old_ctx), SSL_CTX_get_verify_callback(old_ctx));
	}
	return SSL_TLSEXT_ERR_OK;
}

int server_alpn_cb(SSL *s, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
	       	unsigned int inlen, void *arg) {
	tls_opts_t* opts = (tls_opts_t*)arg;
	int ret;
	unsigned char* nc_out;

	//printf("alpn string is %s\n", opts->alpn_string);
	ret = SSL_select_next_proto(&nc_out, outlen, opts->alpn_string, strlen(opts->alpn_string),
			in, inlen);
	*out = nc_out;

	ret = OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
	//printf("ret is %s\n", ret == OPENSSL_NPN_NEGOTIATED ? "good" : "bad");
	return ret;
}

SSL* tls_client_setup(SSL_CTX* tls_ctx, char* hostname) {
	SSL* tls;
	tls = SSL_new(tls_ctx);
	if (tls == NULL) {
		return NULL;
	}
	/* set server name indication for client hello */
	if (hostname != NULL) {
		SSL_set_tlsext_host_name(tls, hostname);
	}

	return tls;
}

SSL* tls_server_setup(SSL_CTX* tls_ctx) {
	SSL* tls = SSL_new(tls_ctx);
	if (tls == NULL) {
		return NULL;
	}
	return tls;
}

int set_netlink_cb_params(tls_conn_ctx_t* conn, tls_daemon_ctx_t* daemon_ctx, unsigned long id) {
	if (conn->tls == NULL) {
		return 1;
	}
	conn->daemon = daemon_ctx;
	conn->id = id;
	return 1;
}

void tls_bev_write_cb(struct bufferevent *bev, void *arg) {
	//log_printf(LOG_DEBUG, "write event on bev %p\n", bev);
	tls_conn_ctx_t* ctx = arg;
	channel_t* endpoint = (bev == ctx->secure.bev) ? &ctx->plain : &ctx->secure;
	struct evbuffer* out_buf;

	if (endpoint->closed) {
		out_buf = bufferevent_get_output(bev);
		if (evbuffer_get_length(out_buf) == 0) {
			bufferevent_free(bev);
			/* Should we free anything else here? */
		}
		return;
	}

	if (endpoint->bev && !(bufferevent_get_enabled(endpoint->bev) & EV_READ)) {
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		bufferevent_enable(endpoint->bev, EV_READ);
	}
	return;
}

void tls_bev_read_cb(struct bufferevent *bev, void *arg) {
	//log_printf(LOG_DEBUG, "read event on bev %p\n", bev);
	tls_conn_ctx_t* ctx = arg;
	channel_t* endpoint = (bev == ctx->secure.bev) ? &ctx->plain : &ctx->secure;
	struct evbuffer* in_buf;
	struct evbuffer* out_buf;
	size_t in_len;

	in_buf = bufferevent_get_input(bev);
	in_len = evbuffer_get_length(in_buf);
	
	if (endpoint->closed) {
		evbuffer_drain(in_buf, in_len);
		return;
	}

	if (in_len == 0) {
		return;
	}

	out_buf = bufferevent_get_output(endpoint->bev);
	evbuffer_add_buffer(out_buf, in_buf);

	if (evbuffer_get_length(out_buf) >= MAX_BUFFER) {
		log_printf(LOG_DEBUG, "Overflowing buffer, slowing down\n");
		bufferevent_setwatermark(endpoint->bev, EV_WRITE, MAX_BUFFER / 2, MAX_BUFFER);
		bufferevent_disable(bev, EV_READ);
	}
	return;
}

void tls_bev_event_cb(struct bufferevent *bev, short events, void *arg) {
	char* servername;
	tls_conn_ctx_t* ctx = arg;
	unsigned long ssl_err;
	channel_t* endpoint = (bev == ctx->secure.bev) ? &ctx->plain : &ctx->secure;
	channel_t* startpoint = (bev == ctx->secure.bev) ? &ctx->secure : &ctx->plain;
	if (events & BEV_EVENT_CONNECTED) {
		log_printf(LOG_DEBUG, "%s endpoint connected\n", bev == ctx->secure.bev ? "encrypted" : "plaintext");
		startpoint->connected = 1;
		if (bev == ctx->secure.bev) {
			//log_printf(LOG_INFO, "Is handshake finished?: %d\n", SSL_is_init_finished(ctx->tls));
			if (bufferevent_getfd(ctx->plain.bev) == -1) {
				netlink_handshake_notify_kernel(ctx->daemon, ctx->id, 0);
			}
			else {
				bufferevent_enable(ctx->plain.bev, EV_READ | EV_WRITE);
				bufferevent_socket_connect(ctx->plain.bev, ctx->addr, ctx->addrlen);
			}
		}
	}
	if (events & BEV_EVENT_ERROR) {
		//log_printf(LOG_DEBUG, "%s endpoint encountered an error\n", bev == ctx->secure.bev ? "encrypted" : "plaintext");
		if (errno) {
			if (errno == ECONNRESET || errno == EPIPE) {
				log_printf(LOG_INFO, "Connection closed\n");
				startpoint->closed = 1;
			}
			else {
				log_printf(LOG_INFO, "An unhandled error has occurred\n");
			}
		}
		if (bev == ctx->secure.bev) {
			while ((ssl_err = bufferevent_get_openssl_error(bev))) {
				log_printf(LOG_ERROR, "SSL error from bufferevent: %s [%s]\n",
					ERR_func_error_string(ssl_err),
					 ERR_reason_error_string(ssl_err));
			}
		}
		if (startpoint->closed == 1 && endpoint->closed == 0) {
			struct evbuffer* out_buf;
			out_buf = bufferevent_get_output(endpoint->bev);
			/* close other buffer if we're closing and it has no data left */
			if (evbuffer_get_length(out_buf) == 0) {
				endpoint->closed = 1;
			}
		}
	}
	if (events & BEV_EVENT_EOF) {
		log_printf(LOG_DEBUG, "%s endpoint got EOF\n", bev == ctx->secure.bev ? "encrypted" : "plaintext");
		startpoint->closed = 1;
		if (endpoint->closed == 0) {
			struct evbuffer* in_buf;
			struct evbuffer* out_buf;
			out_buf = bufferevent_get_output(endpoint->bev);
			in_buf = bufferevent_get_input(bev);
			if (evbuffer_get_length(in_buf) > 0) {
				evbuffer_add_buffer(out_buf, in_buf);
			}
			if (evbuffer_get_length(out_buf) == 0) {
				endpoint->closed = 1;
			}
		}
	}
	/* If both channels are closed now, free everything */
	if (endpoint->closed == 1 && startpoint->closed == 1) {
		if (bufferevent_getfd(ctx->plain.bev) == -1) {
			netlink_handshake_notify_kernel(ctx->daemon, ctx->id, -EHOSTUNREACH);
		}
		shutdown_tls_conn_ctx(ctx);
	}
	return;
}

tls_conn_ctx_t* new_tls_conn_ctx() {
	tls_conn_ctx_t* ctx = (tls_conn_ctx_t*)calloc(1, sizeof(tls_conn_ctx_t));
	return ctx;
}

void shutdown_tls_conn_ctx(tls_conn_ctx_t* ctx) {
	if (ctx == NULL) return;

	if (ctx->tls != NULL) {
		SSL_shutdown(ctx->tls);
	}
	return;
}

void free_tls_conn_ctx(tls_conn_ctx_t* ctx) {
	shutdown_tls_conn_ctx(ctx);
	ctx->tls = NULL;
	if (ctx->secure.bev != NULL) bufferevent_free(ctx->secure.bev);
	ctx->secure.bev = NULL;
	if (ctx->plain.bev != NULL) bufferevent_free(ctx->plain.bev);
	ctx->plain.bev = NULL;
	free(ctx);
	return;
}

