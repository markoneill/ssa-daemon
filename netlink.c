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

#include <event2/util.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "netlink.h"
#include "daemon.h"
#include "log.h"


// Attributes
enum {
        SSA_NL_A_UNSPEC,
	SSA_NL_A_SOCKADDR_INTERNAL,
	SSA_NL_A_SOCKADDR_EXTERNAL,
        SSA_NL_A_PAD,
        __SSA_NL_A_MAX,
};

#define SSA_NL_A_MAX (__SSA_NL_A_MAX - 1)

// Operations
enum {
        SSA_NL_C_UNSPEC,
        SSA_NL_C_NOTIFY,
        __SSA_NL_C_MAX,
};

#define SSA_NL_C_MAX (__SSA_NL_C_MAX - 1)

// Multicast group
enum ssa_nl_groups {
        SSA_NL_NOTIFY,
};

static const struct nla_policy ssa_nl_policy[SSA_NL_A_MAX + 1] = {
        [SSA_NL_A_UNSPEC] = { .type = NLA_UNSPEC },
        [SSA_NL_A_SOCKADDR_INTERNAL] = { .type = NLA_UNSPEC },
        [SSA_NL_A_SOCKADDR_EXTERNAL] = { .type = NLA_UNSPEC },
};



int handle_netlink_msg(struct nl_msg* msg, void* arg);

struct nl_sock* netlink_connect(tls_daemon_ctx_t* ctx) {
	int group;
	int family;
	struct nl_sock* netlink_sock = nl_socket_alloc();
	nl_socket_set_local_port(netlink_sock, 0);
	nl_socket_disable_seq_check(netlink_sock);
	ctx->netlink_sock = netlink_sock;
	nl_socket_modify_cb(netlink_sock, NL_CB_VALID, NL_CB_CUSTOM, handle_netlink_msg, (void*)ctx);
	if (netlink_sock == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate socket\n");
		return NULL;
	}

	if (genl_connect(netlink_sock) != 0) {
		log_printf(LOG_ERROR, "Failed to connect to Generic Netlink control\n");
		return NULL;
	}

	if ((family = genl_ctrl_resolve(netlink_sock, "SSA")) < 0) {
		log_printf(LOG_ERROR, "Failed to resolve SSA family identifier\n");
		return NULL;
	}

	if ((group = genl_ctrl_resolve_grp(netlink_sock, "SSA", "notify")) < 0) {
		log_printf(LOG_ERROR, "Failed to resolve group identifier\n");
		return NULL;
	}

	if (nl_socket_add_membership(netlink_sock, group) < 0) {
		log_printf(LOG_ERROR, "Failed to add membership to group\n");
		return NULL;
	}
	return netlink_sock;
}

void netlink_recv(evutil_socket_t fd, short events, void *arg) {
	log_printf(LOG_INFO, "Got a message from the kernel!\n");
	struct nl_sock* netlink_sock = (struct nl_sock*)arg;
	nl_recvmsgs_default(netlink_sock);
	return;
}

int handle_netlink_msg(struct nl_msg* msg, void* arg) {
	tls_daemon_ctx_t* ctx = (tls_daemon_ctx_t*)arg;
        struct nlmsghdr* nlh;
        struct genlmsghdr* gnlh;
        struct nlattr* attrs[SSA_NL_A_MAX + 1];

	int addr_internal_len;
	int addr_external_len;
	struct sockaddr_in addr_internal;
	struct sockaddr_in addr_external;

        // Get Message
        nlh = nlmsg_hdr(msg);
        gnlh = (struct genlmsghdr*)nlmsg_data(nlh);
        genlmsg_parse(nlh, 0, attrs, SSA_NL_A_MAX, ssa_nl_policy);
        switch (gnlh->cmd) {
		case SSA_NL_C_NOTIFY:
			addr_internal_len = nla_len(attrs[SSA_NL_A_SOCKADDR_INTERNAL]);
			addr_external_len = nla_len(attrs[SSA_NL_A_SOCKADDR_EXTERNAL]);
			addr_internal = *(struct sockaddr_in*)nla_data(attrs[SSA_NL_A_SOCKADDR_INTERNAL]);
			addr_external = *(struct sockaddr_in*)nla_data(attrs[SSA_NL_A_SOCKADDR_EXTERNAL]);
			listen_cb(ctx, (struct sockaddr*)&addr_internal, addr_internal_len,
					 (struct sockaddr*)&addr_external, addr_external_len);
			break;
		default:
			log_printf(LOG_ERROR, "unrecognized command\n");
			break;
	}
	return 0;
}

int netlink_disconnect(struct nl_sock* sock) {
        nl_socket_free(sock);
        return 0;
}