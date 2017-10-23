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

struct nl_sock* netlink_connect(void) {
	int group;
	int family;
	struct nl_sock* netlink_sock = nl_socket_alloc();
	nl_socket_set_local_port(netlink_sock, 0);
	nl_socket_disable_seq_check(netlink_sock);
	nl_socket_modify_cb(netlink_sock, NL_CB_VALID, NL_CB_CUSTOM, handle_netlink_msg, (void*)netlink_sock);
	if (netlink_sock == NULL) {
		fprintf(stderr, "Failed to allocate socket\n");
		return NULL;
	}

	if (genl_connect(netlink_sock) != 0) {
		fprintf(stderr, "Failed to connect to Generic Netlink control\n");
		return NULL;
	}

	if ((family = genl_ctrl_resolve(netlink_sock, "SSA")) < 0) {
		fprintf(stderr, "Failed to resolve SSA family identifier\n");
		return NULL;
	}

	if ((group = genl_ctrl_resolve_grp(netlink_sock, "SSA", "notify")) < 0) {
		fprintf(stderr, "Failed to resolve group identifier\n");
		return NULL;
	}

	if (nl_socket_add_membership(netlink_sock, group) < 0) {
		fprintf(stderr, "Failed to add membership to group\n");
		return NULL;
	}
	printf("p is %p\n", netlink_sock);
	return netlink_sock;
}

void netlink_recv(evutil_socket_t fd, short events, void *arg) {
	printf("Got a message from the kernel!\n");
	struct nl_sock* netlink_sock = (struct nl_sock*)arg;
	printf("p is %p\n", netlink_sock);
	nl_recvmsgs_default(netlink_sock);
	return;
}

int handle_netlink_msg(struct nl_msg* msg, void* arg) {
        struct nlmsghdr* nlh;
        struct genlmsghdr* gnlh;
        struct nlattr* attrs[SSA_NL_A_MAX + 1];

        // Get Message
        nlh = nlmsg_hdr(msg);
        gnlh = (struct genlmsghdr*)nlmsg_data(nlh);
        genlmsg_parse(nlh, 0, attrs, SSA_NL_A_MAX, ssa_nl_policy);
        switch (gnlh->cmd) {
		case SSA_NL_C_NOTIFY:
			
			break;
		default:
			printf("unrecognized command\n");
			break;
	}
	return 0;
}

int netlink_disconnect(struct nl_sock* sock) {
        nl_socket_free(sock);
        return 0;
}
