#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <openssl/x509.h>
#include "tb_communications.h"
#include "tb_connector.h"

static struct nla_policy tb_policy[TRUSTBASE_A_MAX + 1] = {
        [TRUSTBASE_A_CERTCHAIN] = { .type = NLA_UNSPEC },
	[TRUSTBASE_A_HOSTNAME] = { .type = NLA_STRING },
        [TRUSTBASE_A_PORTNUMBER] = { .type = NLA_U16 },
	[TRUSTBASE_A_RESULT] = { .type = NLA_U32 },
        [TRUSTBASE_A_STATE_PTR] = { .type = NLA_U64 },
};

static int family;
struct nl_sock* netlink_sock;
int last_response;

#define CERT_LENGTH_FIELD_SIZE	3

int recv_response_cb(struct nl_msg *msg, void *arg);

int send_query_openssl(uint64_t id, char* host, int port, STACK_OF(X509)* chain) {
	unsigned char* asn1_chain;
	unsigned char* cur_ptr;
	size_t asn1_chain_length;
	X509* cur_cert;
	unsigned int* cert_lengths;
	int i;
	int num_certs;
	int ret;

	num_certs = sk_X509_num(chain);
	asn1_chain_length = 0;
	cert_lengths = (unsigned int*)malloc(sizeof(unsigned int) * num_certs);
	for (i = 0; i < num_certs; i++) {
		cur_cert = sk_X509_value(chain, i);
		cert_lengths[i] = i2d_X509(cur_cert, NULL);
		asn1_chain_length += cert_lengths[i] + CERT_LENGTH_FIELD_SIZE;
	}

	asn1_chain = (unsigned char*)OPENSSL_malloc(asn1_chain_length);
	cur_ptr = asn1_chain;

	for (i = 0; i < num_certs; i++) {
		cur_cert = sk_X509_value(chain, i);
		// Convert to 24-bit big endian number
		cur_ptr[0] = (cert_lengths[i] >> 16) & 0xFF;
		cur_ptr[1] = (cert_lengths[i] >> 8) & 0xFF;
		cur_ptr[2] = cert_lengths[i] & 0xFF;
		cur_ptr += CERT_LENGTH_FIELD_SIZE;

		// Convert X509* to byte array
		i2d_X509(cur_cert, &cur_ptr);
		
	}

	ret = send_query(id, host, port, asn1_chain, asn1_chain_length);

	free(cert_lengths);
	OPENSSL_free(asn1_chain);
	return ret;
}


int send_query(uint64_t id, char* host, int port, unsigned char* chain, int length) {
	int rc;
	struct nl_msg* msg;
	void* msg_head;
	msg = nlmsg_alloc();
	
	if (msg == NULL) {
		fprintf(stderr, "failed to allocate message buffer\n");
		return -1;
	}
	msg_head = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 0, TRUSTBASE_C_QUERY_NATIVE, 1);
	if (msg_head == NULL) {
		fprintf(stderr, "failed in genlmsg_put\n");
		return -1;
	}
	rc = nla_put_u64(msg, TRUSTBASE_A_STATE_PTR, id);
	if (rc != 0) {
		fprintf(stderr, "failed to insert request ID\n");
		return -1;
	}
	rc = nla_put(msg, TRUSTBASE_A_CERTCHAIN, length, chain);
	if (rc != 0) {
		fprintf(stderr, "failed to insert chain data\n");
		return -1;
	}
	rc = nla_put_u16(msg, TRUSTBASE_A_PORTNUMBER, port);
	if (rc != 0) {
		fprintf(stderr, "failed in nla_put_u16 (port number)\n");
		return -1;
	}
	rc = nla_put_string(msg, TRUSTBASE_A_HOSTNAME, host);
	if (rc != 0) {
		fprintf(stderr, "failed in nla_put_string (host)\n");
		return -1;
	}
	nl_socket_set_peer_port(netlink_sock, 100);
	rc = nl_send_auto(netlink_sock, msg);
	if (rc < 0) {
		fprintf(stderr, "failed in nl send with error code %d\n", rc);
		return -1;
	}
	return 0;	
}

int recv_response(void) {
	if (nl_recvmsgs_default(netlink_sock) < 0) {
		printf("Failed to receieve message\n");
	}
	return last_response;
}

int recv_response_cb(struct nl_msg *msg, void *arg) {
	struct nlmsghdr* nlh;
	struct genlmsghdr* gnlh;
	struct nlattr* attrs[TRUSTBASE_A_MAX + 1];
	uint64_t id;
	uint32_t result;
	

	// Get Message
	nlh = nlmsg_hdr(msg);
	gnlh = (struct genlmsghdr*)nlmsg_data(nlh);
	genlmsg_parse(nlh, 0, attrs, TRUSTBASE_A_MAX, tb_policy);
	switch (gnlh->cmd) {
		case TRUSTBASE_C_RESPONSE:
			/* Get message fields */
			id = nla_get_u64(attrs[TRUSTBASE_A_STATE_PTR]);
			result = nla_get_u32(attrs[TRUSTBASE_A_RESULT]);
			last_response = result;
			break;
		default:
			printf("Received unanticipated response\n");
			break;
	}
	return 0;
}

int trustbase_connect(void) {
	int group;
	netlink_sock = nl_socket_alloc();
	nl_socket_set_local_port(netlink_sock, 0);
	//printf("native lib has PID %u", nl_socket_get_local_port(netlink_sock));
	//printf("native lib peer has PID %u", nl_socket_get_peer_port(netlink_sock));
	nl_socket_disable_seq_check(netlink_sock);
	nl_socket_modify_cb(netlink_sock, NL_CB_VALID, NL_CB_CUSTOM, recv_response_cb, (void*)netlink_sock);
	if (netlink_sock == NULL) {
		fprintf(stderr, "Failed to allocate socket\n");
		return -1;
	}
	if (genl_connect(netlink_sock) != 0) {
		fprintf(stderr, "Failed to connect to Generic Netlink control\n");
		return -1;
	}
	
	if ((family = genl_ctrl_resolve(netlink_sock, "TRUSTBASE")) < 0) {
		fprintf(stderr, "Failed to resolve TRUSTBASE family identifier\n");
		return -1;
	}

	if ((group = genl_ctrl_resolve_grp(netlink_sock, "TRUSTBASE", "query")) < 0) {
		fprintf(stderr, "Failed to resolve group identifier\n");
		return -1;
	}

	if (nl_socket_add_membership(netlink_sock, group) < 0) {
		fprintf(stderr, "Failed to add membership to group\n");
		return -1;
	}
	return 0;
}

int trustbase_disconnect(void) {
	nl_socket_free(netlink_sock);
	return 0;
}

