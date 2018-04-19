#ifndef _TB_COMMUNICATIONS_H
#define _TB_COMMUNICATIONS_H

struct handler_state_t;

int tb_register_netlink(void);
void tb_unregister_netlink(void);
int tb_send_certificate_query(struct handler_state_t* state, unsigned char* certificate, size_t length);
int tb_send_is_starttls_query(struct handler_state_t* state);
int tb_send_shutdown(void);
//int tb_get_certificate_response(void);

// Attributes
enum {
	TRUSTBASE_A_UNSPEC,
	TRUSTBASE_A_CERTCHAIN,
	TRUSTBASE_A_HOSTNAME,
	TRUSTBASE_A_CLIENT_HELLO,
	TRUSTBASE_A_SERVER_HELLO,
	TRUSTBASE_A_IP,
	TRUSTBASE_A_PORTNUMBER,
	TRUSTBASE_A_RESULT,
	TRUSTBASE_A_STATE_PTR,
	TRUSTBASE_A_PAD,
	__TRUSTBASE_A_MAX,
};

#define TRUSTBASE_A_MAX	(__TRUSTBASE_A_MAX - 1)

// Operations
enum {
	TRUSTBASE_C_UNSPEC,
	TRUSTBASE_C_QUERY,
	TRUSTBASE_C_QUERY_NATIVE,
	TRUSTBASE_C_RESPONSE,
	TRUSTBASE_C_SHUTDOWN,
	TRUSTBASE_C_SHOULDTLS,
	__TRUSTBASE_C_MAX,
};

#define TRUSTBASE_C_MAX	(__TRUSTBASE_C_MAX - 1)

// Multicast group
enum trustbase_groups {
	TRUSTBASE_QUERY,
};


#endif
