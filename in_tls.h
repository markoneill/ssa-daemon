#ifndef IN_TLS
#define IN_TLS

/* Protocol */
#define IPPROTO_TLS 	(715 % 255)

/* Options */
#define TCP_REMOTE_HOSTNAME               85
#define TCP_HOSTNAME                      86
#define TCP_TRUSTED_PEER_CERTIFICATES     87
#define TCP_CERTIFICATE_CHAIN             88
#define TCP_PRIVATE_KEY                   89
#define TCP_ALPN                          90
#define TCP_SESSION_TTL                   91
#define TCP_DISABLE_CIPHER                92
#define TCP_PEER_IDENTITY		 93
#define TCP_REQUEST_PEER_AUTH		 94

/* Internal use only */
#define TCP_PEER_CERTIFICATE              95
#define TCP_ID                            96

/* TCP options */
#define TCP_UPGRADE_TLS         33

/* Address types */
#define AF_HOSTNAME	43

struct host_addr { 
	unsigned char name[255]; 
}; 
 
struct sockaddr_host { 
	sa_family_t sin_family; 
	unsigned short sin_port; 
	struct host_addr sin_addr; 
}; 


#endif
