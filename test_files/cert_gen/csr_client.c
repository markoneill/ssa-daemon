#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#include <openssl/bio.h>

#include "../../in_tls.h"

#define DEFAULT_ADDR    "localhost"
#define DEFAULT_PORT    "8040"
#define FAIL_MSG "SIGNING REQUEST FAILED"

char example_csr[] = "-----BEGIN CERTIFICATE REQUEST-----\n"
					"MIIDMzCCAhsCAQAwfDELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxDjAMBgNV\n"
					"BAcMBVByb3ZvMRQwEgYDVQQKDAtVUyBDaXRpemVuczEWMBQGA1UEAwwNVGFubmVy\n"
					"IFBlcmR1ZTEgMB4GCSqGSIb3DQEJARYRdGFubmVyQHRhbm5lci5jb20wggEiMA0G\n"
					"CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBitlwHJNS/ns3WPtz4MponRFbPP1U\n"
					"gZTV7lPbTlC3zTzHNV/q5LIsY7m49f1cpJlikAbkiqXSIbfu674S83XNNutT60aV\n"
					"zX0Suj4BJQx8qIBiwLhAsM9JGxG/8B/Nxeup0ZJ0omijPnIHNYJJZwrSHF3h95vm\n"
					"30qUKenxmmWRqWqNmOPl9w9dxHHgQRnsYuA8ErBN355wT0W7IfTex4X3irDe+pPY\n"
					"66p2+1R9oYNxns41OG5FHJ6gc3IbBLG9UB7xqykw8EoPM6lRRVO5cp9Oy7NA8YiC\n"
					"H4y9O197v90nocVSdzdX+z4gpxnsmR1VVGIdTJGOBfqWImwsQOd/xsNbAgMBAAGg\n"
					"cjBwBgkqhkiG9w0BCQ4xYzBhMB0GA1UdDgQWBBSuhUW0yYXwEEDfawCrQYpA7y7p\n"
					"+jAJBgNVHRMEAjAAMAsGA1UdDwQEAwIFoDAoBglghkgBhvhCAQ0EGxYZU1NBIEdl\n"
					"bmVyYXRlZCBDZXJ0aWZpY2F0ZTANBgkqhkiG9w0BAQsFAAOCAQEAD2CeUUWDUKK4\n"
					"LKE2wlaw6IG4CuWh8ZGUBv7onx3Pkgk3Pjv9Y7Ak9CDnfgEQ4duc3UpPtFl+B04E\n"
					"dQL0W+ls3HIS0q6DREOoj99UCNWtRtCRhtrC/089b+ub4BmJsrOGcegNHb2KG0Pp\n"
					"rWoUzKxbgu8uueX2R4PfeAfrw87jjDz4GpJIEmNDk9E4eI79c4AhBIl6bP2tqh9h\n"
					"ttJE8TJ+YmG060j80pzZxdT/4w4Nh5SY8E8uDEftFb6hvGTmjg3JlZLgAiMKRVkJ\n"
					"S0wJKPX1Rt+Rpuz3aBn0mv/eOHPeVGjtg5zC4eVjibi8CD2f60ROfVejQPbQ5cAZ\n"
					"SMN9ZQ9TRA==\n"
					"-----END CERTIFICATE REQUEST-----\n";


void usage(char* name);
int write_cert(char* cert_path, X509* cert);
int read_csr(char* csr_path, char** csr);
int validate_request(char* cert);
int send_request(int sock_fd, char* csr, int csr_len, unsigned char** cert);
int connect_to_host(char* host, char* service);
X509* net_decode_cert(unsigned char* cert_buf,int len);


int main(int argc, char* argv[]) {
	int sock_fd;
	int csr_len;
	int ret_size;
	unsigned char* cert = NULL;
	X509* decoded_cert;
	char* port = NULL;
	char* host = NULL;
	char* csr = NULL;
	char* csr_path = NULL;
	char* cert_path = NULL;
	int READ_CSR = 0;
	int WRITE_CERT = 0;

	port = DEFAULT_PORT;
	host = DEFAULT_ADDR;
	csr = example_csr;
	csr_len = sizeof(example_csr);

	int c;
	while ((c = getopt(argc, argv, "np:h:c:o:")) != -1) {
		switch (c) {
			case 'p':
				port = optarg;
				break;
			case 'h':
				host = optarg;
				break;
			case 'c':
				csr_path = optarg;
				READ_CSR = 1;
				break;
			case 'o' :
				cert_path = optarg;
				WRITE_CERT = 1;
				break;
			case '?':
				if (optopt == 'p' || optopt == 'h' || optopt == 'c' || optopt == 'o' ) {
					fprintf(stderr, "Option -%c requires an argument\n", optopt);
					usage(argv[0]);
					exit(EXIT_FAILURE);
				}
			default:
				fprintf(stderr, "Unknown option encountered %c\n",c);
				usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if (READ_CSR) {
		csr_len = read_csr(csr_path,&csr);
		if(csr_len < 0) {
			fprintf(stderr, "Unable to read csr file\n");
			return -1;
		}
	}

	sock_fd = connect_to_host(host, port);

	ret_size = send_request(sock_fd,csr,csr_len,&cert);

	close(sock_fd);

	if(ret_size > 0 && !validate_request(cert)) {
		fprintf(stderr, "Server unable to validate certificate\n");
		free(csr);
		free(cert);
		exit(-1);
	}

	if (ret_size > 0) {
		decoded_cert = net_decode_cert(cert,ret_size);
		if (decoded_cert == NULL) {
			fprintf(stderr, "Unable unserialize cert\n");
			return -1;
		}

		if (WRITE_CERT && cert) {
			write_cert(cert_path, decoded_cert);
		}

		PEM_write_X509(stdout, decoded_cert);
		free(decoded_cert);
		free(cert);
	}


	if (READ_CSR) {
		free(csr);
	}
	
	return 0;
}

void usage(char* name) {
	printf("Usage: %s [-p port] [-h host] [-c csr_file] [-o out_file]\n", name);
	printf("Example:\n");
        printf("\t%s -h localhost -p 8040 -c my.csr -o my.crt \n", name);
	return;
}

int write_cert(char* cert_path, X509* cert) {
	FILE* fp = fopen(cert_path,"wb");

	if (fp){
		PEM_write_X509(fp,cert);
	}
	else{
		return 0;
	}

	fclose(fp);
	return 1;
}

int read_csr(char* csr_path, char** csr) {
	long file_size;
	size_t cert_size = -1;
	FILE *fp = fopen(csr_path, "r");
	char * hold;

	if (fp != NULL) {

		if (fseek(fp, 0L, SEEK_END) == 0) {

			file_size = ftell(fp);
			if (file_size == -1) {
				*csr = NULL;
				return -1;
			}

			*csr = malloc(sizeof(char) * (file_size + 50));

			if (fseek(fp, 0L, SEEK_SET) != 0) {
				free(*csr);
				*csr = NULL;
				return -1;
			}

			cert_size = fread(*csr, sizeof(char), file_size, fp);
			if (ferror( fp ) != 0) {
				
				free(*csr);
				*csr = NULL;
				return -1;
			} 
			else {
				hold = *csr;
				hold[cert_size++] = '\0';
			}
		}
		fclose(fp);
	}

	return cert_size;
}

int validate_request(char* cert) {
	//
	if(strcmp(cert,FAIL_MSG) == 0) {
		return 0;
	}
	// Other validations?

	return 1;
}

int send_request(int sock_fd, char* csr, int csr_len, unsigned char** cert) {
	
	// I should make this more dynamic
	char response[12288];
	size_t size = 0 ;

	if (send(sock_fd, csr, csr_len, 0) < 0) {
		*cert = NULL;
		perror("send");
		return -1;
	}

	size = recv(sock_fd, response, sizeof(response), 0);
	if (size == -1) {
		*cert = NULL;
		perror("recv");
		return -1;
	}

	*cert = malloc(size);
	memcpy(*cert,response,size);

	return size;
}

int connect_to_host(char* host, char* service) {
	int sock;
	int ret;
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	ret = getaddrinfo(host, service, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {

		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (sock == -1) {
			perror("socket");
			continue;
		}
		
		if (connect(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect");
			close(sock);
			continue;
		}

		break;
	}
	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "failed to find a suitable address for connection\n");
		exit(EXIT_FAILURE);
	}
	return sock;
}

X509* net_decode_cert(unsigned char* cert_buf,int len){
	unsigned char *p = cert_buf;
	return d2i_X509(NULL, (const unsigned char **)&p, len);
}