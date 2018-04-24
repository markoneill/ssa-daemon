#ifndef ISSUE_CERT_H
#define ISSUE_CERT_H

char req_buf[] =
"-----BEGIN CERTIFICATE REQUEST-----\n\
MIICtjCCAZ4CAQIwODELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCVRydXN0QmFzZTEV\n\
MBMGA1UEAwwMTWFyayBPJ05laWxsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n\
CgKCAQEAxJHMm6BT3ioPmNDR7R/r+DTRaTb+mvVt8uj26J8GB7k9UHEDKtctX+Jh\n\
qtsIe5UYHI+Lz506TlVaXkn+dtqS2uj+fYu1Owz6YoeStHYQAJetfTIcE8xCfnRW\n\
sXntqfLtOGarT+DxWvl8TweYhJ2PRM9PDyiMvrOGJZV1KOReAIXTaavAWfMcLXGX\n\
drpHlhcJkD7rGlUi0ZgS63vtmHWxw3s0kUWGDqyHln51Q+Gx9IEp9pwZZS5CbVsL\n\
SF/FxeoC9pK9oHmPys4uYbVE9Mpr5cjCw8H+IUcTRQnMb/w6ReSs2Rmi+y0JhHRV\n\
IQEt5jdSbdMkNX5N4ckuNsT9VioFnQIDAQABoDkwNwYJKoZIhvcNAQkOMSowKDAO\n\
BgNVHQ8BAf8EBAMCBaAwFgYDVR0RBA8wDYELbXRvQGJ5dS5lZHUwDQYJKoZIhvcN\n\
AQELBQADggEBABv21IU4M2LPRVT8yzwObaMJQpJCkvIaHJY1Dk4vhhQn6Ix9o/6L\n\
yZQ4cZeTtuVsul+/06pnJBe/0/vHp3ENoMm1gYo0JoY8s3uPG9oHmumPbjXOqSmG\n\
u2zL8S2hxrHx9K9LEDjsXaFA4UlK5edFV4sIBraxu8R/+Z1n0xwGgqAWiWHSJKIw\n\
AEv65D2z0K5847xXUQfeGFru7oRrExbvMZS/Ud6nb7Lppxrl0ZyTbN+6CmQU7wK+\n\
jWmfDNEvebB5wl6eytDDEv41nD4gJ/7qKNltIbVbAtk0J5x94tM7ulBOl+FQxPW3\n\
3hJd+iRbFGOnHGB8WrmjjaiVbuvPxiNXfDs=\n\
-----END CERTIFICATE REQUEST-----";

unsigned char* net_encode_cert(X509* cert, int* len);
X509* net_decode_cert(unsigned char* cert_buf,int len);
char *X509_to_PEM(X509 *cert, int* bio_len);
X509 *PEM_to_X509(char *pem);
X509_REQ* get_csr_from_buf(char* buffer);
X509* get_cert_from_file(char* filename);
EVP_PKEY* get_private_key_from_file(char* filename);
X509* issue_certificate(X509_REQ* cert_req, X509* ca_cert, EVP_PKEY* ca_key,
		int serial, int days);
int add_ext(X509* cert, int nid, char* value);

#endif /*ISSUE_CERT_H*/
