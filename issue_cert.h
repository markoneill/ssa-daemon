#ifndef ISSUE_CERT_H
#define ISSUE_CERT_H

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
