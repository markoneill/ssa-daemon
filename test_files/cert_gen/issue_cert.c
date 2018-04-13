#include <stdio.h>
#include <stdlib.h>


#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#include <openssl/bio.h>


X509_REQ* get_csr_from_buf(char* buffer);
X509* get_cert_from_file(char* filename);
EVP_PKEY* get_private_key_from_file(char* filename);
X509* issue_certificate(X509_REQ* cert_req, X509* ca_cert, EVP_PKEY* ca_key,
		int serial, int days);
int add_ext(X509* cert, int nid, char* value);


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

int main(int argc, char* argv[]) {
	X509* new_cert;
	X509* ca_cert;
	EVP_PKEY* ca_key;
	X509_REQ* cert_req;

	cert_req = get_csr_from_buf(req_buf);
	if (cert_req == NULL) {
		printf("Error parsing CSR\n");
		return 1;
	}
	ca_cert = get_cert_from_file("../certificate_ca.pem");
	if (ca_cert == NULL) {
		printf("Error loading CA cert\n");
		return 1;
	}
	ca_key = get_private_key_from_file("../key_ca.pem");
	if (ca_key == NULL) {
		printf("Error loading CA key\n");
		return 1;
	}
	new_cert = issue_certificate(cert_req, ca_cert, ca_key, 0, 365);
	if (new_cert == NULL) {
		printf("Certificate issuance failed\n");
		return 1;
	}

	PEM_write_X509(stdout, new_cert);
	       	
	/* Free data from CSR */
	X509_REQ_free(cert_req);
	X509_free(new_cert);

	/* Free CA data */
	X509_free(ca_cert);
	EVP_PKEY_free(ca_key);
	ENGINE_cleanup();
	return 0;
}

/* buffer must be null-terminated */
X509_REQ* get_csr_from_buf(char* buffer) {
	BIO* req_bio;
	X509_REQ* cert_req;
	req_bio = BIO_new_mem_buf(buffer, -1);
	if (req_bio == NULL) {
		return NULL;
	}
	cert_req = PEM_read_bio_X509_REQ(req_bio, NULL, NULL, NULL);
	if (cert_req == NULL) {
		BIO_free_all(req_bio);
		return NULL;
	}
	BIO_free_all(req_bio);
	return cert_req;
}

X509* get_cert_from_file(char* filename) {
	X509* cert;
	FILE* cert_file;
	cert_file = fopen(filename, "r");
	if (cert_file == NULL) {
		return NULL;
	}

	cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
	if (cert == NULL) {
		fclose(cert_file);
		return NULL;
	}
	fclose(cert_file);
	return cert;
}

EVP_PKEY* get_private_key_from_file(char* filename) {
	EVP_PKEY* key;
	FILE* key_file;
	key_file = fopen(filename, "r");
	if (key_file == NULL) {
		return NULL;
	}

	key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
	if (key == NULL) {
		fclose(key_file);
		return NULL;
	}
	fclose(key_file);
	return key;
}

X509* issue_certificate(X509_REQ* cert_req, X509* ca_cert, EVP_PKEY* ca_key,
		int serial, int days) {
	X509* new_cert;
	X509_NAME* name;
	EVP_PKEY* req_pub_key;
	new_cert = X509_new();
	STACK_OF(X509_EXTENSION)* exts;
	int ext_loc;
	if (new_cert == NULL) {
		return NULL;
	}

	/* Version */
	X509_set_version(new_cert, 2);
	/* Serial Number */
	ASN1_INTEGER_set(X509_get_serialNumber(new_cert), serial);
	/* Validity dates */
	X509_gmtime_adj(X509_get_notBefore(new_cert), 0);
	X509_gmtime_adj(X509_get_notAfter(new_cert), (long)60 * 60 * 24 * days);

	/* Subject */
	if ((name = X509_REQ_get_subject_name(cert_req)) == NULL) {
		return NULL;
	}
	if (X509_set_subject_name(new_cert, name) != 1) {
		return NULL;
	}

	/* Issuer */
	if ((name = X509_get_subject_name(ca_cert)) == NULL) {
		return NULL;
	}
	if (X509_set_issuer_name(new_cert, name) != 1) {
		return NULL;
	}

	/* Public key */
	req_pub_key = X509_REQ_get0_pubkey(cert_req);
	if (req_pub_key == NULL) {
		return NULL;
	}
	if (X509_REQ_verify(cert_req, req_pub_key) != 1) {
		return NULL;
	}
	if (X509_set_pubkey(new_cert, req_pub_key) != 1) {
		return NULL;
	}

	/* Extensions */
	exts = X509_REQ_get_extensions(cert_req);

	/* SAN */
	ext_loc = X509v3_get_ext_by_NID(exts, NID_subject_alt_name, -1);
	if (ext_loc != -1) {
		X509_add_ext(new_cert, X509v3_get_ext(exts, ext_loc), -1);
	}
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);


	/* Basic constraints */
	add_ext(new_cert, NID_basic_constraints, "critical,CA:FALSE");

	/* Key Usage */
	add_ext(new_cert, NID_key_usage, "critical,digitalSignature,keyEncipherment");

	/* Signature */
	if (X509_sign(new_cert, ca_key, EVP_sha256()) == 0) {
		return NULL;
	}

	return new_cert;

}

int add_ext(X509* cert, int nid, char* value) {
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (ex == NULL) {
		return 0;
	}
	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}

