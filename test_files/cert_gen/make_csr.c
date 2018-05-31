#include <stdio.h>
#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>


int generate_rsa_key(EVP_PKEY** key_out, int bits);
int generate_cert_req(X509_REQ **req_out, EVP_PKEY **keypair_out, int bits, int serial, int days);
int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char* value);

int main(int argc, char* argv[]) {
	X509_REQ* req;
	EVP_PKEY* pkey;

	generate_cert_req(&req, &pkey, 2048, 0, 365);

	X509_REQ_print_fp(stdout, req);
	PEM_write_X509_REQ(stdout, req);

	if (X509_REQ_check_private_key(req, pkey) != 1) {
		printf("Private key does not match CSR\n");
	}
	else {
		printf("Private key matches CSR\n");
	}

	X509_REQ_free(req);
	EVP_PKEY_free(pkey);
	ENGINE_cleanup();
	CRYPTO_cleanup_all_ex_data();
	return 0;
}

int generate_rsa_key(EVP_PKEY** key_out, int bits) {
	unsigned long e;
	BIGNUM* bn_e;
	RSA* rsa;
	EVP_PKEY* keypair;

	e = RSA_F4;

	bn_e = BN_new();
	if (bn_e == NULL) {
		return 0;
	}
	if (BN_set_word(bn_e, e) != 1) {
		BN_free(bn_e);
		return 0;
	}

	rsa = RSA_new();
	if (rsa == NULL) {
		BN_free(bn_e);
		return 0;
	}
	
	if (RSA_generate_key_ex(rsa, bits, bn_e, NULL) != 1) {
		BN_free(bn_e);
		RSA_free(rsa);
		return 0;
	}

	keypair = EVP_PKEY_new();
	if (keypair == NULL) {
		RSA_free(rsa);
		BN_free(bn_e);
		return 0;
	}

	if (EVP_PKEY_assign_RSA(keypair, rsa) != 1) {
		RSA_free(rsa);
		BN_free(bn_e);
		return 0;
	}

	*key_out = keypair;
	/*RSA_free(rsa); // apparently this gets freed with the key */
	BN_free(bn_e);
	return 1;
}

int generate_cert_req(X509_REQ **req_out, EVP_PKEY **keypair_out, int bits, int serial, int days) {
	X509_REQ* cert_req;
	EVP_PKEY* keypair;
	X509_NAME* name;
	STACK_OF(X509_EXTENSION)* exts;

	if (generate_rsa_key(&keypair, bits) != 1) {
		return 0;
	}

	cert_req = X509_REQ_new();
	if (cert_req == NULL) {
		free(keypair);
		return 0;
	}

	
	if (X509_REQ_set_pubkey(cert_req, keypair) != 1) {
		free(keypair);
		return 0;
	}


	X509_REQ_set_version(cert_req, 2);
	//ASN1_INTEGER_set(X509_REQ_get_serialNumber(cert_req), serial);
	//X509_REQ_gmtime_adj(X509_REQ_get_notBefore(cert_req), 0);
	//X509_REQ_gmtime_adj(X509_REQ_get_notAfter(cert_req),(long)60 * 60 * 24 * days);*/

	name = X509_REQ_get_subject_name(cert_req);
	/* Country */
	if (X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
				"US", -1, -1, 0) != 1) {
		free(keypair);
		return 0;
	}
	/* Organization */
	if (X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
				"TrustBase", -1, -1, 0) != 1) {
		free(keypair);
		return 0;
	}
	/* Common Name */
	if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				"Mark O'Neill", -1, -1, 0) != 1) {
		free(keypair);
		return 0;
	}

	exts = sk_X509_EXTENSION_new_null();
	if (exts == NULL) {
		free(keypair);
		return 0;
	}

	/* Standard extenions */
	add_ext(exts, NID_key_usage, "critical,digitalSignature,keyEncipherment");

	/* This is a typical use for request extensions: requesting a value for
	 * subject alternative name.
	 */

	add_ext(exts, NID_subject_alt_name, "email:mto@byu.edu");

	X509_REQ_add_extensions(cert_req, exts);

	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	if (X509_REQ_sign(cert_req, keypair, EVP_sha256()) == 0) {
		free(keypair);
		return 0;
	}

	*req_out = cert_req;
	*keypair_out = keypair;
	return 1;
}



/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */

int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char* value) {
	X509_EXTENSION* ex;
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (ex == NULL) {
		return 0;
	}
	sk_X509_EXTENSION_push(sk, ex);

	return 1;
}

