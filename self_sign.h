#ifndef SELF_SIGN_H
#define SELF_SIGN_H

int generate_rsa_key(EVP_PKEY** key_out, int bits);
X509* generate_self_signed_certificate(EVP_PKEY* key, int serial, int days);

#endif
