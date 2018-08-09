#include <stdio.h>
#include <gcrypt.h>

#include "baseencode.h"
#include "otp.h"

#define DIGITS 8
#define PERIOD 30
#define SHA1 GCRY_MD_SHA1
#define SHA256 GCRY_MD_SHA256
#define SHA512 GCRY_MD_SHA512

char* generate_totp() {
    cotp_error_t err;
    char* totp = NULL;
    const char *secret = "123456789012345678905465413546513541651966543216543543212";

    baseencode_error_t base_err;
    char *secret_base32 = base32_encode(secret, strlen(secret)+1, &base_err);
    totp = get_totp(secret_base32, DIGITS, PERIOD, SHA256, &err);

    free(secret_base32);
    return totp;
}

char* validate_totp(char* key, char* totp, char* crypto) {
    printf("Validate Otp Not implemented\n");
    //int is_valid = totp_verify(secret_base32, user_totp, DIGITS, PERIOD, SHA256);
    return NULL;
}

