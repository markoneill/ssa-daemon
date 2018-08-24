#ifndef TOTP_H
#define TOTP_H

#define EMAIL_TOTP_LENGTH ((int)6)
#define PHONE_TOTP_LENGTH ((int)8)

typedef struct totps {
    char *access_code_phone;
    char *access_code_email;
    char *email_totp;
    char *phone_totp;
} totps_t;

totps_t* generate_totp();
char* validate_totp(char* key, char* totp, int length);

void free_totps(totps_t *totps);

#endif /* TOTP_H */
