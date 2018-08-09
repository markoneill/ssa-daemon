#ifndef TOTP_H
#define TOTP_H

char* generate_totp();
char* validate_totp(char* key, char* totp);

#endif /* TOTP_H */
