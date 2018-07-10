#ifndef TOTP_H
#define TOTP_H

char* generate_totp(char* key, char* time, char* return_digits, char* crypto);
char* validate_totp(char* key, char* totp);

#endif /* TOTP_H */
