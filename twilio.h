#include <curl/curl.h>

#ifndef TWILIO_H
#define TWILIO_H

int twilio_send_message(char* to_number, char* msg, char* response);

#endif /* TWILIO_H */


