#include <stdio.h>
#include "../../twilio.h"

int main(int argC, char** argV) {
    char response[100];
    int success = twilio_send_message("9737273220", "Test Message", response);
    printf("%s:response: %s\n", success==0?"Success":"Failure", response);
    return 0;
}

