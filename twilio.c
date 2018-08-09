#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>

#define MAX_MSG_LEN 1600

/**
 * Only a return value of 0 signals that there were no errors.
 */
int twilio_send_message(char* to_number, char* msg, const char* error) {
    // message is over the max length
    if (strlen(msg) > 1600)  {
        printf("Twilio: Invalid Message length.\n");
        return 1;
    }

    char* ACCOUNT_SID = getenv("TWILIO_ACCOUNT_SID");
    char* AUTH_TOKEN = getenv("TWILIO_AUTH_TOKEN");
    char* TWILIO_NUMBER = getenv("TWILIO_FROM_NUMBER");
    if (ACCOUNT_SID == NULL || AUTH_TOKEN == NULL || TWILIO_NUMBER == NULL) {
        printf("Twilio: Could not load twilio credentials from environment.\n");
        return 1;
    }
    printf("SID: %s AUTHTOKEN %s NUML: %s\n", ACCOUNT_SID, AUTH_TOKEN, TWILIO_NUMBER);

    curl_global_init(CURL_GLOBAL_ALL);
    CURL* curl = curl_easy_init();
    if (!curl) {
        printf("Twilio: Error initializing cURL.\n");
        return 1;
    }

    curl_easy_setopt (curl, CURLOPT_VERBOSE, 0L);
    char* message_body_escaped = curl_easy_escape(curl, msg, 0);

    char url[100];
    int chars_copied = sprintf(url, "https://api.twilio.com/2010-04-01/Accounts/%s/Messages", ACCOUNT_SID);

    if (chars_copied <= 0)  {
        printf("Twilio: Error creating twilio request url.\n");
        return 1;
    }

    char query_params[MAX_MSG_LEN + 100];
    int params_copied = sprintf(query_params, "To=%s&From=%s&Body=%s", to_number, TWILIO_NUMBER, message_body_escaped);

    if (params_copied <= 0) {
        // verify the amount of parameters copied
        printf("Twilio: Error creating twilio request url.\n");
        return 1;
    }

    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query_params);
    curl_easy_setopt(curl, CURLOPT_USERNAME, ACCOUNT_SID);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, AUTH_TOKEN);

    CURLcode res = curl_easy_perform(curl);
    curl_free(message_body_escaped);
    curl_easy_cleanup(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (res != CURLE_OK) {
        error = curl_easy_strerror(res);
        return 1;
    } else if (http_code != 200 && http_code != 201) {
        printf("Twilio: Error %li sending sms to %s\n", http_code, to_number);
        return 1;
    } else {
        printf("Twilio: Success sending sms to %s\n", to_number);
        return 0;
    }
}

