#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>

#define MAX_MSG_LEN 1600

int twilio_send_message(char* to_number, char* msg, const char* error) {
    // message is over the max length
    if (strlen(msg) > 1600)  {
        return 1;
        printf("Invalid Message length.");
    }

    char* ACCOUNT_SID = getenv("TWILIO_ACCOUNT_SID");
    char* AUTH_TOKEN = getenv("TWILIO_AUTH_TOKEN");
    char* TWILIO_NUMBER = getenv("TWILIO_FROM_NUMBER");

    curl_global_init(CURL_GLOBAL_ALL);
    CURL* curl = curl_easy_init();
    if (!curl) {
        printf("Error initializing cURL");
        return 1;
    }

    curl_easy_setopt (curl, CURLOPT_VERBOSE, 0L);
    char* message_body_escaped = curl_easy_escape(curl, msg, 0);

    char url[100];
    int chars_copied = sprintf(url, "https://api.twilio.com/2010-04-01/Accounts/%s/Messages", ACCOUNT_SID);

    if (chars_copied <= 0)  {
        printf("Error creating twilio request url.\n");
        return 1;
    }

    char query_params[MAX_MSG_LEN + 100];
    int params_copied = sprintf(query_params, "To=%s&From=%s&Body=%s", to_number, TWILIO_NUMBER, message_body_escaped);

    if (params_copied <= 0) {
        // verify the amount of parameters copied
        printf("Error creating twilio request url.");
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
        printf("Error %li sending sms to %s\n", http_code, to_number);
        return 1;
    } else {
        printf("Success sending sms to %s\n", to_number);
        return 0;
    }
}

