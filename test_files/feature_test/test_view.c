#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include "test_view.h"

void run_tests(char* title, test_t* tests, size_t num_tests) {
	char buf[BUFFER_SIZE];
	char border[BUFFER_SIZE];
	int ret;
	int i;
	int len;
	int passed_tests = 0;
	
	len = strlen(title);
	if ( len >  MAX_TITLE_LENGTH) {
		len =  MAX_TITLE_LENGTH;
	}
	memset(border,'*',WINDOW_SIZE);	
	border[WINDOW_SIZE] = '\0';
	snprintf(buf,len+3, "* %s",title);
	memset(&buf[len+2],' ',WINDOW_SIZE-len);
	strcpy(&buf[WINDOW_SIZE-1],"*");
	printf("\n%s\n",border);
	printf("%s\n",buf);
	printf("%s\n",border);
	for (i = 0 ; i < num_tests ; i++ ){
		ret = (*tests[i].func)();
		len = strlen(tests[i].name);	
		if (len >  MAX_TITLE_LENGTH) {
			len =  MAX_TITLE_LENGTH;
		}
		snprintf(buf,len+1,"%s",tests[i].name);
		memset(&buf[len],'.',RESULT_POSITION-len);
		strcpy(&buf[RESULT_POSITION],ret ? PASSED_TEST :FAILED_TEST);
		printf("%s\n", buf);
		passed_tests+= ret;
	}
	memset(border,'_',WINDOW_SIZE);	
	printf("%s\n",border);
	
	memset(buf,' ',RESULT_POSITION);
	if ( passed_tests == num_tests){
		sprintf(&buf[RESULT_POSITION-4],"\x1B[32mALL TESTS PASSED\x1B[0m");
	} else {
		sprintf(&buf[RESULT_POSITION-4],"\x1B[33mPASSED %d/%ld TESTS\x1B[0m",passed_tests,num_tests);	
	}

	printf("%s\n\n", buf);
}
