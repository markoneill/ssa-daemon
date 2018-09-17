
#define PASS 1
#define FAIL 0

#define MAX_TITLE_LENGTH 60
#define RESULT_POSITION 65
#define PASSED_TEST "\x1B[32mPASSED\x1B[0m" 
#define FAILED_TEST "\x1B[31mFAILED\x1B[0m"
#define BUFFER_SIZE	100
#define WINDOW_SIZE	80

typedef int (*test_funct_t)(void);
typedef struct {
	test_funct_t func;
	char* name;
}test_t;

void run_tests(char* title, test_t* tests, size_t num_tests);
