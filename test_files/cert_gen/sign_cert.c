#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#define CERT_START "-----BEGIN CERTIFICATE-----"

char example_cert[] = "-----BEGIN CERTIFICATE REQUEST-----\n"
					"MIIDMzCCAhsCAQAwfDELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxDjAMBgNV\n"
					"BAcMBVByb3ZvMRQwEgYDVQQKDAtVUyBDaXRpemVuczEWMBQGA1UEAwwNVGFubmVy\n"
					"IFBlcmR1ZTEgMB4GCSqGSIb3DQEJARYRdGFubmVyQHRhbm5lci5jb20wggEiMA0G\n"
					"CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBitlwHJNS/ns3WPtz4MponRFbPP1U\n"
					"gZTV7lPbTlC3zTzHNV/q5LIsY7m49f1cpJlikAbkiqXSIbfu674S83XNNutT60aV\n"
					"zX0Suj4BJQx8qIBiwLhAsM9JGxG/8B/Nxeup0ZJ0omijPnIHNYJJZwrSHF3h95vm\n"
					"30qUKenxmmWRqWqNmOPl9w9dxHHgQRnsYuA8ErBN355wT0W7IfTex4X3irDe+pPY\n"
					"66p2+1R9oYNxns41OG5FHJ6gc3IbBLG9UB7xqykw8EoPM6lRRVO5cp9Oy7NA8YiC\n"
					"H4y9O197v90nocVSdzdX+z4gpxnsmR1VVGIdTJGOBfqWImwsQOd/xsNbAgMBAAGg\n"
					"cjBwBgkqhkiG9w0BCQ4xYzBhMB0GA1UdDgQWBBSuhUW0yYXwEEDfawCrQYpA7y7p\n"
					"+jAJBgNVHRMEAjAAMAsGA1UdDwQEAwIFoDAoBglghkgBhvhCAQ0EGxYZU1NBIEdl\n"
					"bmVyYXRlZCBDZXJ0aWZpY2F0ZTANBgkqhkiG9w0BAQsFAAOCAQEAD2CeUUWDUKK4\n"
					"LKE2wlaw6IG4CuWh8ZGUBv7onx3Pkgk3Pjv9Y7Ak9CDnfgEQ4duc3UpPtFl+B04E\n"
					"dQL0W+ls3HIS0q6DREOoj99UCNWtRtCRhtrC/089b+ub4BmJsrOGcegNHb2KG0Pp\n"
					"rWoUzKxbgu8uueX2R4PfeAfrw87jjDz4GpJIEmNDk9E4eI79c4AhBIl6bP2tqh9h\n"
					"ttJE8TJ+YmG060j80pzZxdT/4w4Nh5SY8E8uDEftFb6hvGTmjg3JlZLgAiMKRVkJ\n"
					"S0wJKPX1Rt+Rpuz3aBn0mv/eOHPeVGjtg5zC4eVjibi8CD2f60ROfVejQPbQ5cAZ\n"
					"SMN9ZQ9TRA==\n"
					"-----END CERTIFICATE REQUEST-----\n";



int read_cert(char* cert_file, char** cert) {
	long file_size;
	size_t cert_size;
	FILE *fp = fopen(cert_file, "r");
	char * hold;

	if (fp != NULL) {

		if (fseek(fp, 0L, SEEK_END) == 0) {

			file_size = ftell(fp);
			if (file_size == -1) {
				printf("file_size\n");
				*cert = NULL;
				return 0;
			}

			*cert = malloc(sizeof(char) * (file_size + 50));

			if (fseek(fp, 0L, SEEK_SET) != 0) {
				printf("file_size\n");
				free(*cert);
				*cert = NULL;
				return 0;
			}

			cert_size = fread(*cert, sizeof(char), file_size, fp);
			if (ferror( fp ) != 0) {
				printf("file_size\n");
				free(*cert);
				*cert = NULL;
				return 0;
			} 
			else {
				hold = *cert;
				hold[cert_size++] = '\0';
			}
		}
		fclose(fp);
	}

	return 1;
}


int write_cert(char* csr_file, char* csr)
{
	FILE* fp = fopen(csr_file,"wb");

	if (fp){
		fwrite(csr, sizeof(char), strlen(csr), fp);
	}
	else{
		printf("Something wrong writing to File.");
		return 0;
	}

	fclose(fp);
	return 0;
}

int main(void) {
	pid_t childpid;
	int status;
	char cert_file[] = "personal.crt";
	char tmp_csr[] = "tmp.csr";
	char* full_cert;
	char* cert_encoded;

	// write the cert we care about to disk
	if(write_cert(tmp_csr,example_cert)) {
		printf("Unable to write CSR to disk\n");
		return -1;
	}


	int dev_null_fd = open("/dev/null", O_RDWR);
  	if (dev_null_fd < 0) perror("Unable to open /dev/null");

	if((childpid = fork()) == -1) {
		perror("fork");
		exit(1);
	}

	if(childpid == 0) {
		dup2(dev_null_fd, 1);
		dup2(dev_null_fd, 2);

		execlp("openssl","openssl","ca","-config","openssl-ca.cnf","-batch","-policy","signing_policy",
			"-extensions","signing_req","-out",cert_file,"-infiles",tmp_csr,NULL);
		// execlp("./test","./test",NULL);
 		exit(-1);
	}
	
	if (waitpid(childpid, &status, 0) > 0) {

		if (WIFEXITED(status) && !WEXITSTATUS(status)) {
			// Finished successfully
			//printf("Success\n");
			// return 1;

		}

		else if (WIFEXITED(status) && WEXITSTATUS(status)) {
			if (WEXITSTATUS(status) == 127) {
			// execv failed
			printf("execv failed\n");
		}
		else
			printf("program terminated normally,"
			" but returned a non-zero status\n");                
	}
	else
		printf("program didn't terminate normally\n");            
	} 
	else {
		printf("waitpid() failed\n");
	}

	if(!read_cert(cert_file,&full_cert)) {
		printf("Unable to read generated cert\n");
		return 1;
	}
	else {
		cert_encoded = strstr(full_cert,CERT_START);
		printf("%s\n", cert_encoded);
		free(full_cert);
	}		

	// delete generated cert file
	if (unlink(cert_file))
	{
		printf("Unable to remove singed cert file %s\n",cert_file );
		return 1;
	}
	// delete csr request
	if (unlink(tmp_csr))
	{
		printf("Unable to remove csr request file %s\n",tmp_csr );
		return 1;
	}

	return(0);
}