/**
 *   Copyright(C) 2011-2015 Intel Corporation All Rights Reserved.
 *
 *   The source code, information  and  material ("Material") contained herein is
 *   owned  by Intel Corporation or its suppliers or licensors, and title to such
 *   Material remains  with Intel Corporation  or its suppliers or licensors. The
 *   Material  contains proprietary information  of  Intel or  its  suppliers and
 *   licensors. The  Material is protected by worldwide copyright laws and treaty
 *   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
 *   modified, published, uploaded, posted, transmitted, distributed or disclosed
 *   in any way  without Intel's  prior  express written  permission. No  license
 *   under  any patent, copyright  or  other intellectual property rights  in the
 *   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
 *   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
 *   intellectual  property  rights must  be express  and  approved  by  Intel in
 *   writing.
 *
 *   *Third Party trademarks are the property of their respective owners.
 *
 *   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
 *   this  notice or  any other notice embedded  in Materials by Intel or Intel's
 *   suppliers or licensors in any way.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#ifdef _MSC_VER
# include <Shlobj.h>
#else
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#endif

#define PORT 7891
#define BACKLOG 10
#define LOCALHOST "127.0.0.1"

#include "sgx_urts.h"
#include "sgx_status.h"
#include "App.h"
#include "Enclave_u.h"


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
	sgx_status_t err;
	const char *msg;
	const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] =
		{ { SGX_ERROR_UNEXPECTED, "Unexpected error occurred.",
		NULL }, { SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.",
		NULL }, { SGX_ERROR_OUT_OF_MEMORY, "Out of memory.",
		NULL }, { SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.",
				"Please refer to the sample \"PowerTransition\" for details." },
				{ SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.",
				NULL }, { SGX_ERROR_INVALID_ENCLAVE_ID,
						"Invalid enclave identification.",
						NULL }, { SGX_ERROR_INVALID_SIGNATURE,
						"Invalid enclave signature.",
						NULL }, { SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.",
				NULL },
				{ SGX_ERROR_NO_DEVICE, "Invalid SGX device.",
						"Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards." },
				{ SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.",
				NULL }, { SGX_ERROR_INVALID_METADATA,
						"Invalid enclave metadata.",
						NULL }, { SGX_ERROR_DEVICE_BUSY, "SGX device was busy.",
				NULL }, { SGX_ERROR_INVALID_VERSION,
						"Enclave version was invalid.",
						NULL }, { SGX_ERROR_INVALID_ATTRIBUTE,
						"Enclave was not authorized.",
						NULL }, { SGX_ERROR_ENCLAVE_FILE_ACCESS,
						"Can't open enclave file.",
						NULL }, };

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++) {
		if (ret == sgx_errlist[idx].err) {
			if (NULL != sgx_errlist[idx].sug)
				printf("Info: %s\n", sgx_errlist[idx].sug);
			printf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void) {
	char token_path[MAX_PATH] = { '\0' };
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	/* Step 1: retrive the launch token saved by last transaction */
#ifdef _MSC_VER
	/* try to get the token saved in CSIDL_LOCAL_APPDATA */
	if (S_OK != SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, token_path)) {
		strncpy_s(token_path, _countof(token_path), TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	} else {
		strncat_s(token_path, _countof(token_path), "\\" TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+2);
	}

	/* open the token file */
	HANDLE token_handler = CreateFileA(token_path, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
	if (token_handler == INVALID_HANDLE_VALUE) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	} else {
		/* read the token from saved file */
		DWORD read_num = 0;
		ReadFile(token_handler, token, sizeof(sgx_launch_token_t), &read_num, NULL);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}
#else /* __GNUC__ */
	/* try to get the token saved in $HOME */
	const char *home_dir = getpwuid(getuid())->pw_dir;

	if (home_dir != NULL
			&& (strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1)
					<= MAX_PATH) {
		/* compose the token path */
		strncpy(token_path, home_dir, strlen(home_dir));
		strncat(token_path, "/", strlen("/"));
		strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
	} else {
		/* if token path is too long or $HOME is NULL */
		strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}

	FILE *fp = fopen(token_path, "rb");
	if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n",
				token_path);
	}

	if (fp != NULL) {
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n",
					token_path);
		}
	}
#endif
	/* Step 2: call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
			&global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret);
#ifdef _MSC_VER
		if (token_handler != INVALID_HANDLE_VALUE)
		CloseHandle(token_handler);
#else
		if (fp != NULL)
			fclose(fp);
#endif
		return -1;
	}

	/* Step 3: save the launch token if it is updated */
#ifdef _MSC_VER
	if (updated == FALSE || token_handler == INVALID_HANDLE_VALUE) {
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (token_handler != INVALID_HANDLE_VALUE)
		CloseHandle(token_handler);
		return 0;
	}

	/* flush the file cache */
	FlushFileBuffers(token_handler);
	/* set access offset to the begin of the file */
	SetFilePointer(token_handler, 0, NULL, FILE_BEGIN);

	/* write back the token */
	DWORD write_num = 0;
	WriteFile(token_handler, token, sizeof(sgx_launch_token_t), &write_num, NULL);
	if (write_num != sizeof(sgx_launch_token_t))
	printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	CloseHandle(token_handler);
#else /* __GNUC__ */
	if (updated == FALSE || fp == NULL) {
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (fp != NULL)
			fclose(fp);
		return 0;
	}

	/* reopen the file with write capablity */
	fp = freopen(token_path, "wb", fp);
	if (fp == NULL)
		return 0;
	size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	fclose(fp);
#endif
	return 0;
}

#if defined(_MSC_VER)
/* query and enable SGX device*/
int query_sgx_status()
{
	sgx_device_status_t sgx_device_status;
	sgx_status_t sgx_ret = sgx_enable_device(&sgx_device_status);
	if (sgx_ret != SGX_SUCCESS) {
		printf("Failed to get SGX device status.\n");
		return -1;
	}
	else {
		switch (sgx_device_status) {
			case SGX_ENABLED:
			return 0;
			case SGX_DISABLED_REBOOT_REQUIRED:
			printf("SGX device has been enabled. Please reboot your machine.\n");
			return -1;
			case SGX_DISABLED_LEGACY_OS:
			printf("SGX device can't be enabled on an OS that doesn't support EFI interface.\n");
			return -1;
			case SGX_DISABLED:
			printf("SGX device not found.\n");
			return -1;
			default:
			printf("Unexpected error.\n");
			return -1;
		}
	}
}
#endif

/* OCall functions */
void ocall_print_string(const char *str) {
	/* Proxy/Bridge will check the length and null-terminate
	 * the input string to prevent buffer overflow.
	 */
	printf("%s", str);
}

/* Read config file data */

void ocall_read_config_data(const char * filename) {
	FILE * fp;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	fp = fopen(filename, "r");
	if (fp == NULL){
		printf("\nConfiguration file not found");
		exit(EXIT_FAILURE);
	}

	while ((read = getline(&line, &len, fp)) != -1) {
		printf("\n[CONFIG STRING-%zu]:%s", read, line);
		generate_config(global_eid, line, (int) read);
	}

	fclose(fp);
	if (line)
		free(line);
}


void ocall_read_log_messages(const char * filename) {
	FILE * fp;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	fp = fopen(filename, "r");
	if (fp == NULL)
		exit(EXIT_FAILURE);

	while ((read = getline(&line, &len, fp)) != -1) {
		printf("\n[LOG MESSAGE-%zu]:%s", read, line);
		process_log(global_eid, line);
	}

	fclose(fp);
	if (line)
		free(line);

}


void ocall_listen_log_messages(){
	  int printerSocket, newSocket, num;
	  char buffer[10241];
	  char stdinBuffer[1024];
	  struct sockaddr_in serverAddr;
	  struct sockaddr_storage serverStorage;
	  socklen_t addr_size;

	  // create socket
	  if ( (printerSocket = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
	      fprintf(stderr, "Welcome Socket failure!!\n");
	      exit(1);
	  }

	  // Configure: Address family = Internet, port number, IP address to localhost
	  serverAddr.sin_family = AF_INET;
	  serverAddr.sin_port = htons(PORT);
	  serverAddr.sin_addr.s_addr = inet_addr(LOCALHOST);

	  // Set all bits of the padding field to 0
	  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

	  // bind address to socket
	  if ((bind(printerSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr))) == -1) {
	        fprintf(stderr, "Binding Failure\n");
	        exit(1);
	  }

	  //////////////
	  // Behavior
	  //////////////

	  int count = 0;

	  while(1) {
	    count = count + 1;
	    if (count == 10) {
	      printf("Count has reached 3, exiting! Good bye!\n");
	      break;
	    }

	    // Keep listening before count reaches 3 or client requests for connection
	    if((listen(printerSocket, 1)) == 0) {
	      printf("Listening\n");
	    }
	    else {
	      printf("Error listening\n");
	    }

	    // accept to create new connection w/ client
	    addr_size = sizeof serverStorage;
	    if ( (newSocket = accept(printerSocket, (struct sockaddr *) &serverStorage, &addr_size)) == -1) {
	        perror("accept");
	        exit(1);
	    }
	    else {
	      printf("Server got connection from client \n");

	      // Keep receieving the messages from client per 1 second delay
	      while(1) {
	            if ((num = recv(newSocket, buffer, 10240, 0)) == -1) {
	                perror("recv");
	                exit(1);
	            }
	            else if (num == 0) {
	                // printf("Connection closed\n");
	                printf("Waiting for receiving \n");
	                sleep(1);
	                break;
	            }

	            buffer[num] = '\0';
	            printf("Message received: %s\n", buffer);
	            process_log(global_eid, buffer);
	            sleep(1);
	      }

	      close(newSocket);
	    }

	  }

	  // Close when counter reached 3 and we want to exit program
	  close(printerSocket);
}


static uint8_t untrusted_buf[102400];
static uint32_t untrusted_buf_len;

uint32_t ocall_write_region_data( uint8_t *buf, uint32_t buflen) {
	if (buflen > sizeof untrusted_buf)
		return 2;
	memcpy(untrusted_buf, buf, buflen);
	untrusted_buf_len = buflen;
	return 1;
}


uint32_t ocall_read_region_data(uint8_t *buf, uint32_t buflen,
		uint32_t *buflen_out) {
	if (untrusted_buf_len == 0)
		return 2;

	if (buflen < untrusted_buf_len)
		return 3;

	memcpy(buf, untrusted_buf, untrusted_buf_len);
	*buflen_out = untrusted_buf_len;
	return 0;
}


uint32_t ocall_write_sealed_data( uint8_t *buffer, uint32_t buflen,
		const char * filename) {
	FILE* pFile;
	pFile = fopen(filename, "a+");
	if (pFile) {
		fwrite(buffer, 1, buflen, pFile);
		fwrite("\n",1,1,pFile);
		printf("\nBuffer Written:%d\n", buflen);
		//for(int j=0; j< buflen ;j++){
		//	printf("%x ", (char*)buffer[j]);
		//}

	} else{
		printf("\nCan't open file");
		return 1;
	}
	printf("\n Sealed data written successfully");
	fclose(pFile);
	return 0;
}


// reads sealed log data where each block is separated using three (\n\n\n) characters
uint32_t ocall_read_sealed_data( char * filename) {
	FILE * fp;
		char * line = NULL;
		char data [204800];
		int size = 0;
		size_t len = 0;
		ssize_t read;
		uint32_t pwerr;
		char ch;
		int ch1, ch2, ch3;
		int count = 0;
		clock_t start , end;
		double cpu_time_used=0;

		printf("\nReading sealed data from file:%s", filename);
		fp = fopen(filename, "r");
		if (fp == NULL){
			printf("\nCan't open file to read");
			exit(EXIT_FAILURE);
		}
		fseek(fp, 0L, SEEK_END);
		int f_size = ftell(fp);
		fseek(fp, 0L, SEEK_SET);

		printf("\nSealed file");

		while(count<=f_size){
			ch1 = fgetc(fp);
			//printf("%x ", ch1);
				if(ch1=='\n'){
					ch2 = fgetc(fp);
					if(ch2== '\n'){
						ch3 = fgetc(fp);
						if(ch3== '\n'){
							//printf("\n\n Sending input:%d\n",size);
							//for(int j=0; j< size ;j++){
							//	printf("%x ", data[j]);
							//}
							start = clock();
							memcpy(untrusted_buf, data, size);
							untrusted_buf_len = size;
							verify_block_messages(global_eid, &pwerr);

							size = 0;
							end = clock();
							cpu_time_used = ((double)(end-start))/ CLOCKS_PER_SEC;
							//printf("\nCPU TIME = %f ", cpu_time_used);

						}else{
							data[size++] = ch1;
							data[size++] = ch2;
							data[size++] = ch3;
							count = count+3;
						}
					}else{
						data[size++] = ch1;
						data[size++] = ch2;
						count = count+2;
					}
				}else{
					data[size++] = ch1;
					count++;
				}

		}
		fclose(fp);
		if (line)
			free(line);

}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
	(void)(argc);
	(void)(argv);

	#if defined(_MSC_VER)
		if (query_sgx_status() < 0) {
			/* either SGX is disabled, or a reboot is required to enable SGX */
			printf("Enter a character before exit ...\n");
			getchar();
			return -1;
		}
	#endif

	/* Initialize the enclave */
	if(initialize_enclave() < 0) {
		printf("Enter a character before exit ...\n");
		getchar();
		return -1;
	}


	printf("\n Starting up log server:\n");
    startup_phase(global_eid);

	ocall_read_config_data("log-server.conf");

	ocall_listen_log_messages();


	// Enable following block for testing messages from log file
	/*
	printf("\n READING LOG MESSAGES:\n");
	ocall_read_log_messages("kernel.logs");
	 */

	// Uncomment following block for verifying log messages
	/*
	printf("\n Resetting B_KEY:\n");
	reset_block_key(global_eid);

	printf("\n Starting up log server:\n");
    startup_phase(global_eid);

	printf("\n\n READING SEALED MESSAGES:\n");
    ocall_read_sealed_data("sealed-logs/kern.log"); // update sealed log file path as required
     */

	/* Destroy the enclave */
	sgx_destroy_enclave(global_eid);

	printf("Info: SampleEnclave successfully returned.\n");

	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}

