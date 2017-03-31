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

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "sgx_tcrypto.h"
#include "sgx_utils.h"
#include "sgx_tseal.h"
#include "handy.h"
#include <string.h>
#include <cstring>

// ecall printf for debug
void printf(const char *fmt, ...) {
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

typedef struct config_data {
	uint8_t * facility;
	uint8_t * priority;
	uint8_t * filename;
	uint8_t * log_buffer;
	uint32_t log_buffer_length;
	uint32_t msg_count;
};

static int config_rule_length = 0;
static struct config_data config[10];
static int LOG_BUFFER_MAX_SIZE = 4096;
static int log_count = 0;
static int seal = 1;
static int MAX_BLOCK_SIZE = 3;
static char *ROOT_KEY, *B_KEY, *M_KEY, *NEXT_B_KEY;
;
static int B_ID, M_ID;
static int monotonic_counter;

void reset_block_key() {
	B_KEY = NULL;
}

void create_block() {
	printf("\nCreating a new block.");
	if (B_KEY == NULL) {
		monotonic_counter = 100;
		B_KEY = ROOT_KEY;
		B_ID = monotonic_counter;

	} else {
		B_KEY = NEXT_B_KEY; // read from sealed value
		monotonic_counter = monotonic_counter + 1;
		B_ID = monotonic_counter;
	}
	///printf("%s", B_KEY);
	NEXT_B_KEY = get_next_block_key(B_KEY, strlen(B_KEY), B_ID);
	//seal_and_write(NEXT_B_KEY, "sealed-logs/bkey.log");

	if (B_ID != monotonic_counter) {
		printf("\nRoll-back attack detected..");
		return;
	}
	M_ID = 0;
}

void startup_phase() {
	printf("\nRunning startup_phase.");
	//initialize rootkey for first execution else use sealed block key
	ROOT_KEY = "secret_root_key";
	monotonic_counter = 100;
	create_block();
}

void init_config(struct config_data * cd) {
	printf("\nInitializing log configuration.");
	cd->facility = (uint8_t*) malloc(64);
	cd->priority = (uint8_t*) malloc(64);
	cd->filename = (uint8_t*) malloc(64);
	cd->log_buffer = (uint8_t*) malloc(LOG_BUFFER_MAX_SIZE);
	cd->log_buffer_length = 0;
	cd->msg_count = 0;
}

// ecall to build config data structure
void generate_config(const char *str, int len) {
	init_config(&config[config_rule_length]);

	int j = 0;
	for (int i = 0; i < len; i++) {
		if (str[i] == '.') {
			j = i;
			break;
		}
		config[config_rule_length].facility[i] = str[i];
	}
	int k = 0;
	for (int i = j + 1; i < len; i++) {
		if (str[i + 1] == '-') {
			break;
		}
		config[config_rule_length].priority[k++] = str[i];
	}
	int flag = 0;
	k = 0;
	for (int i = j + 2;
			i < len && str[i] != ' ' && str[i] != '\0' && str[i] != '\n'; i++) {
		//printf("\nCurrent %c", str[i]);
		if (str[i] == '/') {
			flag = 1;
		}
		if (flag == 1)
			config[config_rule_length].filename[k++] = str[i];
	}
	config[config_rule_length].filename[k] = '\0';
	printf("Filename-%s-", config[config_rule_length].filename);
	config_rule_length++;
}


void process_log(char *log) {
	printf("\n[Processing Log]:%s", log);
	int num = strlen(log);
	char buf[2048];
	itoa(num, buf, 10);
	char * msg = (char *) malloc(2048);
	int k = 0;
	for (int i = 0; i < strlen(buf); i++) {
		msg[k++] = buf[i];
	}
	for (int i = 0; i < strlen(log); i++) {
		msg[k++] = log[i];
	}
	//printf("\nLog Message:%s", msg);

	// find out rule matching the log entry
	for (int i = 0; i < config_rule_length; i++) {
		uint8_t * filename;
		int32_t need_len;
		uint32_t err;

		// apply Parsing using log configuration
		if (strstr((const char *) msg, (const char *) config[i].facility)
				!= '\0') {
			//printf("\nMatched config[%d]", i);
			//printf("\nFacility:%s", config[i].facility);
			//printf("\nPriority:%s", config[i].priority);
			//printf("\nFilename:%s", config[i].filename);

			uint32_t log_length = strlen(msg);
			//printf("\nMsg length:%d", strlen(msg));

			// buffer current log message
			if (config[i].log_buffer_length < LOG_BUFFER_MAX_SIZE) {
				for (int j = 0; j < log_length; j++) {
					//printf("\ncopying %d", j);
					config[i].log_buffer[j + config[i].log_buffer_length] =
							msg[j];
				}
				config[i].log_buffer_length = config[i].log_buffer_length
						+ log_length;
				//printf("\n Log buffer size:%d", config[i].log_buffer_length);

				// increase message counter
				config[i].msg_count++;
				//printf("\nMessage count:%d", config[i].msg_count);
			}

			//Generate message key
			if (M_ID == 0) {
				printf("\nGenerating first message key:");
				M_KEY = get_next_message_key(B_KEY, strlen((char*) B_KEY),
						M_ID);
			} else {
				printf("\nGenerating intermediate message key:");
				M_KEY = get_next_message_key(M_KEY, strlen((char*) M_KEY),
						M_ID);
			}
			M_ID = M_ID + 1;

			printf("\nMKEY=");
			for (int h = 0; h < 16; h++) {
				printf("%x", M_KEY[h]);
			}

			printf("\nGenerating MAC:");
			char * msg_mac = get_mac(msg, strlen(msg), M_KEY);

			if (M_ID == MAX_BLOCK_SIZE) {
				create_block();
			}

			// Generate hash value for message
			char * msg_hash = get_hash(msg, strlen(msg));

			if (config[i].log_buffer_length < LOG_BUFFER_MAX_SIZE) {
				for (int j = 0; j < strlen(msg_mac); j++) {
					//printf("\ncopying %d", j);
					config[i].log_buffer[j + config[i].log_buffer_length] =
							(uint8_t) msg_mac[j];
				}
				config[i].log_buffer_length = config[i].log_buffer_length
						+ strlen(msg_mac);
				printf("\n Log buffer size:%d", config[i].log_buffer_length);
			}

			// Add message to message separators
			config[i].log_buffer[config[i].log_buffer_length] = '\n';
			config[i].log_buffer_length = config[i].log_buffer_length + 1;

			// If buffer is full then seal data
			if ((config[i].msg_count == MAX_BLOCK_SIZE)
					&& (config[i].log_buffer_length < LOG_BUFFER_MAX_SIZE)
					&& seal == 1) {
				need_len = sgx_calc_sealed_data_size(0,
						config[i].log_buffer_length);
				uint8_t * sealed_data = (uint8_t*) seal_data(
						config[i].log_buffer, config[i].log_buffer_length);
				uint8_t sealed_log_buf[240000];

				for (int j = 0; j < need_len; j++) {
					sealed_log_buf[j] = sealed_data[j];
				}

				sealed_log_buf[need_len] = '\n';
				sealed_log_buf[need_len + 1] = '\n';
				sealed_log_buf[need_len + 2] = '\n';
				need_len = need_len + 3;
				//printf("\n need_length:%d", need_len);

				printf("\n Writing log buffer in file:%s",
						(char*) config[i].filename);

				if (ocall_write_sealed_data(&err, sealed_log_buf, need_len,
						(char*) config[i].filename)) {
					printf("\nBuffer writing to file failed.\n");
					return;
				}

				printf("\n No of bytes written:%d", need_len);

				mem_clean(config[i].log_buffer, config[i].log_buffer_length);
				config[i].log_buffer_length = 0;
				config[i].msg_count = 0;
			}

			// Log emitting in plain text data for debug (sealing disabled)
			if ((config[i].msg_count == MAX_BLOCK_SIZE)
					&& (config[i].log_buffer_length < LOG_BUFFER_MAX_SIZE)
					&& seal == 0) {

				printf("\n Before log buffer size:%d",
						config[i].log_buffer_length);
				printf("\n Writing log buffer in file:%s",
						(char*) config[i].filename);
				config[i].log_buffer[config[i].log_buffer_length] = '\n';
				config[i].log_buffer_length++;

				if (ocall_write_sealed_data(&err, config[i].log_buffer,
						config[i].log_buffer_length,
						(char*) config[i].filename)) {
					printf("\nBuffer writing to file failed.\n");
					return;
				}

				printf("\n Number of logs written:%d", config[i].msg_count);
				printf("\n No of bytes written:%d", log_length);

				mem_clean(config[i].log_buffer, config[i].log_buffer_length);
				config[i].log_buffer_length = 0;
				config[i].msg_count = 0;
			}

		}
	}
}

static uint32_t g_have_region_key = 0;
static sgx_aes_ctr_128bit_key_t g_region_key;

/* Fill in g_region_key by fetching a sealed copy from our caller
 * (via the read_region_data ocall) and then unsealing it. */
uint32_t verify_block_messages(void) {
	uint8_t blob[102400];
	uint8_t block_data[102400];
	uint32_t err, bloblen, block_data_length;
	uint8_t new_blob[10240];
	uint8_t new_blob_length = 0;
	int result = 1;

	if (ocall_read_region_data(&err, blob, sizeof(blob), &bloblen))
		return 2;
	//printf("\nError:%d", err);
	if (err)
		return err;

	block_data_length = sizeof(block_data);
	//printf("\nBlob length=%d", bloblen);

	sgx_status_t unseal_result = sgx_unseal_data(
			(const sgx_sealed_data_t *) blob, NULL, NULL, block_data,
			&block_data_length);
	// unseal block data containing bsize messages and hash values
	if (sgx_unseal_data((const sgx_sealed_data_t *) blob, NULL, NULL,
			block_data, &block_data_length)) {
		//printf("Unsealing failed");
		return 2;
	}

	/*
	printf("\n Unsealed size:%d\n", block_data_length);
	for (int i = 0; i < block_data_length; i++)
		printf("%c", block_data[i]);
	*/

	for (int i = 0; i < block_data_length; i++) {

		//Generate message key
		if (M_ID == 0) {
			//printf("\nGenerating first message key:");
			M_KEY = get_next_message_key(B_KEY, strlen((char*) B_KEY), M_ID);
		} else {
			//printf("\nGenerating intermediate message key:");
			M_KEY = get_next_message_key(M_KEY, strlen((char*) M_KEY), M_ID);
		}

		// increament message identifier
		M_ID = M_ID + 1;

		char * num = (char *) malloc(5);
		int k = 0;
		char * msg = (char *) malloc(2048);

		while (block_data[i] <= '9' && block_data[i] >= '0') {
			num[k] = block_data[i];
			msg[k++] = block_data[i++];
		}
		//printf("\nCurrent Num %s", num);

		int msg_len = atoi(num);
		//printf("\n INT:%d", atoi(num));

		for (int m = i; m < msg_len + i; m++) {
			msg[k++] = block_data[m];
		}

		//printf("\nMessage:");
		for (int l = 0; l < k; l++) {
			printf("%c", msg[l]);
		}

		//printf("\nRecomputing MAC:");
		char * new_mac = get_mac(msg, k, M_KEY);

		/*
		printf("\nMKEY=");
		for (int h = 0; h < 16; h++) {
			printf("%x", M_KEY[h]);
		}
		*/

		int new_mac_length = strlen((char*) new_mac);

		/*
		printf("\nNew MAC of length %d:", new_mac_length);
		for (int h = 0; h < new_mac_length; h++) {
			printf("%x", new_mac[h]);
		}
		*/

		i = msg_len + i;
		char * old_mac = (char *) malloc(35);
		int p = 0;

		//printf("\nOLD MAC:");
		for (int m = i; m < new_mac_length + i; m++) {
			printf("%x", block_data[m]);
			old_mac[p++] = block_data[m];
		}
		result = result
				&& compareHashValues((char*) old_mac, new_mac, new_mac_length);
		//printf("\nresult = %d", result);
		i = i + new_mac_length;
	}

	if (M_ID == MAX_BLOCK_SIZE) {
		create_block();
	}

	if (result == 1) {
		printf("\nBlock verified successfully");
	} else {
		printf("\nDetected intrusion in current block");
	}
	return result;
}

