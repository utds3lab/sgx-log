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

void seal_and_write(char* str, char* filename){
	uint32_t err;
	const char * data = str;
	uint8_t need_len=0;
	need_len = sgx_calc_sealed_data_size(0, strlen(data));
	uint8_t * sealed_data = (uint8_t*) seal_data((uint8_t*) data,
			(uint8_t) strlen(data));
	uint8_t sealed_buf[24000];

	for (int j = 0; j < need_len; j++) {
		sealed_buf[j] = sealed_data[j];
	}
	sealed_buf[need_len] = '\n';
	sealed_buf[need_len + 1] = '\n';
	sealed_buf[need_len + 2] = '\n';

	if (ocall_write_sealed_data(&err, sealed_buf, need_len, filename)) {
		printf("\nBuffer writing to file failed.\n");
		return;
	}
 }
