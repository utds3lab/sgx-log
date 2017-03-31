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


char* get_hash( char* str, int len){
	//printf("Testing hash for %s", str);
	sgx_sha256_hash_t * p_hash = (sgx_sha256_hash_t *) malloc(1000);
	sgx_status_t hash_status = sgx_sha256_msg((uint8_t *)str, len, p_hash);
	//printf("\nHash status:%d", hash_status);
	//printf("\n Hash length:%d", strlen((char*)p_hash));
	return (char*) p_hash;
}

char* seal_data(uint8_t * buffer, uint32_t buffer_length) {
	printf("\nSealing data..");
	int32_t need_len;
	sgx_sealed_data_t* sealed_buf = (sgx_sealed_data_t * ) malloc(20480);
	need_len = sgx_calc_sealed_data_size(0, buffer_length);

	if (need_len > 20408) {
		printf("\n Buffer size is smaller to hold sealed data.\n");
		return NULL;
	}
	if (sgx_seal_data(0, NULL, buffer_length, buffer, need_len, (sgx_sealed_data_t *) sealed_buf)) {
		printf("\n Sealing of log buffer failed.");
		return NULL;
	}

	/*
	printf("\n [Data sealed]");
	printf("\n Log length:%d", buffer_length);
	printf("\n need_length:%d", need_len);
	printf("\n Before log buffer size:%d", buffer_length);

	printf("\n [Sealed data]:");
	for(int k=0;k<need_len;k++){
		printf("%x ",sealed_log_buf[k]);
	}
	*/

	return (char *) sealed_buf;
}
