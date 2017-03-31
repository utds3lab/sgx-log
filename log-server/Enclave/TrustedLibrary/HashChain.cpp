/*
 * HashChain.cpp
 *
 *  Created on: Mar 29, 2017
 *      Author: vishal
 */
#include <string.h>
#include <sgx_cpuid.h>

#include "sgx_trts.h"
#include "../Enclave.h"
#include "Enclave_t.h"


char* hash(char* str, int len){
	//printf("Testing hash for %s", str);
	sgx_sha256_hash_t * p_hash = (sgx_sha256_hash_t *) malloc(1000);
	sgx_status_t hash_status = sgx_sha256_msg((uint8_t *)str, len, p_hash);
	//printf("\nHash status:%d", hash_status);
	//printf("\n Hash length:%d", strlen((char*)p_hash));
	return (char*) p_hash;
}

char* get_next_block_key(char *str, int len, int B_ID){
	//printf("BID=%d", B_ID);
	char buf[10];
	itoa(B_ID, buf, 10);
	char * input = (char *) malloc(2048);
	int i = 0;
	while(i<len){
		input[i]= str[i];
		i++;
	}
	int j=0;
	while(j<strlen(buf)){
		input[i++] = str[j++];
	}
	return hash(input, i);
}

char* get_next_message_key(char *str, int len, int M_ID){
	//printf("MID=%d", M_ID);
	char buf[10];
	itoa(M_ID, buf, 10);
	char * input = (char *) malloc(2048);
	int i = 0;
	while(i<len){
		input[i]= str[i];
		i++;
	}
	int j=0;
	while(j<strlen(buf)){
			input[i++] = str[j++];
		}
	return hash(input, i);
}

char* get_mac(char * str, int len, char * key){

	//printf("\n\nInside mac:");
	//printf("\n Message:");

	for(int i=0;i<len;i++){
		printf("%c", str[i]);
	}
	//printf("\nLength=%d", len);
	char* key_128 = (char *) malloc(16);

	//printf("\n Key:");
	for(int i=0;i<16;i++){
		key_128[i] = key[i];
		//printf("%d", key[i]);

	}

	sgx_cmac_128bit_tag_t * p_hash = (sgx_cmac_128bit_tag_t *) malloc(1000);
	sgx_status_t hash_status =  sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t*) key_128, (uint8_t *)str, len, p_hash);
	//printf("\nMAC status:%d", hash_status);
	//printf("\n MAC length:%d", strlen((char*)p_hash));
	return (char*) p_hash;

}
