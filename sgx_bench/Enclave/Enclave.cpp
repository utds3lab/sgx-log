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

#include <string.h>

#include <sgx_tseal.h>

#include <sgx_utils.h>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...) {
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

void test_function(const char *str) {
	printf(str);
}

int add(int x, int y) {
	return x + y;
}

void nothing() {
	return;
}

uint32_t secret_size = 0;
uint8_t secret_data[10240]; //Causes a SEGFAULT when seal is called if allocated on the heap!  WHY?
uint8_t sealed_data[12800]; //Buffer to hold the sealed_data struct
//sgx_sealed_data_t sealed_data;

void init_secret_data(size_t amount) {
	uint32_t i;
	secret_size = amount;
	//secret_data = (uint8_t*)malloc(amount);
	for (i = 0; i < amount; i++) {
		secret_data[i] = (uint8_t) i;/*This will overflow, but the values don't matter*/
	}
}

//void free_secret_data(){
//This is actually not secure for a real SGX application; an attacker can perform a double-free
//    free(secret_data); 
//}

void test_seal_data() {
	size_t length;
	/*Do this in the enclave so opponent can't attack*/
	length = sgx_calc_sealed_data_size(0, secret_size);

//printf("secret_data[5] %u\n", secret_data[5]);
	/*sealed is an sgx_sealed_data_t, already allocated*/
	sgx_seal_data(0, NULL, secret_size, secret_data, length,
			(sgx_sealed_data_t*) sealed_data);
//printf("payload size: %lu\n", ((sgx_sealed_data_t*)sealed_data)->aes_data.payload_size);

	ocall_seal_data(sealed_data, length);
}

void test_unseal_data(uint8_t* sealed) {
	uint32_t length = 0;
	/*sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed);*/
	length = sgx_calc_sealed_data_size(0, secret_size);
	memcpy(sealed_data, sealed, length); //Copy it ourselves instead of using bridge
//printf("Unencrypted length: %lu\n", secret_size);
	/*Allocate for decrypted text*/
	sgx_unseal_data((sgx_sealed_data_t*) sealed_data, NULL, 0, secret_data,
			&secret_size);
//printf("secret_data[5] %u, secret_size %lu\n", secret_data[5], secret_size);
}

void test_report(sgx_report_t* report) {
	sgx_create_report(NULL, NULL, report);
}

uint8_t secret_buffer[10240];

void test_copy_in(uint8_t* buf, size_t len, size_t offset) {
	memcpy(secret_buffer + offset, buf, len);
}

void test_copy_out(uint8_t* buf, size_t len, size_t offset) {
	memcpy(buf, secret_buffer + offset, len);
}

sgx_aes_gcm_128bit_tag_t mac;
uint8_t encrypted_buffer[12800];
const sgx_aes_gcm_128bit_key_t key[] = { '1', '2', '3', '4', '5', '6', '7', '8',
		'9', '0', '1', '2', '3', '4', '5', '6' };
const uint8_t iv[] = { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
		'2' };

//Note this is NOT testing for data crossing the boundary and is only testing encryption speed
void test_encrypt(size_t length) {
	//secret_buffer[0] = 'q';
	sgx_status_t stat = sgx_rijndael128GCM_encrypt(key, secret_buffer, length,
			encrypted_buffer, iv, 12, NULL, 0, &mac);
	/*
	 printf("STATUS: %d\nENCRYPTED MESSAGE: %s\n",stat,(char*)encrypted_buffer);
	 printf("Encrypted bytes: \n");
	 for( int i = 0; i < sizeof(encrypted_buffer); i++)
	 printf("%x ",encrypted_buffer[i]);

	 sgx_status_t stat1 = sgx_rijndael128GCM_decrypt(key,encrypted_buffer,length,secret_buffer,iv,12,NULL,0,&mac);
	 printf("\nSTATUS: %d \nDECRYPTED MESSAGE: %s\n",stat,(char*)secret_buffer);
	 printf("Decrypted bytes: \n");
	 for( int i = 0; i < sizeof(secret_buffer); i++)
	 printf("%x ",encrypted_buffer[i]);*/
}

uint8_t priv_key[1024];
uint8_t pub_key[1024];
void test_create_key_pair() {
	sgx_ecc_state_handle_t state;
	printf("before opening\n");
	sgx_status_t err = sgx_ecc256_open_context(&state);

	printf("after opening, %x\n", err);
	err = sgx_ecc256_create_key_pair((sgx_ec256_private_t*) priv_key,
			(sgx_ec256_public_t*) pub_key, &state);
	printf("create key pair status: %x\n", err);
	printf("after create\n");
	sgx_ecc256_close_context(&state);
}

uint8_t shared_key[1024];
void test_shared_dhkey() {
	sgx_ecc_state_handle_t state;

	printf("before opening\n");
	sgx_status_t err = sgx_ecc256_open_context(&state);

	printf("after opening, %x\n", err);
	err = sgx_ecc256_compute_shared_dhkey((sgx_ec256_private_t*) priv_key,
			(sgx_ec256_public_t*) pub_key, (sgx_ec256_dh_shared_t*) shared_key,
			&state);
	printf("after that\n");
	printf("create shared dhkey status: %x\n", err);
	sgx_ecc256_close_context(&state);
	printf("after closing\n");
}

void test_decrypt(size_t length) {
	sgx_status_t stat = sgx_rijndael128GCM_decrypt(key, encrypted_buffer,
			length, secret_buffer, iv, 12, NULL, 0, &mac);
	/*
	 printf("STATUS: %d\nDECRYPTED MESSAGE: %s\n",stat,(char*)secret_buffer);*/
}

void test_hash(size_t length) {
	sgx_status_t hash_status = sgx_sha256_msg(secret_buffer, length,
			(sgx_sha256_hash_t*) encrypted_buffer);
	//printf("Hash status:%d\n", hash_status);
}

const sgx_cmac_128bit_key_t mac_key[] = { '1', '2', '3', '4', '5', '6', '7',
		'8', '9', '0', '1', '2', '3', '4', '5', '6' };
void test_mac(size_t length) {
	sgx_status_t hash_status = sgx_rijndael128_cmac_msg(mac_key, secret_buffer,
			length, (sgx_cmac_128bit_tag_t*) encrypted_buffer);
	//printf("\nMAC status:%d", hash_status);
}

