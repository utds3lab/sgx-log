#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"
#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void test_function(const char* str);
int add(int x, int y);
void nothing();
void init_secret_data(size_t amount);
void test_seal_data();
void test_unseal_data(uint8_t* sealed);
void test_report(sgx_report_t* report);
void test_copy_in(uint8_t* buf, size_t len, size_t offset);
void test_copy_out(uint8_t* buf, size_t len, size_t offset);
void test_create_key_pair();
void test_shared_dhkey();
void test_encrypt(size_t length);
void test_decrypt(size_t length);
void test_hash(size_t length);
void test_mac(size_t length);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_seal_data(uint8_t* sealed, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
