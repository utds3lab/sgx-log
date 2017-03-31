#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "user_types.h"
#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_seal_data, (uint8_t* sealed, size_t len));

sgx_status_t test_function(sgx_enclave_id_t eid, const char* str);
sgx_status_t add(sgx_enclave_id_t eid, int* retval, int x, int y);
sgx_status_t nothing(sgx_enclave_id_t eid);
sgx_status_t init_secret_data(sgx_enclave_id_t eid, size_t amount);
sgx_status_t test_seal_data(sgx_enclave_id_t eid);
sgx_status_t test_unseal_data(sgx_enclave_id_t eid, uint8_t* sealed);
sgx_status_t test_report(sgx_enclave_id_t eid, sgx_report_t* report);
sgx_status_t test_copy_in(sgx_enclave_id_t eid, uint8_t* buf, size_t len, size_t offset);
sgx_status_t test_copy_out(sgx_enclave_id_t eid, uint8_t* buf, size_t len, size_t offset);
sgx_status_t test_create_key_pair(sgx_enclave_id_t eid);
sgx_status_t test_shared_dhkey(sgx_enclave_id_t eid);
sgx_status_t test_encrypt(sgx_enclave_id_t eid, size_t length);
sgx_status_t test_decrypt(sgx_enclave_id_t eid, size_t length);
sgx_status_t test_hash(sgx_enclave_id_t eid, size_t length);
sgx_status_t test_mac(sgx_enclave_id_t eid, size_t length);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
