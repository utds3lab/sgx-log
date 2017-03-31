#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_test_function_t {
	char* ms_str;
} ms_test_function_t;

typedef struct ms_add_t {
	int ms_retval;
	int ms_x;
	int ms_y;
} ms_add_t;


typedef struct ms_init_secret_data_t {
	size_t ms_amount;
} ms_init_secret_data_t;


typedef struct ms_test_unseal_data_t {
	uint8_t* ms_sealed;
} ms_test_unseal_data_t;

typedef struct ms_test_report_t {
	sgx_report_t* ms_report;
} ms_test_report_t;

typedef struct ms_test_copy_in_t {
	uint8_t* ms_buf;
	size_t ms_len;
	size_t ms_offset;
} ms_test_copy_in_t;

typedef struct ms_test_copy_out_t {
	uint8_t* ms_buf;
	size_t ms_len;
	size_t ms_offset;
} ms_test_copy_out_t;



typedef struct ms_test_encrypt_t {
	size_t ms_length;
} ms_test_encrypt_t;

typedef struct ms_test_decrypt_t {
	size_t ms_length;
} ms_test_decrypt_t;

typedef struct ms_test_hash_t {
	size_t ms_length;
} ms_test_hash_t;

typedef struct ms_test_mac_t {
	size_t ms_length;
} ms_test_mac_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_seal_data_t {
	uint8_t* ms_sealed;
	size_t ms_len;
} ms_ocall_seal_data_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_seal_data(void* pms)
{
	ms_ocall_seal_data_t* ms = SGX_CAST(ms_ocall_seal_data_t*, pms);
	ocall_seal_data(ms->ms_sealed, ms->ms_len);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_Enclave = {
	2,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_seal_data,
	}
};
sgx_status_t test_function(sgx_enclave_id_t eid, const char* str)
{
	sgx_status_t status;
	ms_test_function_t ms;
	ms.ms_str = (char*)str;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t add(sgx_enclave_id_t eid, int* retval, int x, int y)
{
	sgx_status_t status;
	ms_add_t ms;
	ms.ms_x = x;
	ms.ms_y = y;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t nothing(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t init_secret_data(sgx_enclave_id_t eid, size_t amount)
{
	sgx_status_t status;
	ms_init_secret_data_t ms;
	ms.ms_amount = amount;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t test_seal_data(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t test_unseal_data(sgx_enclave_id_t eid, uint8_t* sealed)
{
	sgx_status_t status;
	ms_test_unseal_data_t ms;
	ms.ms_sealed = sealed;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t test_report(sgx_enclave_id_t eid, sgx_report_t* report)
{
	sgx_status_t status;
	ms_test_report_t ms;
	ms.ms_report = report;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t test_copy_in(sgx_enclave_id_t eid, uint8_t* buf, size_t len, size_t offset)
{
	sgx_status_t status;
	ms_test_copy_in_t ms;
	ms.ms_buf = buf;
	ms.ms_len = len;
	ms.ms_offset = offset;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t test_copy_out(sgx_enclave_id_t eid, uint8_t* buf, size_t len, size_t offset)
{
	sgx_status_t status;
	ms_test_copy_out_t ms;
	ms.ms_buf = buf;
	ms.ms_len = len;
	ms.ms_offset = offset;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t test_create_key_pair(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t test_shared_dhkey(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t test_encrypt(sgx_enclave_id_t eid, size_t length)
{
	sgx_status_t status;
	ms_test_encrypt_t ms;
	ms.ms_length = length;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t test_decrypt(sgx_enclave_id_t eid, size_t length)
{
	sgx_status_t status;
	ms_test_decrypt_t ms;
	ms.ms_length = length;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t test_hash(sgx_enclave_id_t eid, size_t length)
{
	sgx_status_t status;
	ms_test_hash_t ms;
	ms.ms_length = length;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t test_mac(sgx_enclave_id_t eid, size_t length)
{
	sgx_status_t status;
	ms_test_mac_t ms;
	ms.ms_length = length;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
	return status;
}

