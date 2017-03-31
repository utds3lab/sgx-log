#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_test_function(void* pms)
{
	ms_test_function_t* ms = SGX_CAST(ms_test_function_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = _tmp_str ? strlen(_tmp_str) + 1 : 0;
	char* _in_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_test_function_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_str, _tmp_str, _len_str);
		_in_str[_len_str - 1] = '\0';
	}
	test_function((const char*)_in_str);
err:
	if (_in_str) free((void*)_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_add(void* pms)
{
	ms_add_t* ms = SGX_CAST(ms_add_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_add_t));

	ms->ms_retval = add(ms->ms_x, ms->ms_y);


	return status;
}

static sgx_status_t SGX_CDECL sgx_nothing(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	nothing();
	return status;
}

static sgx_status_t SGX_CDECL sgx_init_secret_data(void* pms)
{
	ms_init_secret_data_t* ms = SGX_CAST(ms_init_secret_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_init_secret_data_t));

	init_secret_data(ms->ms_amount);


	return status;
}

static sgx_status_t SGX_CDECL sgx_test_seal_data(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	test_seal_data();
	return status;
}

static sgx_status_t SGX_CDECL sgx_test_unseal_data(void* pms)
{
	ms_test_unseal_data_t* ms = SGX_CAST(ms_test_unseal_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed = ms->ms_sealed;

	CHECK_REF_POINTER(pms, sizeof(ms_test_unseal_data_t));

	test_unseal_data(_tmp_sealed);


	return status;
}

static sgx_status_t SGX_CDECL sgx_test_report(void* pms)
{
	ms_test_report_t* ms = SGX_CAST(ms_test_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(*_tmp_report);
	sgx_report_t* _in_report = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_test_report_t));
	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);

	if (_tmp_report != NULL) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}
	test_report(_in_report);
err:
	if (_in_report) {
		memcpy(_tmp_report, _in_report, _len_report);
		free(_in_report);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_test_copy_in(void* pms)
{
	ms_test_copy_in_t* ms = SGX_CAST(ms_test_copy_in_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len * 1;
	uint8_t* _in_buf = NULL;

	if ((size_t)_tmp_len > (SIZE_MAX / 1)) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_test_copy_in_t));
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL) {
		_in_buf = (uint8_t*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_buf, _tmp_buf, _len_buf);
	}
	test_copy_in(_in_buf, _tmp_len, ms->ms_offset);
err:
	if (_in_buf) free(_in_buf);

	return status;
}

static sgx_status_t SGX_CDECL sgx_test_copy_out(void* pms)
{
	ms_test_copy_out_t* ms = SGX_CAST(ms_test_copy_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len * 1;
	uint8_t* _in_buf = NULL;

	if ((size_t)_tmp_len > (SIZE_MAX / 1)) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_test_copy_out_t));
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL) {
		if ((_in_buf = (uint8_t*)malloc(_len_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_buf, 0, _len_buf);
	}
	test_copy_out(_in_buf, _tmp_len, ms->ms_offset);
err:
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_test_create_key_pair(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	test_create_key_pair();
	return status;
}

static sgx_status_t SGX_CDECL sgx_test_shared_dhkey(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	test_shared_dhkey();
	return status;
}

static sgx_status_t SGX_CDECL sgx_test_encrypt(void* pms)
{
	ms_test_encrypt_t* ms = SGX_CAST(ms_test_encrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_test_encrypt_t));

	test_encrypt(ms->ms_length);


	return status;
}

static sgx_status_t SGX_CDECL sgx_test_decrypt(void* pms)
{
	ms_test_decrypt_t* ms = SGX_CAST(ms_test_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_test_decrypt_t));

	test_decrypt(ms->ms_length);


	return status;
}

static sgx_status_t SGX_CDECL sgx_test_hash(void* pms)
{
	ms_test_hash_t* ms = SGX_CAST(ms_test_hash_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_test_hash_t));

	test_hash(ms->ms_length);


	return status;
}

static sgx_status_t SGX_CDECL sgx_test_mac(void* pms)
{
	ms_test_mac_t* ms = SGX_CAST(ms_test_mac_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_test_mac_t));

	test_mac(ms->ms_length);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[15];
} g_ecall_table = {
	15,
	{
		{(void*)(uintptr_t)sgx_test_function, 0},
		{(void*)(uintptr_t)sgx_add, 0},
		{(void*)(uintptr_t)sgx_nothing, 0},
		{(void*)(uintptr_t)sgx_init_secret_data, 0},
		{(void*)(uintptr_t)sgx_test_seal_data, 0},
		{(void*)(uintptr_t)sgx_test_unseal_data, 0},
		{(void*)(uintptr_t)sgx_test_report, 0},
		{(void*)(uintptr_t)sgx_test_copy_in, 0},
		{(void*)(uintptr_t)sgx_test_copy_out, 0},
		{(void*)(uintptr_t)sgx_test_create_key_pair, 0},
		{(void*)(uintptr_t)sgx_test_shared_dhkey, 0},
		{(void*)(uintptr_t)sgx_test_encrypt, 0},
		{(void*)(uintptr_t)sgx_test_decrypt, 0},
		{(void*)(uintptr_t)sgx_test_hash, 0},
		{(void*)(uintptr_t)sgx_test_mac, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][15];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_seal_data(uint8_t* sealed, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealed = len * 1;

	ms_ocall_seal_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_seal_data_t);
	void *__tmp = NULL;

	ocalloc_size += (sealed != NULL && sgx_is_within_enclave(sealed, _len_sealed)) ? _len_sealed : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_seal_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_seal_data_t));

	if (sealed != NULL && sgx_is_within_enclave(sealed, _len_sealed)) {
		ms->ms_sealed = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_sealed);
		memcpy(ms->ms_sealed, sealed, _len_sealed);
	} else if (sealed == NULL) {
		ms->ms_sealed = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

