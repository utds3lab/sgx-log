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


typedef struct ms_process_log_t {
	char* ms_str;
} ms_process_log_t;

typedef struct ms_verify_block_messages_t {
	uint32_t ms_retval;
} ms_verify_block_messages_t;

typedef struct ms_generate_config_t {
	char* ms_str;
	int ms_len;
} ms_generate_config_t;



typedef struct ms_ecall_type_char_t {
	char ms_val;
} ms_ecall_type_char_t;

typedef struct ms_ecall_type_int_t {
	int ms_val;
} ms_ecall_type_int_t;

typedef struct ms_ecall_type_float_t {
	float ms_val;
} ms_ecall_type_float_t;

typedef struct ms_ecall_type_double_t {
	double ms_val;
} ms_ecall_type_double_t;

typedef struct ms_ecall_type_size_t_t {
	size_t ms_val;
} ms_ecall_type_size_t_t;

typedef struct ms_ecall_type_wchar_t_t {
	wchar_t ms_val;
} ms_ecall_type_wchar_t_t;

typedef struct ms_ecall_type_struct_t {
	struct struct_foo_t ms_val;
} ms_ecall_type_struct_t;

typedef struct ms_ecall_type_enum_union_t {
	enum enum_foo_t ms_val1;
	union union_foo_t* ms_val2;
} ms_ecall_type_enum_union_t;

typedef struct ms_ecall_pointer_user_check_t {
	size_t ms_retval;
	void* ms_val;
	size_t ms_sz;
} ms_ecall_pointer_user_check_t;

typedef struct ms_ecall_pointer_in_t {
	int* ms_val;
} ms_ecall_pointer_in_t;

typedef struct ms_ecall_pointer_out_t {
	int* ms_val;
} ms_ecall_pointer_out_t;

typedef struct ms_ecall_pointer_in_out_t {
	int* ms_val;
} ms_ecall_pointer_in_out_t;

typedef struct ms_ecall_pointer_string_t {
	char* ms_str;
} ms_ecall_pointer_string_t;

typedef struct ms_ecall_pointer_string_const_t {
	char* ms_str;
} ms_ecall_pointer_string_const_t;

typedef struct ms_ecall_pointer_size_t {
	void* ms_ptr;
	size_t ms_len;
} ms_ecall_pointer_size_t;

typedef struct ms_ecall_pointer_count_t {
	int* ms_arr;
	int ms_cnt;
} ms_ecall_pointer_count_t;

typedef struct ms_ecall_pointer_isptr_readonly_t {
	buffer_t ms_buf;
	size_t ms_len;
} ms_ecall_pointer_isptr_readonly_t;

typedef struct ms_ecall_pointer_sizefunc_t {
	char* ms_buf;
} ms_ecall_pointer_sizefunc_t;


typedef struct ms_ecall_array_user_check_t {
	int* ms_arr;
} ms_ecall_array_user_check_t;

typedef struct ms_ecall_array_in_t {
	int* ms_arr;
} ms_ecall_array_in_t;

typedef struct ms_ecall_array_out_t {
	int* ms_arr;
} ms_ecall_array_out_t;

typedef struct ms_ecall_array_in_out_t {
	int* ms_arr;
} ms_ecall_array_in_out_t;

typedef struct ms_ecall_array_isary_t {
	array_t*  ms_arr;
} ms_ecall_array_isary_t;



typedef struct ms_ecall_function_private_t {
	int ms_retval;
} ms_ecall_function_private_t;


typedef struct ms_ecall_sgx_cpuid_t {
	int* ms_cpuinfo;
	int ms_leaf;
} ms_ecall_sgx_cpuid_t;



typedef struct ms_ecall_increase_counter_t {
	size_t ms_retval;
} ms_ecall_increase_counter_t;



typedef struct ms_get_next_block_key_t {
	char* ms_retval;
	char* ms_str;
	int ms_len;
	int ms_B_ID;
} ms_get_next_block_key_t;

typedef struct ms_get_next_message_key_t {
	char* ms_retval;
	char* ms_str;
	int ms_len;
	int ms_M_ID;
} ms_get_next_message_key_t;

typedef struct ms_get_mac_t {
	char* ms_retval;
	char* ms_str;
	int ms_len;
	char* ms_key;
} ms_get_mac_t;

typedef struct ms_hash_t {
	char* ms_retval;
	char* ms_str;
	int ms_len;
} ms_hash_t;

typedef struct ms_compareHashValues_t {
	int ms_retval;
	char* ms_old_hash;
	char* ms_new_hash;
	int ms_len;
} ms_compareHashValues_t;

typedef struct ms_reverse_t {
	char* ms_str;
	int ms_length;
} ms_reverse_t;

typedef struct ms_itoa_t {
	char* ms_retval;
	int ms_num;
	char* ms_str;
	int ms_base;
} ms_itoa_t;

typedef struct ms_myAtoi_t {
	int ms_retval;
	char* ms_str;
} ms_myAtoi_t;

typedef struct ms_get_hash_t {
	char* ms_retval;
	char* ms_str;
	int ms_len;
} ms_get_hash_t;

typedef struct ms_seal_data_t {
	char* ms_retval;
	uint8_t* ms_log_buffer;
	uint32_t ms_log_buffer_length;
} ms_seal_data_t;

typedef struct ms_seal_and_write_t {
	char* ms_str;
	char* ms_filename;
} ms_seal_and_write_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_read_config_data_t {
	char* ms_str;
} ms_ocall_read_config_data_t;

typedef struct ms_ocall_read_log_messages_t {
	char* ms_str;
} ms_ocall_read_log_messages_t;


typedef struct ms_ocall_write_region_data_t {
	uint32_t ms_retval;
	uint8_t* ms_blob;
	uint32_t ms_bloblen;
} ms_ocall_write_region_data_t;

typedef struct ms_ocall_read_region_data_t {
	uint32_t ms_retval;
	uint8_t* ms_blob;
	uint32_t ms_bloblen_in;
	uint32_t* ms_bloblen_out;
} ms_ocall_read_region_data_t;

typedef struct ms_ocall_write_sealed_data_t {
	uint32_t ms_retval;
	uint8_t* ms_blob;
	uint32_t ms_bloblen;
	char* ms_str;
} ms_ocall_write_sealed_data_t;

typedef struct ms_ocall_read_sealed_data_t {
	uint32_t ms_retval;
	char* ms_str;
} ms_ocall_read_sealed_data_t;

typedef struct ms_ocall_pointer_user_check_t {
	int* ms_val;
} ms_ocall_pointer_user_check_t;

typedef struct ms_ocall_pointer_in_t {
	int* ms_val;
} ms_ocall_pointer_in_t;

typedef struct ms_ocall_pointer_out_t {
	int* ms_val;
} ms_ocall_pointer_out_t;

typedef struct ms_ocall_pointer_in_out_t {
	int* ms_val;
} ms_ocall_pointer_in_out_t;

typedef struct ms_memccpy_t {
	void* ms_retval;
	void* ms_dest;
	void* ms_src;
	int ms_val;
	size_t ms_len;
} ms_memccpy_t;


typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_process_log(void* pms)
{
	ms_process_log_t* ms = SGX_CAST(ms_process_log_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = _tmp_str ? strlen(_tmp_str) + 1 : 0;
	char* _in_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_process_log_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
		_in_str[_len_str - 1] = '\0';
	}
	process_log(_in_str);
err:
	if (_in_str) free(_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_verify_block_messages(void* pms)
{
	ms_verify_block_messages_t* ms = SGX_CAST(ms_verify_block_messages_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_verify_block_messages_t));

	ms->ms_retval = verify_block_messages();


	return status;
}

static sgx_status_t SGX_CDECL sgx_generate_config(void* pms)
{
	ms_generate_config_t* ms = SGX_CAST(ms_generate_config_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = _tmp_str ? strlen(_tmp_str) + 1 : 0;
	char* _in_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_generate_config_t));
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
	generate_config((const char*)_in_str, ms->ms_len);
err:
	if (_in_str) free((void*)_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_startup_phase(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	startup_phase();
	return status;
}

static sgx_status_t SGX_CDECL sgx_reset_block_key(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	reset_block_key();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_char(void* pms)
{
	ms_ecall_type_char_t* ms = SGX_CAST(ms_ecall_type_char_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_char_t));

	ecall_type_char(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_int(void* pms)
{
	ms_ecall_type_int_t* ms = SGX_CAST(ms_ecall_type_int_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_int_t));

	ecall_type_int(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_float(void* pms)
{
	ms_ecall_type_float_t* ms = SGX_CAST(ms_ecall_type_float_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_float_t));

	ecall_type_float(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_double(void* pms)
{
	ms_ecall_type_double_t* ms = SGX_CAST(ms_ecall_type_double_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_double_t));

	ecall_type_double(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_size_t(void* pms)
{
	ms_ecall_type_size_t_t* ms = SGX_CAST(ms_ecall_type_size_t_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_size_t_t));

	ecall_type_size_t(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_wchar_t(void* pms)
{
	ms_ecall_type_wchar_t_t* ms = SGX_CAST(ms_ecall_type_wchar_t_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_wchar_t_t));

	ecall_type_wchar_t(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_struct(void* pms)
{
	ms_ecall_type_struct_t* ms = SGX_CAST(ms_ecall_type_struct_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_struct_t));

	ecall_type_struct(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_enum_union(void* pms)
{
	ms_ecall_type_enum_union_t* ms = SGX_CAST(ms_ecall_type_enum_union_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	union union_foo_t* _tmp_val2 = ms->ms_val2;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_enum_union_t));

	ecall_type_enum_union(ms->ms_val1, _tmp_val2);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_user_check(void* pms)
{
	ms_ecall_pointer_user_check_t* ms = SGX_CAST(ms_ecall_pointer_user_check_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_val = ms->ms_val;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_user_check_t));

	ms->ms_retval = ecall_pointer_user_check(_tmp_val, ms->ms_sz);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_in(void* pms)
{
	ms_ecall_pointer_in_t* ms = SGX_CAST(ms_ecall_pointer_in_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(*_tmp_val);
	int* _in_val = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_in_t));
	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	if (_tmp_val != NULL) {
		_in_val = (int*)malloc(_len_val);
		if (_in_val == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_val, _tmp_val, _len_val);
	}
	ecall_pointer_in(_in_val);
err:
	if (_in_val) free(_in_val);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_out(void* pms)
{
	ms_ecall_pointer_out_t* ms = SGX_CAST(ms_ecall_pointer_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(*_tmp_val);
	int* _in_val = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_out_t));
	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	if (_tmp_val != NULL) {
		if ((_in_val = (int*)malloc(_len_val)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_val, 0, _len_val);
	}
	ecall_pointer_out(_in_val);
err:
	if (_in_val) {
		memcpy(_tmp_val, _in_val, _len_val);
		free(_in_val);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_in_out(void* pms)
{
	ms_ecall_pointer_in_out_t* ms = SGX_CAST(ms_ecall_pointer_in_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(*_tmp_val);
	int* _in_val = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_in_out_t));
	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	if (_tmp_val != NULL) {
		_in_val = (int*)malloc(_len_val);
		if (_in_val == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_val, _tmp_val, _len_val);
	}
	ecall_pointer_in_out(_in_val);
err:
	if (_in_val) {
		memcpy(_tmp_val, _in_val, _len_val);
		free(_in_val);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_string(void* pms)
{
	ms_ecall_pointer_string_t* ms = SGX_CAST(ms_ecall_pointer_string_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = _tmp_str ? strlen(_tmp_str) + 1 : 0;
	char* _in_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_string_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
		_in_str[_len_str - 1] = '\0';
	}
	ecall_pointer_string(_in_str);
err:
	if (_in_str) {
		memcpy(_tmp_str, _in_str, _len_str);
		free(_in_str);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_string_const(void* pms)
{
	ms_ecall_pointer_string_const_t* ms = SGX_CAST(ms_ecall_pointer_string_const_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = _tmp_str ? strlen(_tmp_str) + 1 : 0;
	char* _in_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_string_const_t));
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
	ecall_pointer_string_const((const char*)_in_str);
err:
	if (_in_str) free((void*)_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_size(void* pms)
{
	ms_ecall_pointer_size_t* ms = SGX_CAST(ms_ecall_pointer_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_ptr = ms->ms_ptr;
	size_t _tmp_len = ms->ms_len;
	size_t _len_ptr = _tmp_len;
	void* _in_ptr = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_size_t));
	CHECK_UNIQUE_POINTER(_tmp_ptr, _len_ptr);

	if (_tmp_ptr != NULL) {
		_in_ptr = (void*)malloc(_len_ptr);
		if (_in_ptr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ptr, _tmp_ptr, _len_ptr);
	}
	ecall_pointer_size(_in_ptr, _tmp_len);
err:
	if (_in_ptr) {
		memcpy(_tmp_ptr, _in_ptr, _len_ptr);
		free(_in_ptr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_count(void* pms)
{
	ms_ecall_pointer_count_t* ms = SGX_CAST(ms_ecall_pointer_count_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	int _tmp_cnt = ms->ms_cnt;
	size_t _len_arr = _tmp_cnt * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	if ((size_t)_tmp_cnt > (SIZE_MAX / sizeof(*_tmp_arr))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_count_t));
	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	ecall_pointer_count(_in_arr, _tmp_cnt);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_isptr_readonly(void* pms)
{
	ms_ecall_pointer_isptr_readonly_t* ms = SGX_CAST(ms_ecall_pointer_isptr_readonly_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	buffer_t _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len;
	buffer_t _in_buf = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_isptr_readonly_t));
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL) {
		_in_buf = (buffer_t)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_buf, _tmp_buf, _len_buf);
	}
	ecall_pointer_isptr_readonly(_in_buf, _tmp_len);
err:
	if (_in_buf) free((void*)_in_buf);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_sizefunc(void* pms)
{
	ms_ecall_pointer_sizefunc_t* ms = SGX_CAST(ms_ecall_pointer_sizefunc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _len_buf = ((_tmp_buf) ? get_buffer_len(_tmp_buf) : 0);
	char* _in_buf = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_sizefunc_t));
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL) {
		_in_buf = (char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_buf, _tmp_buf, _len_buf);

		/* check whether the pointer is modified. */
		if (get_buffer_len(_in_buf) != _len_buf) {
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
	}
	ecall_pointer_sizefunc(_in_buf);
err:
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ocall_pointer_attr(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_pointer_attr();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_user_check(void* pms)
{
	ms_ecall_array_user_check_t* ms = SGX_CAST(ms_ecall_array_user_check_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_user_check_t));

	ecall_array_user_check(_tmp_arr);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_in(void* pms)
{
	ms_ecall_array_in_t* ms = SGX_CAST(ms_ecall_array_in_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_in_t));
	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	ecall_array_in(_in_arr);
err:
	if (_in_arr) free(_in_arr);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_out(void* pms)
{
	ms_ecall_array_out_t* ms = SGX_CAST(ms_ecall_array_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_out_t));
	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL) {
		if ((_in_arr = (int*)malloc(_len_arr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_arr, 0, _len_arr);
	}
	ecall_array_out(_in_arr);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_in_out(void* pms)
{
	ms_ecall_array_in_out_t* ms = SGX_CAST(ms_ecall_array_in_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_in_out_t));
	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	ecall_array_in_out(_in_arr);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_isary(void* pms)
{
	ms_ecall_array_isary_t* ms = SGX_CAST(ms_ecall_array_isary_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_isary_t));

	ecall_array_isary((ms->ms_arr != NULL) ? (*ms->ms_arr) : NULL);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_calling_convs(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_function_calling_convs();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_public(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_function_public();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_private(void* pms)
{
	ms_ecall_function_private_t* ms = SGX_CAST(ms_ecall_function_private_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_function_private_t));

	ms->ms_retval = ecall_function_private();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_malloc_free(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_malloc_free();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sgx_cpuid(void* pms)
{
	ms_ecall_sgx_cpuid_t* ms = SGX_CAST(ms_ecall_sgx_cpuid_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_cpuinfo = ms->ms_cpuinfo;
	size_t _len_cpuinfo = 4 * sizeof(*_tmp_cpuinfo);
	int* _in_cpuinfo = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sgx_cpuid_t));
	CHECK_UNIQUE_POINTER(_tmp_cpuinfo, _len_cpuinfo);

	if (_tmp_cpuinfo != NULL) {
		_in_cpuinfo = (int*)malloc(_len_cpuinfo);
		if (_in_cpuinfo == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_cpuinfo, _tmp_cpuinfo, _len_cpuinfo);
	}
	ecall_sgx_cpuid(_in_cpuinfo, ms->ms_leaf);
err:
	if (_in_cpuinfo) {
		memcpy(_tmp_cpuinfo, _in_cpuinfo, _len_cpuinfo);
		free(_in_cpuinfo);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_exception(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_exception();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_map(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_map();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_increase_counter(void* pms)
{
	ms_ecall_increase_counter_t* ms = SGX_CAST(ms_ecall_increase_counter_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_increase_counter_t));

	ms->ms_retval = ecall_increase_counter();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_producer(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_producer();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_consumer(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_consumer();
	return status;
}

static sgx_status_t SGX_CDECL sgx_get_next_block_key(void* pms)
{
	ms_get_next_block_key_t* ms = SGX_CAST(ms_get_next_block_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = sizeof(*_tmp_str);
	char* _in_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_get_next_block_key_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
	}
	ms->ms_retval = get_next_block_key(_in_str, ms->ms_len, ms->ms_B_ID);
err:
	if (_in_str) free(_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_get_next_message_key(void* pms)
{
	ms_get_next_message_key_t* ms = SGX_CAST(ms_get_next_message_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = sizeof(*_tmp_str);
	char* _in_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_get_next_message_key_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
	}
	ms->ms_retval = get_next_message_key(_in_str, ms->ms_len, ms->ms_M_ID);
err:
	if (_in_str) free(_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_get_mac(void* pms)
{
	ms_get_mac_t* ms = SGX_CAST(ms_get_mac_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = sizeof(*_tmp_str);
	char* _in_str = NULL;
	char* _tmp_key = ms->ms_key;
	size_t _len_key = sizeof(*_tmp_key);
	char* _in_key = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_get_mac_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);
	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
	}
	if (_tmp_key != NULL) {
		_in_key = (char*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_key, _tmp_key, _len_key);
	}
	ms->ms_retval = get_mac(_in_str, ms->ms_len, _in_key);
err:
	if (_in_str) free(_in_str);
	if (_in_key) free(_in_key);

	return status;
}

static sgx_status_t SGX_CDECL sgx_hash(void* pms)
{
	ms_hash_t* ms = SGX_CAST(ms_hash_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = sizeof(*_tmp_str);
	char* _in_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_hash_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
	}
	ms->ms_retval = hash(_in_str, ms->ms_len);
err:
	if (_in_str) free(_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_compareHashValues(void* pms)
{
	ms_compareHashValues_t* ms = SGX_CAST(ms_compareHashValues_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_old_hash = ms->ms_old_hash;
	size_t _len_old_hash = sizeof(*_tmp_old_hash);
	char* _in_old_hash = NULL;
	char* _tmp_new_hash = ms->ms_new_hash;
	size_t _len_new_hash = sizeof(*_tmp_new_hash);
	char* _in_new_hash = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_compareHashValues_t));
	CHECK_UNIQUE_POINTER(_tmp_old_hash, _len_old_hash);
	CHECK_UNIQUE_POINTER(_tmp_new_hash, _len_new_hash);

	if (_tmp_old_hash != NULL) {
		_in_old_hash = (char*)malloc(_len_old_hash);
		if (_in_old_hash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_old_hash, _tmp_old_hash, _len_old_hash);
	}
	if (_tmp_new_hash != NULL) {
		_in_new_hash = (char*)malloc(_len_new_hash);
		if (_in_new_hash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_new_hash, _tmp_new_hash, _len_new_hash);
	}
	ms->ms_retval = compareHashValues(_in_old_hash, _in_new_hash, ms->ms_len);
err:
	if (_in_old_hash) free(_in_old_hash);
	if (_in_new_hash) free(_in_new_hash);

	return status;
}

static sgx_status_t SGX_CDECL sgx_reverse(void* pms)
{
	ms_reverse_t* ms = SGX_CAST(ms_reverse_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	int _tmp_length = ms->ms_length;
	size_t _len_str = _tmp_length * sizeof(*_tmp_str);
	char* _in_str = NULL;

	if ((size_t)_tmp_length > (SIZE_MAX / sizeof(*_tmp_str))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_reverse_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
	}
	reverse(_in_str, _tmp_length);
err:
	if (_in_str) free(_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_itoa(void* pms)
{
	ms_itoa_t* ms = SGX_CAST(ms_itoa_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = sizeof(*_tmp_str);
	char* _in_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_itoa_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
	}
	ms->ms_retval = itoa(ms->ms_num, _in_str, ms->ms_base);
err:
	if (_in_str) free(_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_myAtoi(void* pms)
{
	ms_myAtoi_t* ms = SGX_CAST(ms_myAtoi_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = sizeof(*_tmp_str);
	char* _in_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_myAtoi_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
	}
	ms->ms_retval = myAtoi(_in_str);
err:
	if (_in_str) free(_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_get_hash(void* pms)
{
	ms_get_hash_t* ms = SGX_CAST(ms_get_hash_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	int _tmp_len = ms->ms_len;
	size_t _len_str = _tmp_len * sizeof(*_tmp_str);
	char* _in_str = NULL;

	if ((size_t)_tmp_len > (SIZE_MAX / sizeof(*_tmp_str))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_get_hash_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
	}
	ms->ms_retval = get_hash(_in_str, _tmp_len);
err:
	if (_in_str) free(_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_seal_data(void* pms)
{
	ms_seal_data_t* ms = SGX_CAST(ms_seal_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_log_buffer = ms->ms_log_buffer;
	uint32_t _tmp_log_buffer_length = ms->ms_log_buffer_length;
	size_t _len_log_buffer = _tmp_log_buffer_length * sizeof(*_tmp_log_buffer);
	uint8_t* _in_log_buffer = NULL;

	if ((size_t)_tmp_log_buffer_length > (SIZE_MAX / sizeof(*_tmp_log_buffer))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_seal_data_t));
	CHECK_UNIQUE_POINTER(_tmp_log_buffer, _len_log_buffer);

	if (_tmp_log_buffer != NULL) {
		_in_log_buffer = (uint8_t*)malloc(_len_log_buffer);
		if (_in_log_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_log_buffer, _tmp_log_buffer, _len_log_buffer);
	}
	ms->ms_retval = seal_data(_in_log_buffer, _tmp_log_buffer_length);
err:
	if (_in_log_buffer) free(_in_log_buffer);

	return status;
}

static sgx_status_t SGX_CDECL sgx_seal_and_write(void* pms)
{
	ms_seal_and_write_t* ms = SGX_CAST(ms_seal_and_write_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = sizeof(*_tmp_str);
	char* _in_str = NULL;
	char* _tmp_filename = ms->ms_filename;
	size_t _len_filename = sizeof(*_tmp_filename);
	char* _in_filename = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_seal_and_write_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);
	CHECK_UNIQUE_POINTER(_tmp_filename, _len_filename);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
	}
	if (_tmp_filename != NULL) {
		_in_filename = (char*)malloc(_len_filename);
		if (_in_filename == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_filename, _tmp_filename, _len_filename);
	}
	seal_and_write(_in_str, _in_filename);
err:
	if (_in_str) free(_in_str);
	if (_in_filename) free(_in_filename);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[50];
} g_ecall_table = {
	50,
	{
		{(void*)(uintptr_t)sgx_process_log, 0},
		{(void*)(uintptr_t)sgx_verify_block_messages, 0},
		{(void*)(uintptr_t)sgx_generate_config, 0},
		{(void*)(uintptr_t)sgx_startup_phase, 0},
		{(void*)(uintptr_t)sgx_reset_block_key, 0},
		{(void*)(uintptr_t)sgx_ecall_type_char, 0},
		{(void*)(uintptr_t)sgx_ecall_type_int, 0},
		{(void*)(uintptr_t)sgx_ecall_type_float, 0},
		{(void*)(uintptr_t)sgx_ecall_type_double, 0},
		{(void*)(uintptr_t)sgx_ecall_type_size_t, 0},
		{(void*)(uintptr_t)sgx_ecall_type_wchar_t, 0},
		{(void*)(uintptr_t)sgx_ecall_type_struct, 0},
		{(void*)(uintptr_t)sgx_ecall_type_enum_union, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_user_check, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_in, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_out, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_in_out, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_string, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_string_const, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_size, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_count, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_isptr_readonly, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_sizefunc, 0},
		{(void*)(uintptr_t)sgx_ocall_pointer_attr, 0},
		{(void*)(uintptr_t)sgx_ecall_array_user_check, 0},
		{(void*)(uintptr_t)sgx_ecall_array_in, 0},
		{(void*)(uintptr_t)sgx_ecall_array_out, 0},
		{(void*)(uintptr_t)sgx_ecall_array_in_out, 0},
		{(void*)(uintptr_t)sgx_ecall_array_isary, 0},
		{(void*)(uintptr_t)sgx_ecall_function_calling_convs, 0},
		{(void*)(uintptr_t)sgx_ecall_function_public, 0},
		{(void*)(uintptr_t)sgx_ecall_function_private, 1},
		{(void*)(uintptr_t)sgx_ecall_malloc_free, 0},
		{(void*)(uintptr_t)sgx_ecall_sgx_cpuid, 0},
		{(void*)(uintptr_t)sgx_ecall_exception, 0},
		{(void*)(uintptr_t)sgx_ecall_map, 0},
		{(void*)(uintptr_t)sgx_ecall_increase_counter, 0},
		{(void*)(uintptr_t)sgx_ecall_producer, 0},
		{(void*)(uintptr_t)sgx_ecall_consumer, 0},
		{(void*)(uintptr_t)sgx_get_next_block_key, 0},
		{(void*)(uintptr_t)sgx_get_next_message_key, 0},
		{(void*)(uintptr_t)sgx_get_mac, 0},
		{(void*)(uintptr_t)sgx_hash, 0},
		{(void*)(uintptr_t)sgx_compareHashValues, 0},
		{(void*)(uintptr_t)sgx_reverse, 0},
		{(void*)(uintptr_t)sgx_itoa, 0},
		{(void*)(uintptr_t)sgx_myAtoi, 0},
		{(void*)(uintptr_t)sgx_get_hash, 0},
		{(void*)(uintptr_t)sgx_seal_data, 0},
		{(void*)(uintptr_t)sgx_seal_and_write, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[19][50];
} g_dyn_entry_table = {
	19,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
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

sgx_status_t SGX_CDECL ocall_read_config_data(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_read_config_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_config_data_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_config_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_config_data_t));

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
	
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read_log_messages(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_read_log_messages_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_log_messages_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_log_messages_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_log_messages_t));

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
	
	status = sgx_ocall(2, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_listen_log_messages()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(3, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_write_region_data(uint32_t* retval, uint8_t* blob, uint32_t bloblen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_blob = bloblen;

	ms_ocall_write_region_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_region_data_t);
	void *__tmp = NULL;

	ocalloc_size += (blob != NULL && sgx_is_within_enclave(blob, _len_blob)) ? _len_blob : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_region_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_region_data_t));

	if (blob != NULL && sgx_is_within_enclave(blob, _len_blob)) {
		ms->ms_blob = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_blob);
		memcpy(ms->ms_blob, blob, _len_blob);
	} else if (blob == NULL) {
		ms->ms_blob = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_bloblen = bloblen;
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read_region_data(uint32_t* retval, uint8_t* blob, uint32_t bloblen_in, uint32_t* bloblen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_blob = bloblen_in;
	size_t _len_bloblen_out = sizeof(*bloblen_out);

	ms_ocall_read_region_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_region_data_t);
	void *__tmp = NULL;

	ocalloc_size += (blob != NULL && sgx_is_within_enclave(blob, _len_blob)) ? _len_blob : 0;
	ocalloc_size += (bloblen_out != NULL && sgx_is_within_enclave(bloblen_out, _len_bloblen_out)) ? _len_bloblen_out : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_region_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_region_data_t));

	if (blob != NULL && sgx_is_within_enclave(blob, _len_blob)) {
		ms->ms_blob = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_blob);
		memset(ms->ms_blob, 0, _len_blob);
	} else if (blob == NULL) {
		ms->ms_blob = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_bloblen_in = bloblen_in;
	if (bloblen_out != NULL && sgx_is_within_enclave(bloblen_out, _len_bloblen_out)) {
		ms->ms_bloblen_out = (uint32_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_bloblen_out);
		memset(ms->ms_bloblen_out, 0, _len_bloblen_out);
	} else if (bloblen_out == NULL) {
		ms->ms_bloblen_out = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;
	if (blob) memcpy((void*)blob, ms->ms_blob, _len_blob);
	if (bloblen_out) memcpy((void*)bloblen_out, ms->ms_bloblen_out, _len_bloblen_out);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write_sealed_data(uint32_t* retval, uint8_t* blob, uint32_t bloblen, const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_blob = bloblen;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_write_sealed_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_sealed_data_t);
	void *__tmp = NULL;

	ocalloc_size += (blob != NULL && sgx_is_within_enclave(blob, _len_blob)) ? _len_blob : 0;
	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_sealed_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_sealed_data_t));

	if (blob != NULL && sgx_is_within_enclave(blob, _len_blob)) {
		ms->ms_blob = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_blob);
		memcpy(ms->ms_blob, blob, _len_blob);
	} else if (blob == NULL) {
		ms->ms_blob = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_bloblen = bloblen;
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
	
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read_sealed_data(uint32_t* retval, char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_read_sealed_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_sealed_data_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_sealed_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_sealed_data_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy(ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_user_check(int* val)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pointer_user_check_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_user_check_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_user_check_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_user_check_t));

	ms->ms_val = SGX_CAST(int*, val);
	status = sgx_ocall(8, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_in(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(*val);

	ms_ocall_pointer_in_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_in_t);
	void *__tmp = NULL;

	ocalloc_size += (val != NULL && sgx_is_within_enclave(val, _len_val)) ? _len_val : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_in_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_in_t));

	if (val != NULL && sgx_is_within_enclave(val, _len_val)) {
		ms->ms_val = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_val);
		memcpy(ms->ms_val, val, _len_val);
	} else if (val == NULL) {
		ms->ms_val = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(9, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_out(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(*val);

	ms_ocall_pointer_out_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_out_t);
	void *__tmp = NULL;

	ocalloc_size += (val != NULL && sgx_is_within_enclave(val, _len_val)) ? _len_val : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_out_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_out_t));

	if (val != NULL && sgx_is_within_enclave(val, _len_val)) {
		ms->ms_val = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_val);
		memset(ms->ms_val, 0, _len_val);
	} else if (val == NULL) {
		ms->ms_val = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(10, ms);

	if (val) memcpy((void*)val, ms->ms_val, _len_val);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_in_out(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(*val);

	ms_ocall_pointer_in_out_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_in_out_t);
	void *__tmp = NULL;

	ocalloc_size += (val != NULL && sgx_is_within_enclave(val, _len_val)) ? _len_val : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_in_out_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_in_out_t));

	if (val != NULL && sgx_is_within_enclave(val, _len_val)) {
		ms->ms_val = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_val);
		memcpy(ms->ms_val, val, _len_val);
	} else if (val == NULL) {
		ms->ms_val = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(11, ms);

	if (val) memcpy((void*)val, ms->ms_val, _len_val);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL memccpy(void** retval, void* dest, const void* src, int val, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dest = len;
	size_t _len_src = len;

	ms_memccpy_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_memccpy_t);
	void *__tmp = NULL;

	ocalloc_size += (dest != NULL && sgx_is_within_enclave(dest, _len_dest)) ? _len_dest : 0;
	ocalloc_size += (src != NULL && sgx_is_within_enclave(src, _len_src)) ? _len_src : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_memccpy_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_memccpy_t));

	if (dest != NULL && sgx_is_within_enclave(dest, _len_dest)) {
		ms->ms_dest = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dest);
		memcpy(ms->ms_dest, dest, _len_dest);
	} else if (dest == NULL) {
		ms->ms_dest = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (src != NULL && sgx_is_within_enclave(src, _len_src)) {
		ms->ms_src = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_src);
		memcpy((void*)ms->ms_src, src, _len_src);
	} else if (src == NULL) {
		ms->ms_src = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_val = val;
	ms->ms_len = len;
	status = sgx_ocall(12, ms);

	if (retval) *retval = ms->ms_retval;
	if (dest) memcpy((void*)dest, ms->ms_dest, _len_dest);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_function_allow()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(13, NULL);

	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(14, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(15, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(16, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(17, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(18, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

