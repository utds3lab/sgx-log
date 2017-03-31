#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_config_data(void* pms)
{
	ms_ocall_read_config_data_t* ms = SGX_CAST(ms_ocall_read_config_data_t*, pms);
	ocall_read_config_data((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_log_messages(void* pms)
{
	ms_ocall_read_log_messages_t* ms = SGX_CAST(ms_ocall_read_log_messages_t*, pms);
	ocall_read_log_messages((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_listen_log_messages(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_listen_log_messages();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write_region_data(void* pms)
{
	ms_ocall_write_region_data_t* ms = SGX_CAST(ms_ocall_write_region_data_t*, pms);
	ms->ms_retval = ocall_write_region_data(ms->ms_blob, ms->ms_bloblen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_region_data(void* pms)
{
	ms_ocall_read_region_data_t* ms = SGX_CAST(ms_ocall_read_region_data_t*, pms);
	ms->ms_retval = ocall_read_region_data(ms->ms_blob, ms->ms_bloblen_in, ms->ms_bloblen_out);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write_sealed_data(void* pms)
{
	ms_ocall_write_sealed_data_t* ms = SGX_CAST(ms_ocall_write_sealed_data_t*, pms);
	ms->ms_retval = ocall_write_sealed_data(ms->ms_blob, ms->ms_bloblen, (const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_sealed_data(void* pms)
{
	ms_ocall_read_sealed_data_t* ms = SGX_CAST(ms_ocall_read_sealed_data_t*, pms);
	ms->ms_retval = ocall_read_sealed_data(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_user_check(void* pms)
{
	ms_ocall_pointer_user_check_t* ms = SGX_CAST(ms_ocall_pointer_user_check_t*, pms);
	ocall_pointer_user_check(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_in(void* pms)
{
	ms_ocall_pointer_in_t* ms = SGX_CAST(ms_ocall_pointer_in_t*, pms);
	ocall_pointer_in(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_out(void* pms)
{
	ms_ocall_pointer_out_t* ms = SGX_CAST(ms_ocall_pointer_out_t*, pms);
	ocall_pointer_out(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_in_out(void* pms)
{
	ms_ocall_pointer_in_out_t* ms = SGX_CAST(ms_ocall_pointer_in_out_t*, pms);
	ocall_pointer_in_out(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_memccpy(void* pms)
{
	ms_memccpy_t* ms = SGX_CAST(ms_memccpy_t*, pms);
	ms->ms_retval = memccpy(ms->ms_dest, (const void*)ms->ms_src, ms->ms_val, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_function_allow(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_function_allow();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[19];
} ocall_table_Enclave = {
	19,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_read_config_data,
		(void*)Enclave_ocall_read_log_messages,
		(void*)Enclave_ocall_listen_log_messages,
		(void*)Enclave_ocall_write_region_data,
		(void*)Enclave_ocall_read_region_data,
		(void*)Enclave_ocall_write_sealed_data,
		(void*)Enclave_ocall_read_sealed_data,
		(void*)Enclave_ocall_pointer_user_check,
		(void*)Enclave_ocall_pointer_in,
		(void*)Enclave_ocall_pointer_out,
		(void*)Enclave_ocall_pointer_in_out,
		(void*)Enclave_memccpy,
		(void*)Enclave_ocall_function_allow,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t process_log(sgx_enclave_id_t eid, char* str)
{
	sgx_status_t status;
	ms_process_log_t ms;
	ms.ms_str = str;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t verify_block_messages(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_verify_block_messages_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t generate_config(sgx_enclave_id_t eid, const char* str, int len)
{
	sgx_status_t status;
	ms_generate_config_t ms;
	ms.ms_str = (char*)str;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t startup_phase(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t reset_block_key(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_type_char(sgx_enclave_id_t eid, char val)
{
	sgx_status_t status;
	ms_ecall_type_char_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_int(sgx_enclave_id_t eid, int val)
{
	sgx_status_t status;
	ms_ecall_type_int_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_float(sgx_enclave_id_t eid, float val)
{
	sgx_status_t status;
	ms_ecall_type_float_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_double(sgx_enclave_id_t eid, double val)
{
	sgx_status_t status;
	ms_ecall_type_double_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_size_t(sgx_enclave_id_t eid, size_t val)
{
	sgx_status_t status;
	ms_ecall_type_size_t_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_wchar_t(sgx_enclave_id_t eid, wchar_t val)
{
	sgx_status_t status;
	ms_ecall_type_wchar_t_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_struct(sgx_enclave_id_t eid, struct struct_foo_t val)
{
	sgx_status_t status;
	ms_ecall_type_struct_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_enum_union(sgx_enclave_id_t eid, enum enum_foo_t val1, union union_foo_t* val2)
{
	sgx_status_t status;
	ms_ecall_type_enum_union_t ms;
	ms.ms_val1 = val1;
	ms.ms_val2 = val2;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_user_check(sgx_enclave_id_t eid, size_t* retval, void* val, size_t sz)
{
	sgx_status_t status;
	ms_ecall_pointer_user_check_t ms;
	ms.ms_val = val;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_pointer_in(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_ecall_pointer_in_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_out(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_ecall_pointer_out_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_in_out(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_ecall_pointer_in_out_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 16, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_string(sgx_enclave_id_t eid, char* str)
{
	sgx_status_t status;
	ms_ecall_pointer_string_t ms;
	ms.ms_str = str;
	status = sgx_ecall(eid, 17, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_string_const(sgx_enclave_id_t eid, const char* str)
{
	sgx_status_t status;
	ms_ecall_pointer_string_const_t ms;
	ms.ms_str = (char*)str;
	status = sgx_ecall(eid, 18, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_size(sgx_enclave_id_t eid, void* ptr, size_t len)
{
	sgx_status_t status;
	ms_ecall_pointer_size_t ms;
	ms.ms_ptr = ptr;
	ms.ms_len = len;
	status = sgx_ecall(eid, 19, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_count(sgx_enclave_id_t eid, int* arr, int cnt)
{
	sgx_status_t status;
	ms_ecall_pointer_count_t ms;
	ms.ms_arr = arr;
	ms.ms_cnt = cnt;
	status = sgx_ecall(eid, 20, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_isptr_readonly(sgx_enclave_id_t eid, buffer_t buf, size_t len)
{
	sgx_status_t status;
	ms_ecall_pointer_isptr_readonly_t ms;
	ms.ms_buf = (buffer_t)buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 21, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_sizefunc(sgx_enclave_id_t eid, char* buf)
{
	sgx_status_t status;
	ms_ecall_pointer_sizefunc_t ms;
	ms.ms_buf = buf;
	status = sgx_ecall(eid, 22, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ocall_pointer_attr(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 23, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_array_user_check(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_user_check_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 24, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_in(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_in_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 25, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_out(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_out_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 26, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_in_out(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_in_out_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 27, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_isary(sgx_enclave_id_t eid, array_t arr)
{
	sgx_status_t status;
	ms_ecall_array_isary_t ms;
	ms.ms_arr = (array_t *)&arr[0];
	status = sgx_ecall(eid, 28, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_function_calling_convs(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 29, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_function_public(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 30, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_function_private(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_function_private_t ms;
	status = sgx_ecall(eid, 31, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_malloc_free(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 32, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_sgx_cpuid(sgx_enclave_id_t eid, int cpuinfo[4], int leaf)
{
	sgx_status_t status;
	ms_ecall_sgx_cpuid_t ms;
	ms.ms_cpuinfo = (int*)cpuinfo;
	ms.ms_leaf = leaf;
	status = sgx_ecall(eid, 33, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_exception(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 34, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_map(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 35, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_increase_counter(sgx_enclave_id_t eid, size_t* retval)
{
	sgx_status_t status;
	ms_ecall_increase_counter_t ms;
	status = sgx_ecall(eid, 36, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_producer(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 37, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_consumer(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 38, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t get_next_block_key(sgx_enclave_id_t eid, char** retval, char* str, int len, int B_ID)
{
	sgx_status_t status;
	ms_get_next_block_key_t ms;
	ms.ms_str = str;
	ms.ms_len = len;
	ms.ms_B_ID = B_ID;
	status = sgx_ecall(eid, 39, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_next_message_key(sgx_enclave_id_t eid, char** retval, char* str, int len, int M_ID)
{
	sgx_status_t status;
	ms_get_next_message_key_t ms;
	ms.ms_str = str;
	ms.ms_len = len;
	ms.ms_M_ID = M_ID;
	status = sgx_ecall(eid, 40, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_mac(sgx_enclave_id_t eid, char** retval, char* str, int len, char* key)
{
	sgx_status_t status;
	ms_get_mac_t ms;
	ms.ms_str = str;
	ms.ms_len = len;
	ms.ms_key = key;
	status = sgx_ecall(eid, 41, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t hash(sgx_enclave_id_t eid, char** retval, char* str, int len)
{
	sgx_status_t status;
	ms_hash_t ms;
	ms.ms_str = str;
	ms.ms_len = len;
	status = sgx_ecall(eid, 42, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t compareHashValues(sgx_enclave_id_t eid, int* retval, char* old_hash, char* new_hash, int len)
{
	sgx_status_t status;
	ms_compareHashValues_t ms;
	ms.ms_old_hash = old_hash;
	ms.ms_new_hash = new_hash;
	ms.ms_len = len;
	status = sgx_ecall(eid, 43, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t reverse(sgx_enclave_id_t eid, char* str, int length)
{
	sgx_status_t status;
	ms_reverse_t ms;
	ms.ms_str = str;
	ms.ms_length = length;
	status = sgx_ecall(eid, 44, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t itoa(sgx_enclave_id_t eid, char** retval, int num, char* str, int base)
{
	sgx_status_t status;
	ms_itoa_t ms;
	ms.ms_num = num;
	ms.ms_str = str;
	ms.ms_base = base;
	status = sgx_ecall(eid, 45, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t myAtoi(sgx_enclave_id_t eid, int* retval, char* str)
{
	sgx_status_t status;
	ms_myAtoi_t ms;
	ms.ms_str = str;
	status = sgx_ecall(eid, 46, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_hash(sgx_enclave_id_t eid, char** retval, char* str, int len)
{
	sgx_status_t status;
	ms_get_hash_t ms;
	ms.ms_str = str;
	ms.ms_len = len;
	status = sgx_ecall(eid, 47, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal_data(sgx_enclave_id_t eid, char** retval, uint8_t* log_buffer, uint32_t log_buffer_length)
{
	sgx_status_t status;
	ms_seal_data_t ms;
	ms.ms_log_buffer = log_buffer;
	ms.ms_log_buffer_length = log_buffer_length;
	status = sgx_ecall(eid, 48, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal_and_write(sgx_enclave_id_t eid, char* str, char* filename)
{
	sgx_status_t status;
	ms_seal_and_write_t ms;
	ms.ms_str = str;
	ms.ms_filename = filename;
	status = sgx_ecall(eid, 49, &ocall_table_Enclave, &ms);
	return status;
}

