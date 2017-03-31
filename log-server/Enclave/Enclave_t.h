#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"
#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct struct_foo_t {
	uint32_t struct_foo_0;
	uint64_t struct_foo_1;
} struct_foo_t;

typedef enum enum_foo_t {
	ENUM_FOO_0 = 0,
	ENUM_FOO_1 = 1,
} enum_foo_t;

typedef union union_foo_t {
	uint32_t union_foo_0;
	uint32_t union_foo_1;
	uint64_t union_foo_3;
} union_foo_t;

size_t get_buffer_len(const char* val);

void process_log(char* str);
uint32_t verify_block_messages();
void generate_config(const char* str, int len);
void startup_phase();
void reset_block_key();
void ecall_type_char(char val);
void ecall_type_int(int val);
void ecall_type_float(float val);
void ecall_type_double(double val);
void ecall_type_size_t(size_t val);
void ecall_type_wchar_t(wchar_t val);
void ecall_type_struct(struct struct_foo_t val);
void ecall_type_enum_union(enum enum_foo_t val1, union union_foo_t* val2);
size_t ecall_pointer_user_check(void* val, size_t sz);
void ecall_pointer_in(int* val);
void ecall_pointer_out(int* val);
void ecall_pointer_in_out(int* val);
void ecall_pointer_string(char* str);
void ecall_pointer_string_const(const char* str);
void ecall_pointer_size(void* ptr, size_t len);
void ecall_pointer_count(int* arr, int cnt);
void ecall_pointer_isptr_readonly(buffer_t buf, size_t len);
void ecall_pointer_sizefunc(char* buf);
void ocall_pointer_attr();
void ecall_array_user_check(int arr[4]);
void ecall_array_in(int arr[4]);
void ecall_array_out(int arr[4]);
void ecall_array_in_out(int arr[4]);
void ecall_array_isary(array_t arr);
void ecall_function_calling_convs();
void ecall_function_public();
int ecall_function_private();
void ecall_malloc_free();
void ecall_sgx_cpuid(int cpuinfo[4], int leaf);
void ecall_exception();
void ecall_map();
size_t ecall_increase_counter();
void ecall_producer();
void ecall_consumer();
char* get_next_block_key(char* str, int len, int B_ID);
char* get_next_message_key(char* str, int len, int M_ID);
char* get_mac(char* str, int len, char* key);
char* hash(char* str, int len);
int compareHashValues(char* old_hash, char* new_hash, int len);
void reverse(char* str, int length);
char* itoa(int num, char* str, int base);
int myAtoi(char* str);
char* get_hash(char* str, int len);
char* seal_data(uint8_t* log_buffer, uint32_t log_buffer_length);
void seal_and_write(char* str, char* filename);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_read_config_data(const char* str);
sgx_status_t SGX_CDECL ocall_read_log_messages(const char* str);
sgx_status_t SGX_CDECL ocall_listen_log_messages();
sgx_status_t SGX_CDECL ocall_write_region_data(uint32_t* retval, uint8_t* blob, uint32_t bloblen);
sgx_status_t SGX_CDECL ocall_read_region_data(uint32_t* retval, uint8_t* blob, uint32_t bloblen_in, uint32_t* bloblen_out);
sgx_status_t SGX_CDECL ocall_write_sealed_data(uint32_t* retval, uint8_t* blob, uint32_t bloblen, const char* str);
sgx_status_t SGX_CDECL ocall_read_sealed_data(uint32_t* retval, char* str);
sgx_status_t SGX_CDECL ocall_pointer_user_check(int* val);
sgx_status_t SGX_CDECL ocall_pointer_in(int* val);
sgx_status_t SGX_CDECL ocall_pointer_out(int* val);
sgx_status_t SGX_CDECL ocall_pointer_in_out(int* val);
sgx_status_t SGX_CDECL memccpy(void** retval, void* dest, const void* src, int val, size_t len);
sgx_status_t SGX_CDECL ocall_function_allow();
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
