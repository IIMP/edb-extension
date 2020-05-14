#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ec_int4_cmp(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size);
int ec_int4_add(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_int4_sub(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_int4_mul(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_int4_div(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_int4_mod(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_int4_pow(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_int4_div2(uint8_t* lhs, size_t lhs_size, int rhs, uint8_t* result, size_t result_size);
int ec_float4_cmp(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size);
int ec_float4_add(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_float4_sub(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_float4_mul(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_float4_div(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_float4_mod(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_float4_pow(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_float4_div2(uint8_t* lhs, size_t lhs_size, float rhs, uint8_t* result, size_t result_size);
int ec_text_cmp(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size);
size_t ec_text_concat(uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
int ec_text_match_like(uint8_t* text, size_t text_size, uint8_t* pattern, size_t pattern_size);
int ecall_encrypt_value(uint8_t* input, size_t input_size, char* output);
int ecall_decrypt_value(uint8_t* input, size_t input_size, char* output);

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
