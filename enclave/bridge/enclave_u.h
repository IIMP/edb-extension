#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t ec_int4_cmp(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size);
sgx_status_t ec_int4_add(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_int4_sub(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_int4_mul(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_int4_div(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_int4_mod(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_int4_pow(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_int4_div2(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, int rhs, uint8_t* result, size_t result_size);
sgx_status_t ec_float4_cmp(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size);
sgx_status_t ec_float4_add(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_float4_sub(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_float4_mul(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_float4_div(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_float4_mod(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_float4_pow(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_float4_div2(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, float rhs, uint8_t* result, size_t result_size);
sgx_status_t ec_text_cmp(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size);
sgx_status_t ec_text_concat(sgx_enclave_id_t eid, size_t* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size);
sgx_status_t ec_text_match_like(sgx_enclave_id_t eid, int* retval, uint8_t* text, size_t text_size, uint8_t* pattern, size_t pattern_size);
sgx_status_t ecall_encrypt_value(sgx_enclave_id_t eid, int* retval, uint8_t* input, size_t input_size, char* output);
sgx_status_t ecall_decrypt_value(sgx_enclave_id_t eid, int* retval, uint8_t* input, size_t input_size, char* output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
