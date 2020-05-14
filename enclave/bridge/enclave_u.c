#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ec_int4_cmp_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
} ms_ec_int4_cmp_t;

typedef struct ms_ec_int4_add_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_int4_add_t;

typedef struct ms_ec_int4_sub_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_int4_sub_t;

typedef struct ms_ec_int4_mul_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_int4_mul_t;

typedef struct ms_ec_int4_div_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_int4_div_t;

typedef struct ms_ec_int4_mod_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_int4_mod_t;

typedef struct ms_ec_int4_pow_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_int4_pow_t;

typedef struct ms_ec_int4_div2_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	int ms_rhs;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_int4_div2_t;

typedef struct ms_ec_float4_cmp_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
} ms_ec_float4_cmp_t;

typedef struct ms_ec_float4_add_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_float4_add_t;

typedef struct ms_ec_float4_sub_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_float4_sub_t;

typedef struct ms_ec_float4_mul_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_float4_mul_t;

typedef struct ms_ec_float4_div_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_float4_div_t;

typedef struct ms_ec_float4_mod_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_float4_mod_t;

typedef struct ms_ec_float4_pow_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_float4_pow_t;

typedef struct ms_ec_float4_div2_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	float ms_rhs;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_float4_div2_t;

typedef struct ms_ec_text_cmp_t {
	int ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
} ms_ec_text_cmp_t;

typedef struct ms_ec_text_concat_t {
	size_t ms_retval;
	uint8_t* ms_lhs;
	size_t ms_lhs_size;
	uint8_t* ms_rhs;
	size_t ms_rhs_size;
	uint8_t* ms_result;
	size_t ms_result_size;
} ms_ec_text_concat_t;

typedef struct ms_ec_text_match_like_t {
	int ms_retval;
	uint8_t* ms_text;
	size_t ms_text_size;
	uint8_t* ms_pattern;
	size_t ms_pattern_size;
} ms_ec_text_match_like_t;

typedef struct ms_ecall_encrypt_value_t {
	int ms_retval;
	uint8_t* ms_input;
	size_t ms_input_size;
	char* ms_output;
} ms_ecall_encrypt_value_t;

typedef struct ms_ecall_decrypt_value_t {
	int ms_retval;
	uint8_t* ms_input;
	size_t ms_input_size;
	char* ms_output;
} ms_ecall_decrypt_value_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_enclave = {
	5,
	{
		(void*)enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)enclave_ocall_print_string,
	}
};
sgx_status_t ec_int4_cmp(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size)
{
	sgx_status_t status;
	ms_ec_int4_cmp_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	status = sgx_ecall_switchless(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_int4_add(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_int4_add_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_int4_sub(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_int4_sub_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_int4_mul(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_int4_mul_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_int4_div(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_int4_div_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 4, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_int4_mod(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_int4_mod_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 5, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_int4_pow(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_int4_pow_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 6, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_int4_div2(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, int rhs, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_int4_div2_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 7, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_float4_cmp(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size)
{
	sgx_status_t status;
	ms_ec_float4_cmp_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	status = sgx_ecall_switchless(eid, 8, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_float4_add(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_float4_add_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 9, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_float4_sub(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_float4_sub_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 10, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_float4_mul(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_float4_mul_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 11, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_float4_div(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_float4_div_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 12, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_float4_mod(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_float4_mod_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 13, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_float4_pow(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_float4_pow_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 14, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_float4_div2(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, float rhs, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_float4_div2_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 15, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_text_cmp(sgx_enclave_id_t eid, int* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size)
{
	sgx_status_t status;
	ms_ec_text_cmp_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	status = sgx_ecall_switchless(eid, 16, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_text_concat(sgx_enclave_id_t eid, size_t* retval, uint8_t* lhs, size_t lhs_size, uint8_t* rhs, size_t rhs_size, uint8_t* result, size_t result_size)
{
	sgx_status_t status;
	ms_ec_text_concat_t ms;
	ms.ms_lhs = lhs;
	ms.ms_lhs_size = lhs_size;
	ms.ms_rhs = rhs;
	ms.ms_rhs_size = rhs_size;
	ms.ms_result = result;
	ms.ms_result_size = result_size;
	status = sgx_ecall_switchless(eid, 17, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ec_text_match_like(sgx_enclave_id_t eid, int* retval, uint8_t* text, size_t text_size, uint8_t* pattern, size_t pattern_size)
{
	sgx_status_t status;
	ms_ec_text_match_like_t ms;
	ms.ms_text = text;
	ms.ms_text_size = text_size;
	ms.ms_pattern = pattern;
	ms.ms_pattern_size = pattern_size;
	status = sgx_ecall_switchless(eid, 18, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_encrypt_value(sgx_enclave_id_t eid, int* retval, uint8_t* input, size_t input_size, char* output)
{
	sgx_status_t status;
	ms_ecall_encrypt_value_t ms;
	ms.ms_input = input;
	ms.ms_input_size = input_size;
	ms.ms_output = output;
	status = sgx_ecall_switchless(eid, 19, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_decrypt_value(sgx_enclave_id_t eid, int* retval, uint8_t* input, size_t input_size, char* output)
{
	sgx_status_t status;
	ms_ecall_decrypt_value_t ms;
	ms.ms_input = input;
	ms.ms_input_size = input_size;
	ms.ms_output = output;
	status = sgx_ecall_switchless(eid, 20, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

