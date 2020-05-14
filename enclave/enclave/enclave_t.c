#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ec_int4_cmp(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_int4_cmp_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_int4_cmp_t* ms = SGX_CAST(ms_ec_int4_cmp_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ec_int4_cmp(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size);

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_int4_add(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_int4_add_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_int4_add_t* ms = SGX_CAST(ms_ec_int4_add_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_int4_add(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_int4_sub(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_int4_sub_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_int4_sub_t* ms = SGX_CAST(ms_ec_int4_sub_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_int4_sub(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_int4_mul(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_int4_mul_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_int4_mul_t* ms = SGX_CAST(ms_ec_int4_mul_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_int4_mul(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_int4_div(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_int4_div_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_int4_div_t* ms = SGX_CAST(ms_ec_int4_div_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_int4_div(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_int4_mod(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_int4_mod_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_int4_mod_t* ms = SGX_CAST(ms_ec_int4_mod_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_int4_mod(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_int4_pow(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_int4_pow_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_int4_pow_t* ms = SGX_CAST(ms_ec_int4_pow_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_int4_pow(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_int4_div2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_int4_div2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_int4_div2_t* ms = SGX_CAST(ms_ec_int4_div2_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_int4_div2(_in_lhs, _tmp_lhs_size, ms->ms_rhs, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_float4_cmp(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_float4_cmp_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_float4_cmp_t* ms = SGX_CAST(ms_ec_float4_cmp_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ec_float4_cmp(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size);

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_float4_add(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_float4_add_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_float4_add_t* ms = SGX_CAST(ms_ec_float4_add_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_float4_add(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_float4_sub(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_float4_sub_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_float4_sub_t* ms = SGX_CAST(ms_ec_float4_sub_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_float4_sub(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_float4_mul(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_float4_mul_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_float4_mul_t* ms = SGX_CAST(ms_ec_float4_mul_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_float4_mul(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_float4_div(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_float4_div_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_float4_div_t* ms = SGX_CAST(ms_ec_float4_div_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_float4_div(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_float4_mod(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_float4_mod_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_float4_mod_t* ms = SGX_CAST(ms_ec_float4_mod_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_float4_mod(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_float4_pow(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_float4_pow_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_float4_pow_t* ms = SGX_CAST(ms_ec_float4_pow_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_float4_pow(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_float4_div2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_float4_div2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_float4_div2_t* ms = SGX_CAST(ms_ec_float4_div2_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_float4_div2(_in_lhs, _tmp_lhs_size, ms->ms_rhs, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_text_cmp(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_text_cmp_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_text_cmp_t* ms = SGX_CAST(ms_ec_text_cmp_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ec_text_cmp(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size);

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_text_concat(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_text_concat_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_text_concat_t* ms = SGX_CAST(ms_ec_text_concat_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_lhs = ms->ms_lhs;
	size_t _tmp_lhs_size = ms->ms_lhs_size;
	size_t _len_lhs = _tmp_lhs_size * sizeof(uint8_t);
	uint8_t* _in_lhs = NULL;
	uint8_t* _tmp_rhs = ms->ms_rhs;
	size_t _tmp_rhs_size = ms->ms_rhs_size;
	size_t _len_rhs = _tmp_rhs_size * sizeof(uint8_t);
	uint8_t* _in_rhs = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _tmp_result_size = ms->ms_result_size;
	size_t _len_result = _tmp_result_size * sizeof(uint8_t);
	uint8_t* _in_result = NULL;

	if (sizeof(*_tmp_lhs) != 0 &&
		(size_t)_tmp_lhs_size > (SIZE_MAX / sizeof(*_tmp_lhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_rhs) != 0 &&
		(size_t)_tmp_rhs_size > (SIZE_MAX / sizeof(*_tmp_rhs))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_size > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_lhs, _len_lhs);
	CHECK_UNIQUE_POINTER(_tmp_rhs, _len_rhs);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_lhs != NULL && _len_lhs != 0) {
		if ( _len_lhs % sizeof(*_tmp_lhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_lhs = (uint8_t*)malloc(_len_lhs);
		if (_in_lhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_lhs, _len_lhs, _tmp_lhs, _len_lhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_rhs != NULL && _len_rhs != 0) {
		if ( _len_rhs % sizeof(*_tmp_rhs) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rhs = (uint8_t*)malloc(_len_rhs);
		if (_in_rhs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rhs, _len_rhs, _tmp_rhs, _len_rhs)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ec_text_concat(_in_lhs, _tmp_lhs_size, _in_rhs, _tmp_rhs_size, _in_result, _tmp_result_size);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_lhs) free(_in_lhs);
	if (_in_rhs) free(_in_rhs);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ec_text_match_like(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ec_text_match_like_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ec_text_match_like_t* ms = SGX_CAST(ms_ec_text_match_like_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_text = ms->ms_text;
	size_t _tmp_text_size = ms->ms_text_size;
	size_t _len_text = _tmp_text_size * sizeof(uint8_t);
	uint8_t* _in_text = NULL;
	uint8_t* _tmp_pattern = ms->ms_pattern;
	size_t _tmp_pattern_size = ms->ms_pattern_size;
	size_t _len_pattern = _tmp_pattern_size * sizeof(uint8_t);
	uint8_t* _in_pattern = NULL;

	if (sizeof(*_tmp_text) != 0 &&
		(size_t)_tmp_text_size > (SIZE_MAX / sizeof(*_tmp_text))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_pattern) != 0 &&
		(size_t)_tmp_pattern_size > (SIZE_MAX / sizeof(*_tmp_pattern))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_text, _len_text);
	CHECK_UNIQUE_POINTER(_tmp_pattern, _len_pattern);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_text != NULL && _len_text != 0) {
		if ( _len_text % sizeof(*_tmp_text) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_text = (uint8_t*)malloc(_len_text);
		if (_in_text == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_text, _len_text, _tmp_text, _len_text)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_pattern != NULL && _len_pattern != 0) {
		if ( _len_pattern % sizeof(*_tmp_pattern) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_pattern = (uint8_t*)malloc(_len_pattern);
		if (_in_pattern == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pattern, _len_pattern, _tmp_pattern, _len_pattern)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ec_text_match_like(_in_text, _tmp_text_size, _in_pattern, _tmp_pattern_size);

err:
	if (_in_text) free(_in_text);
	if (_in_pattern) free(_in_pattern);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_encrypt_value(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_encrypt_value_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_encrypt_value_t* ms = SGX_CAST(ms_ecall_encrypt_value_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_input = ms->ms_input;
	size_t _tmp_input_size = ms->ms_input_size;
	size_t _len_input = _tmp_input_size * sizeof(uint8_t);
	uint8_t* _in_input = NULL;
	char* _tmp_output = ms->ms_output;

	if (sizeof(*_tmp_input) != 0 &&
		(size_t)_tmp_input_size > (SIZE_MAX / sizeof(*_tmp_input))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_input != NULL && _len_input != 0) {
		if ( _len_input % sizeof(*_tmp_input) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_input = (uint8_t*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_input, _len_input, _tmp_input, _len_input)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_encrypt_value(_in_input, _tmp_input_size, _tmp_output);

err:
	if (_in_input) free(_in_input);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_decrypt_value(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_decrypt_value_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_decrypt_value_t* ms = SGX_CAST(ms_ecall_decrypt_value_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_input = ms->ms_input;
	size_t _tmp_input_size = ms->ms_input_size;
	size_t _len_input = _tmp_input_size * sizeof(uint8_t);
	uint8_t* _in_input = NULL;
	char* _tmp_output = ms->ms_output;

	if (sizeof(*_tmp_input) != 0 &&
		(size_t)_tmp_input_size > (SIZE_MAX / sizeof(*_tmp_input))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_input != NULL && _len_input != 0) {
		if ( _len_input % sizeof(*_tmp_input) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_input = (uint8_t*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_input, _len_input, _tmp_input, _len_input)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_decrypt_value(_in_input, _tmp_input_size, _tmp_output);

err:
	if (_in_input) free(_in_input);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[21];
} g_ecall_table = {
	21,
	{
		{(void*)(uintptr_t)sgx_ec_int4_cmp, 0, 1},
		{(void*)(uintptr_t)sgx_ec_int4_add, 0, 1},
		{(void*)(uintptr_t)sgx_ec_int4_sub, 0, 1},
		{(void*)(uintptr_t)sgx_ec_int4_mul, 0, 1},
		{(void*)(uintptr_t)sgx_ec_int4_div, 0, 1},
		{(void*)(uintptr_t)sgx_ec_int4_mod, 0, 1},
		{(void*)(uintptr_t)sgx_ec_int4_pow, 0, 1},
		{(void*)(uintptr_t)sgx_ec_int4_div2, 0, 1},
		{(void*)(uintptr_t)sgx_ec_float4_cmp, 0, 1},
		{(void*)(uintptr_t)sgx_ec_float4_add, 0, 1},
		{(void*)(uintptr_t)sgx_ec_float4_sub, 0, 1},
		{(void*)(uintptr_t)sgx_ec_float4_mul, 0, 1},
		{(void*)(uintptr_t)sgx_ec_float4_div, 0, 1},
		{(void*)(uintptr_t)sgx_ec_float4_mod, 0, 1},
		{(void*)(uintptr_t)sgx_ec_float4_pow, 0, 1},
		{(void*)(uintptr_t)sgx_ec_float4_div2, 0, 1},
		{(void*)(uintptr_t)sgx_ec_text_cmp, 0, 1},
		{(void*)(uintptr_t)sgx_ec_text_concat, 0, 1},
		{(void*)(uintptr_t)sgx_ec_text_match_like, 0, 1},
		{(void*)(uintptr_t)sgx_ecall_encrypt_value, 0, 1},
		{(void*)(uintptr_t)sgx_ecall_decrypt_value, 0, 1},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[5][21];
} g_dyn_entry_table = {
	5,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


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
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
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
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
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
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall_switchless(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

