#include "enclave_u.h"
#include <errno.h>


typedef struct ms_ecall_generate_password_t {
	int ms_retval;
	char* ms_p_value;
	int ms_p_length;
} ms_ecall_generate_password_t;

typedef struct ms_ecall_create_wallet_t {
	int ms_retval;
	uint8_t* ms_swallet
	const char* ms_master_password;
} ms_ecall_create_wallet_t;

typedef struct ms_ecall_change_master_password_t {
	int ms_retval;
	uint8_t* ms_swallet;
	const char* ms_old_password;
	const char* ms_new_password;
} ms_ecall_change_master_password_t;


typedef struct ms_ecall_show_wallet_t {
	int ms_retval;
	uint8_t* ms_swallet;
	const char* ms_master_password;
} ms_ecall_show_wallet_t;


typedef struct ms_ecall_add_item_t {
	int ms_retval;
	uint8_t* ms_swallet
	const char* ms_master_password;
	const item_t* ms_item;
	const size_t ms_item_size;
} ms_ecall_add_item_t;

typedef struct ms_ecall_remove_item_t {
	int ms_retval;
	uint8_t* ms_swallet
	const char* ms_master_password;
	const int ms_index;
} ms_ecall_remove_item_t;

typedef struct ms_ocall_print_string_t {
	int ms_retval;
	const char *ms_str
} ms_ocall_print_string_t;

/*
static sgx_status_t SGX_CDECL enclave_ocall_save_wallet(void* pms)
{
	ms_ocall_save_wallet_t* ms = SGX_CAST(ms_ocall_save_wallet_t*, pms);
	ms->ms_retval = ocall_save_wallet(ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_load_wallet(void* pms)
{
	ms_ocall_load_wallet_t* ms = SGX_CAST(ms_ocall_load_wallet_t*, pms);
	ms->ms_retval = ocall_load_wallet(ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_is_wallet(void* pms)
{
	ms_ocall_is_wallet_t* ms = SGX_CAST(ms_ocall_is_wallet_t*, pms);
	ms->ms_retval = ocall_is_wallet();

	return SGX_SUCCESS;
}

*/

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ms->ms_retval = ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}


static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_enclave = {
	1,
	{
	(void*)enclave_ocall_print_string,
	},
};

sgx_status_t ecall_generate_password(sgx_enclave_id_t eid, int* retval, char *p_value, int p_length)
{
	sgx_status_t status;
	ms_ecall_generate_password_t ms;
	ms.ms_p_value = p_value;
	ms.ms_p_length = p_length;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_create_wallet(sgx_enclave_id_t eid, int* retval, uint8_t *swallet ,const char* master_password)
{
	sgx_status_t status;
	ms_ecall_create_wallet_t ms;
	ms.ms_swallet = swallet;
	ms.ms_master_password = master_password;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_change_master_password(sgx_enclave_id_t eid, int* retval, uint8_t *swallet, const char* old_password, const char* new_password);
{
	sgx_status_t status;
	ms_ecall_create_wallet_t ms;
	ms.ms_swallet = swallet;
	ms.ms_old_password = old_password;
	ms.ms_new_password = new_password;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_show_wallet(sgx_enclave_id_t eid, int* retval, uint8_t *swallet, const char* master_password)
{
	sgx_status_t status;
	ms_ecall_create_wallet_t ms;
	ms.ms_swallet = swallet;
	ms.ms_master_password = master_password;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_add_item(sgx_enclave_id_t eid, int* retval, uint8_t *swallet, const char* master_password, const item_t* item, const size_t item_size)
{
	sgx_status_t status;
	ms_ecall_create_wallet_t ms;
	ms.ms_swallet = swallet;
	ms.ms_master_password = master_password;
	ms.ms_item = item;
	ms.ms_item_size = item_size;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_remove_item(sgx_enclave_id_t eid, int* retval, uint8_t *swallet, const char* master_password, const int index)
{
	sgx_status_t status;
	ms_ecall_create_wallet_t ms;
	ms.ms_swallet = swallet;
	ms.ms_master_password = master_password;
	ms.ms_index = index;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}


