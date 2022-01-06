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


typedef struct ms_ecall_generate_password_t {
	int ms_retval;
	char* ms_p_value;
	int ms_p_length;
} ms_ecall_generate_password_t;

typedef struct ms_ecall_create_wallet_t {
	int ms_retval;
	uint8_t* ms_swallet;
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
	const char* ms_master_password;
	wallet_t* ms_wallet;
	size_t ms_wallet_size;
} ms_ecall_show_wallet_t;


typedef struct ms_ecall_add_item_t {
	int ms_retval;
	uint8_t* ms_sealed_wallet;
	const char* ms_master_password;
	const item_t* ms_item;
	const size_t ms_item_size;
} ms_ecall_add_item_t;

typedef struct ms_ecall_remove_item_t {
	int ms_retval;
	uint8_t* ms_sealed_wallet;
	const char* ms_master_password;
	const int ms_index;
} ms_ecall_remove_item_t;

//FALTA MUDAR
typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;




static sgx_status_t SGX_CDECL sgx_ecall_generate_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_password_t* ms = SGX_CAST(ms_ecall_generate_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char * _tmp_p_value = ms->ms_p_value;
	size_t _len_p_value = ms->ms_p_length;
	char* _in_p_value = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_value, _len_p_value);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_value != NULL && _len_p_value != 0) {
		if ( _len_p_value % sizeof(*_tmp_p_value) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_value = (char*)malloc(_len_p_value)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_value, 0, _len_p_value);
	}

	ms->ms_retval = ecall_generate_password(_in_p_value,_len_p_value);
	if (_in_p_value) {
		if (memcpy_s(_tmp_p_value, _len_p_value, _in_p_value, _len_p_value)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_value) free(_in_p_value);
	return status;
}


static sgx_status_t SGX_CDECL sgx_ecall_create_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_wallet_t* ms = SGX_CAST(ms_ecall_create_wallet_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	uint8_t* _tmp_swallet = ms->ms_swallet;
	size_t _len_swallet = sizeof(sgx_sealed_data_t)+sizeof(wallet_t);
	uint8_t* _in_swallet = NULL;	
		

	const char* _tmp_master_password = ms->ms_master_password
	size_t _len_master_password = strlen(ms->ms_master_password)+1;
	char* _in_master_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_swallet != NULL && _len_swallet != 0) {
		if ( _len_swallet % sizeof(*_tmp_swallet) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_swallet = (uint8_t*)malloc(_len_swallet)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_swallet, 0, _len_swallet);
	}
	if (_in_swallet) {
		if (memcpy_s(_tmp_swallet, _len_swallet, _in_swallet, _len_swallet)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		if ( _len_master_password % sizeof(*_tmp_master_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_master_password = (char*)malloc(_len_master_password)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_master_password, 0, _len_master_password);
	}

	
	if (_in_master_password) {
		if (memcpy_s(_tmp_master_password, _len_master_password, _in_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	ms->ms_retval = ecall_create_wallet(_in_swallet,_in_master_password);

err:
	if (_in_swallet) free(_in_swallet);
	if (_in_master_password) free(_in_master_password);
	return status;
}


static sgx_status_t SGX_CDECL sgx_ecall_change_master_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_change_master_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_change_master_password_t* ms = SGX_CAST(ms_ecall_change_master_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	uint8_t* _tmp_swallet = ms->ms_swallet;
	size_t _len_swallet = sizeof(sgx_sealed_data_t)+sizeof(wallet_t);
	uint8_t* _in_swallet = NULL;	
	
	const char* _tmp_old_password = ms->ms_old_password
	size_t _len_old_password = strlen(ms->ms_old_password)+1;
	char* _in_old_password = NULL;

	const char* _tmp_new_password = ms->ms_new_password
	size_t _len_new_password = strlen(ms->ms_new_password)+1;
	char* _in_new_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_old_password, _len_old_password);
	CHECK_UNIQUE_POINTER(_tmp_new_password, _len_new_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_swallet != NULL && _len_swallet != 0) {
		if ( _len_swallet % sizeof(*_tmp_swallet) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_swallet = (uint8_t*)malloc(_len_swallet)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_swallet, 0, _len_swallet);
	}
	if (_in_swallet) {
		if (memcpy_s(_tmp_swallet, _len_swallet, _in_swallet, _len_swallet)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	

	if (_tmp_old_password != NULL && _len_old_password != 0) {
		if ( _len_old_password % sizeof(*_tmp_old_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_old_password = (char*)malloc(_len_old_password)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_old_password, 0, _len_old_password);
	}

	if (_in_old_password) {
		if (memcpy_s(_tmp_old_password, _len_old_password, _in_old_password, _len_old_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	if (_tmp_new_password != NULL && _len_new_password != 0) {
		if ( _len_new_password % sizeof(*_tmp_new_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_new_password = (char*)malloc(_len_new_password)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_new_password, 0, _len_new_password);
	}

	if (_in_new_password) {
		if (memcpy_s(_tmp_new_password, _len_new_password, _in_new_password, _len_new_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}


	ms->ms_retval = ecall_change_master_password(_in_swallet,_in_old_password,_in_new_password);
err:
	if (_in_swallet) free(_in_swallet);
	if (_in_old_password) free(_in_old_password);
	if (_in_new_password) free(_in_new_password);
	return status;
}


static sgx_status_t SGX_CDECL sgx_ecall_add_item(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_add_item_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_add_item_t* ms = SGX_CAST(ms_ecall_add_item_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	uint8_t* _tmp_sealed_wallet = ms->ms_sealed_wallet;
	size_t _len_sealed_wallet = sizeof(sgx_sealed_data_t)+sizeof(wallet_t);
	uint8_t* _in_sealed_wallet = NULL;

	const char* _tmp_master_password = ms->ms_master_password
	size_t _len_master_password = strlen(ms->ms_master_password)+1;
	char* _in_master_password = NULL;

	const item_t* _tmp_item = ms->ms_item;
	size_t _len_item = ms->ms_item_size;
	item_t* _in_item = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_wallet, _len_sealed_wallet);
	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);
	CHECK_UNIQUE_POINTER(_tmp_item, _len_item);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_wallet != NULL && _len_sealed_wallet != 0) {
		if ( _len_sealed_wallet % sizeof(*_tmp_sealed_wallet) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_wallet = (uint8_t*)malloc(_len_sealed_wallet)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_wallet, 0, _len_sealed_wallet);
	}
	if (_in_sealed_wallet) {
		if (memcpy_s(_tmp_sealed_wallet, _len_sealed_wallet, _in_sealed_wallet, _len_sealed_wallet)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}


	if (_tmp_master_password != NULL && _len_master_password != 0) {
		if ( _len_master_password % sizeof(*_tmp_master_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_master_password = (char*)malloc(_len_master_password)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_master_password, 0, _len_master_password);
	}
	if (_in_master_password) {
		if (memcpy_s(_tmp_master_password, _len_master_password, _in_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	if (_tmp_item != NULL && _len_item != 0) {
		if ( _len_item % sizeof(*_tmp_item) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_item = (item_t*)malloc(_len_item)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_item, 0, _len_item);
	}
	if (_in_item) {
		if (memcpy_s(_tmp_item, _len_item, _in_item, _len_item)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}


ms->ms_retval = ecall_add_item(_in_sealed_wallet,_in_master_password,_in_item, _len_item);

err:
	if (_in_sealed_wallet) free(_in_sealed_wallet);
	if (_in_master_password) free(_in_master_password);
	if (_in_item) free(_in_item);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_remove_item(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_add_item_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_add_item_t* ms = SGX_CAST(ms_ecall_add_item_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	uint8_t* _tmp_sealed_wallet = ms->ms_sealed_wallet;
	size_t _len_sealed_wallet = sizeof(sgx_sealed_data_t)+sizeof(wallet_t);
	uint8_t* _in_sealed_wallet = NULL;

	const char* _tmp_master_password = ms->ms_master_password
	size_t _len_master_password = strlen(ms->ms_master_password)+1;
	char* _in_master_password = NULL;

	const int _tmp_index = ms->ms_index;
	size_t _len_index = sizeof(int);
	int _in_index = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_wallet, _len_sealed_wallet);
	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);
	CHECK_UNIQUE_POINTER(_tmp_index, _len_index);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_wallet != NULL && _len_sealed_wallet != 0) {
		if ( _len_sealed_wallet % sizeof(*_tmp_sealed_wallet) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_wallet = (uint8_t*)malloc(_len_sealed_wallet)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_wallet, 0, _len_sealed_wallet);
	}
	if (_in_sealed_wallet) {
		if (memcpy_s(_tmp_sealed_wallet, _len_sealed_wallet, _in_sealed_wallet, _len_sealed_wallet)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}


	if (_tmp_master_password != NULL && _len_master_password != 0) {
		if ( _len_master_password % sizeof(*_tmp_master_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_master_password = (char*)malloc(_len_master_password)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_master_password, 0, _len_master_password);
	}
	if (_in_master_password) {
		if (memcpy_s(_tmp_master_password, _len_master_password, _in_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	if (_tmp_index != NULL && _len_index != 0) {
		if ( _len_index % sizeof(*_tmp_index) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_index = (int)malloc(_len_index)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_item, 0, _len_index);
	}
	if (_in_index) {
		if (memcpy_s(_tmp_index, _len_index, _in_index, _len_index)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}


ms->ms_retval = ecall_remove_item(_in_sealed_wallet,_in_master_password,_in_index);

err:
	if (_in_sealed_wallet) free(_in_sealed_wallet);
	if (_in_master_password) free(_in_master_password);
	if (_in_index) free(_in_index);
	return status;
}


SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_ecall_generate_password, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_wallet, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_change_master_password, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_show_wallet, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_add_item, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_remove_item, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
//aqui e um array de zeros com ocallsXecalls
} g_dyn_entry_table = {
	0,
};
SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][1];
} g_dyn_entry_table = {
	1,
	{
		{0, },
	}
};


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
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

