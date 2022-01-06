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

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char *str));
#endif


int get_random_int(int* number);
char get_pwd_char(char *charlist, int len);
int printf(const char* fmt, ...);
void print_wallet(const wallet_t* wallet);
uint8_t* seal_wallet(wallet_t* wallet);
wallet_t unseal_wallet(uint8_t* sealed_wallet);

sgx_status_t ecall_generate_password(sgx_enclave_id_t eid, int* retval, char *p_value, int p_length);
sgx_status_t ecall_create_wallet(sgx_enclave_id_t eid, int* retval, uint8_t* swallet, const char* master_password);
sgx_status_t ecall_change_master_password(sgx_enclave_id_t eid, int* retval, uint8_t* swallet, const char* old_password, const char* new_password);
sgx_status_t ecall_show_wallet(sgx_enclave_id_t eid, int* retval, uint8_t* wallet, const char* master_password);
sgx_status_t ecall_add_item(sgx_enclave_id_t eid, int* retval, uint8_t* sealed_wallet, const char* master_password, const item_t* item, const size_t item_size);
sgx_status_t ecall_remove_item(sgx_enclave_id_t eid, int* retval, uint8_t* sealed_wallet, const char* master_password, const int index);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
