#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#define ALPHA_SIZE 26
#define NUM_SIZE 10
#define SYM_SIZE 21

#define RET_SUCCESS 0
#define ERR_PASSWORD_OUT_OF_RANGE 1
#define ERR_WALLET_ALREADY_EXISTS 2
#define ERR_CANNOT_SAVE_WALLET 3
#define ERR_CANNOT_LOAD_WALLET 4
#define ERR_WRONG_MASTER_PASSWORD 5
#define ERR_WALLET_FULL 6
#define ERR_ITEM_DOES_NOT_EXIST 7
#define ERR_ITEM_TOO_LONG 8
#define ERR_SEAL_WALLET_FAILED 9
#define ERR_UNSEAL_WALLET_FAILED 10

static char numbers[] = "1234567890";
static char letter[]  = "abcdefghijklmnoqprstuvwyzx";
static char letterr[] = "ABCDEFGHIJKLMNOQPRSTUYWVZX";
static char symbols[] = "!@#$%^&*(){}[]:<>?,./";


int printf(const char* fmt, ...);
void print_wallet(const wallet_t* wallet);
int get_random_int(int* number);
char get_pwd_char(char *charlist, int len);

sgx_status_t ecall_generate_password(char *p_value, int p_length);
sgx_status_t ecall_create_wallet(uint8_t* swallet, const char* master_password);
sgx_status_t ecall_change_master_password(uint8_t* swallet, const char* old_password, const char* new_password);
sgx_status_t ecall_show_wallet(uint8_t* swallet, const char* master_password );
sgx_status_t ecall_add_item(uint8_t* sealed_wallet, const char* master_password, const item_t* item, const size_t item_size);
sgx_status_t ecall_remove_item(uint8_t* sealed_wallet,const char* master_password, const int index)

uint8_t* seal_wallet(wallet_t* wallet);
wallet_t unseal_wallet(uint8_t* sealed_wallet);

#endif /* !_ENCLAVE_H_ */
