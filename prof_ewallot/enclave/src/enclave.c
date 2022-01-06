#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "sgx_trts.h"

#include "enclave.h"
#include "enclave_t.h"  



int printf(const char* fmt, ...){
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}



void print_wallet(const wallet_t* wallet) {
    printf("\n-----------------------------------------\n");
    printf("Simple password eWallet.\n");
    printf("-----------------------------------------\n");
    printf("Number of items: %lu\n", wallet->size);
    for (int i = 0; i < wallet->size; ++i) {
        printf("\n#%d -- %s\n", i, wallet->items[i].title);
        printf("Username: %s\n", wallet->items[i].username);
        printf("Password: %s\n", wallet->items[i].password);
    }
    printf("\n------------------------------------------\n\n");
}


int get_random_int(int* number){
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	ret = sgx_read_rand( (unsigned char*) number, sizeof(int));

	if(ret!=SGX_SUCCESS) return -1;	

	return 0;
}


sgx_status_t ecall_generate_password(char *p_value, int p_length) {

	int i, randomizer,n;

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	// check password policy
	if (p_length < 8 || p_length+1 > WALLET_MAX_ITEM_SIZE) {
		return ERR_PASSWORD_OUT_OF_RANGE;
	}

	for (i=0; i<p_length; i++) {

		ret = get_random_int(&n);

		if(ret != SGX_SUCCESS){
			print_error_message(ret);
			return -1;		
		}

        	randomizer = n % 4;

        	switch(randomizer) {
            		case 0:
                		p_value[i] = get_pwd_char(numbers, NUM_SIZE);
                		break;
            		case 1:
                		p_value[i] = get_pwd_char(letter, ALPHA_SIZE);
                		break;
            		case 2:
                		p_value[i] = get_pwd_char(letterr, ALPHA_SIZE);
                		break;
            		case 3:
                		p_value[i] = get_pwd_char(symbols, SYM_SIZE);
                		break;
            		default:
                		break;
        	}
	}

	p_value[p_length] = '\0';

	return RET_SUCCESS;
}

char get_pwd_char(char *charlist, int len){
	int n;

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	ret = get_random_int(&n);

		if(ret != SGX_SUCCESS){
			print_error_message(ret);
			return -1;		
		}

	return (charlist[( n / (RAND_MAX / len))]);
}


sgx_status_t ecall_create_wallet(uint8_t* swallet, const char* master_password) {

	sgx_status_t ret;

	// create new wallet
	wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));
	wallet->size = 0;
	strncpy(wallet->master_password, master_password, strlen(master_password)+1);

	
	swallet = seal_wallet(wallet);

	free(wallet);

	if (swallet == ERR_SEAL_WALLET_FAILED) {
		
		return ERR_SEAL_WALLET_FAILED; 
	}

	return RET_SUCCESS;
}

uint8_t* seal_wallet(wallet_t* wallet){
	
	size_t sealed_size= sizeof(sgx_sealed_data_t) + sizeof(wallet_t); //tamanho do que vais ser selado
	uint8_t* sealed_wallet = (uint8_t*)malloc(sealed_size); //memoria dinamica para guardar a informacao
	
	ret = sgx_seal_data(0,NULL,sizeof(wallet_t),(uint8_t*) wallet, sealed_size, (sgx_sealed_data_t *)sealed_wallet);

	if (ret != SGX_SUCCESS) {
		free(sealed_wallet);
		return ERR_SEAL_WALLET_FAILED; 
	}

	return sealed_wallet;

}

wallet_t unseal_wallet(uint8_t* sealed_wallet){
	

	wallet_t* unsealed_wallet = (wallet_t*)malloc(sizeof(wallet_t)); //memoria dinamica para guardar a informacao
	
	ret = sgx_unseal_data((sgx_sealed_data_t *) sealed_wallet,NULL,NULL,(uint8_t*) unseal_wallet, sizeof(wallet_t));

	if (ret != SGX_SUCCESS) {
		free(unseal_wallet);
		return ERR_UNSEAL_WALLET_FAILED; 
	}

	return unsealed_wallet;

}



sgx_status_t ecall_change_master_password(uint8_t* swallet, const char* old_password, const char* new_password) {
	
	sgx_status_t ret;
	size_t sealed_size= sizeof(sgx_sealed_data_t) + sizeof(wallet_t);

	// unsealed wallet
	
	wallet_t* unsealed_wallet = unseal_wallet(swallet);


	if (unsealed_wallet == ERR_UNSEAL_WALLET_FAILED) {
		return ERR_UNSEAL_WALLET_FAILED; 
	}


	// verify master-password
	if (strcmp(unsealed_wallet->master_password, old_password) != 0) {
		free(unsealed_wallet);
		return ERR_WRONG_MASTER_PASSWORD;
	}

	// update password
	strncpy(unsealed_wallet->master_password, new_password, strlen(new_password)+1);
	

	//sealed wallet

	swallet = seal_wallet(unsealed_wallet);

	free(unsealed_wallet);

	if (swallet == ERR_SEAL_WALLET_FAILED) {
		return ERR_SEAL_WALLET_FAILED; 
	}	

	return RET_SUCCESS;

}

//FALTA ALTERAR
sgx_status_t ecall_show_wallet(uint8_t* swallet, const char* master_password ) {

	int ret;

	// unsealed wallet
	
	wallet_t* unsealed_wallet = unseal_wallet(sealed_wallet);

	free(sealed_wallet);

	if (unsealed_wallet == ERR_UNSEAL_WALLET_FAILED) {
		return ERR_UNSEAL_WALLET_FAILED; 
	}


	// verify master-password
	if (strcmp(unsealed_wallet->master_password, master_password) != 0) {
		free(unsealed_wallet);
		return ERR_WRONG_MASTER_PASSWORD;
	}

	//print
	print_wallet(unsealed_wallet);

	return RET_SUCCESS;
}

sgx_status_t ecall_add_item(uint8_t* sealed_wallet, const char* master_password, const item_t* item, const size_t item_size) {

	sgx_status_t ret;

	// unsealed wallet
	
	wallet_t* unsealed_wallet = unseal_wallet(sealed_wallet);

	//free(sealed_wallet);

	if (unsealed_wallet == ERR_UNSEAL_WALLET_FAILED) {
		return ERR_UNSEAL_WALLET_FAILED; 
	}

	// verify master-password
	if (strcmp(unseald_wallet->master_password, master_password) != 0) {
		free(unsealed_wallet);
		return ERR_WRONG_MASTER_PASSWORD;
	}

	// add item to the wallet
	size_t wallet_size = unsealed_wallet->size;
	if (wallet_size >= WALLET_MAX_ITEMS) {
		free(unsealed_wallet);
		return ERR_WALLET_FULL;
	}

	unsealed_wallet->items[wallet_size] = *item;
	++wallet->size;


	//sealed wallet

	sealed_wallet = seal_wallet(unsealed_wallet);

	free(unsealed_wallet);

	if (resealed_wallet == ERR_SEAL_WALLET_FAILED) {
		return ERR_SEAL_WALLET_FAILED; 
	}	


	return RET_SUCCESS;
}


sgx_status_t ecall_remove_item(uint8_t* sealed_wallet,const char* master_password, const int index) {

	sgx_status_t ret;


	// unsealed wallet
	
	wallet_t* unsealed_wallet = unseal_wallet(sealed_wallet);

	//free(sealed_wallet);

	if (unsealed_wallet == ERR_UNSEAL_WALLET_FAILED) {
		return ERR_UNSEAL_WALLET_FAILED; 
	}

	// verify master-password
	if (strcmp(unsealed_wallet->master_password, master_password) != 0) {
		free(unsealed_wallet);
		return ERR_WRONG_MASTER_PASSWORD;
	}

	// remove item from the wallet
	size_t wallet_size = unsealed_wallet->size;
	if (index >= wallet_size) {
		free(unsealed_wallet);
		return ERR_ITEM_DOES_NOT_EXIST;
	}
	for (int i = index; i < wallet_size-1; ++i) {
		unsealed_wallet->items[i] = unsealed_wallet->items[i+1];
	}
	--unsealed_wallet->size;

	
	//sealed wallet
	sealed_wallet = seal_wallet(unsealed_wallet);

	free(unsealed_wallet);

	if (sealed_wallet == ERR_SEAL_WALLET_FAILED) {
		return ERR_SEAL_WALLET_FAILED; 
	}	
	
	return RET_SUCCESS;

}

