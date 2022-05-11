/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <iostream>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <pthread.h>

# define MAX_PATH FILENAME_MAX


#include <sgx_urts.h>

#include "TestApp.h"

#include "TestEnclave_u.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/time.h> 
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>

using namespace std;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid Intel® Software Guard Extensions device.",
        "Please make sure Intel® Software Guard Extensions module is enabled in the BIOS, and install Intel® Software Guard Extensions driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "Intel® Software Guard Extensions device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred [0x%x].\n", ret);
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    printf("token_path: %s\n", token_path);
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(TESTENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);

    return 0;
}

/* OCall functions */
void uprint(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
    fflush(stdout);
}


void usgx_exit(int reason)
{
	printf("usgx_exit: %d\n", reason);
	exit(reason);
}

/* Calculate the difference of the given start and finish timevals given.
   Returns seconds value calculated. */
double time_difference(const struct timeval start,
                       const struct timeval finish)
{
        if (finish.tv_usec >= start.tv_usec) { 
                return (double) (finish.tv_sec - start.tv_sec)
                        + (double) (finish.tv_usec - start.tv_usec)/1E6;
        } else { 
                return (double) (finish.tv_sec - start.tv_sec - 1)
                        + (double) (finish.tv_usec - start.tv_usec + 1000000)
                        /1E6;
        }
}

RSA *global_keypair = NULL;

int gen_keys_size(int keySize, unsigned char *buf)
{
    BIGNUM *bn = BN_new();
    if (bn == NULL) {
        printf("BN_new failure: %ld\n", ERR_get_error());
        return 0;
    }
    
    int ret = BN_set_word(bn, RSA_F4);
    if (!ret) {
        printf("BN_set_word failure\n");
        return 0;
    }
	
    global_keypair = RSA_new();
    if (global_keypair == NULL) {
        printf("RSA_new failure: %ld\n", ERR_get_error());
        return 0;
    }
    ret = RSA_generate_key_ex(global_keypair, keySize, bn, NULL);
    if (!ret) {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
        return 0;
    }
    
    int len = 0;
    unsigned char *secureBuf = NULL;
    len = i2d_RSAPublicKey(global_keypair, &secureBuf);
    memcpy(buf, secureBuf, len);
    free(secureBuf);
    return len;
}

int decrypt_msg(unsigned char *inMsg, int inLen, unsigned char *outMsg)
{
    if (global_keypair == NULL) {
        printf("No global keys generated!");
    }
    return RSA_private_decrypt(inLen, inMsg, outMsg, global_keypair,
                               RSA_PKCS1_PADDING);
}


/* Application entry */
int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    sgx_status_t status;

    /* Changing dir to where the executable is.*/
    char absolutePath[MAX_PATH];
    char *ptr = NULL;

    ptr = realpath(dirname(argv[0]), absolutePath);

    if (ptr == NULL || chdir(absolutePath) != 0)
    	return 1;

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
        return 1;
    
    unsigned char *buf = (unsigned char *)malloc(8192);
    int keylen;
    
    RSA *pPubRSA;
    
    int num;
    int plen;
    unsigned char ctext[256];
    static unsigned char ptext_ex[] = "Hello Enclave!";
    plen = sizeof(ptext_ex) - 1;
    
    int retNum;
    unsigned char ptext[256];
    
    struct rusage start_total, finish_total;

    double user_average_enclave, system_average_enclave,
        user_average_plain, system_average_plain;

    int NUMREPS = 1000;
    
    ///////////////////////////////////////
    //////////// TIMING KEY GENERATION

#if 0
    cout << endl << "Non-enclave key generation-----------" << endl << endl;
    for (int i = 1; i <= 4; i++) { // change to 4, i * 1024
        int keySize = i * 1024;
        cout << "Key size " << keySize << endl;

        getrusage(RUSAGE_SELF, &start_total);
        for (int j = 0; j < NUMREPS; j++) {
            keylen = gen_keys_size(keySize, buf);
        }
        getrusage(RUSAGE_SELF, &finish_total);
        
        cout << "Average User:" <<
          time_difference(start_total.ru_utime, finish_total.ru_utime)
          / (double) NUMREPS << endl;
        cout << "Average System:" <<
          time_difference(start_total.ru_stime, finish_total.ru_stime)
          / (double) NUMREPS << endl;
    }

    cout << endl << "Enclave key generation------------" << endl;
    for (int i = 1; i <= 4; i++) { // change to 4, i * 1024
        int keySize = i * 1024;
        cout << "Key size " << keySize << endl;

        getrusage(RUSAGE_SELF, &start_total);
        for (int j = 0; j < NUMREPS; j++) {
            t_gen_keys_size(global_eid, &keylen, keySize, buf);
        }
        getrusage(RUSAGE_SELF, &finish_total);
        
        cout << "Average User:" <<
          time_difference(start_total.ru_utime, finish_total.ru_utime)
          / (double) NUMREPS << endl;
        cout << "Average System:" <<
          time_difference(start_total.ru_stime, finish_total.ru_stime)
          / (double) NUMREPS << endl;
    }
#endif


    ///////////////////////////////////////
    //////////// TIMING DECRYPTION


    cout << endl << "Non-enclave decryption------------" << endl;
    for (int i = 1; i <= 4; i++) { // change to 4, i * 1024
        int keySize = i * 1024;
        cout << "Key size " << keySize << endl;
        keylen = gen_keys_size(keySize, buf);
        pPubRSA = d2i_RSAPublicKey(NULL, (const unsigned char**)&buf,
                                    (long)keylen);
        num = RSA_public_encrypt(plen, ptext_ex, ctext, pPubRSA, RSA_PKCS1_PADDING);
        if (num < 0) {
            std::cout << "Got error " << ERR_peek_last_error() << std::endl;
            return 1;
        }

        getrusage(RUSAGE_SELF, &start_total);
        for (int j = 0; j < NUMREPS; j++) {
            retNum = decrypt_msg(ctext, num, ptext);
        }
        getrusage(RUSAGE_SELF, &finish_total);
        
        cout << "Average User:" <<
          time_difference(start_total.ru_utime, finish_total.ru_utime)
          / (double) NUMREPS << endl;
        cout << "Average System:" <<
          time_difference(start_total.ru_stime, finish_total.ru_stime)
          / (double) NUMREPS << endl;
    }
    
    cout << endl << "Enclave decryption------------" << endl;
    for (int i = 1; i <= 4; i++) { // change to 4, i * 1024
        int keySize = i * 1024;
        cout << "Key size " << keySize << endl;
        status = t_gen_keys_size(global_eid, &keylen, keySize, buf);
        if (status != SGX_SUCCESS) {
            printf("Call to SGX has failed.\n");
            return 1;    //Test failed
        }
        if (keylen == 0) return 1;
        pPubRSA = d2i_RSAPublicKey(NULL, (const unsigned char**)&buf,
                                    (long)keylen);
        num = RSA_public_encrypt(plen, ptext_ex, ctext, pPubRSA, RSA_PKCS1_PADDING);
        if (num < 0) {
            std::cout << "Got error " << ERR_peek_last_error() << std::endl;
            return 1;
        }

        getrusage(RUSAGE_SELF, &start_total);
        for (int j = 0; j < NUMREPS; j++) {
            t_decrypt_msg(global_eid, &retNum, ctext, num, ptext);
        }
        getrusage(RUSAGE_SELF, &finish_total);
        
        cout << "Average User:" <<
          time_difference(start_total.ru_utime, finish_total.ru_utime)
          / (double) NUMREPS << endl;
        cout << "Average System:" <<
          time_difference(start_total.ru_stime, finish_total.ru_stime)
          / (double) NUMREPS << endl;
    }
    
    //////////
    sgx_destroy_enclave(global_eid);
    return 0;
}
