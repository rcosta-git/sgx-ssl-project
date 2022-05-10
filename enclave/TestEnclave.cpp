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


#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#include "TestEnclave.h"
#include "TestEnclave_t.h"  /* print_string */
#include "tSgxSSL_api.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define ADD_ENTROPY_SIZE	32

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

typedef void CRYPTO_RWLOCK;

struct evp_pkey_st {
    int type;
    int save_type;
    int references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    union {
        char *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
# endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */ ;

RSA *global_keypair = NULL;

int t_gen_keys(unsigned char *buf)
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
    ret = RSA_generate_key_ex(global_keypair, 4096, bn, NULL);
    if (!ret) {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
        return 0;
    }
    
    int len = 0;
    unsigned char *secureBuf = NULL;
    len = i2d_RSAPublicKey(global_keypair, &secureBuf);
    memcpy(buf, secureBuf, len);
    return len;
}

int t_gen_keys_size(int keySize, unsigned char *buf)
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

int t_decrypt_msg(unsigned char *inMsg, int inLen, unsigned char *outMsg)
{
    if (global_keypair == NULL) {
        printf("No global keys generated!");
    }
    return RSA_private_decrypt(inLen, inMsg, outMsg, global_keypair,
                               RSA_PKCS1_PADDING);
}

