/* verify.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <stdio.h>
#include<wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include<wolfssl/ssl.h>
#include<wolfssl/test.h>

/* RSA public key to verify with. */
static const unsigned char public_key_2048_n[] = {
    0xC3, 0x03, 0xD1, 0x2B, 0xFE, 0x39, 0xA4, 0x32,
    0x45, 0x3B, 0x53, 0xC8, 0x84, 0x2B, 0x2A, 0x7C,
    0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
    0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
    0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
    0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
    0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2,
    0x1B, 0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF,
    0xEC, 0xF1, 0x81, 0x1E, 0x7B, 0x9B, 0x03, 0x47,
    0x9A, 0xBF, 0x65, 0xCC, 0x7F, 0x65, 0x24, 0x69,
    0xA6, 0xE8, 0x14, 0x89, 0x5B, 0xE4, 0x34, 0xF7,
    0xC5, 0xB0, 0x14, 0x93, 0xF5, 0x67, 0x7B, 0x3A,
    0x7A, 0x78, 0xE1, 0x01, 0x56, 0x56, 0x91, 0xA6,
    0x13, 0x42, 0x8D, 0xD2, 0x3C, 0x40, 0x9C, 0x4C,
    0xEF, 0xD1, 0x86, 0xDF, 0x37, 0x51, 0x1B, 0x0C,
    0xA1, 0x3B, 0xF5, 0xF1, 0xA3, 0x4A, 0x35, 0xE4,
    0xE1, 0xCE, 0x96, 0xDF, 0x1B, 0x7E, 0xBF, 0x4E,
    0x97, 0xD0, 0x10, 0xE8, 0xA8, 0x08, 0x30, 0x81,
    0xAF, 0x20, 0x0B, 0x43, 0x14, 0xC5, 0x74, 0x67,
    0xB4, 0x32, 0x82, 0x6F, 0x8D, 0x86, 0xC2, 0x88,
    0x40, 0x99, 0x36, 0x83, 0xBA, 0x1E, 0x40, 0x72,
    0x22, 0x17, 0xD7, 0x52, 0x65, 0x24, 0x73, 0xB0,
    0xCE, 0xEF, 0x19, 0xCD, 0xAE, 0xFF, 0x78, 0x6C,
    0x7B, 0xC0, 0x12, 0x03, 0xD4, 0x4E, 0x72, 0x0D,
    0x50, 0x6D, 0x3B, 0xA3, 0x3B, 0xA3, 0x99, 0x5E,
    0x9D, 0xC8, 0xD9, 0x0C, 0x85, 0xB3, 0xD9, 0x8A,
    0xD9, 0x54, 0x26, 0xDB, 0x6D, 0xFA, 0xAC, 0xBB,
    0xFF, 0x25, 0x4C, 0xC4, 0xD1, 0x79, 0xF4, 0x71,
    0xD3, 0x86, 0x40, 0x18, 0x13, 0xB0, 0x63, 0xB5,
    0x72, 0x4E, 0x30, 0xC4, 0x97, 0x84, 0x86, 0x2D,
    0x56, 0x2F, 0xD7, 0x15, 0xF7, 0x7F, 0xC0, 0xAE,
    0xF5, 0xFC, 0x5B, 0xE5, 0xFB, 0xA1, 0xBA, 0xD3,
};

static const unsigned long public_key_2048_e = 0x010001;

unsigned char msg[] = {
    0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x6d, 0x65, 0x73, 0x73,
    0x61, 0x67, 0x65,
};

unsigned char rsa_sig_2048[] = {
    0x41, 0xeb, 0xf5, 0x5e, 0x97, 0x43, 0xf4, 0xd1,
    0xda, 0xb6, 0x5c, 0x75, 0x57, 0x2c, 0xe1, 0x01,
    0x07, 0xdc, 0x42, 0xc4, 0x2d, 0xe2, 0xb5, 0xc8,
    0x63, 0xe8, 0x45, 0x9a, 0x4a, 0xfa, 0xdf, 0x5e,
    0xa6, 0x08, 0x0a, 0x26, 0x2e, 0xca, 0x2c, 0x10,
    0x7a, 0x15, 0x8d, 0xc1, 0x55, 0xcc, 0x33, 0xdb,
    0xb2, 0xef, 0x8b, 0xa6, 0x4b, 0xef, 0xa1, 0xcf,
    0xd3, 0xe2, 0x5d, 0xac, 0x88, 0x86, 0x62, 0x67,
    0x8b, 0x8c, 0x45, 0x7f, 0x10, 0xad, 0xfa, 0x27,
    0x7a, 0x35, 0x5a, 0xf9, 0x09, 0x78, 0x83, 0xba,
    0x18, 0xcb, 0x3e, 0x8e, 0x08, 0xbe, 0x36, 0xde,
    0xac, 0xc1, 0x77, 0x44, 0xe8, 0x43, 0xdb, 0x52,
    0x23, 0x08, 0x36, 0x8f, 0x74, 0x4a, 0xbd, 0xa3,
    0x3f, 0xc1, 0xfb, 0xd6, 0x45, 0x25, 0x61, 0xe2,
    0x19, 0xcb, 0x0b, 0x28, 0xef, 0xca, 0x0a, 0x3b,
    0x7b, 0x3d, 0xe3, 0x47, 0x46, 0x07, 0x1a, 0x7f,
    0xff, 0x38, 0xfd, 0x59, 0x94, 0x0b, 0xeb, 0x00,
    0xab, 0xcc, 0x8c, 0x48, 0x7b, 0xd6, 0x87, 0xb8,
    0x54, 0xb0, 0x2a, 0x07, 0xcf, 0x44, 0x11, 0xd4,
    0xb6, 0x9a, 0x4e, 0x6d, 0x5c, 0x1a, 0xe3, 0xc7,
    0xf3, 0xc7, 0xcb, 0x8e, 0x82, 0x7d, 0xc8, 0x77,
    0xf0, 0xb6, 0xd0, 0x85, 0xcb, 0xdb, 0xd0, 0xb0,
    0xe0, 0xcf, 0xca, 0x3f, 0x17, 0x46, 0x84, 0xcb,
    0x5b, 0xfe, 0x51, 0x3a, 0xaa, 0x71, 0xad, 0xeb,
    0xf1, 0xed, 0x3f, 0xf8, 0xde, 0xb4, 0xa1, 0x26,
    0xdb, 0xc6, 0x8e, 0x70, 0xd4, 0x58, 0xa8, 0x31,
    0xd8, 0xdb, 0xcf, 0x64, 0x4a, 0x5f, 0x1b, 0x89,
    0x22, 0x03, 0x3f, 0xab, 0xb5, 0x6d, 0x2a, 0x63,
    0x2f, 0x4e, 0x7a, 0xe1, 0x89, 0xb4, 0xf0, 0x9a,
    0xb7, 0xd3, 0xd6, 0x0a, 0x10, 0x67, 0x28, 0x25,
    0x6d, 0xda, 0x92, 0x99, 0x3f, 0x64, 0xa7, 0xea,
    0xe0, 0xdc, 0x7c, 0xe8, 0x41, 0xb0, 0xeb, 0x45,
};

void print_buffer(char* name, unsigned char* data, word32 len)
{
    word32 i;

    printf("unsigned char %s[] = {\n", name);
    for (i = 0; i < len; i++) {
        if ((i % 8) == 0)
            printf("   ");
        printf(" 0x%02x,", data[i]);
        if ((i % 8) == 7)
            printf("\n");
    }
    if ((i % 8) != 0)
        printf("\n");
    printf("};\n");

}


/* ASN.1 encoding of digest algorithm before hash */
#define ENC_ALG_SZ     19

/* verify entry point.
 *
 * Verifies the signature with the message and RSA public key.
 * Returns 0 on success and 1 otherwise.
 */
int verify()
{
    int            ret = 0;
    Sha256         sha256;
    Sha256*        pSha256 = NULL;
    RsaKey         rsaKey;
    RsaKey*        pRsaKey = NULL;
    unsigned char  decSig[sizeof(rsa_sig_2048)];
    word32         decSigLen = 0;
    unsigned char  encSig[ENC_ALG_SZ + WC_SHA256_DIGEST_SIZE] = {
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20, 0x00,
    };

/* Variables for a benchmark*/
    double start, total_time;
#ifndef BENCH_TIME_SEC
    #define BENCH_TIME_SEC 3
#endif
    int count;

#ifdef DEBUG_MEMORY
    wolfCrypt_Init();
    InitMemoryTracker();
#endif
    /* Calculate SHA-256 digest of message */
    if (ret == 0)
        ret = wc_InitSha256(&sha256);
    if (ret == 0) {
        pSha256 = &sha256;
        ret = wc_Sha256Update(&sha256, msg, sizeof(msg));
    }
    if (ret == 0)
        ret = wc_Sha256Final(&sha256, encSig + ENC_ALG_SZ);

    /* Initialize the RSA key and decode the DER encoded public key. */
    if (ret == 0)
        ret = wc_InitRsaKey(&rsaKey, NULL);
    if (ret == 0) {
        pRsaKey = &rsaKey;

        ret = mp_read_unsigned_bin(&rsaKey.n, public_key_2048_n,
                                   sizeof(public_key_2048_n));
    }
    if (ret == 0)
        ret = mp_set_int(&rsaKey.e, public_key_2048_e);
#ifdef BENCHMARK 
    count = 0;
    printf("Running benchmark...\n");
    printf("Please Wait %.2f seconds\n", (double)BENCH_TIME_SEC);
    start = current_time(0);// 1 0
    while( (double)BENCH_TIME_SEC > (total_time = current_time(0) - start ) ){
    if (ret != 0 ) printf("Invalid signature in benchmark\n");    
#endif
    /* Verify the signature by decrypting the value. */
    if (ret == 0) {
        decSigLen = wc_RsaSSL_Verify(rsa_sig_2048, sizeof(rsa_sig_2048),
                                           decSig, sizeof(decSig), &rsaKey);
        if ((int)decSigLen < 0)
            ret = (int)decSigLen;
    }

    

    /* Check the decrypted result matches the encoded digest. */
    if (ret == 0 && decSigLen != sizeof(encSig))
        ret = -1;
    if (ret == 0 && XMEMCMP(encSig, decSig, decSigLen) != 0)
        ret = -1;

#ifdef BENCHMARK
        count++;
    }
   
    printf("Takes %1.2f Sec for %d times,    %6.2f Cycles/sec\n", total_time, count, count/total_time);
    printf("Finished Benchmark \n");
#else 
    printf("Verified\n");
#endif

    /* Free the data structures */
    if (pRsaKey != NULL)
        wc_FreeRsaKey(pRsaKey);
    if (pSha256 != NULL)
        wc_Sha256Free(pSha256);

#ifdef DEBUG_MEMORY
    ShowMemoryTracker();
    CleanupMemoryTracker();
    wolfCrypt_Cleanup();
#endif 
    return ret == 0 ? 0 : 1;
}

int main(){
#ifdef BENCHMARK
    printf("---------------------------------------------------------------\n");
#if defined(SP_C64_FLAG)
    printf("Enabled 64-bit SP \n");
#elif defined(SP_C32_FLAG)
    printf("Enabled 32-bit SP \n");
#elif defined(SP_X86_64_FLAG)
    printf("Enabled SP for x86_64\n");
#elif defined(SP_ARM64_FLAG)
    printf("Enabled SP for Arm64\n");
#elif defined(TFM_FLAG)
    printf("Enabled TFM \n");
#endif
    printf("---------------------------------------------------------------\n");
#endif /* BENCHMARK */

#ifdef DEBUG_MEMORY
    return StackSizeCheck(NULL, (thread_func)verify);
#else 

    return verify();
#endif
}
