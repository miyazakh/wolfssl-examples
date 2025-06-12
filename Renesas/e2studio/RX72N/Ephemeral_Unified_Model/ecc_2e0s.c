
/* ./configure --enable-keygen */
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/aes.h>

static struct timespec start, stop;

static void print_hex(char* who, byte* s, int sLen)
{
    int i;
    printf("%ss' : ", who);
    for (i = 0; i < sLen; i++)
        printf("%02x", s[i]);
    printf("\n");
}

static void starttime()
{
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
}

static double elapsedtime()
{
    double ret;

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

    ret = (stop.tv_sec - start.tv_sec ) * 1e3 + (stop.tv_nsec - start.tv_nsec) / 1e6;

    return ret;

}

static int derive_aes_key_from_shared_secret(const byte* shared_secret, word32 secret_len, byte* aes_key, word32 aes_key_len)
{
    int ret = 0;
    byte fixedInfo[] = { 'A', 'E', 'S', '-', 'K', 'E', 'Y' };

    ret = wc_KDA_KDF_onestep(
        shared_secret, secret_len,
        fixedInfo, sizeof(fixedInfo),
        aes_key_len,
        WC_HASH_TYPE_SHA256,
        aes_key, aes_key_len
    );

    if (ret != 0) {
        printf("Failed to derive AES key: %d\n", ret);
    }
    return ret;
}

static int Ephemeral_Unified_Model()
{
    int ret;
    WC_RNG rng;
    ecc_key a_key, b_key;
    byte a_pub[256], b_pub[256];
    word32 a_pubSz = sizeof(a_pub), b_pubSz = sizeof(b_pub);
    byte z_a[256], z_b[256];
    word32 z_aSz = sizeof(z_a), z_bSz = sizeof(z_b);

    byte aesKey_A[32];  // AES-256 key size
    word32 aesKeySz_A = sizeof(aesKey_A);
    byte aesKey_B[32];  // AES-256 key size
    word32 aesKeySz_B = sizeof(aesKey_B);
    Aes aes_A, aes_B;
    byte iv[AES_BLOCK_SIZE] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};  // Initialization vector for AES
                         /*012345678901234*/
    byte plaintext[16] = {"This is a test."};
    byte ciphertext[128] = {0};  // Buffer for ciphertext
    byte decryptedtext[128] = {0};  // Buffer for decrypted text
    // Initialize
    wolfCrypt_Init();
    wc_ecc_init(&a_key);
    wc_ecc_init(&b_key);
    wc_InitRng(&rng);

    // Make keys at both sides(curve:SECP256R1）
    ret = wc_ecc_make_key(&rng, 32, &a_key);  // A: ephemeral
    if (ret != 0) { printf("Failed to make A key: %d\n", ret); return -1; }
    ret = wc_ecc_make_key(&rng, 32, &b_key);  // B: ephemeral
    if (ret != 0) { printf("Failed to make B key: %d\n", ret); return -1; }

    // export public keys in X9.63 format
    wc_ecc_export_x963(&a_key, a_pub, &a_pubSz);
    wc_ecc_export_x963(&b_key, b_pub, &b_pubSz);

    // read public keys from each other
    ecc_key a_peer, b_peer;
    wc_ecc_init(&a_peer);
    wc_ecc_init(&b_peer);

    if (ret != 0) { printf("Failed to set RNG for B's peer: %d\n", ret); return -1; }
    ret = wc_ecc_import_x963(b_pub, b_pubSz, &a_peer);  // A receives B's public key
    if (ret != 0) { printf("Failed to import B's public key: %d\n", ret); return -1; }
    ret = wc_ecc_import_x963(a_pub, a_pubSz, &b_peer);  // B receives A's public key
    if (ret != 0) { printf("Failed to import A's public key: %d\n", ret); return -1; }

    // Make shared secrets (Z = dA · QB, Z = dB · QA)
    wc_ecc_set_rng(&a_key, &rng);
    ret = wc_ecc_shared_secret(&a_key, &a_peer, z_a, &z_aSz);
    if (ret != 0) { printf("Failed to make A's shared secret: %d\n", ret); return -1; }

    wc_ecc_set_rng(&b_key, &rng);
    ret = wc_ecc_shared_secret(&b_key, &b_peer, z_b, &z_bSz);
    if (ret != 0) { printf("Failed to make B's shared secret: %d\n", ret); return -1; }

    // Compare shared secrets
    if (z_aSz != z_bSz || memcmp(z_a, z_b, z_aSz) != 0) {
        printf("Shared secret mismatch\n");
    } else {
        printf("✅ 鍵共有成功（Z 一致）: %d バイト\n", z_aSz);

    }
    // Derive AES key from shared secret

    // Derive AES A key from shared secret
    ret = derive_aes_key_from_shared_secret(z_a, z_aSz, aesKey_A, aesKeySz_A);
    if (ret != 0) {
        printf("Failed to derive AES key for A: %d\n", ret);
        return -1;
    }
    // Derive AES B key from shared secret
    ret = derive_aes_key_from_shared_secret(z_b, z_bSz, aesKey_B, aesKeySz_B);
    if (ret != 0) {
        printf("Failed to derive AES key for B: %d\n", ret);
        return -1;
    }
     // Compare derived keys
    if (memcmp(aesKey_A, aesKey_B, aesKeySz_A) != 0) {
        printf("derived key mismatch\n");
    } else {
        printf("✅ 鍵成功（一致）: %d バイト\n", z_aSz);
        print_hex("AES Key A", aesKey_A, aesKeySz_A);
        print_hex("AES Key B", aesKey_B, aesKeySz_B);
    }
    wc_AesInit(&aes_A, NULL, INVALID_DEVID);
    wc_AesInit(&aes_B, NULL, INVALID_DEVID);
    // Set AES keys
    ret = wc_AesSetKey(&aes_A, aesKey_A, aesKeySz_A, (const byte*)&iv, AES_ENCRYPTION);
    if (ret != 0) {
        printf("Failed to set AES key for A: %d\n", ret);
        return -1;
    }
    ret = wc_AesSetKey(&aes_B, aesKey_B, aesKeySz_B, (const byte*)&iv, AES_DECRYPTION);
    if (ret != 0) {
        printf("Failed to set AES key for B: %d\n", ret);
        return -1;
    }
    // Encrypt a message using AES
    ret = wc_AesCbcEncrypt(&aes_A, ciphertext, plaintext, sizeof(plaintext));
    if (ret != 0) {
        printf("Failed to encrypt message with AES for A: %d\n", ret);
        return -1;
    }
    printf("✅ A側でメッセージを暗号化しました: %s(len %ld)\n", ciphertext, sizeof(ciphertext));
    printf("暗号化されたメッセージ: ");
    int i = 0;
    do{
        printf("%02x ", ciphertext[i]);
    } while(ciphertext[i] != 0 && i++ < sizeof(ciphertext));
    printf("\n");
    // Decrypt the message using AES
    ret = wc_AesCbcDecrypt(&aes_B, decryptedtext, ciphertext, 16);
    if (ret != 0) {
        printf("Failed to decrypt message with AES for B: %d\n", ret);
        return -1;
    }
    printf("✅ B側でメッセージを復号化しました: %s\n", decryptedtext);
    // Check if decrypted text matches original plaintext
    if (memcmp(plaintext, decryptedtext, sizeof(plaintext)) == 0) {
        printf("✅ 復号化されたメッセージは元のメッセージと一致します。\n");
    } else {
        printf("❌ 復号化されたメッセージは元のメッセージと一致しません。\n");
    }
    // Clean up
    wc_ecc_free(&a_key); wc_ecc_free(&b_key);
    wc_ecc_free(&a_peer); wc_ecc_free(&b_peer);
    wc_FreeRng(&rng);
    wc_AesFree(&aes_A);
    wc_AesFree(&aes_B);
    wolfCrypt_Cleanup();
    return 0;
}

int main(int argc, char** argv)
{
    int ret = 0;

    (void)starttime;
    (void)elapsedtime;

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    ret = Ephemeral_Unified_Model();

    exit(ret);
}