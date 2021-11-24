#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "CryptoKit_global.h"

#ifdef __cplusplus
extern "C" {
#endif

// 加密解密类型，必须连续，否则遍历会出错
typedef enum {
    CRYPTO_TYPE_MIN, // 方便遍历
    AES_256_CBC = CRYPTO_TYPE_MIN,
    SM4_CBC,
    CRYPTO_TYPE_MAX
} CryptoType;

typedef enum {
    DIGEST_TYPE_MIN,
    DIGEST_TYPE_SM3 = DIGEST_TYPE_MIN,
    DIGEST_TYPE_SH256,
    DIGEST_TYPE_MAX,
} DigestType;

// 初始化
void  CryptoKitInit();
void  CryptoKitUnInit();

// 生成Key
void  CreateKey(const unsigned char* buffer, int buffer_length,
    unsigned char* key, int key_length,
    char** json_data, int* json_data_length);

// 生成Iv
void  CreateIv(const unsigned char* buffer, int buffer_length,
    unsigned char* iv, int iv_length,
    char** json_data, int* json_data_length);

// 通过json 解析出Key
bool  GetKey(const unsigned char* buffer, int buffer_length,
    const char* json_data, unsigned char** key, int* key_length);

// 通过json 解析出Iv
bool  GetIv(const unsigned char* buffer, int buffer_length,
    const char* json_data, unsigned char** iv, int* iv_length);

int  CryptoKitEncryptBase64(
    const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char** ciphertext,
    CryptoType type = AES_256_CBC);

int  CryptoKitDecryptBase64(const unsigned char* ciphertext,
    int ciphertext_len, const unsigned char* key, const unsigned char* iv,
    unsigned char** plaintext,
    CryptoType type = AES_256_CBC);

int  CryptoKitDigest(const unsigned char* plaintext,
    int plaintext_len,
    unsigned char** ciphertext,
    DigestType type);

// 释放库中创建的内存资源
void  CryptoKitFreeBuffer(unsigned char* buffer);
#ifdef __cplusplus
}
#endif

#endif // __CRYPTO_H__