#ifndef __CRYPTOKIT_ENGINE_H__
#define __CRYPTOKIT_ENGINE_H__

#include "CryptoKit.h"

#include <string>

typedef enum {
    ADD, // 加
    REDUCE, // 减
    XOR, // 异或
    NEGATE, // 取反
    // 需要考虑小数
    /*
    RIDE, // 乘
    EXCEPT, // 除
    */
    OPERATETYPEMAX,
} OperateType;

// 密码本，密码本带有随机接口，生成随机密钥
class CodeBook {
public:
    CodeBook();
    ~CodeBook();

    bool Init(const unsigned char* buffer, int buffer_length);

    char RandCode(int& x, int& y, int& o, int& v); // 生成随机点和值
    char GetCode(int x, int y, int o, int v); // 通过坐标，获取值

private:
    unsigned char* code_book_;
    int width_;
    int height_;
    int comp_;
};

// 单例模式加密引擎
class CryptoKitEngine {
public:
    static void Init();
    static void UnInit();

    // 生成Key
    static void CreateKey(const unsigned char* buffer, int buffer_length,
        unsigned char* key, int key_length,
        char** json_data, int* json_data_length);

    // 生成Iv
    static void CreateIv(const unsigned char* buffer, int buffer_length,
        unsigned char* iv, int iv_length,
        char** json_data, int* json_data_length);

    // 通过json 解析出Key
    static bool GetKey(const unsigned char* buffer, int buffer_length,
        const char* json_data, unsigned char** key, int* key_length);

    // 通过json 解析出Iv
    static bool GetIv(const unsigned char* buffer, int buffer_length,
        const char* json_data, unsigned char** iv, int* iv_length);

    // 加密解密
    static int CryptoKitEncrypt(const unsigned char* plaintext, int plaintext_len,
        const unsigned char* key, const unsigned char* iv, unsigned char** ciphertext, CryptoType type = AES_256_CBC);
    static int CryptoKitDecrypt(const unsigned char* ciphertext, int ciphertext_len,
        const unsigned char* key, const unsigned char* iv, unsigned char** plaintext, CryptoType type = AES_256_CBC);

    // 摘要
    static int CryptoKitDigest(const unsigned char* plaintext, int plaintext_len,
        unsigned char** ciphertext, DigestType type);
};
#endif // __CRYPTOKIT_ENGINE_H__
