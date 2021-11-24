#ifndef __CRYPTOKIT_ENGINE_H__
#define __CRYPTOKIT_ENGINE_H__

#include "CryptoKit.h"

#include <string>

typedef enum {
    ADD, // ��
    REDUCE, // ��
    XOR, // ���
    NEGATE, // ȡ��
    // ��Ҫ����С��
    /*
    RIDE, // ��
    EXCEPT, // ��
    */
    OPERATETYPEMAX,
} OperateType;

// ���뱾�����뱾��������ӿڣ����������Կ
class CodeBook {
public:
    CodeBook();
    ~CodeBook();

    bool Init(const unsigned char* buffer, int buffer_length);

    char RandCode(int& x, int& y, int& o, int& v); // ����������ֵ
    char GetCode(int x, int y, int o, int v); // ͨ�����꣬��ȡֵ

private:
    unsigned char* code_book_;
    int width_;
    int height_;
    int comp_;
};

// ����ģʽ��������
class CryptoKitEngine {
public:
    static void Init();
    static void UnInit();

    // ����Key
    static void CreateKey(const unsigned char* buffer, int buffer_length,
        unsigned char* key, int key_length,
        char** json_data, int* json_data_length);

    // ����Iv
    static void CreateIv(const unsigned char* buffer, int buffer_length,
        unsigned char* iv, int iv_length,
        char** json_data, int* json_data_length);

    // ͨ��json ������Key
    static bool GetKey(const unsigned char* buffer, int buffer_length,
        const char* json_data, unsigned char** key, int* key_length);

    // ͨ��json ������Iv
    static bool GetIv(const unsigned char* buffer, int buffer_length,
        const char* json_data, unsigned char** iv, int* iv_length);

    // ���ܽ���
    static int CryptoKitEncrypt(const unsigned char* plaintext, int plaintext_len,
        const unsigned char* key, const unsigned char* iv, unsigned char** ciphertext, CryptoType type = AES_256_CBC);
    static int CryptoKitDecrypt(const unsigned char* ciphertext, int ciphertext_len,
        const unsigned char* key, const unsigned char* iv, unsigned char** plaintext, CryptoType type = AES_256_CBC);

    // ժҪ
    static int CryptoKitDigest(const unsigned char* plaintext, int plaintext_len,
        unsigned char** ciphertext, DigestType type);
};
#endif // __CRYPTOKIT_ENGINE_H__
