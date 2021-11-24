#include "CryptoKit.h"
#include "CryptoKitEngine.h"

#include "Base64.h"
#include <stdlib.h>
#include <string.h>

void CryptoKitInit()
{
    CryptoKitEngine::Init();
}

void CryptoKitUnInit()
{
    CryptoKitEngine::UnInit();
}

void CreateKey(const unsigned char* buffer, int buffer_length,
    unsigned char* key, int key_length,
    char** json_data, int* json_data_length)
{
    CryptoKitEngine::CreateKey(buffer, buffer_length, key, key_length, json_data, json_data_length);
}

void CreateIv(const unsigned char* buffer, int buffer_length,
    unsigned char* iv, int iv_length,
    char** json_data, int* json_data_length)
{
    CryptoKitEngine::CreateIv(buffer, buffer_length, iv, iv_length, json_data, json_data_length);
}

bool GetKey(const unsigned char* buffer, int buffer_length,
    const char* json_data, unsigned char** key, int* key_length)
{
    return CryptoKitEngine::GetKey(buffer, buffer_length, json_data, key, key_length);
}

bool GetIv(const unsigned char* buffer, int buffer_length,
    const char* json_data, unsigned char** iv, int* iv_length)
{
    return CryptoKitEngine::GetIv(buffer, buffer_length, json_data, iv, iv_length);
}

int CryptoKitEncryptBase64(const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char** out, CryptoType type)
{
    if (plaintext_len == 0) {
        return true;
    }

    CBase64 base64;
    unsigned char* ciphertext = 0;
    int ciphertext_len = CryptoKitEngine::CryptoKitEncrypt(plaintext, plaintext_len, key, iv, &ciphertext, type);

    if (ciphertext_len != 0) {
        base64.Encode((const unsigned char*)ciphertext, ciphertext_len);
        *out = (unsigned char*)malloc((base64.GetOutputLength() + 1) * sizeof(char));
        memset(*out, 0, (base64.GetOutputLength() + 1) * sizeof(char));
        memcpy(*out, base64.GetOutput(), base64.GetOutputLength() * sizeof(char));
    }

    CryptoKitFreeBuffer(ciphertext);
    return base64.GetOutputLength();
}

int CryptoKitDecryptBase64(const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char** out, CryptoType type)
{
    if (ciphertext_len == 0) {
        return true;
    }

    CBase64 base64;
    base64.Decode(ciphertext, ciphertext_len);

    return CryptoKitEngine::CryptoKitDecrypt((unsigned char*)base64.GetOutput(), base64.GetOutputLength(), key, iv, out, type);
}

void CryptoKitFreeBuffer(unsigned char* buffer)
{
    if (buffer) {
        free(buffer);
        buffer = 0;
    }
}
