#include "CryptoKitEngine.h"

#include <stdlib.h>
#include <time.h>

#include <memory.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/sm3.h>
#include <openssl/sm4.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <vector>

#define STB_IMAGE_IMPLEMENTATION
#include "cJSON.h"
#include "cJSON_Utils.h"
#include "stb_image.h"

#define JSON_FORMAT 0

namespace {
const char kTypes[] = "types";
const char kType[] = "type";

const char kKey[] = "data";
const char kIv[] = "data";
const char kX[] = "x";
const char kY[] = "y";
const char kO[] = "o";
const char kV[] = "v";

const char kChars[] = "!\"#$%&'()*+,-./"
                      "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^`"
                      "abcdefghijklmnopqrstuvwxyz{|}~";
const int kCharsLength = 93;

const CryptoType kDefaultCryptoType = AES_256_CBC;
const int kMAXOperate = 1024;

char RGBToKey(unsigned char r, unsigned char g, unsigned char b)
{
    return kChars[(r | g & b) % kCharsLength];
}

void MixPoint(int& x, int& y, int& o, int& v)
{

    switch (o % OPERATETYPEMAX) {
    case ADD:
        x += v;
        y += v;
        break;
    case REDUCE:
        x -= v;
        y -= v;
        break;

    case XOR:
        x ^= v;
        y ^= v;
        break;
    case NEGATE:
        x = ~x;
        y = ~y;
        break;
    default:
        break;
    }
}

void ReductionPoint(int& x, int& y, int& o, int& v)
{
    switch (o % OPERATETYPEMAX) {
    case ADD:
        x -= v;
        y -= v;
        break;
    case REDUCE:
        x += v;
        y += v;
        break;

    case XOR:
        x ^= v;
        y ^= v;
        break;
    case NEGATE:
        x = ~x;
        y = ~y;
        break;
    default:
        break;
    }
}

size_t CipherLength(int plaintext_len, CryptoType type)
{
    size_t cipher_length = 0;
    switch (type) {
    case AES_256_CBC:
        cipher_length = (plaintext_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
        break;
    case SM4_CBC:
        cipher_length = (plaintext_len / SM4_BLOCK_SIZE + 1) * SM4_BLOCK_SIZE;
        break;
    default:
        cipher_length = 0;
        break;
    }
    return cipher_length;
}

int DigestLength(DigestType type)
{
    int digest_length = 0;
    switch (type) {
    case DIGEST_TYPE_SM3:
        digest_length = SM3_DIGEST_LENGTH;
        break;
    case DIGEST_TYPE_SH256:
        digest_length = SHA256_DIGEST_LENGTH;
        break;
    default:
        digest_length = 0;
        break;
    }
    return digest_length;
}

EVP_CIPHER* GetEvpCipher(CryptoType type)
{
    EVP_CIPHER* cipher = 0;
    switch (type) {
    case AES_256_CBC:
        cipher = (EVP_CIPHER*)EVP_aes_256_cbc();
        break;
    case SM4_CBC:
        cipher = (EVP_CIPHER*)EVP_sm4_cbc();
        break;
    default:
        break;
    }
    return cipher;
}

EVP_MD* GetEvpMD(DigestType type)
{
    EVP_MD* md = 0;
    switch (type) {
    case DIGEST_TYPE_SM3:
        md = (EVP_MD*)EVP_sm3();
        break;
    case DIGEST_TYPE_SH256:
        md = (EVP_MD*)EVP_sha256();
        break;
    default:
        break;
    }
    return md;
}

int Encrypt(const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char** ciphertext, CryptoType type)
{
    EVP_CIPHER_CTX* ctx = 0;
    int len = 0;
    int ciphertext_len = 0;

    EVP_CIPHER* cipher = GetEvpCipher(type);
    int cipher_len = (int)CipherLength(plaintext_len, type);
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        ciphertext_len = 0;
        goto error;
    }

    if (!cipher || !cipher_len) {
        ERR_print_errors_fp(stderr);
        ciphertext_len = 0;
        goto error;
    }

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        ciphertext_len = 0;
        goto error;
    }

    *ciphertext = (unsigned char*)malloc(sizeof(unsigned char) * (cipher_len + 1));
    memset(*ciphertext, 0, sizeof(unsigned char) * (cipher_len + 1));

    /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) {
        ERR_print_errors_fp(stderr);
        ciphertext_len = 0;
        goto error;
    }
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) {
        ERR_print_errors_fp(stderr);
        ciphertext_len = 0;
        goto error;
    }

    ciphertext_len += len;

error:
    if (ctx) {
        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);
    }

    if (ciphertext_len == 0 && *ciphertext) {
        free(*ciphertext);
    }

    return ciphertext_len;
}

int Decrypt(const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char** plaintext, CryptoType type)
{
    EVP_CIPHER_CTX* ctx = 0;
    int len = 0;
    int plaintext_len = 0;

    EVP_CIPHER* cipher = GetEvpCipher(type);
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        plaintext_len = 0;
        goto error;
    }

    if (!cipher) {
        ERR_print_errors_fp(stderr);
        plaintext_len = 0;
        goto error;
    }

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        plaintext_len = 0;
        goto error;
    }

    *plaintext = (unsigned char*)malloc(sizeof(unsigned char) * (ciphertext_len + 1));
    memset(*plaintext, 0, sizeof(unsigned char) * (ciphertext_len + 1));

    /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) {
        plaintext_len = 0;
        ERR_print_errors_fp(stderr);
        goto error;
    }
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
    if (1 != EVP_DecryptFinal_ex(ctx, (*plaintext) + len, &len)) {
        ERR_print_errors_fp(stderr);
        plaintext_len = 0;
        goto error;
    }

    plaintext_len += len;
    *(*plaintext + plaintext_len) = (unsigned char)'\0'; // 添加结束符
error:
    if (ctx) {
        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);
    }

    if (ciphertext_len == 0 && *ciphertext) {
        free((char*)*ciphertext);
    }

    return plaintext_len;
}

} // namespace

CodeBook::CodeBook()
    : code_book_(0)
    , width_(0)
    , height_(0)
    , comp_(0)
{
}

bool CodeBook::Init(const unsigned char* buffer, int buffer_length)
{
    code_book_ = stbi_load_from_memory(buffer, buffer_length, &width_, &height_,
        &comp_, 0);
    return code_book_ != 0;
}

char CodeBook::RandCode(int& x, int& y, int& o, int& v)
{
    x = rand() % width_;
    y = rand() % height_;

    unsigned char r = code_book_[comp_ * width_ * x + y * comp_ + 0];
    unsigned char g = code_book_[comp_ * width_ * x + y * comp_ + 1];
    unsigned char b = code_book_[comp_ * width_ * x + y * comp_ + 2];

    o = (rand() % kMAXOperate);   // 随机操作方法
    v = (rand() % 512);

    // printf("old x:%d, y:%d, o:%d, v:%d \n", x, y, o, v);
    MixPoint(x, y, o, v);
    // printf("new x:%d, y:%d, o:%d, v:%d \n", x, y, o, v);

    return RGBToKey(r, g, b);
}

char CodeBook::GetCode(int x, int y, int o, int v)
{
    // printf("old x:%d, y:%d, o:%d, v:%d \n", x, y, o, v);
    ReductionPoint(x, y, o, v);
    // printf("new x:%d, y:%d, o:%d, v:%d \n", x, y, o, v);
    assert(x >= 0 && x < width_);
    assert(y >= 0 && y < height_);

    unsigned char r = code_book_[comp_ * width_ * x + y * comp_ + 0];
    unsigned char g = code_book_[comp_ * width_ * x + y * comp_ + 1];
    unsigned char b = code_book_[comp_ * width_ * x + y * comp_ + 2];
    return RGBToKey(r, g, b);
}

CodeBook::~CodeBook()
{
    stbi_image_free(code_book_);
}

void CryptoKitEngine::Init()
{
    srand((unsigned)time(NULL));
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}

void CryptoKitEngine::UnInit()
{
    /* Clean up */
    CONF_modules_unload(1);        //for conf
    EVP_cleanup();                 //For EVP
    ENGINE_cleanup();              //for engine
    CRYPTO_cleanup_all_ex_data();  //generic 
    ERR_remove_state(0);           //for ERR
    ERR_free_strings();            //for ERR
}

#if JSON_FORMAT
/*
{
  "type": 1,
  "data": [
    -71,67,1,300,-68,-391,3,356,
  ]
}
*/
void CryptoKitEngine::CreateKey(const unsigned char* buffer, int buffer_length,
    unsigned char* key, int key_length,
    char** json_data, int* json_data_length)
{
    CodeBook code_book;
    code_book.Init(buffer, buffer_length);

    cJSON* root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, kType, cJSON_CreateNumber(kDefaultCryptoType));

    cJSON* key_array = cJSON_CreateArray();
    for (int i = 0; i < key_length; ++i) {
        int x = 0;
        int y = 0;
        OperateType o;
        int value = 0;

        key[i] = code_book.RandCode(x, y, o, value);
        cJSON_AddItemToArray(key_array, cJSON_CreateNumber(x));
        cJSON_AddItemToArray(key_array, cJSON_CreateNumber(y));
        cJSON_AddItemToArray(key_array, cJSON_CreateNumber(o));
        cJSON_AddItemToArray(key_array, cJSON_CreateNumber(value));
    }
    cJSON_AddItemToObject(root, kKey, key_array);
    *json_data = cJSON_PrintBuffered(root, 1, 0);
    *json_data_length = strlen(*json_data);

    cJSON_Delete(root);
}

/*
{
  "types": [
    1,
    2
  ],
  "data": [
    -71,67,1,300,-68,-391,3,356,
  ]
}
*/
void CryptoKitEngine::CreateIv(const unsigned char* buffer, int buffer_length,
    unsigned char* iv, int iv_length,
    char** json_data, int* json_data_length)
{
    CodeBook code_book;
    code_book.Init(buffer, buffer_length);

    cJSON* root = cJSON_CreateObject();

    cJSON* type_array = cJSON_CreateArray();
    for (CryptoType e = CRYPTO_TYPE_MIN; e < CRYPTO_TYPE_MAX;
         e = (CryptoType)(e + 1)) {
        cJSON_AddItemToArray(type_array, cJSON_CreateNumber(e));
    }

    cJSON_AddItemToObject(root, kTypes, type_array);

    cJSON* iv_array = cJSON_CreateArray();
    for (int i = 0; i < iv_length; ++i) {
        int x = 0;
        int y = 0;
        OperateType o;
        int value = 0;
        iv[i] = (code_book.RandCode(x, y, o, value));

        cJSON_AddItemToArray(iv_array, cJSON_CreateNumber(x));
        cJSON_AddItemToArray(iv_array, cJSON_CreateNumber(y));
        cJSON_AddItemToArray(iv_array, cJSON_CreateNumber(o));
        cJSON_AddItemToArray(iv_array, cJSON_CreateNumber(value));
    }
    cJSON_AddItemToObject(root, kIv, iv_array);
    *json_data = cJSON_PrintBuffered(root, 1, 0);
    *json_data_length = strlen(*json_data);

    cJSON_Delete(root);
}

bool CryptoKitEngine::GetKey(const unsigned char* buffer, int buffer_length,
    const char* json_data, unsigned char** key, int* key_length)
{
    CodeBook code_book;
    code_book.Init(buffer, buffer_length);

    bool result = false;

    cJSON* root = cJSON_Parse(json_data);
    if (root) {
        cJSON* obj_key = cJSON_GetObjectItem(root, kKey);
        if (cJSON_IsArray(obj_key)) {
            *key_length = cJSON_GetArraySize(obj_key) / 4;
            *key = (unsigned char*)malloc((*key_length + 1) * sizeof(unsigned char));
            memset(*key, 0, (*key_length + 1) * sizeof(unsigned char));

            for (int i = 0, j = 0; i < cJSON_GetArraySize(obj_key);) {
                cJSON* item_x = cJSON_GetArrayItem(obj_key, i++);
                cJSON* item_y = cJSON_GetArrayItem(obj_key, i++);
                cJSON* item_o = cJSON_GetArrayItem(obj_key, i++);
                cJSON* item_v = cJSON_GetArrayItem(obj_key, i++);
                int x = (int)cJSON_GetNumberValue(item_x);
                int y = (int)cJSON_GetNumberValue(item_y);
				int type = static_cast<int>(cJSON_GetNumberValue(item_o));
                OperateType o = (OperateType)type;
                int v = (int)cJSON_GetNumberValue(item_v);

                (*key)[j++] = code_book.GetCode(x, y, o, v);
            }
        } else {
            goto error;
        }
    }

    result = true;
error:
    cJSON_Delete(root);
    return result;
}

bool CryptoKitEngine::GetIv(const unsigned char* buffer, int buffer_length,
    const char* json_data, unsigned char** iv, int* iv_length)
{
    CodeBook code_book;
    code_book.Init(buffer, buffer_length);
    bool result = false;
    cJSON* root = cJSON_Parse(json_data);
    if (root) {
        cJSON* obj_vi = cJSON_GetObjectItem(root, kIv);
        if (cJSON_IsArray(obj_vi)) {
            *iv_length = cJSON_GetArraySize(obj_vi) / 4;
            *iv = (unsigned char*)malloc((*iv_length + 1) * sizeof(unsigned char));
            memset(*iv, 0, (*iv_length + 1) * sizeof(unsigned char));

            for (int i = 0, j = 0; i < cJSON_GetArraySize(obj_vi);) {
                cJSON* item_x = cJSON_GetArrayItem(obj_vi, i++);
                cJSON* item_y = cJSON_GetArrayItem(obj_vi, i++);
                cJSON* item_o = cJSON_GetArrayItem(obj_vi, i++);
                cJSON* item_v = cJSON_GetArrayItem(obj_vi, i++);
                int x = (int)cJSON_GetNumberValue(item_x);
                int y = (int)cJSON_GetNumberValue(item_y);
                int type = static_cast<int>(cJSON_GetNumberValue(item_o));
                OperateType o = (OperateType)type;
                int v = (int)cJSON_GetNumberValue(item_v);

                (*iv)[j++] = code_book.GetCode(x, y, o, v);
            }
        } else {
            goto error;
        }
    }
    result = true;
error:
    cJSON_Delete(root);
    return result;
}
#else
void CryptoKitEngine::CreateKey(const unsigned char* buffer, int buffer_length,
    unsigned char* key, int key_length,
    char** json_data, int* json_data_length)
{
    CodeBook code_book;
    code_book.Init(buffer, buffer_length);

    *json_data_length = 0;
    cJSON* key_array = cJSON_CreateArray();
    for (int i = 0; i < key_length; ++i) {
        int x = 0;
        int y = 0;
        int o = 0;
        int value = 0;

        key[i] = code_book.RandCode(x, y, o, value);
        cJSON_AddItemToArray(key_array, cJSON_CreateNumber(x));
        cJSON_AddItemToArray(key_array, cJSON_CreateNumber(y));
        cJSON_AddItemToArray(key_array, cJSON_CreateNumber(o));
        cJSON_AddItemToArray(key_array, cJSON_CreateNumber(value));
    }

    char* json_tmp = cJSON_PrintBuffered(key_array, 1, 0);
    if (json_tmp) {
        *json_data_length = (int)strlen(json_tmp);

        *json_data = (char*)malloc(*json_data_length);
        if (*json_data) {
            memset(*json_data, 0, *json_data_length);

            // 拷贝字符串
            *json_data_length -= 2;
            memcpy(*json_data, json_tmp + 1, *json_data_length);
        } else {
            *json_data_length = 0;
        }
        free(json_tmp);
        json_tmp = 0;
    }
    cJSON_Delete(key_array);
}

void CryptoKitEngine::CreateIv(const unsigned char* buffer, int buffer_length,
    unsigned char* iv, int iv_length,
    char** json_data, int* json_data_length)
{
    CodeBook code_book;
    code_book.Init(buffer, buffer_length);

    cJSON* iv_array = cJSON_CreateArray();
    for (int i = 0; i < iv_length; ++i) {
        int x = 0;
        int y = 0;
        int o = 0;
        int value = 0;
        iv[i] = (code_book.RandCode(x, y, o, value));

        cJSON_AddItemToArray(iv_array, cJSON_CreateNumber(x));
        cJSON_AddItemToArray(iv_array, cJSON_CreateNumber(y));
        cJSON_AddItemToArray(iv_array, cJSON_CreateNumber(o));
        cJSON_AddItemToArray(iv_array, cJSON_CreateNumber(value));
    }

    char* json_tmp = cJSON_PrintBuffered(iv_array, 1, 0);
    if (json_tmp) {
        *json_data_length = (int)strlen(json_tmp);

        *json_data = (char*)malloc(*json_data_length);
        if (*json_data) {
            memset(*json_data, 0, *json_data_length);

            // 拷贝字符串，去掉 []
            *json_data_length -= 2;
            memcpy(*json_data, json_tmp + 1, *json_data_length);
        } else {
            *json_data_length = 0;
        }
        free(json_tmp);
        json_tmp = 0;
    }

    cJSON_Delete(iv_array);
}

bool CryptoKitEngine::GetKey(const unsigned char* buffer, int buffer_length,
    const char* json_data, unsigned char** key, int* key_length)
{
    CodeBook code_book;
    code_book.Init(buffer, buffer_length);

    bool result = false;
    *key_length = 0;
    cJSON* obj_key = 0;

    // 前后添加 []，再解析
    int temp_json_length = (int)strlen(json_data);
    char* temp_json = (char*)malloc((temp_json_length + 3) * sizeof(char*)); // 还需要空格结束
    if (temp_json) {
        memset(temp_json, 0, temp_json_length + 3);
        temp_json[0] = '[';
        memcpy(temp_json + 1, json_data, temp_json_length); // 拷贝字符串
        temp_json[temp_json_length + 1] = ']';

        obj_key = cJSON_Parse(temp_json);
        if (obj_key && cJSON_IsArray(obj_key)) {
            *key_length = cJSON_GetArraySize(obj_key) / 4;
            *key = (unsigned char*)malloc((*key_length + 1) * sizeof(unsigned char));
            memset(*key, 0, (*key_length + 1) * sizeof(unsigned char));

            for (int i = 0, j = 0; i < cJSON_GetArraySize(obj_key);) {
                cJSON* item_x = cJSON_GetArrayItem(obj_key, i++);
                cJSON* item_y = cJSON_GetArrayItem(obj_key, i++);
                cJSON* item_o = cJSON_GetArrayItem(obj_key, i++);
                cJSON* item_v = cJSON_GetArrayItem(obj_key, i++);
                int x = (int)cJSON_GetNumberValue(item_x);
                int y = (int)cJSON_GetNumberValue(item_y);
                int type = static_cast<int>(cJSON_GetNumberValue(item_o));
                OperateType o = (OperateType)type;
                int v = (int)cJSON_GetNumberValue(item_v);

                (*key)[j++] = code_book.GetCode(x, y, o, v);
            }
        } else {
            goto error;
        }

        result = true;
    } else {
        goto error;
    }
error:
    if (temp_json) {
        free(temp_json);
    }

    cJSON_Delete(obj_key);
    return result;
}

bool CryptoKitEngine::GetIv(const unsigned char* buffer, int buffer_length,
    const char* json_data, unsigned char** iv, int* iv_length)
{
    CodeBook code_book;
    code_book.Init(buffer, buffer_length);
    bool result = false;

    *iv_length = 0;
    // 前后添加 []，再解析
    int temp_json_length = (int)strlen(json_data);
    char* temp_json = (char*)malloc((temp_json_length + 3) * sizeof(char*)); // 还需要空格结束
    cJSON* obj_vi = 0;
    if (temp_json) {
        memset(temp_json, 0, temp_json_length + 3);
        temp_json[0] = '[';
        memcpy(temp_json + 1, json_data, temp_json_length); // 拷贝字符串
        temp_json[temp_json_length + 1] = ']';

        obj_vi = cJSON_Parse(temp_json);
        if (obj_vi && cJSON_IsArray(obj_vi)) {
            *iv_length = cJSON_GetArraySize(obj_vi) / 4;
            *iv = (unsigned char*)malloc((*iv_length + 1) * sizeof(unsigned char));
            memset(*iv, 0, (*iv_length + 1) * sizeof(unsigned char));

            for (int i = 0, j = 0; i < cJSON_GetArraySize(obj_vi);) {
                cJSON* item_x = cJSON_GetArrayItem(obj_vi, i++);
                cJSON* item_y = cJSON_GetArrayItem(obj_vi, i++);
                cJSON* item_o = cJSON_GetArrayItem(obj_vi, i++);
                cJSON* item_v = cJSON_GetArrayItem(obj_vi, i++);
                int x = (int)cJSON_GetNumberValue(item_x);
                int y = (int)cJSON_GetNumberValue(item_y);
                int type = static_cast<int>(cJSON_GetNumberValue(item_o));
                OperateType o = (OperateType)type;
                int v = (int)cJSON_GetNumberValue(item_v);

                (*iv)[j++] = code_book.GetCode(x, y, o, v);
            }
        } else {
            goto error;
        }

        result = true;
    } else {
        goto error;
    }
error:
    if (temp_json) {
        free(temp_json);
    }

    cJSON_Delete(obj_vi);
    return result;
}
#endif // JSON_FORMAT

int CryptoKitEngine::CryptoKitEncrypt(const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char** ciphertext, CryptoType type)
{
    return Encrypt(plaintext, plaintext_len, key, iv, ciphertext, type);
}

int CryptoKitEngine::CryptoKitDecrypt(const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char** plaintext, CryptoType type)
{
    return Decrypt(ciphertext, ciphertext_len, key, iv, plaintext, type);
}

int CryptoKitDigest(const unsigned char* plaintext, int plaintext_len,
    unsigned char** ciphertext, DigestType type)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    int ciphertext_length = DigestLength(type);
    EVP_MD* md = GetEvpMD(type);

    if (ctx == 0 || ciphertext_length == 0 || !md) {
        ciphertext_length = 0;
        goto error;
    }

    *ciphertext = (unsigned char*)malloc(sizeof(unsigned char) * (ciphertext_length + 1));
    memset(*ciphertext, 0, sizeof(unsigned char) * (ciphertext_length + 1));

    if (!EVP_DigestInit_ex(ctx, md, NULL) || !EVP_DigestUpdate(ctx, plaintext, plaintext_len) || !EVP_DigestFinal_ex(ctx, *ciphertext, NULL)) {
        ciphertext_length = 0;
        goto error;
    }

error:
    if (ctx) {
        EVP_MD_CTX_destroy(ctx);
    }

    if (ciphertext_length == 0) {
        free((char*)*ciphertext);
    }

    return ciphertext_length;
}