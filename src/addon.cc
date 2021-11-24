#include <napi.h>
#include <iostream>
#include <fstream>
#include "CryptoKit.h"
#include <Windows.h>
#include "ctk_util.h"

using namespace Napi;
using namespace std;
const unsigned char kDefaultKey[] = "6w3uCqOVJJm9TNgmPeytA58gZl1ugptX";
const unsigned char kDefaultIv[] = "AyvkkWOFyJh0eeQo";
Napi::String Method(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  MessageBox(0, 0, 0, 0);

  const char* filename = "E:/workspace/electronProjects/cryptproject/CryptoKit.jpg";
  char* buffer;
  long size;
  ifstream in(filename, ios::in | ios::binary | ios::ate);
  size = in.tellg();
  in.seekg(0, ios::beg);
  buffer = new char[size];
  in.read(buffer, size);
  in.close();

  CryptoKitInit();
  unsigned char iv[17] = { 0 };
  char* jsonData = nullptr;
  int jsonDataLength = 0;
  CreateIv((unsigned char*)buffer, size,
           iv, 16,
           &jsonData, &jsonDataLength);
  if (jsonDataLength > 0) {
      unsigned char* ciphertext = 0;
      char* in = "aaa";
      cout << "ciphertext before = " << in << endl;
      int ciphertext_len = CryptoKitEncryptBase64((unsigned char*)in, 3, kDefaultKey, kDefaultIv, &ciphertext, AES_256_CBC);
      cout << "ciphertext after = " << ciphertext << endl;;

      unsigned char* decryptedtext = 0;
      int decryptedtext_len = CryptoKitDecryptBase64(ciphertext, ciphertext_len, kDefaultKey, kDefaultIv, &decryptedtext, AES_256_CBC);

      string straa = (char*)decryptedtext;
      cout << "straa = " << straa << endl;;

      CryptoKitFreeBuffer(decryptedtext);

      CryptoKitFreeBuffer(ciphertext);
  }




  CryptoKitUnInit();
  
  cout << "the complete file is in a buffer";
  
  delete[] buffer;
  return Napi::String::New(env, "world");
}

#define REQUIRE_ARGUMENT_STRING(i, var)                                                             \
    if (info.Length() <= (i) || !info[i].IsString()) {                                              \
        Napi::TypeError::New(env, "Argument " #i " must be a string").ThrowAsJavaScriptException(); \
        return env.Null();                                                                          \
    }                                                                                               \
    std::string var = info[i].As<Napi::String>();

#define REQUIRE_ARGUMENT_INTEGER(i, var)                                                              \
    if (info.Length() <= (i) || !info[i].IsNumber()) {                                                \
        Napi::TypeError::New(env, "Argument " #i " must be an integer").ThrowAsJavaScriptException(); \
        return env.Null();                                                                            \
    }                                                                                                 \
    int var(info[i].As<Napi::Number>().Int32Value());

// ckInit(path: string) => bool
Napi::Value ctkInit(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    REQUIRE_ARGUMENT_STRING(0, key);

    // 初始化
    std::string err;
    bool ret = CtkInitUtil(key, err);
    if (!ret)
        Napi::TypeError::New(env, err).ThrowAsJavaScriptException();

    return Boolean::New(env, ret);
}

// ctkUnInit(void) => void
void ctkUnInit(const Napi::CallbackInfo& info)
{
    // 释放，程序退出时释放
    CtkUnInitUtil();

}

// ctkCreateK(v: string, i: string, k string, type: Number) => bool
Napi::Value ctkCreateK(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    REQUIRE_ARGUMENT_STRING(0, strV);
    REQUIRE_ARGUMENT_STRING(1, strI);
    REQUIRE_ARGUMENT_STRING(2, strK);
    REQUIRE_ARGUMENT_INTEGER(3, nType);
    std::string err;
    bool ret = CreateKUtil(strV, strI, strK, nType, err);
    if (!ret)
        Napi::TypeError::New(env, err).ThrowAsJavaScriptException();

    return Boolean::New(env, ret);
}

// 生成IV
// ctkCreateI(void) => bool
Napi::Value ctkCreateI(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    // 生成IV
    std::string strI, err;
    bool ret = CreateIUtil(strI, err);
    if (!ret)
        Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
    return String::New(env, strI);
}


// dataE(data: string, type: Number) => string
Napi::Value dataE(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    REQUIRE_ARGUMENT_STRING(0, data);
    REQUIRE_ARGUMENT_INTEGER(1, type);

    bool ret = DataE(data, type);
    if (!ret)
        Napi::TypeError::New(env, "encrypt failed").ThrowAsJavaScriptException();
    return String::New(env, data);
}

// dataE(data: string, v: string) => string
Napi::Value dataD(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    REQUIRE_ARGUMENT_STRING(0, data);
    REQUIRE_ARGUMENT_STRING(1, v);

    bool ret = DataD(data, v);
    if (!ret)
        Napi::TypeError::New(env, "decrypt failed").ThrowAsJavaScriptException();

    return String::New(env, data);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "ctkInit"), Napi::Function::New(env, ctkInit));
    exports.Set(Napi::String::New(env, "ctkUnInit"), Napi::Function::New(env, ctkUnInit));
    exports.Set(Napi::String::New(env, "ctkCreateI"), Napi::Function::New(env, ctkCreateI));
    exports.Set(Napi::String::New(env, "ctkCreateK"), Napi::Function::New(env, ctkCreateK));
    exports.Set(Napi::String::New(env, "dataE"), Napi::Function::New(env, dataE));
    exports.Set(Napi::String::New(env, "dataD"), Napi::Function::New(env, dataD));
  return exports;
}

NODE_API_MODULE(node_cryptokit, Init)
