#include "ctk_util.h"
#include "CryptoKit.h"

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

#define DEV 1

#if DEV
#include "ctk_dev.h"
#define CTK_IMG ctk_dev
#define CTK_IMG_SIZE 28733
#else
#include "ctk.h"
#define CTK_IMG ctk
#define CTK_IMG_SIZE 42153
#endif

using namespace std;
namespace {
    const string kDKHeader = string("lGzT3mHESuNTFhY6");
    const int kKHeaderLength = 16;
    //unique_ptr<char> g_pFileData = nullptr;
    //long g_fileSize = 0;
    std::map<std::string, ik> g_ikMap; // <密钥版本号, iv-key>
    set<string> g_iSet;
    ik g_curHttpIk; // 当前最新的http iv-key
    ik g_curSocetIk; // 当前最新的socket iv-key

    unique_ptr<char> getFileContent(const std::string& strPath, long &size) {
        char* buffer;
        ifstream in(strPath, ios::in | ios::binary | ios::ate);
        size = in.tellg();
        in.seekg(0, ios::beg);
        buffer = new char[size];
        in.read(buffer, size);
        in.close();
        return unique_ptr<char>(buffer);
    }

    ik& getIk(const int16_t nType) {
        if (0 == nType) {
            return g_curHttpIk;
        } else {
            return g_curSocetIk;
        }
    }
}

// 初始化
bool CtkInitUtil(std::string& err)
{
    CryptoKitInit();
    return true;
}

void CtkUnInitUtil()
{
    CryptoKitUnInit();
}

// 调用此函数必须保证加解密组件已经初始化
bool CreateIUtil(std::string& strI, std::string& err) {
    unsigned char iv[17] = { 0 };
    char* jsonData = nullptr;
    int jsonDataLength = 0;
    CreateIv((unsigned char*)CTK_IMG, CTK_IMG_SIZE,
             iv, 16,
             &jsonData, &jsonDataLength);
    if (jsonDataLength > 0) {
        strI = jsonData; // IV值
        g_iSet.insert(strI);
        
    }
    CryptoKitFreeBuffer((unsigned char*)jsonData);
    return true;
}

bool CreateKUtil(const std::string& strV, const std::string& strI, const std::string& strK, const int16_t nType, std::string& err) {
    if (g_iSet.find(strI) == g_iSet.end()) {
        std::ostringstream oss;
        oss << "create k failed, can not find " << strI << " i" ;
        err = oss.str();
        return false;
    }
    g_iSet.erase(strI);
    unsigned char* key = nullptr;
    int keyLength = 0;
    GetKey((unsigned char*)CTK_IMG, CTK_IMG_SIZE, strK.c_str(), &key, &keyLength);
    if (keyLength > 0) {
        ik& ikTemp = getIk(nType);
        ikTemp.m_strI = strI;
        ikTemp.m_strK = (char*)key;
        g_ikMap.insert(map<string, ik>::value_type(strV, ikTemp));
        CryptoKitFreeBuffer(key);
    } else {
        err = "create k failed";
        return false;
    }
    return true;
}

bool DataE(std::string& strData, const int16_t nType) {
   
    if (strData.empty()) {
        return true;
    }
    ik& curIk = getIk(nType);
    unsigned char* ciphertext = 0;
    int ciphertext_len = CryptoKitEncryptBase64((unsigned char*)strData.c_str(), strData.size(), 
                                                (unsigned char*)curIk.m_strK.c_str(),
                                                (unsigned char*)curIk.m_strI.c_str(), &ciphertext, AES_256_CBC);

    strData = kDKHeader + string((char*)ciphertext);

    CryptoKitFreeBuffer(ciphertext);
    return ciphertext_len != 0;
}

bool DataD(std::string& strData, const std::string& strV) {
    if (g_ikMap.find(strV) == g_ikMap.end()) {
        cout << "d failed" << endl;
        return false;
    }

    if (strData.empty()) {
        return true;
    }


    int nPos = strData.find(kDKHeader);
    if (-1 == nPos) {
        cout << "d failed, can not find header" << endl;
        return false;
    }

    string strTemp = strData.substr(nPos + kDKHeader.size(), strData.size());

    // 密文解密
    unsigned char* decryptedtext = 0;
    int decryptedtext_len = CryptoKitDecryptBase64((unsigned char*)strTemp.c_str(), strTemp.size(),
                                                   (unsigned char*)g_ikMap[strV].m_strK.c_str(),
                                                   (unsigned char*)g_ikMap[strV].m_strI.c_str(),
                                                   &decryptedtext, AES_256_CBC);

    strData = (char*)decryptedtext;

    CryptoKitFreeBuffer(decryptedtext);

    return decryptedtext_len != 0;
}
