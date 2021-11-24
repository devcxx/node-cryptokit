#ifndef __CTK_UTIL_H__
#define __CTK_UTIL_H__
#include <string>


typedef struct _i_k{
    std::string m_strI = ""; // 密钥iv 值
    std::string m_strK = ""; // 密钥key
} ik;

#ifdef __cplusplus
extern "C" {
#endif


// 初始化 只初始化一次就可以了
// 生成iv和key的图片路径
bool CtkInitUtil(const std::string& strPath, std::string& err);

// 释放，程序退出时释放
void CtkUnInitUtil();

// 生成IV
bool CreateIUtil(std::string& strI, std::string& err);

// 生成KEY
// strV：服务端返回的key 版本号
// strI：调用CreateIUtil产生的iv
// strK : 服务端返回的key
// nType: 0 : http key， 1：socket key
bool CreateKUtil(const std::string& strV, const std::string& strI, const std::string& strK, const int16_t nType, std::string& err);

// 数据加密
// strData: in:要加密的明文，out:加密好的密文（带前缀头）
// nType ： 0 : http 数据， 1：socket 数据
bool DataE(std::string& strData, const int16_t nType);

// 数据解密
// strData: in:要解密的密文（带前缀头），out:解密好的明文
// strV: 密钥版本号
bool DataD(std::string& strData, const std::string& strV);

#ifdef __cplusplus
}
#endif

#endif // __CTK_UTIL_H__