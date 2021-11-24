var ctk = require('bindings')('node_cryptokit');

var crytokit = {
   ...ctk,
   // 初始化 只初始化一次就可以了
   init() {
      return ctk.ctkInit()
   },
   // 释放，程序退出时释放
   uninit() {
      return ctk.ctkUnInit()
   },
   // 生成IV
   createI() {
      return ctk.ctkCreateI()
   },
   // 生成KEY
   // v：服务端返回的key 版本号
   // i：调用CreateIUtil产生的iv
   // k : 服务端返回的key
   // n: 0 : http key， 1：socket key
   createK(v, i, k, n) {
      return ctk.ctkCreateK(v, i, k, n)
   },
   // 数据加密
   // strData: in:要加密的明文，out:加密好的密文（带前缀头）
   // nType ： 0 : http 数据， 1：socket 数据
   encrypt(data, n) {
      return ctk.dataE(data, n);
   },
   // 数据解密
   // strData: in:要解密的密文（带前缀头），out:解密好的明文
   // strV: 密钥版本号
   decrypt(data, v) {
      return ctk.dataD(data, v);
   }
}

module.exports = exports = crytokit