# Secure File Transfer
## 1. 简介  
- 程序分为Server和Client  
- 目前只实现了单向传输，即Client向Server的传输  
- 利用国密算法SM2实现认证和密钥分发  
- 利用SM3和SM4算法保护文件的完整性和机密性  
- 使用Qt实现可视化操作界面  

## 2. 依赖  
- 需要安装GmSSL库  
- 安装方法可参考[GmSSL](http://gmssl.org/)
- 也可访问[GmSSL-GitHub](https://github.com/guanzhi/GmSSL/)
- 使用的Qt环境为v5.11.2 + MinGW  

Contack me at <xujin12368@163.com>