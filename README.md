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
- 使用的Qt环境为v5.11.2 + MinGW-32bit  


## 3. 运行
- GmSSL库安装完成后，先构建项目  
- 到GmSSL库`bin`目录下将`libcrypto-1_1.dll`和`libssl-1_1.dll`两个文件复制到构建目录下  
- 即可运行程序  

## 4. 注意  
- Client项目是在Linux环境下构建的，若需在Windows环境下构建，参照Server项目修改即可  

Contack me at <xujin12368@163.com>