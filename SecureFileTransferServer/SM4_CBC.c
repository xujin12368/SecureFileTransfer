#include <openssl/evp.h>
#include "sm4_cbc.h"

int SM4_CBC(const char* InFileName,const char* OutFileName,const unsigned char* key,int enc){
    FILE* fpin;
    FILE* fpout;

    fpin=fopen(InFileName,"rb");
    fpout=fopen(OutFileName,"wb");

    EVP_CIPHER_CTX *cipher_ctx;
    const EVP_CIPHER *cipher;

    const unsigned char in_char[BUFF_SIZE];
    size_t in_len = 0;
    unsigned char out_char[BUFF_SIZE+cipher_block_size];
    int out_len = 0;

    int outm_len;

    cipher=EVP_sm4_cbc();
    cipher_ctx=EVP_CIPHER_CTX_new();

    EVP_CipherInit_ex(cipher_ctx,cipher,NULL,key,NULL,enc);
    //对大文件进行加解密
    for(;;){
        in_len=fread(in_char,1,BUFF_SIZE,fpin);
        if(in_len<=0)
            break;
        EVP_CipherUpdate(cipher_ctx,out_char,&out_len,in_char,in_len);
        if(out_len!=fwrite(out_char,1,out_len,fpout)){
            printf("File Write failed.");
            return -1;
        }
    }

    //
//    EVP_CipherFinal_ex(cipher_ctx,out_char+out_len,&outm_len);
//    out_len+=outm_len;
    EVP_CipherFinal_ex(cipher_ctx,out_char,&out_len);
    fwrite(out_char,1,out_len,fpout);
    //EVP_CipherFinal_ex(cipher_ctx,out_char,&outm_len);
    EVP_CIPHER_CTX_free(cipher_ctx);
    fclose(fpin);
    fclose(fpout);
    return 0;
}
