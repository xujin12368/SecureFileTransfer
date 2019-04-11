#ifndef SM4_CBC_H
#define SM4_CBC_H

#define BUFF_SIZE 1024
#define cipher_block_size 16

#ifdef __cplusplus
extern "C"{
#endif
//Main
int SM4_CBC(const char* InFileName,const char* OutFileName,const unsigned char* key,int enc);
#ifdef __cplusplus
}
#endif

#endif // SM4_CBC_H
