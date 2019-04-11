#ifndef SM4_CBC_H
#define SM4_CBC_H

#include <stdio.h>
#define BUFF_SIZE 1024
#define cipher_block_size 16

#ifdef __cplusplus
extern "C"{
#endif
/*******************************************************************************************
 * Name:SM4_CBC
 * Function:Create Encrypted file or Decrypted file.
 * Parameters:
 * const char* InFileName : Input file's name(path).
 * const char* OutFileName : Output file's name(path).
 * const unsigned char* key : The key whitch can be used to encrypt or decrypt the file.
 * int enc : The encryption or decryption mode,1 to encrypt,0 to decrypt.
 * Return Value:
 * 0 to succeed,other to fail.
 * *****************************************************************************************/
int SM4_CBC(const char *InFileName, const char *OutFileName, const unsigned char* key, int enc);
#ifdef __cplusplus
}
#endif

#endif // SM4_CBC_H
