#ifndef SM3_H
#define SM3_H
typedef unsigned int size_t;
//#ifdef(__cplusplus)||define(c_plusplus)
#ifdef __cplusplus
extern "C"{
#endif
int SM3(const char *message, size_t len, unsigned char *hash, unsigned int *hash_len);
//#ifdef(__cplusplus)||define(c_plusplus)
#ifdef __cplusplus
}
#endif

#endif // SM3_H
