#ifndef SESSION_FUNCS_H
#define SESSION_FUNCS_H

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <openssl/x509.h>

#define size_t unsigned int
#define BUFF_SIZE 1024

#ifdef __cplusplus
extern "C"{
#endif
X509* CerGet(const char* cer_name);
EC_KEY* CerGetPubKey(X509* cert);
int CerGetDigest(X509* cert,unsigned char* digest_buf,unsigned int* len);
int SM2GetSig(unsigned char *digest_buf, unsigned int len);
int CertVerify(const char *cert_name, char *issuer_get);
#ifdef __cplusplus
}
#endif

#endif // SESSION_FUNCS_H
