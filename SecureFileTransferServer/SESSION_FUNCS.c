#include "session_funcs.h"

X509* CerGet(const char* cer_name){
    FILE* cert_file;
    cert_file=fopen(cer_name,"rb");
    if(cert_file==NULL){
        return NULL;
    }
    size_t cert_len=0;
    unsigned char cert_buff[BUFF_SIZE];
    cert_len=fread(cert_buff,1,BUFF_SIZE*4,cert_file);
    fclose(cert_file);
    //Judge the certificate whether is x509 or not.
    const unsigned char *ctemp=cert_buff;
    X509* cert;
    cert=d2i_X509(NULL,&ctemp,cert_len);
    if(cert==NULL){
        BIO* b;
        //Judge the cert whether is PEM or not.
        b=BIO_new_file(cer_name,"r");
        cert=PEM_read_bio_X509(b,NULL,NULL,NULL);
        BIO_free(b);
        if(cert==NULL){
            return NULL;
        }
    }
    return cert;
}

EC_KEY* CerGetPubKey(X509* cert){
    //Parsing certificate.
    EVP_PKEY* pubKey=NULL;
    pubKey=X509_get_pubkey(cert);
    if(NULL==pubKey){
        return NULL;
    }
    return pubKey;
}

int CerGetDigest(X509* cert,unsigned char* digest_buf,unsigned int* len){
    int rc=X509_digest(cert,EVP_sm3(),digest_buf,len);
    if(0==rc||len!=SM3_DIGEST_LENGTH){
        return -1;
    }
    return 0;
}

EC_KEY* GetPriKey(const char* file_name){
    EC_KEY* priKey=NULL;
    BIO* priBp=NULL;
    priBp=BIO_new_file(file_name,"rb");

    if(priBp==NULL){
        return NULL;
    }

    priKey=PEM_read_bio_ECPrivateKey(priBp,NULL,NULL,NULL);
    BIO_free(priBp);
    return priKey;
}
