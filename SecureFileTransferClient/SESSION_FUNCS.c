#include "SESSION_FUNCS.h"

X509* CerGet(const char* cer_name){
    FILE* cert_file;
    cert_file=fopen(cer_name,"rb");
    if(cert_file==NULL){
        printf("\ncert_file is null.\n");
        return NULL;
    }
    size_t cert_len=0;
    unsigned char cert_buff[BUFF_SIZE*4];//can easily overflow.
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
        printf("\npub key is null.\n");
        return NULL;
    }
    BIO* bp=NULL;
    bp=BIO_new_file("pub.key","wb");
    int ret=PEM_write_bio_PUBKEY(bp,pubKey);
    printf("\nret: %d\n",ret);
    BIO_free(bp);

    BIO* skeybp=NULL;
    skeybp=BIO_new_file("pub.key","rb");
    EC_KEY* pub_key=NULL;
    pub_key=PEM_read_bio_EC_PUBKEY(skeybp,NULL,NULL,NULL);
    BIO_free(skeybp);
    return pub_key;
}

int CertVerify(const char* cert_name,char* issuer_get){
    EVP_PKEY* ca_pub_key=NULL;
    X509* ca_cert=NULL;
    X509* server_crt=NULL;
    ca_cert=CerGet("cacert.pem");
    server_crt=CerGet(cert_name);
    ca_pub_key=X509_get_pubkey(ca_cert);
    int verify_result=X509_verify(server_crt,ca_pub_key);
    char* issuer=X509_NAME_oneline(X509_get_issuer_name(ca_cert),NULL,0);
    memcpy(issuer_get,issuer,strlen(issuer));
    X509_free(ca_cert);
    X509_free(server_crt);
    return verify_result;
}
