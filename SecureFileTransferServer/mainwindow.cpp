#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "sm3.h"
#include "sm4_cbc.h"
#include "session_funcs.h"
#include <QMessageBox>
#include <QHostAddress>
#include <QNetworkInterface>
#include <QFileInfo>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    this->setFixedSize(this->width(),this->height());
    this->setWindowTitle(QString("Secure File Transfer Server"));

    server=new QTcpServer();
    socket=new QTcpSocket();
    file=new QFile();
    certFile=new QFile();

    //dstip=QHostAddress("192.168.43.40");
    dstport=9090;

    connect(server,SIGNAL(newConnection()),this,SLOT(ServerNewConnect()));

    ConnectClient();
    //SM3Test();
    //SM4CBCTest();
    //CertificateParsing();
}

MainWindow::~MainWindow()
{
    server->close();
    server->deleteLater();
    delete ui;
}

void MainWindow::ServerNewConnect(){
    socket=server->nextPendingConnection();
    connect(socket,SIGNAL(readyRead()),this,SLOT(SocketReadData()));
    connect(socket,SIGNAL(disconnected()),this,SLOT(SocketDisconnect()));

    qDebug()<<"A client connect.";
    if(socket->ConnectedState){
        qDebug()<<"Connected.";
        bStart=true;
        SocketSendCert();
    }
}

void MainWindow::SocketSendCert(){
    certFile->setFileName("server.crt");
    if(!certFile->open(QIODevice::ReadOnly)){
        qDebug()<<"crt file open failed.";
        ui->statusBar->showMessage(tr("crt file open failed."));
    }
    QFileInfo info(certFile->fileName());
    QString fileHead=QString("%1##%2").arg(info.fileName()).arg(info.size());
    qint64 len=socket->write(fileHead.toUtf8());
    if(len<0){
        qDebug()<<"cert head send failed.";
        ui->statusBar->showMessage(tr("cert head send failed."));
    }
}

void MainWindow::SocketWriteData(){
    qint64 len=0;
    sendSize=0;
    do{
        char buf[BUFF_SIZE]={0};
        len=0;
        len=certFile->read(buf,BUFF_SIZE);
        len=socket->write(buf,len);

        qDebug()<<"File len:"<<len;

        sendSize += len;
    }while(len>0);
}

void MainWindow::SocketReadData(){
    QByteArray buf;
    buf=socket->readAll();
    //qDebug()<<"buf empty:"<<buf.isEmpty()<<" -- buf null:"<<buf.isNull();
    if(QString(FILE_RECV)==QString(buf)){
        SocketWriteData();
    }
    else if(QString(FILE_WDOWN)==QString(buf)){
        qDebug()<<"Peer has got server cert.";
        ui->statusBar->showMessage(tr("Pee has got server cert."));
        certFile->close();
    }
    else{
        if(bStart){
            bStart=false;
            fileName=QString(buf).section("##",0,0);
            fileSize=QString(buf).section("##",1,1).toInt();
            fileHashValue=QString(buf).section("##",2,2);
            QString sessionKey=QString(buf).section("##",3,3);
            SaveSessionKey(sessionKey);
            encFlag=QString(buf).section("##",4,4);
            recvSize=0;

            QString str=QString("Received File:[%1:%2KB:Hash Value:%3]").arg(fileName).arg(fileSize).arg(fileHashValue);

            //ProgressBar
            ui->progressBarReceive->setMaximum(qint32(fileSize));
            ui->progressBarReceive->setMinimum(0);

            file->setFileName(fileName);
            if(!file->open(QIODevice::WriteOnly)){
                QMessageBox::information(this,"Error","File opened failed.");
            }
            socket->write(FILE_RECV);
            qDebug()<<str;
        }
        else{
            qint64 len=file->write(buf);
            recvSize+=len;

            //ProgressBar
            ui->progressBarReceive->setValue(qint32(recvSize));

            if(recvSize==fileSize){
                file->close();
                //QMessageBox::information(this,"Done","File received completly.");
                socket->write(FILE_WDOWN);
                bStart=true;

                HashCheck();

                //以下函数容易无差别攻击非加密文件，所以加入了ENC_FLAG标记
                if(QString(ENC_FLAG)==encFlag){
                    if(-1==DecryptFile()){
                        AlertMessage("Decrypt file failed.");
                    }
                    else{
                        if(-1==DeleteEncryptFile()){
                            AlertMessage("Delete encrypt file failed.");
                        }
                        if(-1==DeleteSessionKey()){
                            AlertMessage("Delete session key file failed.");
                        }
                        AlertMessage("Decrypt file sucessfully.");
                    }
                }

                recvMessage+=fileName;
                recvMessage+="\n";
                ui->textBrowserReceive->setText(recvMessage);
                ui->progressBarReceive->setValue(0);

            }
        }
    }

}

void MainWindow::AlertMessage(QString mes){
    qDebug()<<mes;
    ui->statusBar->showMessage(mes);
}

void MainWindow::SaveSessionKey(QString skey){
    QFile skeyFile("session.key");
    if(!skeyFile.open(QIODevice::WriteOnly)){
        AlertMessage("skey file write failed.");
    }
    skeyFile.write(skey.toLatin1().data());
    skeyFile.close();
}

int MainWindow::DecryptFile(){
    unsigned char outchar[BUFF_SIZE]={};
    size_t out_len=BUFF_SIZE;
    EC_KEY* pri_key=NULL;
    pri_key=GetPriKey("pri.key");
    unsigned char* session_key;
    size_t skey_len;
    QFile skeyFile("session.key");
    if(!skeyFile.open(QIODevice::ReadOnly)){
        qDebug()<<"skey file open failed.";
    }
    QByteArray ba;
    //QByteArray nba;
    ba=skeyFile.readAll();
    //nba=HexStringToByteArray(QString(ba));
    session_key=(unsigned char*)ba.data();
    skey_len=strlen((char*)session_key);
    qDebug()<<"skey_len:"<<skey_len;
    if(0==SM2_decrypt_with_recommended(session_key,skey_len,outchar,&out_len,pri_key)){
        qDebug()<<"decrypt failed.";
        return -1;
    }
    else if(-1==SM4_CBC(fileName.toLatin1().data(),QString("Decrypted_%1").arg(fileName).toLatin1().data(),outchar,0)){
        AlertMessage("File decrypted failed.");
        return -1;
    }
    skeyFile.close();
    return 0;
}

int MainWindow::DeleteEncryptFile(){
    QFile deleteFile(fileName);
    if(!deleteFile.open(QIODevice::ReadWrite)){
        AlertMessage("Encrypt file deleted failed.");
        return -1;
    }
    else if(deleteFile.remove()){
        AlertMessage("Encrypt file deleted successfully.");
    }
    deleteFile.close();
    return 0;
}

int MainWindow::DeleteSessionKey(){
    QFile skeyFile("session.key");
    if(!skeyFile.open(QIODevice::WriteOnly)){
        AlertMessage("skey file write failed.");
        return -1;
    }
    else if(skeyFile.remove()){
        AlertMessage("Session key file deleted successfully.");
    }
    skeyFile.close();
    return 0;
}

void MainWindow::HashCheck(){
    file->setFileName(fileName);
    if(!file->open(QIODevice::ReadOnly)){
        qDebug()<<"Open failed.";
    }
    QString localFileHashValue=GetFileHashValue(file);
    qDebug()<<"Local File hash value:"<<localFileHashValue<<endl;
    qDebug()<<"Peer File hash value:"<<fileHashValue;

    QString hashCheckMessage=QString("Local File Hash Value:%1\nPeer File Hash Value:%2").arg(localFileHashValue).arg(fileHashValue);
    ui->textBrowserCheck->setText(hashCheckMessage);

    if(localFileHashValue==fileHashValue){
        QMessageBox::information(this,"Hash Check","The hash value matches successfully.");
    }
    else{
        QMessageBox::information(this,"Hash Check","File information has been tampered.");
    }
    file->close();
}

void MainWindow::SocketDisconnect(){
    qDebug()<<"Disconnect.";
}

void MainWindow::ConnectClient(){
    quint16 port=dstport;

    if(!server->listen(QHostAddress::Any,port)){
        qDebug()<<server->errorString();
        return;
    }
    qDebug()<<"Listen successfully.";
    GetLocalAddress();
    ui->lineEditPort->setText(QString::number(port));
}

void MainWindow::GetLocalAddress(){
    QList<QHostAddress> addrList=QNetworkInterface::allAddresses();
    foreach(QHostAddress address,addrList){
        if(address.isNull())
            continue;

        QAbstractSocket::NetworkLayerProtocol nProtocol=address.protocol();
        if(nProtocol==QAbstractSocket::IPv4Protocol){
            bool bOK=false;
            quint32 nIPV4=address.toIPv4Address(&bOK);
            if(bOK){
                qDebug()<<nIPV4;
                recvMessage="Server IPv4: ";
                recvMessage+=address.toString();
                recvMessage+="\n";
                ui->textBrowserReceive->setText(recvMessage);
            }
            break;
        }
    }
}

QString MainWindow::GetFileHashValue(QFile *chosedFile){
    QByteArray qbuff=chosedFile->readAll();

    const char *buf=qbuff.data();
    unsigned int buf_len=strlen(buf);

    unsigned char hash_value[64];
    unsigned int hash_len;

    SM3(buf,buf_len,hash_value,&hash_len);


    QByteArray hValue;
    for(int i=0;i<hash_len;i++){
        hValue.append(hash_value[i]);
    }

    QString hashValue=ByteArrayToHexString(hValue);

    if(hash_len>0)
        return hashValue;
    else
        return ERROR;
}

QString MainWindow::ByteArrayToHexString(QByteArray ba){
    QDataStream out(&ba,QIODevice::ReadWrite);
    QString buf;
    while(!out.atEnd()){
        qint8 outChar=0;
        out >> outChar;
        //arg(short a, int fieldWidth = 0, int base = 10, QChar fillChar = QLatin1Char(' ')) const
        QString str = QString("%1").arg(outChar&0xFF,2,16,QLatin1Char('0')).toUpper();
        buf+=str;
    }
    return buf;
}

QByteArray MainWindow::HexStringToByteArray(QString HexString){
    bool bOK;
    QByteArray ret;
    HexString=HexString.trimmed();
    HexString=HexString.simplified();
    QStringList sl=HexString.split(" ");

    foreach(QString s,sl){
        if(!s.isEmpty()){
            char c=s.toInt(&bOK,16)&0xFF;
            if(bOK){
                ret.append(c);
            }
            else{
                qDebug()<<"Invalid Hex string.";
            }
        }
    }
    return ret;
}

void MainWindow::SM3Test(){
    const char buf[]="{'a','c','b'}sdfsdgsdfsdgergxcfbtgjdsfsdkvjlejfvoxcklvnlxcckjosjvnxnvweouovixcjklvlkkackhq";
    unsigned int buf_len=strlen((char*)buf);

    unsigned char hash_value[64];
    unsigned int hash_len;

    SM3(buf,buf_len,hash_value,&hash_len);

    qDebug()<<"buf: "<<buf;
    qDebug()<<"hash value: "<<hash_value<<" -- hash len"<<hash_len;
    for(int i=0;i<hash_len;i++){
        printf("%x",hash_value[i]);
    }

}

void MainWindow::SM4CBCTest(){
    unsigned char outchar[BUFF_SIZE]={};
    size_t out_len=BUFF_SIZE;
    EC_KEY* pri_key=NULL;
    pri_key=GetPriKey("pri.key");
    unsigned char* session_key;
    size_t skey_len;
    QFile skeyFile("session.key");
    if(!skeyFile.open(QIODevice::ReadOnly)){
        qDebug()<<"skey file open failed.";
    }
    QByteArray ba;
    ba=skeyFile.readAll();
    session_key=(unsigned char*)ba.data();
    skey_len=strlen((char*)session_key);
    qDebug()<<"skey_len:"<<skey_len;
    if(0==SM2_decrypt_with_recommended(session_key,skey_len,outchar,&out_len,pri_key)){
        qDebug()<<"decrypt failed.";
    }
    else{
        SM4_CBC("Encryptedauto_upload.sh.cbc","Dencryptedauto_upload.sh",outchar,0);
    }
    skeyFile.close();

    //SM4_CBC("Sm2_sm3_sm4_c.zip","Sm2_sm3_sm4_c.zip.cbc",nullptr,1);

    //SM4_CBC("EncryptedGmSSL.tar.gz.cbc","DencryptedGmSSL.tar.gz",nullptr,0);

//    QFile newFile("netease music.html");
//    if(!newFile.open(QIODevice::ReadOnly)){
//        qDebug()<<"File open failed.";
//    }
//    //加密
//    QString enFilePath=
//    GetFileEncryptionOrDecryption(&newFile,1);
//    //解密
//    newFile.close();
//    newFile.setFileName(enFilePath);
//    if(!newFile.open(QIODevice::ReadOnly)){
//        qDebug()<<"De File open failed.";
//    }
//    GetFileEncryptionOrDecryption(&newFile,0);
//    newFile.close();
//    QByteArray qbuff=newFile.readAll();

//    const unsigned char *in_char=(unsigned char*)qbuff.data();

//    int in_len=strlen((char*)in_char);

//    unsigned char out_char[in_len];
//    int out_len;

//    //const unsigned char key[]="key";

//    SM4_CBC(in_char,in_len,out_char,&out_len,nullptr,1);

//    QByteArray ba;
//    for(int i=0;i<out_len;i++){
//        ba.append(out_char[i]);
//    }

//    QFile outFile(QString("Encrypted%1.%2").arg(newFile.fileName()).arg("cbc"));
//    if(!outFile.open(QIODevice::WriteOnly)){
//        qDebug()<<"Out file open failed.";
//    }
//    outFile.write(ba);
//    outFile.close();
//    qDebug()<<"加密："<<in_len<<":"<<"加密长度："<<out_len;

//    unsigned char de_char[in_len];
//    int de_len;
//    SM4_CBC(out_char,out_len,de_char,&de_len,nullptr,0);
//    qDebug()<<"de_len:"<<de_len;
//    QByteArray de;
//    for(int i=0;i<de_len;i++){
//        de.append(de_char[i]);
//    }

//    QFile deFile(QString("Decrypted%1").arg(newFile.fileName()));
//    if(!deFile.open(QIODevice::WriteOnly)){
//        qDebug()<<"De File open failed.";
//    }
//    deFile.write(de);
//    deFile.close();
//    newFile.close();
//    qDebug()<<"解密："<<de_len;
}

QString MainWindow::GetFileEncryptionOrDecryption(QFile* chosedFile, int enc){
    QByteArray qbuff("");
    QString str("");
    qint64 len;
    int size=0;
//    while(!chosedFile->atEnd()){
//        QString lineString=QString(chosedFile->readLine()).trimmed();
//        str.append(lineString);
//    }
//    do{
//        char buf[1024]={0};
//        len=0;
//        len=chosedFile->read(buf,1024);
//        qbuff.append(buf,len);
//        str.append(buf);

//        size+=len;
//    }while(len>0);
    qDebug()<<"enc:"<<enc<<"Size:"<<size<<"qbuff len:"<<strlen(qbuff.data())<<"str len:"<<str.length()<<"::"<<QString(qbuff);

    chosedFile->seek(0);

    //char *buf = qbuff.data();
    char *buf=str.toLatin1().data();
    //convertStrToUnChar(qbuff.data(),buf);
    int buf_len=strlen(buf);
    qDebug()<<"buf_len:"<<buf_len;
    unsigned char out_char[buf_len];
    int out_len = 0;

    //const unsigned char key[];

    //SM4_CBC(reinterpret_cast<unsigned char*>(buf),buf_len,out_char,&out_len,nullptr,enc);

    QByteArray encryptBA;
    for(int i=0;i<out_len;i++){
        encryptBA.append(out_char[i]);
    }
    QFile newFile;
    if(enc==1)
        newFile.setFileName(QString("Encrypted%1.%2").arg(chosedFile->fileName()).arg("cbc"));
    else if(enc==0)
        newFile.setFileName(QString("Decrypted%1").arg(chosedFile->fileName()));

    if(!newFile.open(QIODevice::ReadWrite)){
        qDebug()<<"File created failed.";
        ui->statusBar->showMessage(tr("File created failed."));
    }

    newFile.write(encryptBA);

    QFileInfo info(newFile);
    QString newFilePath=info.filePath();

    newFile.close();

    return newFilePath;

    //    QFile fpout;

    //    if(enc==1){
    //        fpout.setFileName(QString("Encrypted%1.%2").arg(fileName).arg("cbc"));
    //        if(!fpout.open(QIODevice::WriteOnly)){
    //            qDebug()<<"Write out file failed.";
    //        }
    //    }
    //    else if(enc==0){
    //        fpout.setFileName(QString("Dencrypted%1").arg(fileName));
    //        if(!fpout.open(QIODevice::WriteOnly)){
    //            qDebug()<<"Write out file failed.";
    //        }
    //    }

    //    SM4_CBC(fpin,&fpout,NULL,enc);

    //    QFileInfo info(fpout);
    //    QString outFilePath=info.filePath();
    //    fpout.close();

    //    return outFilePath;
}

//void MainWindow::CertificateParsing(){
//    unsigned char message[]="hello world....fuvk...........fuvk...";
//    size_t mes_len=strlen((char*)message);

//    unsigned char outchar[BUFF_SIZE]={};
//    size_t out_len=BUFF_SIZE;

//    unsigned char de_outchar[BUFF_SIZE]={};
//    size_t de_len=BUFF_SIZE;

//    EC_KEY* priKey=nullptr;
//    EC_KEY* pubKey=nullptr;
//    BIO* priBp=nullptr;
//    BIO* pubBp=nullptr;
//    priBp=BIO_new_file("pri.key","rb");
//    pubBp=BIO_new_file("pub.key","rb");

//    if(priBp==nullptr||pubBp==nullptr){
//        qDebug()<<"open file error.";
//        return;
//    }

//    priKey=PEM_read_bio_ECPrivateKey(priBp,nullptr,nullptr,nullptr);
//    pubKey=PEM_read_bio_EC_PUBKEY(pubBp,nullptr,nullptr,nullptr);
//    BIO_free(priBp);
//    BIO_free(pubBp);

//    if(0==SM2_encrypt_with_recommended(message,mes_len,outchar,&out_len,pubKey)){
//        qDebug()<<"Failed to encrypt.";
//        return;
//    }
//    QString ss=QString(QLatin1String(reinterpret_cast<char*>(outchar)));

//    char* xx=reinterpret_cast<char*>(outchar);

//    QFile file("session.key");
//    if(!file.open(QIODevice::ReadOnly))
//        qDebug()<<"error";
//    QByteArray fba=file.readAll();
////    if(0==SM2_decrypt_with_recommended((unsigned char*)ss.toLatin1().data(),ss.length(),de_outchar,&de_len,priKey)){
////    if(0==SM2_decrypt_with_recommended(outchar,out_len,de_outchar,&de_len,priKey)){
////    if(0==SM2_decrypt_with_recommended((unsigned char*)xx,out_len,de_outchar,&de_len,priKey)){
//    if(0==SM2_decrypt_with_recommended((unsigned char*)fba.data(),fba.length(),de_outchar,&de_len,priKey)){
//        qDebug()<<"Failed to decrypt.";
//        return;
//    }

//    QByteArray ba;
//    for(int i=0;i<de_len;i++){
//        qDebug()<<de_outchar[i];
//        ba.append(de_outchar[i]);
//    }
//    qDebug()<<"De char:"<<QString(ba);

//    free(outchar);
//    free(de_outchar);

//}

void MainWindow::CertificateParsing(){
    QString fileName="server.crt";
    FILE* cert_file;
    cert_file=fopen(fileName.toLatin1().data(),"rb");
    if(cert_file==nullptr){
        qDebug()<<"Cert file open failed.";
        return;
    }
    size_t cert_len=0;
    unsigned char cert[BUFF_SIZE];
    cert_len=fread(cert,1,BUFF_SIZE*4,cert_file);
    fclose(cert_file);
    //Judge the certificate whether is x509 or not.
    const unsigned char *ctemp=cert;
    X509* server_crt;
    server_crt=d2i_X509(nullptr,&ctemp,cert_len);
    if(server_crt==nullptr){
        BIO* b;
        //Judge the cert whether is PEM or not.
        b=BIO_new_file(fileName.toLatin1().data(),"r");
        qDebug()<<"t 2";
        server_crt=PEM_read_bio_X509(b,nullptr,nullptr,nullptr);
        BIO_free(b);
        if(server_crt==nullptr){
            qDebug()<<"PEM file open error.";
            return;
        }
    }
    //Parsing certificate.
    EVP_PKEY* pubKey=nullptr;
    unsigned char* bufPubKey=nullptr;
    long bufPubKeyLen;
    pubKey=X509_get_pubkey(server_crt);
    //ctemp=bufPubKey;
    bufPubKeyLen=i2d_PublicKey(pubKey,&bufPubKey);
    QByteArray ba;
    for(int i=0;i<bufPubKeyLen;i++){
        ba.append(bufPubKey[i]);
        //printf("%x",bufPubKey[i]);
    }
    qDebug()<<"Pub Key:"<<ByteArrayToHexString(ba);

    EVP_PKEY* cakey=nullptr;
    BIO* cabp=nullptr;
    cabp=BIO_new_file("capubkey.pem","r");
    cakey=PEM_read_bio_PUBKEY(cabp,nullptr,nullptr,nullptr);
    int v_result=X509_verify(server_crt,cakey);
    qDebug()<<"verify result:"<<v_result;
    X509_free(server_crt);

    //SM2 Encrypt
    QString message="Hello world.";
    int mesLen=message.length();
    unsigned char c1[65];
    unsigned char c3[32];
    unsigned char* c2=nullptr;
    unsigned char* plainText=nullptr;

    /**************************************/
    unsigned char* bufPriKey=nullptr;
    long bufPriKeyLen;
    unsigned char prikey_buff[BUFF_SIZE];
    size_t prikey_len;

    //pri key
    EVP_PKEY* priKey=nullptr;
//    FILE* pri_key;
//    pri_key=fopen("pri.key","rb");
//    if(pri_key==nullptr){
//        qDebug()<<"Pri Key file open failed.";
//        return;
//    }
//    prikey_len=fread(prikey_buff,1,BUFF_SIZE*4,pri_key);
//    fclose(pri_key);

//    qDebug()<<"prikey_buf:"<<prikey_buff[10];

    QFile priFile("pri.key");
    if(!priFile.open(QIODevice::ReadOnly)){
        qDebug()<<"File open failed.";
    }
    QByteArray priBa;
    priBa=priFile.readAll();
    qDebug()<<"pri file:"<<QString(priBa);
//    priBa.replace("-----BEGIN EC PARAMETERS-----\r\nBggqgRzPVQGCLQ==\r\n-----END EC PARAMETERS-----\r\n-----BEGIN EC PRIVATE KEY-----\r\n","");
//    priBa.replace("-----END EC PRIVATE KEY-----\r\n","");
//    priBa.replace("\r\n","");
//    priBa.replace("/","");
//    qDebug()<<"Replaced pri file:"<<QString(priBa);
//    qDebug()<<"Hex pri file:"<<ByteArrayToHexString(priBa);
}
