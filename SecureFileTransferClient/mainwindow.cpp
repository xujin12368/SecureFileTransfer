#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "SM3.h"
#include "SM4_CBC.h"
#include "SESSION_FUNCS.h"
#include <QDebug>
#include <QMessageBox>
#include <QFileDialog>
#include <QtGlobal>
#include <QTime>
#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <openssl/pem.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    this->setFixedSize(this->width(),this->height());
    this->setWindowTitle(QString("Secure File Transfer Client"));

    socket=new QTcpSocket();
    file=new QFile();
    certFile=new QFile();

    ui->pushButtonSend->setEnabled(false);
    ui->pushButtonChoose->setEnabled(false);
    ui->pushButtonEncryptedSend->setEnabled(false);

    ui->lineEditAddress->setText("192.168.43.40");
    ui->lineEditPort->setText("9090");
    //ConnectServer();
    ui->pushButtonDisconnect->setEnabled(false);
    connect(ui->pushButtonConnect,SIGNAL(clicked()),this,SLOT(ConnectServer()));
    connect(ui->pushButtonDisconnect,SIGNAL(clicked()),this,SLOT(DisconnectServer()));
    connect(ui->actionExit,SIGNAL(triggered()),this,SLOT(ActionExit()));
}

MainWindow::~MainWindow()
{
    delete socket;
    delete file;
    delete certFile;
    delete ui;
}

void MainWindow::ConnectServer(){
    QString IP=ui->lineEditAddress->text();
    QString strPort=ui->lineEditPort->text();
    int port=strPort.toInt();
    socket->abort();
    socket->connectToHost(IP,port);

    if(!socket->waitForConnected()){
        qDebug()<<"Connect Failed";
    }
    else{
        qDebug()<<IP<<":"<<port<<"Connect Successfully.";
        browserText.clear();
        TextBrowserShow("Connect Successfully.");
        bStart=BEGIN_RECV_CRT;

        ui->pushButtonConnect->setEnabled(false);
        ui->pushButtonDisconnect->setEnabled(true);
        ui->pushButtonChoose->setEnabled(true);

        connect(socket,SIGNAL(readyRead()),this,SLOT(SocketReadData()));
        connect(socket,SIGNAL(disconnected()),this,SLOT(SocketDisconnect()));
    }
}

void MainWindow::SocketReadData(){
    QByteArray buf;
    buf=socket->readAll();

    if(BEGIN_RECV_CRT==bStart){
        QString certFileName=QString(buf).section("##",0,0);
        fileSize=QString(buf).section("##",1,1).toInt();
        qDebug()<<"File size:"<<fileSize;
        certFile->setFileName(certFileName);
        if(!certFile->open(QIODevice::WriteOnly)){
            qDebug()<<"cert file create failed.";
            ui->statusBar->showMessage(tr("cert file create failed."));
        }
        socket->write(FILE_RECV);
        receiveSize=0;
        bStart=END_RECV_CRT;
    }
    else if(END_RECV_CRT==bStart){
        qint64 len=certFile->write(buf);
        receiveSize+=len;
        qDebug()<<"ReceiveSize:"<<receiveSize;
        if(fileSize==receiveSize){
            QString certFileName=certFile->fileName();
            certFile->close();
            socket->write(FILE_WDOWN);
            qDebug()<<"here wrie.";
            ui->statusBar->showMessage(tr("has got server cert."));
            bStart=EXIT_RECV_CRT;

            VerifyServer(certFileName.toLatin1().data());
        }
    }
    else if(EXIT_RECV_CRT==bStart){
        if(QString(FILE_RECV)==QString(buf)){
            SocketWriteData();
        }
        else if(QString(FILE_WDOWN)==QString(buf)){
            QMessageBox::information(this,"Done","The peer's done.");
            file->close();
            ClearOldSend();
        }
    }
}

void MainWindow::VerifyServer(const char *cert_name){
    char* issuer=(char*)malloc(sizeof(char*)*BUFF_SIZE);
    int v_result=CertVerify(cert_name,issuer);
    if(1==v_result){
        qDebug()<<"Verify successfuly."<<"--"<<issuer;
        TextBrowserShow("Verify successfuly.");
        if(0==strcmp(issuer,"/C=CN/ST=Beijing/L=Fengtai/O=BESTI/OU=xuxu/CN=xujin/emailAddress=906735362@qq.com")){
            TextBrowserShow("Safe Server.");
        }
        else{
            TextBrowserShow("Unsafe Server.");
        }
    }
    else if(0==v_result){
        qDebug()<<"Verify failed.";
        TextBrowserShow("Verify failed.");
        WarningMessage("This server is not safe , continue connecting?");
    }
    else{
        qDebug()<<"Verify error";
        TextBrowserShow("Verify error");
        WarningMessage("This server is not safe , continue connecting?");
    }
    free(issuer);
}

void MainWindow::TextBrowserShow(QString text){
    browserText+=text;
    browserText+="\n";
    ui->textBrowserSessionInfo->setText(browserText);
}

void MainWindow::WarningMessage(QString mes){
    QMessageBox::StandardButton rb=
            QMessageBox::warning(this,"WARNING!",mes,
                                 QMessageBox::Yes|QMessageBox::No,QMessageBox::No);
    if(QMessageBox::No==rb){
        DisconnectServer();
    }
}

void MainWindow::SocketWriteData(){
    qint64 len=0;
    do{
        char buf[BUF_SIZE]={0};
        len=0;
        len=file->read(buf,BUF_SIZE);
        len=socket->write(buf,len);

        qDebug()<<"File len:"<<len;

        sendSize += len;
    }while(len>0);

//    QByteArray readBuf=file->readAll();
//    len=socket->write(readBuf);
//    sendSize+=len;
}

void MainWindow::SocketDisconnect(){
    socket->close();
    qDebug()<<"Disconnected.";
}

void MainWindow::DisconnectServer(){
    socket->close();
    qDebug()<<"Disconnect";
    TextBrowserShow("Disconnect");
    ui->pushButtonConnect->setEnabled(true);
    ui->pushButtonDisconnect->setEnabled(false);
    ui->pushButtonChoose->setEnabled(false);
    ui->pushButtonSend->setEnabled(false);
}

void MainWindow::ActionExit(){
    this->close();
}

void MainWindow::InitFileInfo(QString filePath){
    fileName.clear();
    fileSize=0;

    QFileInfo info(filePath);
    fileName=info.fileName();
    fileSize=info.size();
    sendSize=0;

    fileHashValue=GetFileHashValue(file);
    qDebug()<<"file hash:"<<fileHashValue<<"length:"<<fileHashValue.length();
}

void MainWindow::on_pushButtonChoose_clicked()
{
    QString filePath=QFileDialog::getOpenFileName(this,"open","../");
    if(!filePath.isEmpty()){
        file->setFileName(filePath);
        if(!file->open(QIODevice::ReadOnly)){
            ui->statusBar->showMessage(tr("ReadOnly Failed."));
        }
        InitFileInfo(filePath);
        ui->statusBar->showMessage(filePath);
        ui->lineEditPath->setText(filePath);

        ui->pushButtonChoose->setEnabled(false);
        ui->pushButtonSend->setEnabled(true);
        ui->pushButtonEncryptedSend->setEnabled(true);
    }
    else{
        ui->statusBar->showMessage(tr("The chosed file is invalid."));
    }
}

void MainWindow::on_pushButtonSend_clicked()
{
    //ui->pushButtonChoose->setEnabled(false);

    QString head=QString("%1##%2##%3").arg(fileName).arg(fileSize).arg(fileHashValue);
    qint64 len=socket->write(head.toUtf8());

    if(len<0){
        ui->statusBar->showMessage(tr("Head sended  failed."));
        file->close();
    }
    else{
        ui->pushButtonSend->setEnabled(false);
    }
}

void MainWindow::ClearOldSend(){
    ui->lineEditPath->setText("");
    ui->pushButtonSend->setEnabled(false);
    ui->pushButtonEncryptedSend->setEnabled(false);
    ui->pushButtonChoose->setEnabled(true);
}

QString MainWindow::GetFileHashValue(QFile *chosedFile){
    QByteArray qbuff=chosedFile->readAll();
    chosedFile->seek(0);//Put file to the head.

    const char *buf=qbuff.data();
    unsigned int buf_len=strlen(buf);

    unsigned char hash_value[64];
    unsigned int hash_len;

    SM3(buf,buf_len,hash_value,&hash_len);

    QByteArray hValue;
    for(int i=0;i<hash_len;i++){
        hValue.append(hash_value[i]);
    }

    if(hash_len>0)
        return ByteArrayToHexString(hValue);
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

void MainWindow::on_pushButtonEncryptedSend_clicked()
{
    QString filePath=GetFileEncryptionOrDecryption(QFileInfo(*file).filePath(),1);
    if(filePath==NULL){
        exit(0);
    }
    file->close();
    file->setFileName(filePath);
    if(!file->open(QIODevice::ReadOnly)){
        qDebug()<<"En or De file open failed.";
    }
    InitFileInfo(QFileInfo(*file).filePath());

    QString head=QString("%1##%2##%3##%4##%5").arg(fileName).arg(fileSize).arg(fileHashValue).arg(sessionKey).arg(ENC_FLAG);
    qint64 len=socket->write(head.toUtf8());

    if(len<0){
        ui->statusBar->showMessage(tr("Head sended  failed."));
        file->close();
    }
    else{
        ui->pushButtonSend->setEnabled(false);
    }
}

QString MainWindow::GetFileEncryptionOrDecryption(QString InFilePath, int enc){
    QString OutFilePath;
    size_t o_len=BUFF_SIZE;
    if(1==enc)
        OutFilePath=QString("/home/Encrypted_%1.%2").arg(fileName).arg("cbc");
    else if(0==enc)
        OutFilePath=QString("/home/Decrypted_%1").arg(fileName);

    char* random_key=CreateRandomKey(RANDOM_KEY_LEN);
    if(random_key==NULL)
        return NULL;
    char* session_key=NULL;

    //new server_crt
//    session_key=CreateSessionKey((unsigned char*)random_key,&o_len);
//    qDebug()<<"random_key:"<<random_key;
//    qDebug()<<"skey len:"<<strlen(session_key);
//    if(session_key==NULL){
//        qDebug()<<"session key error.";
//        return NULL;
//    }
//    /**************/
//    QByteArray ba;
//    for(int i=0;i<o_len;i++){
//        ba.append(session_key[i]);
//    }

//    sessionKey=QString(ba);
//    qDebug()<<"seesionKey len:"<<sessionKey.length()<<"-- ba len:"<<ba.length();

    //ole server_crt
    while(1){
        session_key=CreateSessionKey((unsigned char*)random_key,&o_len);
        qDebug()<<"random_key:"<<random_key;
        qDebug()<<"skey len:"<<strlen(session_key);
        if(session_key==NULL){
            qDebug()<<"session key error.";
            return NULL;
        }
        /**************/
        QByteArray ba;
        for(int i=0;i<o_len;i++){
            ba.append(session_key[i]);
        }

        sessionKey=QString(ba);
        if(RIGHT_LEN==sessionKey.length()){
            qDebug()<<"seesionKey len:"<<sessionKey.length()<<"-- ba len:"<<ba.length();
            break;
        }
    }
    /**************/
    SM4_CBC(InFilePath.toLatin1().data(),OutFilePath.toLatin1().data(),(unsigned char*)random_key,enc);
    return OutFilePath;
    free(random_key);
    free(session_key);
    return NULL;
}

char* MainWindow::CreateSessionKey(const unsigned char* random_key,size_t* o_len){
    X509* server_crt=CerGet("server.crt");
    if(server_crt==NULL){
        qDebug()<<"server_crt is null.";
        return NULL;
    }
    EC_KEY* pub_key=CerGetPubKey(server_crt);
    if(pub_key!=NULL){
        const unsigned char* message=random_key;
        //unsigned char* message=(unsigned char*)"oCRpLVXKH1VHfuLk0IuDmeacYOUj02KS";
        size_t mes_len=strlen((char*)message);

        printf("\nmessage: %d \n",mes_len);
        for(int i=0;i<mes_len;i++){
            printf("%c",message[i]);
        }

        unsigned char outchar[BUFF_SIZE]={};
        size_t out_len=BUFF_SIZE;

        //ner server_crt
//        if(0==SM2_encrypt_with_recommended(message,mes_len,outchar,&out_len,pub_key)){
//            qDebug()<<"sm2 Failed to encrypt.";
//            return NULL;
//        }
        //ole server_crt
        while(1)
        {
            if(0==SM2_encrypt_with_recommended(message,mes_len,outchar,&out_len,pub_key)){
                qDebug()<<"sm2 Failed to encrypt.";
                return NULL;
            }
            if(RIGHT_LEN==out_len)
                break;
        }

//        FILE* fp=NULL;
//        fp=fopen("session.key","wb");
//        if(out_len!=fwrite(outchar,1,out_len,fp)){
//            qDebug()<<"Session file write failed.";
//        }
//        fclose(fp);

        qDebug()<<"out len:"<<out_len;
        *o_len=out_len;

        return (char*)outchar;
    }
    qDebug()<<"pub key is null.";
    return NULL;
}

char* MainWindow::CreateRandomKey(int length){
    static bool seedOK;
    if(!seedOK){
        qsrand(QTime(0,0,0).secsTo(QTime::currentTime()));
        seedOK=true;
    }

    const char temple[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int temple_size = sizeof(temple);

    char* ch = new char[length + 1];
    memset(ch, 0, length + 1);
    int randomx = 0;
    for (int i = 0; i < length; i++)
    {
        randomx= qrand() % (temple_size - 1);
        ch[i] = temple[randomx];
    }

    //QString random_key(ch);
    qDebug()<<"random key:"<<ch;
    return ch;
}
