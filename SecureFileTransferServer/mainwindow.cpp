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
