#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTcpServer>
#include <QTcpSocket>
#include <QFile>

#define FILE_RECV "FileHead Received"
#define FILE_WDOWN "File Write Done"
#define ERROR "Get Hash Value Failed"
#define ENC_FLAG "enc"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void ServerNewConnect();
    void SocketReadData();
    void SocketWriteData();
    void SocketDisconnect();

private:
    Ui::MainWindow *ui;

    QTcpServer *server;
    QTcpSocket *socket;

    quint16 dstport;

    QFile* file;
    QFile* certFile;
    QString fileName;
    QString fileHashValue;
    QString encFlag;
    qint64 recvSize;
    qint64 fileSize;
    qint64 sendSize;

    QString recvMessage;

    bool bStart;

    void ConnectClient();
    void GetLocalAddress();

    //Test
    void SM3Test();
    void SM4CBCTest();

    void HashCheck();
    QString GetFileHashValue(QFile *chosedFile);
    QString ByteArrayToHexString(QByteArray ba);
    QByteArray HexStringToByteArray(QString HexString);

    QString GetFileEncryptionOrDecryption(QFile *chosedFile,int enc);

    void CertificateParsing();
    void SocketSendCert();
    void SaveSessionKey(QString skey);
    void AlertMessage(QString mes);

    int DecryptFile();
    int DeleteEncryptFile();
    int DeleteSessionKey();
};

#endif // MAINWINDOW_H
