#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTcpSocket>
#include <QFile>

#define BUF_SIZE 1024*4
#define FILE_RECV "FileHead Received"
#define FILE_WDOWN "File Write Done"
#define ERROR "Get Hash Value Failed"
#define BEGIN_RECV_CRT 1
#define END_RECV_CRT 0
#define EXIT_RECV_CRT 2
#define RANDOM_KEY_LEN 32
#define RANDOM_KEY_LEN_SHORT 16
#define RIGHT_LEN 139
#define ENC_FLAG "enc"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    
private slots:
    void SocketReadData();
    void SocketWriteData();
    void SocketDisconnect();
    void ConnectServer();
    void DisconnectServer();
    void ActionExit();

    void on_pushButtonChoose_clicked();

    void on_pushButtonSend_clicked();

    void on_pushButtonEncryptedSend_clicked();

private:
    Ui::MainWindow *ui;

    QTcpSocket *socket;

    QFile *file;
    QFile *certFile;
    QString fileName;
    QString fileHashValue;
    QString sessionKey;
    QString browserText;
    qint64 fileSize;
    qint64 sendSize;
    qint64 receiveSize;
    int bStart;

    void ClearOldSend();
    void InitFileInfo(QString filePath);

    //MD
    QString GetFileHashValue(QFile *chosedFile);
    QString ByteArrayToHexString(QByteArray ba);

    //Encrypt
    QString GetFileEncryptionOrDecryption(QString InFilePath,int enc);

    char *CreateSessionKey(const unsigned char *random_key, unsigned int *o_len);
    char *CreateRandomKey(int length);

    void VerifyServer(const char* cert_name);
    void WarningMessage(QString mes);
    void TextBrowserShow(QString text);
};

#endif // MAINWINDOW_H
