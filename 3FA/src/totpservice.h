#ifndef TOTPSERVICE_H
#define TOTPSERVICE_H

#include <QObject>
#include <QString>
#include <QPixmap>
#include <QUrl>
#include <functional>

class QTimer;
class QNetworkAccessManager;
class QTcpServer;
class QTcpSocket;

/**
 * @brief Класс TOTPService обеспечивает генерацию и проверку TOTP кодов
 * 
 * Использует алгоритм TOTP (Time-based One-Time Password) для генерации
 * одноразовых кодов и создания QR-кодов для настройки аутентификаторов.
 */
class TOTPService : public QObject
{
    Q_OBJECT

public:
    explicit TOTPService(QObject *parent = nullptr);
    
    // Генерация секрета и QR-кода
    QString generateSecret();
    QPixmap generateQRCode(const QString &secret, const QString &email, const QString &issuer = "3FA Security",
                           bool startTimer = true, QString *pageUrl = nullptr);
    QString generateTOTPCode(const QString &secret);
    QString generateWebPageURL(const QString &secret, const QString &email, bool startTimer = true);
    void setPageDark(bool dark);
    void openBrowserWithSecret(const QString &secret, const QString &email);
    
    // Проверка TOTP кода
    bool verifyTOTPCode(const QString &secret, const QString &code, int window = 1);
    
    // Утилиты
    QString getOTPAuthURL(const QString &secret, const QString &email, const QString &issuer = "3FA Security");
    void closeWebPage(bool success = false);
    void setCurrentPorts(int websocketPort, int httpPort);
    int currentWebsocketPort() const;
    int currentHttpPort() const;
    
    // Метод для получения текущего TOTP кода
    QString getCurrentTOTPCode(const QString &secret);
    
    // Таймер для обновления кода
    void startCodeUpdateTimer(const QString &secret, const QString &initialCode = QString());
    void stopCodeUpdateTimer();
    
    // Генерация нового кода по запросу (без таймера)
    void generateNewCodeOnRequest();
    
    // IPC сервер для обработки запросов от Python (TCP на localhost)
    void startIpcServer();
    void stopIpcServer();
    int getIpcServerPort() const;
    
    // Сохранение временного шага для синхронизации
    void setCurrentTimeStep(quint64 timeStep);
    quint64 getCurrentTimeStep() const;

private:
    QString generateRandomSecret(int length = 32);
    QString base32Encode(const QByteArray &data);
    QByteArray base32Decode(const QString &data);
    
    // Сохраненный временной шаг для синхронизации
    quint64 m_savedTimeStep;
    int findFreePort();
    bool waitForPortReady(int port, int maxWaitMs = 5000, int checkIntervalMs = 100);
    void postAsync(const QUrl &url,
                   const QByteArray &payload,
                   const QString &context,
                   std::function<void(bool)> onFinished = {},
                   int retryCount = 0);
    void cleanupServers();
    QString getLocalIPAddress();
    QByteArray hmacSha1(const QByteArray &key, const QByteArray &data);
    quint64 getCurrentTimeStepInternal();
    void sendIpcResponse(QTcpSocket *socket, bool success, const QString &message);
    
    // Статус использования кода
    bool m_codeUsed;
    // Текущие порты серверов
    int m_websocketPort;
    int m_httpPort;
    qint64 m_websocketPid;
    qint64 m_httpPid;
    QString m_pagePath;
    bool m_pageDark = false;
    // Таймер для обновления кода
    QTimer *m_codeUpdateTimer;
    QString m_currentSecret;
    QNetworkAccessManager *m_networkManager;
    
    // IPC сервер для связи с Python (TCP на localhost)
    QTcpServer *m_ipcServer;
    int m_ipcPort;
    
private slots:
    void onIpcNewConnection();
    void onIpcReadyRead();
};

#endif // TOTPSERVICE_H
