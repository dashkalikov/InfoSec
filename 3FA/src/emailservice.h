#ifndef EMAILSERVICE_H
#define EMAILSERVICE_H

#include <QObject>
#include <QString>
#include <QNetworkAccessManager>
#include <QNetworkReply>

/**
 * @brief Класс EmailService предоставляет функциональность отправки email
 * 
 * Поддерживает отправку email через SMTP или внешние сервисы (SendGrid, Mailgun и т.д.)
 */
class EmailService : public QObject
{
    Q_OBJECT

public:
    explicit EmailService(QObject *parent = nullptr);
    ~EmailService();
    
    // Настройка SMTP
    void setSmtpConfig(const QString &host, int port, const QString &username, const QString &password, bool useSsl = true);
    
    // Настройка внешнего сервиса (SendGrid, Mailgun и т.д.)
    void setApiConfig(const QString &apiUrl, const QString &apiKey);
    
    // Отправка email
    bool sendEmail(const QString &to, const QString &subject, const QString &body);
    void sendEmailAsync(const QString &to, const QString &subject, const QString &body);
    
    // Отправка кода верификации
    bool sendVerificationCode(const QString &to, const QString &code);
    
    // Проверка конфигурации
    bool isConfigured() const { return m_configured; }
    QString getLastError() const { return m_lastError; }

signals:
    void emailSent(const QString &to);
    void emailFailed(const QString &to, const QString &error);

private slots:
    void onEmailReplyFinished();

private:
    void clearError();
    void setError(const QString &error);
    QString buildEmailBody(const QString &code);
    bool sendEmailViaApi(const QString &to, const QString &subject, const QString &body);
    bool sendEmailViaSmtp(const QString &to, const QString &subject, const QString &body);
    
    QNetworkAccessManager *m_networkManager;
    
    // SMTP настройки
    QString m_smtpHost;
    int m_smtpPort;
    QString m_smtpUsername;
    QString m_smtpPassword;
    bool m_smtpUseSsl;
    
    // API настройки (для внешних сервисов)
    QString m_apiUrl;
    QString m_apiKey;
    
    bool m_configured;
    QString m_lastError;
    
    // Отправитель email
    QString m_fromEmail;
    QString m_fromName;
};

#endif // EMAILSERVICE_H

