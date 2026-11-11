#include "emailservice.h"
#include <QDebug>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrl>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSslSocket>
#include <QEventLoop>
#include <QProcess>
#include <QDir>
#include <QCoreApplication>
#include <QFile>

EmailService::EmailService(QObject *parent)
    : QObject(parent)
    , m_networkManager(new QNetworkAccessManager(this))
    , m_smtpPort(587)
    , m_smtpUseSsl(true)
    , m_configured(false)
    , m_fromEmail("noreply@3fa-security.local")
    , m_fromName("3FA Security")
{
    connect(m_networkManager, &QNetworkAccessManager::finished, this, &EmailService::onEmailReplyFinished);
}

EmailService::~EmailService()
{
}

void EmailService::setSmtpConfig(const QString &host, int port, const QString &username, const QString &password, bool useSsl)
{
    m_smtpHost = host;
    m_smtpPort = port;
    m_smtpUsername = username;
    m_smtpPassword = password;
    m_smtpUseSsl = useSsl;
    m_fromEmail = username;
    m_configured = !host.isEmpty() && !username.isEmpty() && !password.isEmpty();
    
    if (m_configured) {
        qDebug() << "EmailService: SMTP настроен:" << host << ":" << port;
    }
}

void EmailService::setApiConfig(const QString &apiUrl, const QString &apiKey)
{
    m_apiUrl = apiUrl;
    m_apiKey = apiKey;
    m_configured = !apiUrl.isEmpty() && !apiKey.isEmpty();
    
    if (m_configured) {
        qDebug() << "EmailService: API настроен:" << apiUrl;
    }
}

bool EmailService::sendEmail(const QString &to, const QString &subject, const QString &body)
{
    clearError();
    
    if (!m_configured) {
        setError("Email сервис не настроен. Пожалуйста, настройте SMTP или API в конфигурации.");
        qWarning() << "EmailService: Сервис не настроен";
        return false;
    }
    
    if (to.isEmpty()) {
        setError("Email получателя не может быть пустым");
        return false;
    }
    
    // Если настроен API (внешний сервис), используем его
    if (!m_apiUrl.isEmpty() && !m_apiKey.isEmpty()) {
        return sendEmailViaApi(to, subject, body);
    }
    
    // Иначе используем SMTP
    if (!m_smtpHost.isEmpty()) {
        return sendEmailViaSmtp(to, subject, body);
    }
    
    setError("Не настроен ни SMTP, ни API для отправки email");
    return false;
}

bool EmailService::sendEmailViaApi(const QString &to, const QString &subject, const QString &body)
{
    QUrl url(m_apiUrl);
    QNetworkRequest request(url);
    
    // Устанавливаем заголовки для API
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", QString("Bearer %1").arg(m_apiKey).toUtf8());
    
    // Формируем JSON запрос (формат зависит от сервиса, используем универсальный)
    QJsonObject json;
    json["to"] = to;
    json["from"] = m_fromEmail;
    json["from_name"] = m_fromName;
    json["subject"] = subject;
    json["body"] = body;
    json["html"] = body; // Если сервис поддерживает HTML
    
    QJsonDocument doc(json);
    QByteArray data = doc.toJson();
    
    QNetworkReply *reply = m_networkManager->post(request, data);
    reply->setProperty("to", to);
    reply->setProperty("subject", subject);
    
    // Ждем ответа (синхронно)
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    
    bool success = (reply->error() == QNetworkReply::NoError);
    if (!success) {
        setError(QString("Ошибка отправки email через API: %1").arg(reply->errorString()));
    }
    
    reply->deleteLater();
    return success;
}

bool EmailService::sendEmailViaSmtp(const QString &to, const QString &subject, const QString &body)
{
    // Используем Python скрипт для отправки email через SMTP
    // Определяем корень проекта аналогично totpservice.cpp
    QString appDir = QCoreApplication::applicationDirPath();
    QDir projectRootDir(appDir);
    
    // macOS bundle: <project>/build/3FA.app/Contents/MacOS
    if (appDir.contains("/Contents/MacOS")) {
        projectRootDir = QDir(projectRootDir.absoluteFilePath("../../../../")); // поднимаемся до корня проекта
    } else {
        // Обычный случай: бинарь в build/ → поднимаемся на один уровень к корню проекта, если виден CMakeLists.txt
        QDir tryBuildParent(projectRootDir.absoluteFilePath(".."));
        if (tryBuildParent.exists("CMakeLists.txt")) {
            projectRootDir = tryBuildParent;
        } else {
            // Поднимаемся до корня проекта, ища CMakeLists.txt
            while (!projectRootDir.exists("CMakeLists.txt") && projectRootDir.cdUp()) {
                if (projectRootDir.isRoot()) break;
            }
        }
    }
    
    QString projectRoot = projectRootDir.absolutePath();
    QString scriptPath = QDir(projectRoot).absoluteFilePath("scripts/send_email.py");
    
    if (!QFile::exists(scriptPath)) {
        qWarning() << "EmailService: Python скрипт не найден:" << scriptPath;
        setError("Python скрипт для отправки email не найден");
        return false;
    }
    
    // Формируем JSON для передачи в Python скрипт
    QJsonObject json;
    QJsonObject smtpConfig;
    smtpConfig["host"] = m_smtpHost;
    smtpConfig["port"] = m_smtpPort;
    smtpConfig["username"] = m_smtpUsername;
    smtpConfig["password"] = m_smtpPassword;
    smtpConfig["use_ssl"] = m_smtpUseSsl;
    smtpConfig["from_email"] = m_fromEmail;
    smtpConfig["from_name"] = m_fromName;
    
    json["smtp_config"] = smtpConfig;
    json["to"] = to;
    
    // Функция для очистки строки от невалидных суррогатных пар
    // ВАЖНО: Не удаляем валидные суррогатные пары (эмодзи используют их в UTF-16)
    auto cleanString = [](const QString &str) -> QString {
        QString cleaned;
        cleaned.reserve(str.length());
        for (int i = 0; i < str.length(); ++i) {
            QChar ch = str.at(i);
            
            // Проверяем, является ли символ high surrogate (начало валидной пары)
            if (ch.isHighSurrogate()) {
                // Проверяем, есть ли следующий символ и является ли он low surrogate
                if (i + 1 < str.length() && str.at(i + 1).isLowSurrogate()) {
                    // Это валидная суррогатная пара (например, эмодзи) - сохраняем оба символа
                    cleaned.append(ch);
                    cleaned.append(str.at(i + 1));
                    i++; // Пропускаем следующий символ, так как мы его уже добавили
                    continue;
                } else {
                    // High surrogate без соответствующего low surrogate - невалидная пара
                    cleaned.append(QChar::ReplacementCharacter);
                }
            } else if (ch.isLowSurrogate()) {
                // Low surrogate без соответствующего high surrogate - невалидная пара
                cleaned.append(QChar::ReplacementCharacter);
            } else {
                // Обычный символ - сохраняем как есть
                cleaned.append(ch);
            }
        }
        return cleaned;
    };
    
    // Очищаем subject от невалидных суррогатных пар
    // Body не очищаем, так как HTML уже правильно сформирован и содержит валидные эмодзи
    QString cleanSubject = cleanString(subject);
    // Body оставляем как есть - эмодзи в HTML должны сохраниться
    QString cleanBody = body;
    
    json["subject"] = cleanSubject;
    json["body"] = cleanBody;
    
    QJsonDocument doc(json);
    // Используем QJsonDocument::Compact для более компактного JSON
    // и явно указываем UTF-8 кодировку
    QByteArray jsonData = doc.toJson(QJsonDocument::Compact);
    
    // Определяем путь к Python: сначала пробуем виртуальное окружение, затем системный Python
    QString pythonPath;
    
#ifdef Q_OS_WIN
    // На Windows сначала пробуем системный Python
    pythonPath = "python";  // На Windows обычно "python"
    qDebug() << "EmailService: Используем системный Python (Windows):" << pythonPath;
#else
    // На Mac/Linux используем python3
    pythonPath = "python3"; // На Mac/Linux обычно "python3"
    qDebug() << "EmailService: Используем системный Python (Mac/Linux):" << pythonPath;
#endif
    
    // Запускаем Python скрипт
    QProcess process;
    process.setWorkingDirectory(projectRoot);
    
    qDebug() << "EmailService: Запускаем Python скрипт:" << pythonPath << scriptPath;
    process.start(pythonPath, QStringList() << scriptPath);
    
    if (!process.waitForStarted(5000)) {
        QString errorStr = process.errorString();
        qWarning() << "EmailService: Не удалось запустить Python скрипт:" << errorStr;
        qWarning() << "EmailService: Python путь:" << pythonPath;
        qWarning() << "EmailService: Скрипт:" << scriptPath;
        qWarning() << "EmailService: Рабочая директория:" << projectRoot;
        
        // Пробуем альтернативный путь к Python
#ifdef Q_OS_WIN
        QString altPythonPath = "python3";
#else
        QString altPythonPath = "python";
#endif
        
        qDebug() << "EmailService: Пробуем альтернативный Python:" << altPythonPath;
        process.start(altPythonPath, QStringList() << scriptPath);
        
        if (!process.waitForStarted(5000)) {
            setError(QString("Не удалось запустить Python скрипт для отправки email: %1\nПроверьте, что Python установлен и доступен в PATH").arg(errorStr));
            return false;
        }
    }
    
    // Отправляем JSON в stdin с явной UTF-8 кодировкой
    // Убеждаемся, что данные правильно закодированы перед отправкой
    qDebug() << "EmailService: Размер JSON данных:" << jsonData.size() << "байт";
    
    // Проверяем, что данные корректно закодированы в UTF-8
    QString testDecode = QString::fromUtf8(jsonData);
    if (testDecode.isEmpty() && !jsonData.isEmpty()) {
        qWarning() << "EmailService: Предупреждение - JSON данные не декодируются как UTF-8";
        // Пробуем альтернативную кодировку
        testDecode = QString::fromLocal8Bit(jsonData);
    }
    
    // Отправляем данные в процесс
    qint64 written = process.write(jsonData);
    if (written != jsonData.size()) {
        qWarning() << "EmailService: Не все данные записаны в stdin. Записано:" << written << "из" << jsonData.size();
    }
    process.closeWriteChannel();
    
    // Ждем завершения (максимум 30 секунд)
    if (!process.waitForFinished(30000)) {
        qWarning() << "EmailService: Python скрипт не завершился вовремя";
        process.kill();
        setError("Таймаут при отправке email");
        return false;
    }
    
    // Читаем результат из stdout и stderr
    QByteArray output = process.readAllStandardOutput();
    QByteArray errorOutput = process.readAllStandardError();
    
    qDebug() << "EmailService: Python скрипт завершился с кодом:" << process.exitCode();
    qDebug() << "EmailService: stdout:" << QString::fromUtf8(output);
    qDebug() << "EmailService: stderr:" << QString::fromUtf8(errorOutput);
    
    if (process.exitCode() != 0) {
        QString errorMsg;
        
        // Если есть вывод в stdout, пробуем его распарсить
        if (!output.isEmpty()) {
            QJsonParseError parseError;
            QJsonDocument resultDoc = QJsonDocument::fromJson(output, &parseError);
            
            if (parseError.error == QJsonParseError::NoError && resultDoc.isObject()) {
                QJsonObject errorResult = resultDoc.object();
                QString error = errorResult["error"].toString();
                if (!error.isEmpty()) {
                    errorMsg = error;
                    qWarning() << "EmailService: Ошибка отправки email (из JSON):" << errorMsg;
                }
            }
        }
        
        // Если не удалось распарсить JSON, используем stderr или stdout
        if (errorMsg.isEmpty()) {
            errorMsg = QString::fromUtf8(errorOutput).trimmed();
        }
        if (errorMsg.isEmpty()) {
            errorMsg = QString::fromUtf8(output).trimmed();
        }
        
        // Если ошибка слишком короткая или неинформативная, добавляем контекст
        if (errorMsg.isEmpty() || errorMsg.length() < 5) {
            errorMsg = QString("Python скрипт завершился с кодом %1").arg(process.exitCode());
        }
        
        // Проверяем, не является ли ошибка просто "Python" (неинформативно)
        if (errorMsg == "Python" || errorMsg.toLower() == "python") {
            errorMsg = QString("Ошибка выполнения Python скрипта (код выхода: %1). Проверьте логи выше для деталей.").arg(process.exitCode());
        }
        
        qWarning() << "EmailService: Python скрипт завершился с ошибкой:" << process.exitCode();
        qWarning() << "EmailService: Ошибка:" << errorMsg;
        qWarning() << "EmailService: Полный stdout:" << QString::fromUtf8(output);
        qWarning() << "EmailService: Полный stderr:" << QString::fromUtf8(errorOutput);
        
        setError(QString("Ошибка отправки email: %1").arg(errorMsg));
        return false;
    }
    
    // Парсим результат
    if (output.isEmpty()) {
        qWarning() << "EmailService: Python скрипт не вернул результат";
        setError("Python скрипт не вернул результат");
        return false;
    }
    
    QJsonParseError parseError;
    QJsonDocument resultDoc = QJsonDocument::fromJson(output, &parseError);
    
    if (parseError.error != QJsonParseError::NoError) {
        qWarning() << "EmailService: Ошибка парсинга результата от Python скрипта:" << parseError.errorString();
        qWarning() << "EmailService: Содержимое stdout:" << QString::fromUtf8(output);
        setError("Ошибка парсинга результата от Python скрипта");
        return false;
    }
    
    if (!resultDoc.isObject()) {
        qWarning() << "EmailService: Результат от Python скрипта не является объектом";
        setError("Результат от Python скрипта не является объектом");
        return false;
    }
    
    QJsonObject jsonResult = resultDoc.object();
    bool success = jsonResult["success"].toBool();
    
    if (!success) {
        QString error = jsonResult["error"].toString();
        if (error.isEmpty()) {
            error = "Неизвестная ошибка";
        }
        qWarning() << "EmailService: Ошибка отправки email:" << error;
        setError(QString("Ошибка отправки email: %1").arg(error));
        return false;
    }
    
    qDebug() << "EmailService: Email успешно отправлен через SMTP на" << to;
    return true;
}

void EmailService::sendEmailAsync(const QString &to, const QString &subject, const QString &body)
{
    // Асинхронная отправка (используется для длительных операций)
    if (!m_configured) {
        emit emailFailed(to, "Email сервис не настроен");
        return;
    }
    
    // Реализация аналогична sendEmail, но без ожидания ответа
    if (!m_apiUrl.isEmpty() && !m_apiKey.isEmpty()) {
        QUrl url(m_apiUrl);
        QNetworkRequest request(url);
        request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        request.setRawHeader("Authorization", QString("Bearer %1").arg(m_apiKey).toUtf8());
        
        QJsonObject json;
        json["to"] = to;
        json["from"] = m_fromEmail;
        json["from_name"] = m_fromName;
        json["subject"] = subject;
        json["body"] = body;
        json["html"] = body;
        
        QJsonDocument doc(json);
        QByteArray data = doc.toJson();
        
        QNetworkReply *reply = m_networkManager->post(request, data);
        reply->setProperty("to", to);
    }
}

bool EmailService::sendVerificationCode(const QString &to, const QString &code)
{
    QString subject = "Код верификации для восстановления пароля";
    QString body = buildEmailBody(code);
    
    return sendEmail(to, subject, body);
}

void EmailService::onEmailReplyFinished()
{
    QNetworkReply *reply = qobject_cast<QNetworkReply*>(sender());
    if (!reply) {
        return;
    }
    
    QString to = reply->property("to").toString();
    
    if (reply->error() == QNetworkReply::NoError) {
        qDebug() << "EmailService: Email успешно отправлен на" << to;
        emit emailSent(to);
    } else {
        QString error = QString("Ошибка отправки email: %1").arg(reply->errorString());
        qWarning() << "EmailService:" << error;
        emit emailFailed(to, error);
    }
    
    reply->deleteLater();
}

QString EmailService::buildEmailBody(const QString &code)
{
    QString html = QString(R"(
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <style>
        body { background: #fff; font-family: Arial, sans-serif; line-height: 1.5; color: #202020; }
        .container { max-width: 560px; margin: 0 auto; padding: 20px; }
        .brand { color: #0069cc; font-size: 13px; font-weight: bold; }
        h1 { margin: 8px 0 16px; font-size: 24px; }
        .content { background: #fafafd; border: 1px solid #dce0e5; padding: 24px; border-radius: 12px; }
        .code { background: #fff; border: 1px solid #dce0e5; border-radius: 8px; padding: 12px; text-align: center;
                font: bold 28px 'Courier New', monospace; letter-spacing: 6px; }
        .footer { margin-top: 16px; color: #5c6067; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="content">
            <p class="brand">3FA</p>
            <h1>Восстановление пароля</h1>
            <p>Здравствуйте!</p>
            <p>Вы запросили восстановление пароля для вашего аккаунта в системе 3FA Security.</p>
            <p>Используйте следующий код для подтверждения:</p>
            <p class="code">%1</p>
            <p><strong>Код действителен в течение 10 минут.</strong></p>
            <p>Если вы не запрашивали восстановление пароля, проигнорируйте это письмо.</p>
        </div>
        <div class="footer">
            <p>3FA Security - Система многофакторной аутентификации</p>
            <p>Это автоматическое письмо, пожалуйста, не отвечайте на него.</p>
        </div>
    </div>
</body>
</html>
)").arg(code);
    
    return html;
}

void EmailService::clearError()
{
    m_lastError.clear();
}

void EmailService::setError(const QString &error)
{
    m_lastError = error;
    qWarning() << "EmailService:" << error;
}

