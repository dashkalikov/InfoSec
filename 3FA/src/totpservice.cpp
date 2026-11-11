#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <vector>
#endif
#include "totpservice.h"
#include <QRandomGenerator>
#include <QDateTime>
#include <QCryptographicHash>
#include <QByteArray>
#include <QDebug>
#include <QPainter>
#include <QImage>
#include <QFont>
#include <QFontMetrics>
#include <QFile>
#include <QSaveFile>
#include <QDir>
#include <QIODevice>
#include <QDesktopServices>
#include <QUrl>
#include <QUuid>
#include <QNetworkInterface>
#include <QHash>
#include <QHostAddress>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QProcess>
#include <QPointer>
#include <QSharedPointer>
#include <QEventLoop>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QThread>
#include <QTcpSocket>
#include <algorithm>
#include <csignal>
#ifdef Q_OS_UNIX
#include <signal.h>
#endif
#include "qrcodegen.hpp"
#include <QTcpServer>
#include <QTcpSocket>
#include <QJsonDocument>
#include <QJsonObject>

TOTPService::TOTPService(QObject *parent)
    : QObject(parent)
    , m_savedTimeStep(0)
    , m_codeUsed(false)
    , m_websocketPort(0)
    , m_httpPort(0)
    , m_websocketPid(-1)
    , m_httpPid(-1)
    , m_codeUpdateTimer(nullptr)
    , m_networkManager(new QNetworkAccessManager(this))
    , m_ipcServer(nullptr)
    , m_ipcPort(0)
{
}

QString TOTPService::generateSecret()
{
    return generateRandomSecret();
}

QString TOTPService::generateRandomSecret(int length)
{
    const QString chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    QString secret;
    
    for (int i = 0; i < length; ++i) {
        secret += chars[QRandomGenerator::global()->bounded(chars.length())];
    }
    
    return secret;
}

QString TOTPService::base32Encode(const QByteArray &data)
{
    const QString chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    QString result;
    
    int bits = 0;
    int value = 0;
    
    for (unsigned char byte : data) {
        value = (value << 8) | byte;
        bits += 8;
        
        while (bits >= 5) {
            result += chars[(value >> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    
    if (bits > 0) {
        result += chars[(value << (5 - bits)) & 31];
    }
    
    return result;
}

QByteArray TOTPService::base32Decode(const QString &data)
{
    const QString chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    QByteArray result;
    
    int bits = 0;
    int value = 0;
    
    for (QChar ch : data.toUpper()) {
        int index = chars.indexOf(ch);
        if (index == -1) continue;
        
        value = (value << 5) | index;
        bits += 5;
        
        if (bits >= 8) {
            result.append((value >> (bits - 8)) & 255);
            bits -= 8;
        }
    }
    
    return result;
}

QByteArray TOTPService::hmacSha1(const QByteArray &key, const QByteArray &data)
{
    // Простая реализация HMAC-SHA1
    const int blockSize = 64;
    QByteArray keyBytes = key;
    
    if (keyBytes.length() > blockSize) {
        keyBytes = QCryptographicHash::hash(keyBytes, QCryptographicHash::Sha1);
    }
    
    while (keyBytes.length() < blockSize) {
        keyBytes.append('\0');
    }
    
    QByteArray oKeyPad(blockSize, 0x5c);
    QByteArray iKeyPad(blockSize, 0x36);
    
    for (int i = 0; i < blockSize; ++i) {
        oKeyPad[i] = keyBytes[i] ^ 0x5c;
        iKeyPad[i] = keyBytes[i] ^ 0x36;
    }
    
    QByteArray innerHash = QCryptographicHash::hash(iKeyPad + data, QCryptographicHash::Sha1);
    return QCryptographicHash::hash(oKeyPad + innerHash, QCryptographicHash::Sha1);
}

quint64 TOTPService::getCurrentTimeStepInternal()
{
    return QDateTime::currentSecsSinceEpoch() / 30;
}

void TOTPService::setCurrentTimeStep(quint64 timeStep)
{
    m_savedTimeStep = timeStep;
    qDebug() << "TOTPService::setCurrentTimeStep - сохранен временной шаг:" << timeStep;
}

quint64 TOTPService::getCurrentTimeStep() const
{
    return m_savedTimeStep;
}

int TOTPService::findFreePort()
{
    // Запрашиваем у ОС свободный порт
    QTcpServer server;
    for (int attempt = 0; attempt < 10; ++attempt) {
        if (server.listen(QHostAddress::LocalHost, 0)) {
            int port = static_cast<int>(server.serverPort());
            server.close();
            qDebug() << "TOTPService::findFreePort - найден порт:" << port;
            return port;
        }
    }
    
    qDebug() << "TOTPService::findFreePort - не удалось получить свободный порт";
    return 0;
}

bool TOTPService::waitForPortReady(int port, int maxWaitMs, int checkIntervalMs)
{
    // Проверяем готовность порта, пытаясь подключиться к нему и получить HTTP ответ
    // Используем реальный эндпоинт /get_current_code, который всегда возвращает ответ
    QElapsedTimer timer;
    timer.start();
    
    int attemptCount = 0;
    int lastLogTime = 0;
    
    while (timer.elapsed() < maxWaitMs) {
        attemptCount++;
        QTcpSocket socket;
        socket.connectToHost(QHostAddress::LocalHost, port);
        
        // Ждем подключения с коротким таймаутом
        if (socket.waitForConnected(checkIntervalMs)) {
            // Отправляем HTTP GET запрос на реальный эндпоинт /get_current_code
            // Этот эндпоинт всегда возвращает ответ (даже если код еще не установлен)
            QByteArray request = "GET /get_current_code HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            socket.write(request);
            socket.flush();
            
            // Ждем ответа (даже частичного) - увеличиваем таймаут для Windows
            if (socket.waitForReadyRead(checkIntervalMs * 3)) {
                QByteArray response = socket.readAll();
                socket.disconnectFromHost();
                if (socket.state() != QAbstractSocket::UnconnectedState) {
                    socket.waitForDisconnected(checkIntervalMs);
                }
                // Если получили HTTP ответ (даже 404), сервер готов обрабатывать запросы
                if (!response.isEmpty() && response.contains("HTTP/")) {
                    qDebug() << "Порт" << port << "готов (HTTP ответ получен), прошло" << timer.elapsed() << "мс, попыток:" << attemptCount;
                    return true;
                }
            } else {
                // Если не получили ответ, но подключение установлено, сервер может быть еще не готов
                socket.disconnectFromHost();
                if (socket.state() != QAbstractSocket::UnconnectedState) {
                    socket.waitForDisconnected(checkIntervalMs);
                }
            }
        }
        
        // Логируем прогресс каждые 3 секунды
        int elapsed = timer.elapsed();
        if (elapsed - lastLogTime >= 3000) {
            qDebug() << "Ожидание готовности порта" << port << "... прошло" << elapsed << "мс, попыток:" << attemptCount;
            lastLogTime = elapsed;
        }
        
        // Если не подключились или не получили ответ, ждем перед следующей попыткой
        QThread::msleep(checkIntervalMs);
    }
    
    qWarning() << "Порт" << port << "не готов после" << maxWaitMs << "мс, попыток:" << attemptCount;
    qWarning() << "[INFO] Проверьте, что Python скрипт запустился и библиотека websockets установлена: pip install websockets";
    return false;
}

void TOTPService::postAsync(const QUrl &url,
                            const QByteArray &payload,
                            const QString &context,
                            std::function<void(bool)> onFinished,
                            int retryCount)
{
    if (!m_networkManager) {
        m_networkManager = new QNetworkAccessManager(this);
    }

    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    QNetworkReply *reply = m_networkManager->post(request, payload);
    qDebug() << context << "- отправлен запрос" << url;

    connect(reply, &QNetworkReply::finished, this, [this, reply, context, onFinished, url, payload, retryCount]() {
        bool success = (reply->error() == QNetworkReply::NoError);
        if (success) {
            qDebug() << context << "- ответ получен:" << reply->readAll();
        } else {
            // Если Connection refused, это не должно происходить, так как мы проверяем готовность порта
            // Но на всякий случай логируем ошибку
            if (reply->error() == QNetworkReply::ConnectionRefusedError) {
                qWarning() << context << "- [ERROR] Connection refused (сервер должен быть готов, но не отвечает):" << url;
            }
            // Игнорируем ошибку "Connection closed" - страница уже закрылась, это нормально
            QString errorStr = reply->errorString();
            if (errorStr.contains("Connection closed")) {
                qDebug() << context << "- страница уже закрылась (нормальное поведение)";
            } else {
                qDebug() << context << "- ошибка:" << errorStr;
            }
            // Всегда считаем успешным, так как цель - закрыть страницу
            success = true;
        }
        if (onFinished) {
            onFinished(success);
        }
        reply->deleteLater();
    });
}

void TOTPService::cleanupServers()
{
    stopCodeUpdateTimer();
    // Останавливаем IPC сервер
    stopIpcServer();
    // Определяем корень проекта для поиска HTML файла (аналогично generateWebPageURL)
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
        }
    }
    QString projectRoot = projectRootDir.absolutePath();
    
    // Удаляем HTML файл из корня проекта
    QString filePath = QDir(projectRoot).absoluteFilePath("totp_setup.html");

    QFile file(filePath);
    if (file.exists()) {
        file.remove();
        qDebug() << "Файл временной страницы удален:" << filePath;
    }

#ifdef Q_OS_UNIX
    if (m_httpPid > 0) {
        ::kill(static_cast<pid_t>(m_httpPid), SIGTERM);
        qDebug() << "HTTP сервер остановлен, PID:" << m_httpPid;
        m_httpPid = -1;
    }
    if (m_websocketPid > 0) {
        ::kill(static_cast<pid_t>(m_websocketPid), SIGTERM);
        qDebug() << "WebSocket сервер остановлен, PID:" << m_websocketPid;
        m_websocketPid = -1;
    }
#else
    if (m_httpPid > 0) {
        QProcess::startDetached("taskkill", {"/PID", QString::number(m_httpPid), "/F"});
        qDebug() << "HTTP сервер (Windows) остановлен, PID:" << m_httpPid;
        m_httpPid = -1;
    }
    if (m_websocketPid > 0) {
        QProcess::startDetached("taskkill", {"/PID", QString::number(m_websocketPid), "/F"});
        qDebug() << "WebSocket сервер (Windows) остановлен, PID:" << m_websocketPid;
        m_websocketPid = -1;
    }
#endif

    m_websocketPort = 0;
    m_httpPort = 0;
    m_pagePath.clear();
}

void TOTPService::setPageDark(bool dark)
{
    m_pageDark = dark;
    if (m_pagePath.isEmpty()) return;

    QFile current(m_pagePath);
    if (!current.open(QIODevice::ReadOnly)) return;
    QByteArray html = current.readAll();
    current.close();
    const QByteArray lightTag = R"(<html lang="ru" data-theme="light">)";
    const QByteArray darkTag = R"(<html lang="ru" data-theme="dark">)";
    const auto &previous = dark ? lightTag : darkTag;
    if (!html.contains(previous)) return;
    html.replace(previous, dark ? darkTag : lightTag);
    QSaveFile file(m_pagePath);
    if (!file.open(QIODevice::WriteOnly) || file.write(html) != html.size() || !file.commit())
        qWarning() << "Не удалось обновить тему страницы кода";
}

QString TOTPService::generateTOTPCode(const QString &secret)
{
    QByteArray secretBytes = base32Decode(secret);
    quint64 timeStep = m_savedTimeStep > 0 ? m_savedTimeStep : getCurrentTimeStepInternal();
    
    qDebug() << "TOTPService::generateTOTPCode - секрет:" << secret;
    qDebug() << "TOTPService::generateTOTPCode - временной шаг:" << timeStep;
    
    // Конвертируем timeStep в big-endian байты
    QByteArray timeBytes;
    for (int i = 7; i >= 0; --i) {
        timeBytes.append((timeStep >> (i * 8)) & 0xFF);
    }
    
    QByteArray hash = hmacSha1(secretBytes, timeBytes);
    
    // Динамическое усечение
    int offset = hash[hash.length() - 1] & 0x0F;
    int code = ((hash[offset] & 0x7F) << 24) |
               ((hash[offset + 1] & 0xFF) << 16) |
               ((hash[offset + 2] & 0xFF) << 8) |
               (hash[offset + 3] & 0xFF);
    
    code = code % 1000000;
    
    QString result = QString::number(code).rightJustified(6, '0');
    qDebug() << "TOTPService::generateTOTPCode - результат:" << result;
    
    return result;
}

bool TOTPService::verifyTOTPCode(const QString &secret, const QString &code, int window)
{
    quint64 currentTimeStep = m_savedTimeStep > 0 ? m_savedTimeStep : getCurrentTimeStepInternal();
    
    qDebug() << "TOTPService::verifyTOTPCode - проверяем код:" << code;
    qDebug() << "TOTPService::verifyTOTPCode - секрет:" << secret;
    qDebug() << "TOTPService::verifyTOTPCode - текущий временной шаг:" << currentTimeStep;
    
    for (int i = -window; i <= window; ++i) {
        QString expectedCode = generateTOTPCode(secret);
        qDebug() << "TOTPService::verifyTOTPCode - ожидаемый код (offset" << i << "):" << expectedCode;
        if (expectedCode == code) {
            qDebug() << "TOTPService::verifyTOTPCode - код совпадает!";
            m_codeUsed = true; // Устанавливаем флаг использования кода
            
            // Закрываем веб-страницу после успешной проверки
            closeWebPage(true);
            
            return true;
        }
    }
    
    qDebug() << "TOTPService::verifyTOTPCode - код НЕ совпадает";
    return false;
}

QString TOTPService::getOTPAuthURL(const QString &secret, const QString &email, const QString &issuer)
{
    QString url = QString("otpauth://totp/%1:%2?secret=%3&issuer=%4")
                  .arg(issuer)
                  .arg(email)
                  .arg(secret)
                  .arg(issuer);
    
    return url;
}

#ifdef Q_OS_WIN
static QHash<int, DWORD> defaultGatewayMetrics()
{
    ULONG size = 0;
    if (GetIpForwardTable(nullptr, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        return {};
    }

    std::vector<unsigned char> buffer(size);
    auto *table = reinterpret_cast<MIB_IPFORWARDTABLE *>(buffer.data());
    if (GetIpForwardTable(table, &size, FALSE) != NO_ERROR) {
        return {};
    }

    QHash<int, DWORD> metrics;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto &route = table->table[i];
        if (route.dwForwardDest == 0 && route.dwForwardMask == 0 && route.dwForwardNextHop != 0) {
            MIB_IF_ROW2 adapter{};
            adapter.InterfaceIndex = route.dwForwardIfIndex;
            if (GetIfEntry2(&adapter) != NO_ERROR || !adapter.InterfaceAndOperStatusFlags.HardwareInterface) {
                continue;
            }
            const auto index = static_cast<int>(route.dwForwardIfIndex);
            metrics.insert(index, std::min(metrics.value(index, route.dwForwardMetric1), route.dwForwardMetric1));
        }
    }
    return metrics;
}
#endif

QString TOTPService::getLocalIPAddress()
{
    // Получаем все сетевые интерфейсы для более точного выбора
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();
    
    QStringList preferredAddresses;  // Предпочтительные адреса (реальные адаптеры)
    QStringList fallbackAddresses;  // Резервные адреса (виртуальные адаптеры)

#ifdef Q_OS_WIN
    const auto gatewayMetrics = defaultGatewayMetrics();
    QString routedAddress;
    DWORD bestMetric = 0;
#endif
    
    for (const QNetworkInterface &adapter : interfaces) {
        // Пропускаем неактивные интерфейсы и loopback
        if (!(adapter.flags() & QNetworkInterface::IsUp) ||
            !(adapter.flags() & QNetworkInterface::IsRunning) ||
            (adapter.flags() & QNetworkInterface::IsLoopBack)) {
            continue;
        }
        
        // Получаем имя интерфейса для проверки на виртуальные адаптеры
        QString interfaceName = adapter.humanReadableName().toLower();
        bool isVirtual = interfaceName.contains("vmware") || 
                        interfaceName.contains("virtualbox") ||
                        interfaceName.contains("vbox") ||
                        interfaceName.contains("hyper-v") ||
                        interfaceName.contains("virtual") ||
                        interfaceName.contains("vmnet") ||
                        interfaceName.contains("vnic");
        
        // Получаем адреса этого интерфейса
        QList<QNetworkAddressEntry> entries = adapter.addressEntries();
        for (const QNetworkAddressEntry &entry : entries) {
            QHostAddress address = entry.ip();
            
            // Ищем только IPv4 адреса
            if (address.protocol() != QAbstractSocket::IPv4Protocol) {
                continue;
            }
            
            QString addressStr = address.toString();
            
            // Проверяем диапазоны локальных адресов
            if (addressStr.startsWith("192.168.") || 
                addressStr.startsWith("10.") || 
                addressStr.startsWith("172.")) {
                
                if (isVirtual) {
                    fallbackAddresses.append(addressStr);
                } else {
                    preferredAddresses.append(addressStr);
#ifdef Q_OS_WIN
                    const auto metric = gatewayMetrics.constFind(adapter.index());
                    if (metric != gatewayMetrics.cend() && (routedAddress.isEmpty() || *metric < bestMetric)) {
                        routedAddress = addressStr;
                        bestMetric = *metric;
                    }
#endif
                }
            }
        }
    }
    
#ifdef Q_OS_WIN
    if (!routedAddress.isEmpty()) {
        return routedAddress;
    }
#endif

    // Сначала возвращаем предпочтительный адрес (реальный адаптер)
    if (!preferredAddresses.isEmpty()) {
        return preferredAddresses.first();
    }
    
    // Если нет реальных адаптеров, используем виртуальный
    if (!fallbackAddresses.isEmpty()) {
        return fallbackAddresses.first();
    }
    
    return QString();
}

QString TOTPService::generateWebPageURL(const QString &secret, const QString &email, bool startTimer)
{
    if (m_httpPid > 0 || m_websocketPid > 0) {
        cleanupServers();
    }
    // Сохраняем текущий временной шаг для синхронизации
    quint64 currentTimeStep = getCurrentTimeStepInternal();
    setCurrentTimeStep(currentTimeStep);
    
    // Генерируем текущий TOTP код для отображения на странице
    QString currentCode = generateTOTPCode(secret);
    
    // Вычисляем время до следующего обновления TOTP (1-30 секунд)
    quint64 currentTime = QDateTime::currentSecsSinceEpoch();
    int timeUntilNextUpdate = 30 - (currentTime % 30);
    
    // Если время = 0, значит код только что обновился, устанавливаем 30 секунд
    if (timeUntilNextUpdate == 0) {
        timeUntilNextUpdate = 30;
    }
    
    qDebug() << "Генерируем веб-страницу с кодом:" << currentCode << "время до обновления:" << timeUntilNextUpdate << "секунд";
    
    // Docker публикует один фиксированный HTTP-порт для телефона.
    const bool publishedPort = qEnvironmentVariableIsSet("THREEFA_TOTP_HTTP_PORT");
    QString ipAddress = publishedPort ? qEnvironmentVariable("THREEFA_TOTP_HOST", "127.0.0.1")
                                      : getLocalIPAddress();
    const QString websocketAddress = publishedPort || ipAddress.isEmpty() ? QStringLiteral("127.0.0.2") : ipAddress;
    if (ipAddress.isEmpty()) ipAddress = QStringLiteral("localhost");
    if (publishedPort && QHostAddress(ipAddress).protocol() != QAbstractSocket::IPv4Protocol) {
        qWarning() << "THREEFA_TOTP_HOST must be an IPv4 address";
        return {};
    }

    int websocketPort = findFreePort();
    int httpPort = publishedPort ? qEnvironmentVariableIntValue("THREEFA_TOTP_HTTP_PORT") : findFreePort();

    if (websocketPort == 0 || httpPort < 1 || httpPort > 65535) {
        qDebug() << "❌ Ошибка: не удалось получить свободные порты";
        return QString();
    }

    while (httpPort == websocketPort) {
        websocketPort = findFreePort();
        if (websocketPort == 0) {
            qDebug() << "❌ Ошибка: не удалось подобрать уникальный HTTP порт";
            return QString();
        }
    }
    const QString accessToken = publishedPort ? QUuid::createUuid().toString(QUuid::Id128) : QString{};
    
    // Создаем HTML контент с JavaScript для обновления кода
    QString html = QString(R"(
<!DOCTYPE html>
<html lang="ru" data-theme="%4">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>3FA — Код подтверждения</title>
    <style>
        :root {
            color-scheme: light;
            --canvas: #fff;
            --panel: #fafafd;
            --text: #202020;
            --muted: #5c6067;
            --line: #dce0e5;
            --accent: #0069cc;
            font: 16px/1.5 system-ui, sans-serif;
        }
        :root[data-theme="dark"] {
            color-scheme: dark;
            --canvas: #121314;
            --panel: #191a1b;
            --text: #e8e9ea;
            --muted: #a7a9ad;
            --line: #343637;
            --accent: #60b2d4;
        }
        * { box-sizing: border-box; }
        body {
            min-height: 100vh;
            margin: 0;
            display: grid;
            align-items: center;
            padding: 24px;
            background: var(--canvas);
            color: var(--text);
        }
        main { width: min(100%, 26rem); margin: 0 auto; }
        .brand { margin: 0 0 14px; font-weight: 700; }
        .card { padding: 24px; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; }
        .eyebrow { margin: 0 0 6px; color: var(--accent); font-size: .75rem; font-weight: 700; }
        h1 { margin: 0; font-size: 1.45rem; line-height: 1.25; }
        .lead { color: var(--muted); margin: 10px 0 0; }
        .code {
            margin: 20px 0 12px;
            padding: 12px 4px;
            border: 1px solid var(--line);
            border-radius: 8px;
            background: var(--canvas);
            font: 650 clamp(1.55rem, 9vw, 2.45rem)/1.25 ui-monospace, monospace;
            letter-spacing: .14em;
            text-align: center;
        }
        .timer-track { height: 4px; overflow: hidden; border-radius: 4px; background: var(--line); }
        .timer-fill { height: 100%; background: var(--accent); transform-origin: left; }
        .timer-info { margin: 8px 0 0; color: var(--muted); font-size: .875rem; }
    </style>
</head>
<body>
    <main>
        <p class="brand">3FA</p>
        <section class="card" aria-labelledby="heading">
            <p class="eyebrow">ЭТАП 2 ИЗ 3</p>
            <h1 id="heading">Код подтверждения</h1>
            <p class="lead">Введите этот код в окне 3FA на компьютере.</p>
            <div class="code" id="totpCode">------</div>
            <div class="timer-track" aria-hidden="true"><div class="timer-fill" id="timerFill"></div></div>
            <p class="timer-info">Обновление через <span id="timerValue">30</span> с</p>
        </section>
    </main>

    <script>
        let timeLeft = 30;
        let timerRunning = false;
        const websocketPort = %1;
        const httpPort = %2;
        const defaultHost = '%3';
        const accessToken = new URLSearchParams(window.location.search).get('token');
        const isSecure = window.location.protocol === 'https:';
        const websocketScheme = isSecure ? 'wss' : 'ws';
        const httpScheme = isSecure ? 'https' : 'http';
        let pageShouldClose = false;
        let websocket = null;
        let reconnectAttempts = 0;
        const maxReconnectAttempts = 5;

        const codeElement = document.getElementById('totpCode');
        const timerValueElement = document.getElementById('timerValue');
        const timerFillElement = document.getElementById('timerFill');

        function updateTimerDisplay() {
            const clamped = Math.max(0, Math.min(30, timeLeft));
            if (timerValueElement) {
                timerValueElement.textContent = clamped;
            }
            if (timerFillElement) {
                const progress = Math.max(0, Math.min(1, clamped / 30));
                timerFillElement.style.transform = `scaleX(${progress})`;
            }
        }
        
        function startTimer() {
            if (timerRunning) return;
            timerRunning = true;
            debugLog('⏱️ Таймер запущен (30 секунд)');
        }
        
        function stopTimer() {
            timerRunning = false;
            debugLog('⏸️ Таймер остановлен');
        }

        function resolveHost() {
            return window.location.hostname || defaultHost;
        }

        function getHttpBaseUrl() {
            return `${httpScheme}://${resolveHost()}:${httpPort}`;
        }

        function accessPath(path) {
            return accessToken ? `${path}?token=${encodeURIComponent(accessToken)}` : path;
        }

        function debugLog(message) {
            console.log(message);
        }

        function connectWebSocket() {
            const host = resolveHost();
            const wsUrl = `${websocketScheme}://${host}:${websocketPort}`;
            debugLog('🔌 Подключаемся к WebSocket: ' + wsUrl);

            websocket = new WebSocket(wsUrl);

            websocket.onopen = function() {
                debugLog('✅ WebSocket соединение установлено');
                reconnectAttempts = 0;
                websocket.send(JSON.stringify({ type: 'request_code' }));
            };

            websocket.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data);
                    debugLog('📨 Получено сообщение: ' + JSON.stringify(data));

                    if (data.type === 'code_update') {
                        codeElement.textContent = data.code;
                        timeLeft = 30;
                        startTimer();
                        updateTimerDisplay();
                        debugLog('✅ Код получен: ' + data.code + ', таймер запущен с 30 секунд');
                    } else if (data.type === 'pong') {
                        debugLog('🏓 Pong получен');
                    } else if (data.type === 'close_page') {
                        debugLog('✅ Получена команда закрытия страницы через WebSocket!');
                        showSuccessAndClose(true);
                    } else if (data.type === 'success') {
                        debugLog('✅ Получено сообщение об успехе через WebSocket!');
                        showSuccessAndClose(false);
                    }
                } catch (error) {
                    debugLog('❌ Ошибка парсинга сообщения: ' + error.message);
                }
            };

            websocket.onclose = function(event) {
                debugLog('🔌 WebSocket соединение закрыто, код: ' + event.code);
                
                // Если код = 1000 (нормальное закрытие) и мы не находимся в процессе закрытия по команде,
                // значит сервер закрыл соединение
                if (event.code === 1000 && !pageShouldClose) {
                    debugLog('🔌 Сервер закрыл соединение без предупреждения');
                    showSuccessAndClose(true);
                } else if (!pageShouldClose) {
                    websocket = null;
                    if (reconnectAttempts < maxReconnectAttempts) {
                        reconnectAttempts++;
                        debugLog(`🔄 Попытка переподключения ${reconnectAttempts}/${maxReconnectAttempts}`);
                        setTimeout(connectWebSocket, 2000);
                    } else {
                        debugLog('❌ Превышено количество попыток переподключения');
                    }
                }
            };

            websocket.onerror = function(error) {
                debugLog('❌ Ошибка WebSocket: ' + (error.message || 'Неизвестная ошибка'));
            };
        }

        function startPing() {
            setInterval(() => {
                if (websocket && websocket.readyState === WebSocket.OPEN) {
                    websocket.send(JSON.stringify({ type: 'ping' }));
                    debugLog('🏓 Ping отправлен');
                }
            }, 15000);
        }

        setInterval(() => {
            if (timerRunning) {
                timeLeft--;
                if (timeLeft <= 0) {
                    debugLog('⏰ Таймер истек! Запрашиваем новый код...');
                    if (websocket && websocket.readyState === WebSocket.OPEN) {
                        websocket.send(JSON.stringify({ type: 'request_new_code' }));
                    } else {
                        debugLog('❌ WebSocket недоступен, используем HTTP fallback');
                        fetch(accessPath('/get_current_code'))
                            .then(response => response.json())
                            .then(data => {
                                codeElement.textContent = data.code;
                                timeLeft = 30;
                                updateTimerDisplay();
                                debugLog('🔄 HTTP fallback: получен новый код ' + data.code);
                            })
                            .catch(error => {
                                debugLog('❌ Ошибка HTTP fallback: ' + error.message);
                                timeLeft = 30;
                                updateTimerDisplay();
                            });
                    }
                }
                updateTimerDisplay();
            }
        }, 1000);

        function showSuccessAndClose(serverClosed) {
            if (pageShouldClose) return;
            pageShouldClose = true;
            
            if (websocket) websocket.close();

            const heading = serverClosed ? 'Соединение закрыто' : 'Код принят';
            const detail = serverClosed ? 'Приложение 3FA закрыло соединение.' : 'Продолжите вход на компьютере.';
            document.querySelector('.card').innerHTML = `
                <h1 id="heading">${heading}</h1>
                <p class="lead">${detail} Эту вкладку можно закрыть.</p>`;
            setTimeout(() => window.close(), 3000);
        }

        updateTimerDisplay();
        debugLog('🌐 Hostname: ' + window.location.hostname);
        debugLog('🌐 Port: ' + window.location.port);
        debugLog('🌐 WebSocket порт (конфиг): ' + websocketPort);
        debugLog('🌐 HTTP порт (конфиг): ' + httpPort);
        debugLog('🌐 HTTP база: ' + getHttpBaseUrl());

        if (websocketPort) {
            connectWebSocket();
            startPing();
        }

        async function refreshCodeOverHttp() {
            if (pageShouldClose || (websocket && websocket.readyState === WebSocket.OPEN)) return;
            try {
                if (!websocketPort) {
                    const status = await fetch(accessPath('/check_close_status'), {cache: 'no-store'});
                    if (status.ok) {
                        const state = await status.json();
                        if (state.shouldClose) {
                            showSuccessAndClose(!state.accepted);
                            return;
                        }
                    }
                }
                const response = await fetch(accessPath('/get_current_code'), {cache: 'no-store'});
                const data = await response.json();
                if (!response.ok || data.message || !/^\d{6}$/.test(data.code)) return;
                codeElement.textContent = data.code;
                timeLeft = data.timeLeft;
                updateTimerDisplay();
            } catch (error) {
                debugLog('HTTP: ' + error.message);
            }
        }

        refreshCodeOverHttp();
        setInterval(refreshCodeOverHttp, 1000);

        debugLog('🚀 Страница инициализирована, ожидаем код через WebSocket...');
    </script>
</body>
</html>
    )").arg(publishedPort ? 0 : websocketPort)
         .arg(httpPort)
         .arg(ipAddress)
         .arg(m_pageDark ? QStringLiteral("dark") : QStringLiteral("light"));
    
    // Определяем корень проекта для поиска Python скриптов (аналогично database.cpp)
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
        }
    }
    QString projectRoot = projectRootDir.absolutePath();
    
    // Создаем временный HTML файл в корне проекта (чтобы HTTP сервер мог его найти)
    QString fileName = QString("totp_setup.html");
    // Создаем файл в корне проекта, где запускается HTTP сервер
    QString filePath = QDir(projectRoot).absoluteFilePath(fileName);
    
    QSaveFile file(filePath);
    const QByteArray page = html.toUtf8();
    if (file.open(QIODevice::WriteOnly) && file.write(page) == page.size() && file.commit()) {
        m_pagePath = filePath;
        
        // Запускаем WebSocket сервер на случайном порту (используем корень проекта для поиска скрипта)
        QString websocketServerPath = QDir(projectRoot).absoluteFilePath("scripts/websocket_server.py");
        if (!QFile::exists(websocketServerPath)) {
            qWarning() << "[ERROR] websocket_server.py не найден в scripts/:" << websocketServerPath;
        }
        // Определяем команду Python в зависимости от платформы
        // На Windows обычно используется "python", на Mac/Linux - "python3"
        QString pythonCmd;
#ifdef Q_OS_WIN
        pythonCmd = "python";  // На Windows обычно "python"
#else
        pythonCmd = "python3"; // На Mac/Linux обычно "python3"
#endif
        
        qint64 websocketPid = -1;
        // Используем startDetached для независимого запуска процесса
        // Это гарантирует, что процесс не будет уничтожен при выходе из области видимости
        bool websocketStarted = QProcess::startDetached(
            pythonCmd,
            QStringList{"-X", "utf8", websocketServerPath, QString::number(websocketPort), websocketAddress},
            projectRoot,  // запускаем из корня проекта
            &websocketPid
        );
        if (!websocketStarted) {
            // Если не удалось с "python", пробуем "python3" на Windows
#ifdef Q_OS_WIN
            if (pythonCmd == "python") {
                pythonCmd = "python3";
                websocketStarted = QProcess::startDetached(
                    pythonCmd,
                    QStringList{"-X", "utf8", websocketServerPath, QString::number(websocketPort), websocketAddress},
                    projectRoot,
                    &websocketPid
                );
            }
#endif
            if (!websocketStarted) {
                qWarning() << "[ERROR] Не удалось запустить WebSocket сервер на порту" << websocketPort;
                qWarning() << "[INFO] Проверьте, что Python установлен и библиотека websockets установлена: pip install websockets";
                websocketPid = -1;
            } else {
                qDebug() << "[OK] WebSocket сервер запущен (через" << pythonCmd << "), PID:" << websocketPid << "порт:" << websocketPort << "скрипт:" << websocketServerPath;
            }
        } else {
            qDebug() << "[OK] WebSocket сервер запущен, PID:" << websocketPid << "порт:" << websocketPort << "скрипт:" << websocketServerPath;
        }
        
        // Также запускаем HTTP сервер для fallback на другом порту (используем корень проекта)
        QString smartServerPath = QDir(projectRoot).absoluteFilePath("scripts/smart_server.py");
        if (!QFile::exists(smartServerPath)) {
            qWarning() << "[ERROR] smart_server.py не найден в scripts/:" << smartServerPath;
        }
        qint64 httpPid = -1;
        QStringList httpArgs{"-X", "utf8", smartServerPath, QString::number(httpPort), QString::number(websocketPort)};
        if (publishedPort) httpArgs << accessToken;
        bool httpStarted = QProcess::startDetached(
            pythonCmd,
            httpArgs,
            projectRoot,  // запускаем из корня проекта
            &httpPid
        );
        if (!httpStarted) {
            qDebug() << "[ERROR] Не удалось запустить HTTP сервер на порту" << httpPort;
            httpPid = -1;
        } else {
            qDebug() << "[OK] HTTP сервер запущен, PID:" << httpPid << "порт:" << httpPort << "скрипт:" << smartServerPath;
        }
        
        // Сохраняем порты и процессы для последующего использования
        setCurrentPorts(websocketPort, httpPort);
        m_websocketPid = websocketPid;
        m_httpPid = httpPid;
        
        // Запускаем IPC сервер для связи с Python (TCP на localhost)
        startIpcServer();
        
        // Отправляем порт IPC сервера в Python через HTTP запрос
        // На Windows Python скриптам нужно больше времени для запуска (особенно HTTP серверу в потоке)
        if (m_ipcPort > 0) {
            // Увеличиваем начальную задержку до 3 секунд для Windows
            QTimer::singleShot(3000, this, [this, websocketPort]() {
                // Увеличиваем время ожидания до 15 секунд для Windows
                // HTTP сервер запускается в отдельном потоке и может требовать больше времени
                if (waitForPortReady(websocketPort, 15000, 300)) {
                    QUrl updateUrl;
                    updateUrl.setScheme(QStringLiteral("http"));
                    updateUrl.setHost(QStringLiteral("localhost"));
                    updateUrl.setPort(websocketPort);
                    updateUrl.setPath(QStringLiteral("/set_ipc_port"));
                    QByteArray payload = QByteArray("{\"port\":") + QByteArray::number(m_ipcPort) + "}";
                    postAsync(updateUrl, payload, QStringLiteral("[SEND] IPC порт"));
                } else {
                    qWarning() << "[ERROR] WebSocket сервер не готов после 15 секунд, запрос IPC порта не отправлен";
                    qWarning() << "[INFO] Возможно, Python скрипт не запустился или библиотека websockets не установлена";
                }
            });
        }
        
        // Файлы с секретом и текущим кодом больше не используются —
        // секрет хранится в БД, код отправляется по HTTP на WebSocket сервер
        
        // Сохраняем секрет для генерации нового кода по запросу
        m_currentSecret = secret;
        
        // Отправляем начальный код на WebSocket сервер (даже если таймер не запущен)
        // Это нужно для того, чтобы клиент получил код сразу после подключения
        int initWsPort = currentWebsocketPort();
        if (initWsPort > 0 && !currentCode.isEmpty()) {
            // На Windows Python скриптам нужно больше времени для запуска
            QTimer::singleShot(3000, this, [this, currentCode, initWsPort]() {
                // Увеличиваем время ожидания до 15 секунд для Windows
                // HTTP сервер запускается в отдельном потоке и может требовать больше времени
                if (waitForPortReady(initWsPort, 15000, 300)) {
                    QUrl updateUrl;
                    updateUrl.setScheme(QStringLiteral("http"));
                    updateUrl.setHost(QStringLiteral("localhost"));
                    updateUrl.setPort(initWsPort);
                    updateUrl.setPath(QStringLiteral("/update_code"));
                    QByteArray payload = QByteArray("{\"code\":\"") + currentCode.toUtf8() + "\"}";
                    postAsync(updateUrl, payload, QStringLiteral("[SEND] WebSocket начальный код"));
                } else {
                    qWarning() << "[ERROR] WebSocket сервер не готов после 15 секунд, начальный код не отправлен";
                    qWarning() << "[INFO] Возможно, Python скрипт не запустился или библиотека websockets не установлена";
                }
            });
        }
        
        // Таймер больше не используется - код генерируется только по запросу пользователя
        // Оставляем вызов для совместимости, но таймер не запускается
        if (startTimer) {
            // Сохраняем секрет, но не запускаем таймер
            // startCodeUpdateTimer больше не запускает таймер
            startCodeUpdateTimer(secret, currentCode);
        }

        m_codeUpdateTimer = new QTimer(this);
        connect(m_codeUpdateTimer, &QTimer::timeout, this, [this]() {
            if (getCurrentTimeStepInternal() != m_savedTimeStep) {
                generateNewCodeOnRequest();
            }
        });
        m_codeUpdateTimer->start(1000);
        
        // Возвращаем HTTP URL с IP-адресом для QR-кода
        // Добавляем timestamp для предотвращения кэширования
        qint64 timestamp = QDateTime::currentMSecsSinceEpoch();
        QString url = QString("http://%1:%2/%3?t=%4").arg(ipAddress).arg(httpPort).arg(fileName).arg(timestamp);
        if (publishedPort) url += QStringLiteral("&token=") + accessToken;
        return url;
    }
    
    return QString();
}

void TOTPService::setCurrentPorts(int websocketPort, int httpPort)
{
    m_websocketPort = websocketPort;
    m_httpPort = httpPort;
    qDebug() << "TOTPService::setCurrentPorts - WebSocket порт:" << m_websocketPort
             << "HTTP порт:" << m_httpPort;
}

int TOTPService::currentWebsocketPort() const
{
    return m_websocketPort;
}

int TOTPService::currentHttpPort() const
{
    return m_httpPort;
}

QString TOTPService::getCurrentTOTPCode(const QString &secret)
{
    return generateTOTPCode(secret);
}

void TOTPService::startCodeUpdateTimer(const QString &secret, const QString &initialCode)
{
    stopCodeUpdateTimer(); // Останавливаем предыдущий таймер если есть
    
    m_currentSecret = secret;
    // Таймер больше не используется - код генерируется только по запросу пользователя
    // Оставляем метод для совместимости, но не запускаем таймер
    
    // Отправляем начальный код на WebSocket сервер
    // Используем переданный код или генерируем новый, если не передан
    QString codeToSend = initialCode.isEmpty() ? generateTOTPCode(m_currentSecret) : initialCode;
    int initWsPort = currentWebsocketPort();
    
    if (initWsPort > 0 && !codeToSend.isEmpty()) {
        // Отправляем код с небольшой задержкой, чтобы WebSocket сервер успел запуститься
        // Код будет сохранен на сервере и отправлен клиенту при подключении
        QTimer::singleShot(300, this, [this, codeToSend, initWsPort]() {
            QUrl updateUrl;
            updateUrl.setScheme(QStringLiteral("http"));
            updateUrl.setHost(QStringLiteral("localhost"));
            updateUrl.setPort(initWsPort);
            updateUrl.setPath(QStringLiteral("/update_code"));
            QByteArray payload = QByteArray("{\"code\":\"") + codeToSend.toUtf8() + "\"}";
            postAsync(updateUrl, payload, QStringLiteral("[SEND] WebSocket начальное обновление"));
            // Не логируем отправку - код будет отправлен клиенту при подключении
        });
        // Дополнительная отправка через 800ms на случай, если первая не прошла
        QTimer::singleShot(800, this, [this, codeToSend, initWsPort]() {
            QUrl updateUrl;
            updateUrl.setScheme(QStringLiteral("http"));
            updateUrl.setHost(QStringLiteral("localhost"));
            updateUrl.setPort(initWsPort);
            updateUrl.setPath(QStringLiteral("/update_code"));
            QByteArray payload = QByteArray("{\"code\":\"") + codeToSend.toUtf8() + "\"}";
            postAsync(updateUrl, payload, QStringLiteral("[SEND] WebSocket начальное обновление (повтор)"));
            // Не логируем отправку - код будет отправлен клиенту при подключении
        });
    } else {
        qDebug() << "[WARNING] Не удалось отправить начальный код: порт=" << initWsPort << "код=" << codeToSend;
    }
    
    qDebug() << "Запущен таймер обновления TOTP кода с начальным кодом:" << codeToSend;
}

void TOTPService::stopCodeUpdateTimer()
{
    if (m_codeUpdateTimer) {
        m_codeUpdateTimer->stop();
        m_codeUpdateTimer->deleteLater();
        m_codeUpdateTimer = nullptr;
        qDebug() << "Остановлен таймер обновления TOTP кода";
    }
}

void TOTPService::generateNewCodeOnRequest()
{
    if (m_currentSecret.isEmpty()) {
        qWarning() << "TOTPService: Нельзя сгенерировать код - секрет не установлен";
        return;
    }
    
    // Обновляем временной шаг перед генерацией нового кода
    quint64 currentTimeStep = getCurrentTimeStepInternal();
    setCurrentTimeStep(currentTimeStep);
    
    // Генерируем новый код
    QString newCode = generateTOTPCode(m_currentSecret);
    
    // Отправляем обновление в WebSocket сервер
    int websocketPort = currentWebsocketPort();
    if (websocketPort > 0) {
        QUrl updateUrl;
        updateUrl.setScheme(QStringLiteral("http"));
        updateUrl.setHost(QStringLiteral("localhost"));
        updateUrl.setPort(websocketPort);
        updateUrl.setPath(QStringLiteral("/update_code"));
        
        QByteArray payload = QByteArray("{\"code\":\"") + newCode.toUtf8() + "\"}";
        postAsync(updateUrl, payload, QStringLiteral("[SEND] WebSocket обновление по запросу"));
        qDebug() << "[UPDATE] Сгенерирован новый код по запросу:" << newCode;
    } else {
        qDebug() << "[ERROR] WebSocket порт не установлен, код не отправлен";
    }
}

void TOTPService::startIpcServer()
{
    stopIpcServer(); // Останавливаем предыдущий сервер если есть
    
    m_ipcServer = new QTcpServer(this);
    connect(m_ipcServer, &QTcpServer::newConnection, this, &TOTPService::onIpcNewConnection);
    
    // Используем TCP сокет на localhost вместо Unix domain socket
    // Это работает надежнее на всех платформах
    int ipcPort = findFreePort();
    if (ipcPort == 0) {
        qWarning() << "[ERROR] Не удалось найти свободный порт для IPC сервера";
        m_ipcServer->deleteLater();
        m_ipcServer = nullptr;
        return;
    }
    
    if (m_ipcServer->listen(QHostAddress::LocalHost, ipcPort)) {
        m_ipcPort = ipcPort;
        qDebug() << "[IPC] IPC сервер запущен на localhost:" << ipcPort;
        qDebug() << "[IPC] IPC сервер слушает:" << (m_ipcServer->isListening() ? "true" : "false");
    } else {
        qWarning() << "[ERROR] Не удалось запустить IPC сервер:" << m_ipcServer->errorString();
        qWarning() << "[ERROR] Порт:" << ipcPort;
        m_ipcServer->deleteLater();
        m_ipcServer = nullptr;
        m_ipcPort = 0;
    }
}

void TOTPService::stopIpcServer()
{
    if (m_ipcServer) {
        int port = m_ipcPort;
        m_ipcServer->close();
        m_ipcServer->deleteLater();
        m_ipcServer = nullptr;
        m_ipcPort = 0;
        qDebug() << "[IPC] IPC сервер остановлен, порт:" << port;
    }
}

int TOTPService::getIpcServerPort() const
{
    return m_ipcPort;
}

void TOTPService::onIpcNewConnection()
{
    if (!m_ipcServer) {
        return;
    }
    
    QTcpSocket *socket = m_ipcServer->nextPendingConnection();
    if (!socket) {
        return;
    }
    
    qDebug() << "[IPC] Новое IPC соединение от Python";
    
    connect(socket, &QTcpSocket::readyRead, this, &TOTPService::onIpcReadyRead);
    connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
}

void TOTPService::onIpcReadyRead()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) {
        return;
    }
    
    QByteArray data = socket->readAll();
    qDebug() << "[IPC] Получено сообщение:" << data;
    
    // Парсим JSON запрос
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(data, &error);
    
    if (error.error != QJsonParseError::NoError) {
        qWarning() << "[ERROR] IPC: Ошибка парсинга JSON:" << error.errorString();
        sendIpcResponse(socket, false, "Ошибка парсинга JSON");
        return;
    }
    
    QJsonObject obj = doc.object();
    QString action = obj.value("action").toString();
    
    if (action == "generate_new_code") {
        qDebug() << "[UPDATE] IPC: Запрос на генерацию нового кода";
        generateNewCodeOnRequest();
        sendIpcResponse(socket, true, "Код сгенерирован");
    } else {
        qWarning() << "[ERROR] IPC: Неизвестное действие:" << action;
        sendIpcResponse(socket, false, QString("Неизвестное действие: %1").arg(action));
    }
}

void TOTPService::sendIpcResponse(QTcpSocket *socket, bool success, const QString &message)
{
    if (!socket || socket->state() != QAbstractSocket::ConnectedState) {
        return;
    }
    
    QJsonObject response;
    response["status"] = success ? "success" : "error";
    response["message"] = message;
    
    QJsonDocument doc(response);
    QByteArray data = doc.toJson();
    
    socket->write(data);
    socket->flush();
    
    qDebug() << "[SEND] IPC: Отправлен ответ:" << data;
}

void TOTPService::closeWebPage(bool success)
{
    // Останавливаем таймер обновления кода
    stopCodeUpdateTimer();
    
    // Если это успешная проверка, отправляем только сообщение об успехе и выходим
    if (success) {
        qDebug() << "[OK] Отправляем информацию об успехе на страницу";
        const bool publishedPort = qEnvironmentVariableIsSet("THREEFA_TOTP_HTTP_PORT");
        int websocketPort = currentWebsocketPort();
        if (websocketPort > 0) {
            QUrl successUrl;
            successUrl.setScheme(QStringLiteral("http"));
            successUrl.setHost(QStringLiteral("localhost"));
            successUrl.setPort(websocketPort);
            successUrl.setPath(QStringLiteral("/success"));
            postAsync(successUrl,
                      QByteArrayLiteral("{\"action\":\"success\"}"),
                      QStringLiteral("[OK] Успех"),
                      [](bool) {});
        }

        if (publishedPort && m_httpPort > 0) {
            QUrl successUrl(QStringLiteral("http://127.0.0.1/close_page"));
            successUrl.setPort(m_httpPort);
            postAsync(successUrl, QByteArrayLiteral("{\"action\":\"success\"}"), QStringLiteral("[HTTP] Успех"));
        }
        
        // Ждем немного, чтобы сообщение успело отправиться, потом закрываем серверы
        const auto closingHttpPid = m_httpPid;
        const auto closingWebsocketPid = m_websocketPid;
        QTimer::singleShot(publishedPort ? 2500 : 500, this, [this, closingHttpPid, closingWebsocketPid]() {
            if (m_httpPid == closingHttpPid && m_websocketPid == closingWebsocketPid) cleanupServers();
        });
        return;
    }
    
    auto pendingRequests = QSharedPointer<int>::create(0);
    QEventLoop waitLoop;
    QTimer timeoutTimer;
    
    // Ожидаем максимум 2 секунды
    timeoutTimer.setSingleShot(true);
    QObject::connect(&timeoutTimer, &QTimer::timeout, &waitLoop, [&waitLoop]() {
        qDebug() << "[TIMEOUT] Таймаут ожидания подтверждения от страницы";
        waitLoop.quit();
    });
    
    timeoutTimer.start(2000);
    
    auto onResponse = [pendingRequests, loop = QPointer<QEventLoop>(&waitLoop)]() {
        if (--*pendingRequests == 0 && loop) {
            loop->quit();
        }
    };
    
    bool hasAsyncRequests = false;

    int websocketPort = currentWebsocketPort();
    if (websocketPort > 0) {
        ++*pendingRequests;
        hasAsyncRequests = true;
        QUrl wsUrl;
        wsUrl.setScheme(QStringLiteral("http"));
        wsUrl.setHost(QStringLiteral("localhost"));
        wsUrl.setPort(websocketPort);
        wsUrl.setPath(QStringLiteral("/close_page"));
        postAsync(wsUrl,
                  QByteArrayLiteral("{\"action\":\"close\"}"),
                  QStringLiteral("[WS] WebSocket закрытие"),
                  [onResponse, websocketPort](bool success) {
                      qDebug() << "[WS] WebSocket закрытие - ответ:" << (success ? "Успешно" : "Ошибка");
                      qDebug() << "[WS] WebSocket закрытие - порт:" << websocketPort;
                      onResponse();
                  });
    } else {
        qDebug() << "WebSocket порт не установлен, команда закрытия не отправлена";
    }

    if (m_httpPort > 0) {
        ++*pendingRequests;
        hasAsyncRequests = true;
        QUrl httpUrl;
        httpUrl.setScheme(QStringLiteral("http"));
        httpUrl.setHost(QStringLiteral("127.0.0.1"));
        httpUrl.setPort(m_httpPort);
        httpUrl.setPath(QStringLiteral("/close_page"));
        postAsync(httpUrl,
                  QByteArrayLiteral("{\"action\":\"close\"}"),
                  QStringLiteral("[HTTP] HTTP закрытие"),
                  [onResponse, this](bool success) {
                      qDebug() << "[HTTP] HTTP закрытие - ответ:" << (success ? "Успешно" : "Ошибка");
                      qDebug() << "[HTTP] HTTP закрытие - порт:" << m_httpPort;
                      onResponse();
                  });
        qDebug() << "[SEND] Команда закрытия страницы отправлена (WebSocket порт:" << websocketPort << ", HTTP порт:" << m_httpPort << ")";
    } else {
        qDebug() << "HTTP порт не установлен, команда закрытия на HTTP сервер не отправлена";
    }

    if (hasAsyncRequests) {
        qDebug() << "[WAIT] Ожидаем подтверждения от серверов...";
        waitLoop.exec();
    }
    
    // Закрываем серверы после получения подтверждения или таймаута
    qDebug() << "[CLEANUP] Останавливаем серверы после подтверждения";
    cleanupServers();
}


QPixmap TOTPService::generateQRCode(const QString &secret, const QString &email, const QString &issuer,
                                  bool startTimer, QString *pageUrl)
{
    const QString url = generateWebPageURL(secret, email, startTimer);
    if (pageUrl) *pageUrl = url;
    if (url.isEmpty()) return {};

    using qrcodegen::QrCode;
    QrCode qr = QrCode::encodeText(url.toUtf8().constData(), QrCode::Ecc::LOW);

    const int border = 4;        // стандартная белая рамка
    const int targetSize = 200;  // целевой размер QR-кода
    const int qrSize = qr.getSize();
    const int sizeWithBorder = qrSize + border * 2;
    int scale = std::max(1, targetSize / sizeWithBorder);
    int imageSize = sizeWithBorder * scale;

    if (scale == 0) {
        scale = 1;
        imageSize = sizeWithBorder;
    }

    QImage image(imageSize, imageSize, QImage::Format_ARGB32);
    image.fill(Qt::white);

    QPainter painter(&image);
    painter.setRenderHint(QPainter::Antialiasing, false);
    painter.setPen(Qt::NoPen);
    painter.setBrush(Qt::black);

    for (int y = 0; y < qrSize; ++y) {
        for (int x = 0; x < qrSize; ++x) {
            if (qr.getModule(x, y)) {
                int drawX = (x + border) * scale;
                int drawY = (y + border) * scale;
                painter.drawRect(drawX, drawY, scale, scale);
            }
        }
    }

    return QPixmap::fromImage(image);
}
