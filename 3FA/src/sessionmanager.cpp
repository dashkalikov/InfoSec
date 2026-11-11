#include "sessionmanager.h"
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QDebug>
#include <QDateTime>
#include <QMutex>
#include <QMutexLocker>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QDir>
#include <QCoreApplication>
#include <QEventLoop>

SessionManager::SessionManager(QObject *parent)
    : QObject(parent)
    , m_dbInitialized(false)
{
}

SessionManager::~SessionManager()
{
    QMutexLocker locker(&m_mutex);
    m_sessions.clear();
}

QString SessionManager::createSession(int userId, const QString &userEmail)
{
    if (userId <= 0 || userEmail.isEmpty()) {
        qWarning() << "SessionManager: Invalid parameters for session creation";
        return QString();
    }

    QMutexLocker locker(&m_mutex);
    
    // Генерируем уникальный токен
    QString token = generateToken();
    
    // Создаем сессию
    Session session;
    session.userId = userId;
    session.userEmail = userEmail;
    session.createdAt = QDateTime::currentDateTime();
    session.expiresAt = session.createdAt.addSecs(SESSION_DURATION_SECONDS);
    
    m_sessions[token] = session;
    
    // Сохраняем сессию в БД, если БД инициализирована
    if (m_dbInitialized) {
        if (!saveSessionToDb(token, session)) {
            qWarning() << "SessionManager: Failed to save session to database, but session created in memory";
        }
    }
    
    qDebug() << "SessionManager: Created session for user" << userId << "(" << userEmail << "), token:" << token.left(16) << "...";
    
    return token;
}

bool SessionManager::isValidSession(const QString &token) const
{
    if (token.isEmpty()) {
        return false;
    }

    QMutexLocker locker(&m_mutex);
    
    // Сначала проверяем память
    if (m_sessions.contains(token)) {
    const Session &session = m_sessions[token];
    
    // Проверяем истечение сессии
    if (isSessionExpired(session)) {
        // Удаляем истекшую сессию
        const_cast<SessionManager*>(this)->m_sessions.remove(token);
            if (m_dbInitialized) {
                const_cast<SessionManager*>(this)->deleteSessionFromDb(token);
            }
        return false;
    }
    
    return true;
    }
    
    // Если сессии нет в памяти, проверяем БД (для синхронизации между экземплярами)
    if (m_dbInitialized) {
        QSqlDatabase *db = getDbConnection();
        if (db && db->isOpen()) {
            {
                QSqlQuery query(*db);
                query.prepare("SELECT user_id, user_email, created_at, expires_at FROM sessions WHERE token = ? AND expires_at > ?");
                query.addBindValue(token);
                query.addBindValue(QDateTime::currentDateTime().toSecsSinceEpoch());
                
                if (query.exec() && query.next()) {
                    // Сессия существует в БД, загружаем её в память
                    Session session;
                    session.userId = query.value("user_id").toInt();
                    session.userEmail = query.value("user_email").toString();
                    session.createdAt = QDateTime::fromSecsSinceEpoch(query.value("created_at").toLongLong());
                    session.expiresAt = QDateTime::fromSecsSinceEpoch(query.value("expires_at").toLongLong());
                    
                    if (!isSessionExpired(session)) {
                        const_cast<SessionManager*>(this)->m_sessions[token] = session;
                        query.finish(); // Явно завершаем запрос
                        // query уничтожится при выходе из блока
                        closeDbConnection(db);
                        return true;
                    }
                }
                query.finish(); // Явно завершаем запрос
                // query уничтожится при выходе из блока
            }
            
            closeDbConnection(db);
        }
    }
    
    return false;
}

int SessionManager::getUserIdFromToken(const QString &token) const
{
    if (token.isEmpty() || !isValidSession(token)) {
        return -1;
    }

    QMutexLocker locker(&m_mutex);
    
    if (m_sessions.contains(token)) {
        return m_sessions[token].userId;
    }
    
    return -1;
}

QString SessionManager::getUserEmailFromToken(const QString &token) const
{
    if (token.isEmpty() || !isValidSession(token)) {
        return QString();
    }

    QMutexLocker locker(&m_mutex);
    
    if (m_sessions.contains(token)) {
        return m_sessions[token].userEmail;
    }
    
    return QString();
}

void SessionManager::removeSession(const QString &token)
{
    if (token.isEmpty()) {
        return;
    }

    QMutexLocker locker(&m_mutex);
    
    if (m_sessions.remove(token) > 0) {
        // Удаляем сессию из БД, если БД инициализирована
        if (m_dbInitialized) {
            deleteSessionFromDb(token);
        }
        qDebug() << "SessionManager: Removed session:" << token.left(16) << "...";
    }
}

void SessionManager::cleanupExpiredSessions()
{
    QMutexLocker locker(&m_mutex);
    
    QList<QString> expiredTokens;
    
    for (auto it = m_sessions.begin(); it != m_sessions.end(); ++it) {
        if (isSessionExpired(it.value())) {
            expiredTokens.append(it.key());
        }
    }
    
    for (const QString &token : expiredTokens) {
        m_sessions.remove(token);
    }
    
    // Удаляем истекшие сессии из БД, если БД инициализирована
    if (m_dbInitialized && !expiredTokens.isEmpty()) {
        deleteExpiredSessionsFromDb();
    }
    
    if (!expiredTokens.isEmpty()) {
        qDebug() << "SessionManager: Cleaned up" << expiredTokens.size() << "expired sessions";
    }
}

void SessionManager::removeUserSessions(int userId)
{
    if (userId <= 0) {
        return;
    }

    QMutexLocker locker(&m_mutex);
    
    QList<QString> tokensToRemove;
    
    for (auto it = m_sessions.begin(); it != m_sessions.end(); ++it) {
        if (it.value().userId == userId) {
            tokensToRemove.append(it.key());
        }
    }
    
    for (const QString &token : tokensToRemove) {
        m_sessions.remove(token);
    }
    
    // Удаляем сессии пользователя из БД, если БД инициализирована
    if (m_dbInitialized && !tokensToRemove.isEmpty()) {
        deleteUserSessionsFromDb(userId);
    }
    
    if (!tokensToRemove.isEmpty()) {
        qDebug() << "SessionManager: Removed" << tokensToRemove.size() << "sessions for user" << userId;
    }
}

QString SessionManager::generateToken() const
{
    // Генерируем случайный токен на основе текущего времени и случайных данных
    QByteArray randomData;
    randomData.resize(32);
    
    for (int i = 0; i < 32; ++i) {
        randomData[i] = static_cast<char>(QRandomGenerator::global()->bounded(256));
    }
    
    // Добавляем текущее время для уникальности
    QByteArray timeData = QByteArray::number(QDateTime::currentMSecsSinceEpoch());
    
    // Создаем хеш
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(randomData);
    hash.addData(timeData);
    
    // Конвертируем в Base64 для передачи в HTTP заголовках
    QString token = hash.result().toBase64();
    
    // Убираем символы, которые могут быть проблематичными в URL/заголовках
    token.replace("+", "-");
    token.replace("/", "_");
    token.replace("=", "");
    
    return token;
}

bool SessionManager::isSessionExpired(const Session &session) const
{
    return QDateTime::currentDateTime() >= session.expiresAt;
}

bool SessionManager::initialize(const QString &rootDir)
{
    QMutexLocker locker(&m_mutex);
    
    if (rootDir.isEmpty()) {
        qWarning() << "SessionManager: Root directory is empty";
        return false;
    }
    
    m_rootDir = rootDir;
    
    // Создаем таблицу sessions в БД
    if (!ensureSessionsTable()) {
        qWarning() << "SessionManager: Failed to create sessions table";
        return false;
    }
    
    // Загружаем сессии из БД
    if (!loadSessionsFromDb()) {
        qWarning() << "SessionManager: Failed to load sessions from database";
        // Не считаем это критической ошибкой - продолжаем работу с пустыми сессиями
    }
    
    m_dbInitialized = true;
    qDebug() << "SessionManager: Initialized with database support, loaded" << m_sessions.size() << "sessions";
    
    return true;
}

bool SessionManager::ensureSessionsTable()
{
    QSqlDatabase *db = getDbConnection();
    if (!db || !db->isOpen()) {
        return false;
    }
    
    bool success = true;
    {
        QSqlQuery query(*db);
        QString createTable = R"(
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                user_email TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        )";
        
        if (!query.exec(createTable)) {
            qWarning() << "SessionManager: Failed to create sessions table:" << query.lastError().text();
            success = false;
        }
        
        // Создаем индекс для быстрого поиска по user_id
        QString createIndex = "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)";
        if (!query.exec(createIndex)) {
            qWarning() << "SessionManager: Failed to create index on sessions:" << query.lastError().text();
        }
        
        // Создаем индекс для быстрого поиска по expires_at (для очистки истекших сессий)
        QString createExpiresIndex = "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)";
        if (!query.exec(createExpiresIndex)) {
            qWarning() << "SessionManager: Failed to create expires_at index:" << query.lastError().text();
        }
        query.finish(); // Явно завершаем запрос
        // query уничтожится при выходе из блока
    }
    
    // Закрываем соединение
    closeDbConnection(db);
    
    return success;
}

bool SessionManager::saveSessionToDb(const QString &token, const Session &session)
{
    QSqlDatabase *db = getDbConnection();
    if (!db || !db->isOpen()) {
        return false;
    }
    
    bool success = false;
    {
        QSqlQuery query(*db);
        query.prepare("INSERT OR REPLACE INTO sessions (token, user_id, user_email, created_at, expires_at) VALUES (?, ?, ?, ?, ?)");
        query.addBindValue(token);
        query.addBindValue(session.userId);
        query.addBindValue(session.userEmail);
        query.addBindValue(session.createdAt.toSecsSinceEpoch());
        query.addBindValue(session.expiresAt.toSecsSinceEpoch());
        
        success = query.exec();
        if (!success) {
            qWarning() << "SessionManager: Failed to save session to database:" << query.lastError().text();
        }
        query.finish(); // Явно завершаем запрос
        // query уничтожится при выходе из блока
    }
    
    // Закрываем соединение
    closeDbConnection(db);
    
    return success;
}

bool SessionManager::loadSessionsFromDb()
{
    QSqlDatabase *db = getDbConnection();
    if (!db || !db->isOpen()) {
        return false;
    }
    
    int loadedCount = 0;
    QList<QString> expiredTokens;
    
    {
        QSqlQuery query(*db);
        query.prepare("SELECT token, user_id, user_email, created_at, expires_at FROM sessions WHERE expires_at > ?");
        query.addBindValue(QDateTime::currentDateTime().toSecsSinceEpoch());
        
        if (!query.exec()) {
            qWarning() << "SessionManager: Failed to load sessions from database:" << query.lastError().text();
            query.finish(); // Явно завершаем запрос
            closeDbConnection(db);
            return false;
        }
        
        while (query.next()) {
            QString token = query.value(0).toString();
            int userId = query.value(1).toInt();
            QString userEmail = query.value(2).toString();
            qint64 createdAtSecs = query.value(3).toLongLong();
            qint64 expiresAtSecs = query.value(4).toLongLong();
            
            Session session;
            session.userId = userId;
            session.userEmail = userEmail;
            session.createdAt = QDateTime::fromSecsSinceEpoch(createdAtSecs);
            session.expiresAt = QDateTime::fromSecsSinceEpoch(expiresAtSecs);
            
            // Проверяем, не истекла ли сессия (на случай, если время изменилось)
            if (!isSessionExpired(session)) {
                m_sessions[token] = session;
                loadedCount++;
            } else {
                // Сохраняем токены истекших сессий для удаления
                expiredTokens.append(token);
            }
        }
        query.finish(); // Явно завершаем запрос
        // query уничтожится при выходе из блока
    }
    
    // Удаляем истекшие сессии в отдельном блоке
    if (!expiredTokens.isEmpty()) {
        {
            QSqlQuery deleteQuery(*db);
            deleteQuery.prepare("DELETE FROM sessions WHERE token = ?");
            for (const QString &token : expiredTokens) {
                deleteQuery.addBindValue(token);
                deleteQuery.exec();
                deleteQuery.finish(); // Завершаем запрос перед следующим
            }
            // deleteQuery уничтожится при выходе из блока
        }
    }
    
    // Закрываем соединение
    closeDbConnection(db);
    
    qDebug() << "SessionManager: Loaded" << loadedCount << "active sessions from database";
    return true;
}

bool SessionManager::deleteSessionFromDb(const QString &token)
{
    QSqlDatabase *db = getDbConnection();
    if (!db || !db->isOpen()) {
        return false;
    }
    
    bool success = false;
    {
        QSqlQuery query(*db);
        query.prepare("DELETE FROM sessions WHERE token = ?");
        query.addBindValue(token);
        
        success = query.exec();
        if (!success) {
            qWarning() << "SessionManager: Failed to delete session from database:" << query.lastError().text();
        }
        query.finish(); // Явно завершаем запрос
        // query уничтожится при выходе из блока
    }
    
    // Закрываем соединение
    closeDbConnection(db);
    
    return success;
}

bool SessionManager::deleteExpiredSessionsFromDb()
{
    QSqlDatabase *db = getDbConnection();
    if (!db || !db->isOpen()) {
        return false;
    }
    
    bool success = false;
    {
        QSqlQuery query(*db);
        query.prepare("DELETE FROM sessions WHERE expires_at <= ?");
        query.addBindValue(QDateTime::currentDateTime().toSecsSinceEpoch());
        
        success = query.exec();
        if (!success) {
            qWarning() << "SessionManager: Failed to delete expired sessions from database:" << query.lastError().text();
        }
        query.finish(); // Явно завершаем запрос
        // query уничтожится при выходе из блока
    }
    
    // Закрываем соединение
    closeDbConnection(db);
    
    return success;
}

bool SessionManager::deleteUserSessionsFromDb(int userId)
{
    QSqlDatabase *db = getDbConnection();
    if (!db || !db->isOpen()) {
        return false;
    }
    
    bool success = false;
    {
        QSqlQuery query(*db);
        query.prepare("DELETE FROM sessions WHERE user_id = ?");
        query.addBindValue(userId);
        
        success = query.exec();
        if (!success) {
            qWarning() << "SessionManager: Failed to delete user sessions from database:" << query.lastError().text();
        }
        query.finish(); // Явно завершаем запрос
        // query уничтожится при выходе из блока
    }
    
    // Закрываем соединение
    closeDbConnection(db);
    
    return success;
}

void SessionManager::closeDbConnection(QSqlDatabase *db) const
{
    if (!db) {
        return;
    }
    
    const QString connectionName = db->connectionName();
    
    // Закрываем соединение
    db->close();
    
    for (int i = 0; i < 5; ++i) {
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    }

    delete db;
    db = nullptr;
    
    for (int i = 0; i < 3; ++i) {
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    }

    if (QSqlDatabase::contains(connectionName)) {
        QSqlDatabase::removeDatabase(connectionName);
    }
}

QSqlDatabase* SessionManager::getDbConnection() const
{
    static int connectionCounter = 0;
    QString connectionName = QString("session_db_%1").arg(++connectionCounter);
    
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", connectionName);
    QDir rootDirObj(m_rootDir);
    QString dbPath = rootDirObj.absoluteFilePath("databases/3fa_users.db");
    db.setDatabaseName(dbPath);
    
    if (!db.open()) {
        qWarning() << "SessionManager: Failed to open database:" << db.lastError().text();
        QSqlDatabase::removeDatabase(connectionName);
        return nullptr;
    }
    
    QSqlDatabase* dbPtr = new QSqlDatabase(QSqlDatabase::database(connectionName));
    return dbPtr;
}
