#ifndef SESSIONMANAGER_H
#define SESSIONMANAGER_H

#include <QString>
#include <QDateTime>
#include <QMap>
#include <QMutex>
#include <QObject>

class QSqlDatabase;

/**
 * @brief SessionManager - управление сессиями пользователей
 * 
 * Создает и управляет JWT-подобными токенами для аутентификации
 * пользователей в HTTP запросах.
 */
class SessionManager : public QObject
{
    Q_OBJECT

public:
    explicit SessionManager(QObject *parent = nullptr);
    ~SessionManager();

    /**
     * @brief Создает новую сессию для пользователя
     * @param userId ID пользователя
     * @param userEmail Email пользователя
     * @return Токен сессии
     */
    QString createSession(int userId, const QString &userEmail);

    /**
     * @brief Проверяет валидность токена сессии
     * @param token Токен сессии
     * @return true если токен валиден, false иначе
     */
    bool isValidSession(const QString &token) const;

    /**
     * @brief Получает ID пользователя из токена
     * @param token Токен сессии
     * @return ID пользователя или -1 если токен невалиден
     */
    int getUserIdFromToken(const QString &token) const;

    /**
     * @brief Получает email пользователя из токена
     * @param token Токен сессии
     * @return Email пользователя или пустую строку если токен невалиден
     */
    QString getUserEmailFromToken(const QString &token) const;

    /**
     * @brief Удаляет сессию
     * @param token Токен сессии
     */
    void removeSession(const QString &token);

    /**
     * @brief Очищает истекшие сессии
     */
    void cleanupExpiredSessions();

    /**
     * @brief Удаляет все сессии пользователя
     * @param userId ID пользователя
     */
    void removeUserSessions(int userId);

    /**
     * @brief Инициализирует SessionManager с путем к корневой директории для работы с БД
     * @param rootDir Путь к корневой директории проекта
     * @return true если инициализация успешна, false иначе
     */
    bool initialize(const QString &rootDir);

private:
    struct Session {
        int userId;
        QString userEmail;
        QDateTime createdAt;
        QDateTime expiresAt;
    };

    mutable QMutex m_mutex;
    QMap<QString, Session> m_sessions;
    QString m_rootDir;
    bool m_dbInitialized;
    
    // Время жизни сессии (в секундах) - 24 часа
    static const int SESSION_DURATION_SECONDS = 86400;
    
    // Генерация токена
    QString generateToken() const;
    
    // Проверка истечения сессии
    bool isSessionExpired(const Session &session) const;
    
    // Методы для работы с БД
    bool ensureSessionsTable();
    bool saveSessionToDb(const QString &token, const Session &session);
    bool loadSessionsFromDb();
    bool deleteSessionFromDb(const QString &token);
    bool deleteExpiredSessionsFromDb();
    bool deleteUserSessionsFromDb(int userId);
    QSqlDatabase* getDbConnection() const;
    void closeDbConnection(QSqlDatabase *db) const;
};

#endif // SESSIONMANAGER_H


