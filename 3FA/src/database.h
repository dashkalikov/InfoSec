#ifndef DATABASE_H
#define DATABASE_H

#include <QObject>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QString>
#include <QByteArray>
#include <QList>
#include <QMap>
#include <QVariant>
#include <QDir>
#include <optional>
#include "user.h"

/**
 * @brief Класс Database управляет подключением к SQLite базе данных
 * 
 * Обеспечивает создание таблиц, выполнение SQL запросов
 * и управление подключением к базе данных.
 */
class Database : public QObject
{
    Q_OBJECT

public:
    explicit Database(QObject *parent = nullptr);
    ~Database();
    
    // Управление подключением
    // SQLite использует только путь к файлу базы данных
    bool connect(const QString &databasePath = "databases/3fa_users.db");
    void disconnect();
    bool isConnected() const;
    // Переподключение к базе данных
    bool reconnect();
    // Проверка состояния соединения
    bool healthCheck();
    
    // Инициализация схемы базы данных
    bool initializeTables();
    
    // Операции с пользователями
    bool createUser(const User &user);
    User findUserByEmail(const QString &email);
    bool updateUser(const User &user);
    bool updateUserTOTPSecret(const QString &email, const QString &totpSecret);
    bool deleteUser(int userId);
    bool deleteUserPermanently(int userId);
    bool userExists(const QString &email);
    // Обновление роли пользователя
    bool updateUserRole(const QString &email, const QString &role);
    // Блокировка/разблокировка пользователя
    bool setUserBlocked(const QString &email, bool blocked);
    
    // Методы для защиты от brute-force
    bool incrementFailedAttempts(const QString &email);
    bool resetFailedAttempts(const QString &email);
    bool setLockoutUntil(const QString &email, const QDateTime &lockoutUntil);
    bool isLockedOut(const QString &email, QDateTime &lockoutUntil);
    bool logFailedLogin(const QString &email, const QString &reason);
    bool logSuccessfulRegistration(const QString &email);

    // Операции с face embeddings
    std::optional<bool> hasUserFaceEmbedding(int userId);
    QByteArray getUserFaceEmbedding(int userId);
    bool saveUserFaceEmbedding(int userId, const QByteArray &embedding);
    
    // Операции с PDF документами
    bool saveUserPdf(int userId, const QByteArray &pdfData, const QString &filename, const QString &algorithm = QString(), const QString &operation = QString());
    QList<QMap<QString, QVariant>> getUserPdfs(int userId);
    QByteArray getUserPdfById(int userId, int pdfId);
    
    // Методы для администратора
    QList<User> getAllUsers();
    QList<QMap<QString, QVariant>> getAllUserPdfs();
    QByteArray getPdfByIdForAdmin(int pdfId);
    
    // Утилиты
    QString getLastError() const;
    void clearError();
    
    // Публичные методы для выполнения SQL запросов
    // exec - выполняет запрос с параметрами, возвращает true при успехе (для INSERT/UPDATE/DELETE)
    bool exec(const QString &query, const QVariantList &params = QVariantList());
    // select - выполняет SELECT запрос с параметрами, возвращает выполненный QSqlQuery (готов к использованию)
    QSqlQuery select(const QString &query, const QVariantList &params = QVariantList());
    
    // Транзакции
    // beginTransaction - начинает транзакцию
    bool beginTransaction();
    // commit - подтверждает транзакцию
    bool commit();
    // rollback - откатывает транзакцию
    bool rollback();
    // execInTransaction - выполняет запрос в транзакции с автоматическим откатом при ошибке
    bool execInTransaction(const QString &query, const QVariantList &params = QVariantList());

signals:
    void errorOccurred(const QString &error);

private:
    QSqlDatabase m_database;
    QString m_lastError;
    QString m_databasePath; // Сохраняем путь для переподключения

    bool ensureFaceEmbeddingTable();
    bool ensurePdfDocumentsTable();
    bool ensureMasterKeyTable();
    bool ensureUsersRoleColumn();
    bool ensureBruteForceProtectionColumns();
    bool ensureAuditLogTable();
    
    // Методы для работы с мастер-ключом шифрования
    QByteArray getOrCreateMasterKey();
    
    // Методы шифрования/дешифрования PDF
    bool encryptPdfData(const QByteArray &plaintext, QByteArray &ciphertext, QByteArray &iv, QByteArray &tag);
    bool decryptPdfData(const QByteArray &ciphertext, const QByteArray &iv, const QByteArray &tag, QByteArray &plaintext);
    
    bool executeQuery(const QString &query, const QVariantList &params = QVariantList());
    QSqlQuery prepareQuery(const QString &query);
};

#endif // DATABASE_H
