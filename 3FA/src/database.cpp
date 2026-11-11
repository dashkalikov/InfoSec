#include "database.h"
#include <QSqlRecord>
#include <QDebug>
#include <QDir>
#include <QStandardPaths>
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

Database::Database(QObject *parent)
    : QObject(parent)
{
}

Database::~Database()
{
    disconnect();
}

bool Database::connect(const QString &databasePath)
{
    // Проверяем доступность драйвера SQLite
    if (!QSqlDatabase::isDriverAvailable("QSQLITE")) {
        m_lastError = "Драйвер SQLite (QSQLITE) недоступен. Убедитесь, что Qt собран с поддержкой SQLite.";
        emit errorOccurred(m_lastError);
        qCritical() << m_lastError;
        return false;
    }
    
    // Используем SQLite драйвер
    m_database = QSqlDatabase::addDatabase("QSQLITE");
    
    // Определяем путь к базе данных так, чтобы использовать файл из папки databases в корне проекта
    QString dbPath = databasePath;
    if (QDir::isRelativePath(dbPath)) {
        QString appDir = QCoreApplication::applicationDirPath();
        QDir baseDir(appDir);
        // macOS bundle: <project>/build/3FA.app/Contents/MacOS
        if (appDir.contains("/Contents/MacOS")) {
            baseDir = QDir(baseDir.absoluteFilePath("../../../../")); // поднимаемся до корня проекта
        } else {
            // Обычный случай: бинарь в build/ → поднимаемся на один уровень к корню проекта, если виден CMakeLists.txt
            QDir tryBuildParent(baseDir.absoluteFilePath(".."));
            if (tryBuildParent.exists("CMakeLists.txt")) {
                baseDir = tryBuildParent;
            }
        }
        dbPath = baseDir.absoluteFilePath(databasePath);
    }
    
    m_database.setDatabaseName(dbPath);
    m_databasePath = dbPath; // Сохраняем путь для переподключения
    
    qDebug() << "Подключение к SQLite:";
    qDebug() << "  Database:" << dbPath;
    
    if (!m_database.open()) {
        m_lastError = QString("Не удалось подключиться к SQLite: %1").arg(m_database.lastError().text());
        emit errorOccurred(m_lastError);
        return false;
    }
    
    qDebug() << "База данных SQLite подключена успешно";
    return initializeTables();
}

void Database::disconnect()
{
    if (m_database.isOpen()) {
        m_database.close();
        qDebug() << "База данных отключена";
    }
}

bool Database::isConnected() const
{
    return m_database.isOpen();
}

bool Database::reconnect()
{
    disconnect();
    if (m_databasePath.isEmpty()) {
        m_lastError = "Путь к базе данных не сохранен. Используйте connect() для первоначального подключения.";
        emit errorOccurred(m_lastError);
        return false;
    }
    return connect(m_databasePath);
}

bool Database::healthCheck()
{
    if (!isConnected()) {
        return false;
    }
    
    // Выполняем простой запрос для проверки соединения (без использования select(), чтобы избежать рекурсии)
    QSqlQuery query(m_database);
    if (!query.exec("SELECT 1")) {
        return false;
    }
    return query.next();
}

bool Database::initializeTables()
{
    // Создаем таблицу пользователей (SQLite синтаксис)
    QString createUsersTable = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    )";
    
    if (!exec(createUsersTable)) {
        return false;
    }

    // Создаем индекс для быстрого поиска по email
    QString createIndex = "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)";
    if (!exec(createIndex)) {
        return false;
    }

    // Создаем индекс для быстрого поиска по is_active (для фильтрации активных пользователей)
    QString createActiveIndex = "CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active)";
    if (!exec(createActiveIndex)) {
        qDebug() << "Не удалось создать индекс для is_active:" << m_lastError;
    }

    // Создаем составной индекс для оптимизации запросов с фильтрацией по is_active и сортировкой по created_at
    // SQLite поддерживает DESC в индексах, но для совместимости можно использовать без DESC
    QString createCompositeIndex = "CREATE INDEX IF NOT EXISTS idx_users_active_created ON users(is_active, created_at)";
    if (!exec(createCompositeIndex)) {
        qDebug() << "Не удалось создать составной индекс:" << m_lastError;
    }

    // Миграция: добавляем поле role, если его нет
    ensureUsersRoleColumn();
    
    // Миграция: добавляем поля для защиты от brute-force
    ensureBruteForceProtectionColumns();
    
    // Создаем таблицу audit_log для записи событий безопасности
    if (!ensureAuditLogTable()) {
        return false;
    }

    if (!ensureFaceEmbeddingTable()) {
        return false;
    }

    if (!ensurePdfDocumentsTable()) {
        return false;
    }

    if (!ensureMasterKeyTable()) {
        return false;
    }

    const auto protectLastAdminUpdate = R"(
        CREATE TRIGGER IF NOT EXISTS protect_last_active_admin_update
        BEFORE UPDATE OF role, is_active ON users
        WHEN OLD.role = 'admin' AND OLD.is_active = 1
            AND (NEW.role IS NOT 'admin' OR NEW.is_active IS NOT 1)
            AND NOT EXISTS (SELECT 1 FROM users WHERE role = 'admin' AND is_active = 1 AND id <> OLD.id)
        BEGIN
            SELECT RAISE(ABORT, 'Нельзя изменить роль или заблокировать последнего активного администратора');
        END
    )";
    const auto protectLastAdminDelete = R"(
        CREATE TRIGGER IF NOT EXISTS protect_last_active_admin_delete
        BEFORE DELETE ON users
        WHEN OLD.role = 'admin' AND OLD.is_active = 1
            AND NOT EXISTS (SELECT 1 FROM users WHERE role = 'admin' AND is_active = 1 AND id <> OLD.id)
        BEGIN
            SELECT RAISE(ABORT, 'Нельзя удалить последнего активного администратора');
        END
    )";
    if (!exec(protectLastAdminUpdate) || !exec(protectLastAdminDelete)) return false;

    qDebug() << "Таблицы базы данных инициализированы";
    return true;
}

bool Database::createUser(const User &user)
{
    if (!user.isValid()) {
        m_lastError = "Некорректные данные пользователя";
        emit errorOccurred(m_lastError);
        return false;
    }
    
    QString query = R"(
        INSERT INTO users (email, password_hash, totp_secret, created_at, is_active, role)
        VALUES (?, ?, ?, ?, ?, ?)
    )";
    
    QVariantList params;
    params << user.getEmail() 
           << user.getPasswordHash()
           << user.getTOTPSecret()
           << user.getCreatedAt()
           << user.isActive()
           << (user.getRole().isEmpty() ? "user" : user.getRole());
    
    if (!exec(query, params)) {
        return false;
    }
    
    qDebug() << "Пользователь создан:" << user.getEmail();
    return true;
}

User Database::findUserByEmail(const QString &email)
{
    User user;
    
    qDebug() << "Database::findUserByEmail - поиск email:" << email;
    
    QVariantList params;
    params << email;
    // Убираем фильтр is_active = 1, чтобы находить всех пользователей (включая заблокированных)
    // Проверка блокировки будет в AuthService::loginUser
    QSqlQuery sqlQuery = select("SELECT * FROM users WHERE email = ?", params);
    
    if (sqlQuery.next()) {
        QSqlRecord record = sqlQuery.record();
        user.setId(record.value("id").toInt());
        user.setEmail(record.value("email").toString());
        user.setPasswordHash(record.value("password_hash").toString());
        user.setTOTPSecret(record.value("totp_secret").toString());
        user.setCreatedAt(record.value("created_at").toDateTime());
        user.setActive(record.value("is_active").toBool());
        // Проверяем наличие колонки role
        if (record.indexOf("role") >= 0) {
            QString role = record.value("role").toString();
            user.setRole(role.isEmpty() ? "user" : role); // Если роль пустая, устанавливаем "user"
            qDebug() << "Пользователь найден:" << user.getEmail() << "Роль:" << user.getRole() << "Активен:" << user.isActive();
        } else {
            user.setRole("user"); // По умолчанию
            qDebug() << "Пользователь найден:" << user.getEmail() << "Роль: user (по умолчанию, колонка role не найдена)" << "Активен:" << user.isActive();
        }
    } else {
        qDebug() << "Пользователь НЕ найден в базе данных";
    }
    
    return user;
}

bool Database::updateUser(const User &user)
{
    QString query = R"(
        UPDATE users 
        SET email = ?, password_hash = ?, is_active = ?
        WHERE id = ?
    )";
    
    QVariantList params;
    params << user.getEmail()
           << user.getPasswordHash()
           << user.isActive()
           << user.getId();
    
    return exec(query, params);
}

bool Database::updateUserTOTPSecret(const QString &email, const QString &totpSecret)
{
    QString query = "UPDATE users SET totp_secret = ? WHERE email = ? AND is_active = 1";
    
    QVariantList params;
    params << totpSecret << email;
    
    if (!exec(query, params)) {
        return false;
    }
    
    qDebug() << "TOTP секрет обновлен для пользователя:" << email;
    return true;
}

bool Database::ensureFaceEmbeddingTable()
{
    QString createTable = R"(
        CREATE TABLE IF NOT EXISTS user_face_embeddings (
            user_id INTEGER PRIMARY KEY,
            embedding BLOB NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    )";

    if (!exec(createTable)) {
        return false;
    }

    // SQLite синтаксис для триггера
    QString createTrigger = R"(
        CREATE TRIGGER IF NOT EXISTS trg_user_face_embeddings_updated
        AFTER UPDATE ON user_face_embeddings
        BEGIN
            UPDATE user_face_embeddings SET updated_at = CURRENT_TIMESTAMP WHERE user_id = NEW.user_id;
        END;
    )";

    if (!exec(createTrigger)) {
        qDebug() << "Не удалось создать триггер обновления user_face_embeddings:" << m_lastError;
    }

    return true;
}

std::optional<bool> Database::hasUserFaceEmbedding(int userId)
{
    auto query = select("SELECT EXISTS (SELECT 1 FROM user_face_embeddings WHERE user_id = ?)", {userId});
    if (!query.next()) {
        return std::nullopt;
    }
    return query.value(0).toBool();
}

QByteArray Database::getUserFaceEmbedding(int userId)
{
    QByteArray embedding;
    QVariantList params;
    params << userId;
    QSqlQuery query = select("SELECT embedding FROM user_face_embeddings WHERE user_id = ?", params);

    if (query.next()) {
        embedding = query.value(0).toByteArray();
    }

    return embedding;
}

bool Database::saveUserFaceEmbedding(int userId, const QByteArray &embedding)
{
    if (embedding.isEmpty() || (!healthCheck() && !reconnect())) {
        return false;
    }
    // Регистрация лица создаёт образец только один раз и только для активного аккаунта.
    auto query = prepareQuery(R"(
        INSERT INTO user_face_embeddings(user_id, embedding)
        SELECT id, ? FROM users WHERE id = ? AND is_active = 1
        ON CONFLICT (user_id) DO NOTHING
    )");
    query.addBindValue(embedding);
    query.addBindValue(userId);
    if (!query.exec()) {
        m_lastError = query.lastError().text();
        emit errorOccurred(m_lastError);
        return false;
    }
    return query.numRowsAffected() == 1;
}

bool Database::deleteUser(int userId)
{
    QString query = "UPDATE users SET is_active = 0 WHERE id = ?";
    QVariantList params;
    params << userId;
    
    return exec(query, params);
}

bool Database::deleteUserPermanently(int userId)
{
    if (userId <= 0) {
        m_lastError = "Некорректный ID пользователя";
        emit errorOccurred(m_lastError);
        return false;
    }
    
    // Начинаем транзакцию для атомарности операции
    if (!beginTransaction()) {
        m_lastError = "Не удалось начать транзакцию";
        emit errorOccurred(m_lastError);
        return false;
    }
    
    QSqlQuery user = select("SELECT email FROM users WHERE id = ?", {userId});
    if (!user.next()) {
        user.finish();
        rollback();
        m_lastError = "Пользователь не найден";
        return false;
    }
    const auto email = user.value(0).toString();
    user.finish();

    auto sessions = select("SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sessions')");
    if (!sessions.next()) {
        sessions.finish();
        rollback();
        return false;
    }
    const bool hasSessions = sessions.value(0).toBool();
    sessions.finish();

    if ((hasSessions && !exec("DELETE FROM sessions WHERE user_id = ?", {userId})) ||
        !exec("DELETE FROM user_face_embeddings WHERE user_id = ?", {userId}) ||
        !exec("DELETE FROM user_pdf_documents WHERE user_id = ?", {userId}) ||
        !exec("DELETE FROM audit_log WHERE user_email = ?", {email}) ||
        !exec("DELETE FROM users WHERE id = ?", {userId}) || !commit()) {
        rollback();
        return false;
    }
    return true;
}

bool Database::updateUserRole(const QString &email, const QString &role)
{
    if (email.isEmpty()) {
        m_lastError = "Email не может быть пустым";
        emit errorOccurred(m_lastError);
        return false;
    }
    
    QString query = "UPDATE users SET role = ? WHERE email = ?";
    QVariantList params;
    params << role << email;
    
    if (!exec(query, params)) {
        return false;
    }

    // Убрано логирование - слишком много сообщений при частых изменениях
    // qDebug() << "Роль пользователя обновлена:" << email << "->" << role;
    return true;
}

bool Database::setUserBlocked(const QString &email, bool blocked)
{
    if (email.isEmpty()) {
        m_lastError = "Email не может быть пустым";
        emit errorOccurred(m_lastError);
        return false;
    }
    
    QString query = "UPDATE users SET is_active = ? WHERE email = ?";
    QVariantList params;
    params << (!blocked) << email; // is_active = 1 если не заблокирован, 0 если заблокирован
    
    if (!exec(query, params)) {
        return false;
    }

    // Убрано логирование - слишком много сообщений при частых изменениях
    // qDebug() << "Статус блокировки пользователя обновлен:" << email << "->" << (blocked ? "заблокирован" : "разблокирован");
    return true;
}

bool Database::userExists(const QString &email)
{
    QVariantList params;
    params << email;
    QSqlQuery sqlQuery = select("SELECT COUNT(*) FROM users WHERE email = ?", params);
    
    if (sqlQuery.next()) {
        return sqlQuery.value(0).toInt() > 0;
    }
    
    return false;
}

bool Database::ensurePdfDocumentsTable()
{
    // Проверяем, существует ли таблица и какие столбцы в ней есть
    QSqlQuery checkQuery = select("SELECT name FROM sqlite_master WHERE type='table' AND name='user_pdf_documents'");
    bool tableExists = false;
    bool hasEncryption = false;
    
    if (checkQuery.next()) {
        tableExists = true;
        // Проверяем, есть ли столбцы для шифрования
        QSqlQuery columnsQuery = select("PRAGMA table_info(user_pdf_documents)");
        while (columnsQuery.next()) {
            QString columnName = columnsQuery.value("name").toString();
            if (columnName == "encrypted_data" || columnName == "iv" || columnName == "tag") {
                hasEncryption = true;
                break;
            }
        }
    }
    
    // Если таблица существует, но без шифрования, мигрируем её
    if (tableExists && !hasEncryption) {
        qDebug() << "Миграция таблицы user_pdf_documents для поддержки шифрования";
        
        // Создаем временную таблицу с новой структурой
        QString createTempTable = R"(
            CREATE TABLE IF NOT EXISTS user_pdf_documents_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                encrypted_data BLOB NOT NULL,
                iv BLOB NOT NULL,
                tag BLOB NOT NULL,
                algorithm TEXT,
                operation TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        )";
        
        if (!exec(createTempTable)) {
            qWarning() << "Не удалось создать новую таблицу для миграции";
            return false;
        }
        
        // Переименовываем старую таблицу
        if (!exec("ALTER TABLE user_pdf_documents RENAME TO user_pdf_documents_old")) {
            qWarning() << "Не удалось переименовать старую таблицу";
            return false;
        }
        
        // Переименовываем новую таблицу
        if (!exec("ALTER TABLE user_pdf_documents_new RENAME TO user_pdf_documents")) {
            qWarning() << "Не удалось переименовать новую таблицу";
            return false;
        }
        
        // Удаляем старую таблицу (данные будут потеряны, так как они не были зашифрованы)
        exec("DROP TABLE IF EXISTS user_pdf_documents_old");
        qDebug() << "Миграция таблицы завершена";
    } else if (!tableExists) {
        // Создаем новую таблицу с поддержкой шифрования
        QString createTable = R"(
            CREATE TABLE IF NOT EXISTS user_pdf_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                encrypted_data BLOB NOT NULL,
                iv BLOB NOT NULL,
                tag BLOB NOT NULL,
                algorithm TEXT,
                operation TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        )";

        if (!exec(createTable)) {
            return false;
        }
    }

    // Создаем индекс для быстрого поиска по user_id
    QString createIndex = "CREATE INDEX IF NOT EXISTS idx_user_pdf_documents_user_id ON user_pdf_documents(user_id)";
    if (!exec(createIndex)) {
        qDebug() << "Не удалось создать индекс для user_pdf_documents:" << m_lastError;
    }

    // Создаем индекс для сортировки по created_at
    QString createCreatedAtIndex = "CREATE INDEX IF NOT EXISTS idx_user_pdf_documents_created_at ON user_pdf_documents(created_at)";
    if (!exec(createCreatedAtIndex)) {
        qDebug() << "Не удалось создать индекс для created_at:" << m_lastError;
    }

    // Создаем составной индекс для оптимизации запросов с фильтрацией по user_id и сортировкой по created_at
    QString createCompositeIndex = "CREATE INDEX IF NOT EXISTS idx_user_pdf_documents_user_created ON user_pdf_documents(user_id, created_at)";
    if (!exec(createCompositeIndex)) {
        qDebug() << "Не удалось создать составной индекс:" << m_lastError;
    }

    return true;
}

bool Database::saveUserPdf(int userId, const QByteArray &pdfData, const QString &filename, const QString &algorithm, const QString &operation)
{
    if (userId < 0 || pdfData.isEmpty() || filename.isEmpty()) {
        m_lastError = "Некорректные данные PDF";
        emit errorOccurred(m_lastError);
        return false;
    }

    // Шифруем PDF данные перед сохранением
    QByteArray encryptedData, iv, tag;
    if (!encryptPdfData(pdfData, encryptedData, iv, tag)) {
        m_lastError = "Не удалось зашифровать PDF данные";
        emit errorOccurred(m_lastError);
        return false;
    }

    QString query = R"(
        INSERT INTO user_pdf_documents (user_id, filename, encrypted_data, iv, tag, algorithm, operation, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    )";

    // Сохраняем локальное время в формате строки для правильной работы с SQLite
    QString currentDateTime = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    QVariantList params;
    params << userId << filename << encryptedData << iv << tag << algorithm << operation << currentDateTime;

    if (!exec(query, params)) {
        return false;
    }

    qDebug() << "PDF зашифрован и сохранён в базу данных для пользователя ID:" << userId << "файл:" << filename;
    return true;
}

QList<QMap<QString, QVariant>> Database::getUserPdfs(int userId)
{
    QList<QMap<QString, QVariant>> result;

    if (userId < 0) {
        return result;
    }

    QVariantList params;
    params << userId;
    QSqlQuery sqlQuery = select("SELECT id, filename, algorithm, operation, created_at FROM user_pdf_documents WHERE user_id = ? ORDER BY created_at DESC", params);

    while (sqlQuery.next()) {
        QMap<QString, QVariant> pdfInfo;
        pdfInfo["id"] = sqlQuery.value("id").toInt();
        pdfInfo["filename"] = sqlQuery.value("filename").toString();
        pdfInfo["algorithm"] = sqlQuery.value("algorithm").toString();
        pdfInfo["operation"] = sqlQuery.value("operation").toString();
        pdfInfo["created_at"] = sqlQuery.value("created_at").toDateTime();
        result.append(pdfInfo);
    }

    return result;
}

QByteArray Database::getUserPdfById(int userId, int pdfId)
{
    QByteArray pdfData;

    if (userId < 0 || pdfId < 0) {
        return pdfData;
    }

    QVariantList params;
    params << pdfId << userId;
    QSqlQuery sqlQuery = select("SELECT encrypted_data, iv, tag FROM user_pdf_documents WHERE id = ? AND user_id = ?", params);

    if (sqlQuery.next()) {
        QByteArray encryptedData = sqlQuery.value("encrypted_data").toByteArray();
        QByteArray iv = sqlQuery.value("iv").toByteArray();
        QByteArray tag = sqlQuery.value("tag").toByteArray();
        
        // Расшифровываем PDF данные
        if (!decryptPdfData(encryptedData, iv, tag, pdfData)) {
            m_lastError = "Не удалось расшифровать PDF данные";
            emit errorOccurred(m_lastError);
            return QByteArray();
        }
    }

    return pdfData;
}

QList<User> Database::getAllUsers()
{
    QList<User> users;
    
    QSqlQuery sqlQuery = select("SELECT * FROM users WHERE is_active = 1 ORDER BY created_at DESC");
    
    while (sqlQuery.next()) {
        User user;
        QSqlRecord record = sqlQuery.record();
        user.setId(record.value("id").toInt());
        user.setEmail(record.value("email").toString());
        user.setPasswordHash(record.value("password_hash").toString());
        user.setTOTPSecret(record.value("totp_secret").toString());
        user.setCreatedAt(record.value("created_at").toDateTime());
        user.setActive(record.value("is_active").toBool());
        if (record.indexOf("role") >= 0) {
            user.setRole(record.value("role").toString());
        } else {
            user.setRole("user");
        }
        users.append(user);
    }
    
    return users;
}

QList<QMap<QString, QVariant>> Database::getAllUserPdfs()
{
    QList<QMap<QString, QVariant>> result;
    
    QString query = R"(
        SELECT 
            up.id,
            up.user_id,
            u.email as user_email,
            up.filename,
            up.algorithm,
            up.operation,
            up.created_at
        FROM user_pdf_documents up
        JOIN users u ON up.user_id = u.id
        WHERE u.is_active = 1
        ORDER BY up.created_at DESC
    )";
    
    QSqlQuery sqlQuery = select(query);
    
    while (sqlQuery.next()) {
        QMap<QString, QVariant> pdfInfo;
        pdfInfo["id"] = sqlQuery.value("id").toInt();
        pdfInfo["user_id"] = sqlQuery.value("user_id").toInt();
        pdfInfo["user_email"] = sqlQuery.value("user_email").toString();
        pdfInfo["filename"] = sqlQuery.value("filename").toString();
        pdfInfo["algorithm"] = sqlQuery.value("algorithm").toString();
        pdfInfo["operation"] = sqlQuery.value("operation").toString();
        pdfInfo["created_at"] = sqlQuery.value("created_at").toDateTime();
        result.append(pdfInfo);
    }
    
    return result;
}

QByteArray Database::getPdfByIdForAdmin(int pdfId)
{
    QByteArray pdfData;
    
    if (pdfId < 0) {
        return pdfData;
    }
    
    QVariantList params;
    params << pdfId;
    QSqlQuery sqlQuery = select("SELECT encrypted_data, iv, tag FROM user_pdf_documents WHERE id = ?", params);
    
    if (sqlQuery.next()) {
        QByteArray encryptedData = sqlQuery.value("encrypted_data").toByteArray();
        QByteArray iv = sqlQuery.value("iv").toByteArray();
        QByteArray tag = sqlQuery.value("tag").toByteArray();
        
        // Расшифровываем PDF данные
        if (!decryptPdfData(encryptedData, iv, tag, pdfData)) {
            m_lastError = "Не удалось расшифровать PDF данные";
            emit errorOccurred(m_lastError);
            return QByteArray();
        }
    }
    
    return pdfData;
}

QString Database::getLastError() const
{
    return m_lastError;
}

void Database::clearError()
{
    m_lastError.clear();
}

bool Database::executeQuery(const QString &query, const QVariantList &params)
{
    QSqlQuery sqlQuery = prepareQuery(query);
    
    // Привязываем параметры
    for (int i = 0; i < params.size(); ++i) {
        sqlQuery.bindValue(i, params[i]);
    }
    
    if (!sqlQuery.exec()) {
        m_lastError = sqlQuery.lastError().text();
        emit errorOccurred(m_lastError);
        return false;
    }
    
    return true;
}

QSqlQuery Database::prepareQuery(const QString &query)
{
    QSqlQuery sqlQuery(m_database);
    sqlQuery.prepare(query);
    return sqlQuery;
}

bool Database::exec(const QString &query, const QVariantList &params)
{
    // Автоматическая проверка соединения и переподключение при необходимости
    if (!healthCheck()) {
        if (!reconnect()) {
            return false;
        }
    }
    return executeQuery(query, params);
}

QSqlQuery Database::select(const QString &query, const QVariantList &params)
{
    // Автоматическая проверка соединения и переподключение при необходимости
    if (!healthCheck()) {
        if (!reconnect()) {
            return QSqlQuery(m_database); // Возвращаем пустой запрос при ошибке
        }
    }
    
    QSqlQuery sqlQuery = prepareQuery(query);
    
    // Привязываем параметры
    for (int i = 0; i < params.size(); ++i) {
        sqlQuery.bindValue(i, params[i]);
    }
    
    // Выполняем запрос
    if (!sqlQuery.exec()) {
        m_lastError = sqlQuery.lastError().text();
        emit errorOccurred(m_lastError);
        // Возвращаем пустой QSqlQuery при ошибке
        return QSqlQuery(m_database);
    }
    
    return sqlQuery;
}

bool Database::beginTransaction()
{
    if (!healthCheck()) {
        if (!reconnect()) {
            return false;
        }
    }
    
    QSqlQuery query(m_database);
    if (!query.exec("BEGIN TRANSACTION")) {
        m_lastError = QString("Не удалось начать транзакцию: %1").arg(query.lastError().text());
        emit errorOccurred(m_lastError);
        return false;
    }
    return true;
}

bool Database::commit()
{
    if (!isConnected()) {
        m_lastError = "Соединение с базой данных не установлено";
        emit errorOccurred(m_lastError);
        return false;
    }
    
    QSqlQuery query(m_database);
    if (!query.exec("COMMIT")) {
        m_lastError = QString("Не удалось подтвердить транзакцию: %1").arg(query.lastError().text());
        emit errorOccurred(m_lastError);
        return false;
    }
    return true;
}

bool Database::rollback()
{
    if (!isConnected()) {
        m_lastError = "Соединение с базой данных не установлено";
        emit errorOccurred(m_lastError);
        return false;
    }
    
    QSqlQuery query(m_database);
    if (!query.exec("ROLLBACK")) {
        m_lastError = QString("Не удалось откатить транзакцию: %1").arg(query.lastError().text());
        emit errorOccurred(m_lastError);
        return false;
    }
    return true;
}

bool Database::execInTransaction(const QString &query, const QVariantList &params)
{
    if (!beginTransaction()) {
        return false;
    }
    
    if (!exec(query, params)) {
        rollback(); // Автоматический откат при ошибке
        return false;
    }
    
    if (!commit()) {
        rollback(); // Откат, если commit не удался
        return false;
    }
    
    return true;
}

bool Database::ensureMasterKeyTable()
{
    QString createTable = R"(
        CREATE TABLE IF NOT EXISTS master_keys (
            id INTEGER PRIMARY KEY CHECK(id=1),
            master_key BLOB NOT NULL
        )
    )";

    if (!exec(createTable)) {
        return false;
    }

    return true;
}

bool Database::ensureUsersRoleColumn()
{
    // Проверяем, существует ли колонка role
    QSqlQuery query = select("PRAGMA table_info(users)");
    
    bool roleColumnExists = false;
    while (query.next()) {
        QString columnName = query.value("name").toString();
        if (columnName == "role") {
            roleColumnExists = true;
            break;
        }
    }
    
    // Если колонки нет, добавляем её
    if (!roleColumnExists) {
        QString addColumnQuery = "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'";
        if (!exec(addColumnQuery)) {
            qWarning() << "Не удалось добавить колонку role:" << m_lastError;
            return false;
        }
        qDebug() << "Колонка role добавлена в таблицу users";
        
        // Обновляем существующие записи, устанавливая role='user' для всех
        QString updateQuery = "UPDATE users SET role = 'user' WHERE role IS NULL OR role = ''";
        if (!exec(updateQuery)) {
            qWarning() << "Не удалось обновить существующие записи:" << m_lastError;
        }
    }
    
    return true;
}

QByteArray Database::getOrCreateMasterKey()
{
    // Пытаемся загрузить мастер-ключ из базы данных
    QSqlQuery query = select("SELECT master_key FROM master_keys WHERE id=1");
    
    if (query.next()) {
        QByteArray keyData = query.value("master_key").toByteArray();
        if (keyData.size() == 32) {
            return keyData;
        }
    }

    // Если ключа нет, генерируем новый
    QByteArray masterKey(32, 0);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(masterKey.data()), 32) != 1) {
        qCritical() << "Не удалось сгенерировать мастер-ключ";
        return QByteArray();
    }

    // Сохраняем ключ в базу данных
    QVariantList params;
    params << masterKey;
    
    if (!exec("INSERT OR REPLACE INTO master_keys(id, master_key) VALUES(1, ?)", params)) {
        qCritical() << "Не удалось сохранить мастер-ключ в базу данных:" << getLastError();
        return QByteArray();
    }

    qDebug() << "Мастер-ключ сгенерирован и сохранён";
    return masterKey;
}

bool Database::encryptPdfData(const QByteArray &plaintext, QByteArray &ciphertext, QByteArray &iv, QByteArray &tag)
{
    QByteArray masterKey = getOrCreateMasterKey();
    if (masterKey.isEmpty() || masterKey.size() != 32) {
        m_lastError = "Не удалось получить мастер-ключ";
        return false;
    }

    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        m_lastError = "Не удалось создать контекст шифрования";
        return false;
    }

    // Генерируем IV (12 байт для GCM)
    iv.resize(12);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), 12) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        m_lastError = "Не удалось сгенерировать IV";
        return false;
    }

    // Инициализируем шифрование
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, 
                           reinterpret_cast<const unsigned char*>(masterKey.data()), 
                           reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        m_lastError = "Не удалось инициализировать шифрование";
        return false;
    }

    // Шифруем данные
    ciphertext.resize(plaintext.size());
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()), &outlen,
                         reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        m_lastError = "Не удалось зашифровать данные";
        return false;
    }

    // Завершаем шифрование и получаем тег (16 байт для GCM)
    tag.resize(16);
    if (EVP_EncryptFinal_ex(ctx, nullptr, &outlen) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, reinterpret_cast<unsigned char*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        m_lastError = "Не удалось завершить шифрование";
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool Database::decryptPdfData(const QByteArray &ciphertext, const QByteArray &iv, const QByteArray &tag, QByteArray &plaintext)
{
    QByteArray masterKey = getOrCreateMasterKey();
    if (masterKey.isEmpty() || masterKey.size() != 32) {
        m_lastError = "Не удалось получить мастер-ключ";
        return false;
    }

    if (iv.size() != 12 || tag.size() != 16) {
        m_lastError = "Некорректный размер IV или тега";
        return false;
    }

    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        m_lastError = "Не удалось создать контекст расшифровки";
        return false;
    }

    // Инициализируем расшифровку
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr,
                           reinterpret_cast<const unsigned char*>(masterKey.data()),
                           reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        m_lastError = "Не удалось инициализировать расшифровку";
        return false;
    }

    // Расшифровываем данные
    plaintext.resize(ciphertext.size());
    int outlen = 0;
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &outlen,
                         reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        m_lastError = "Не удалось расшифровать данные";
        return false;
    }

    // Устанавливаем тег и проверяем аутентификацию
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tag.data()))) != 1 ||
        EVP_DecryptFinal_ex(ctx, nullptr, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        m_lastError = "Не удалось проверить аутентификацию данных";
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool Database::ensureBruteForceProtectionColumns()
{
    // Проверяем, существуют ли колонки для защиты от brute-force
    QSqlQuery query = select("PRAGMA table_info(users)");
    
    bool failedAttemptsExists = false;
    bool lockoutUntilExists = false;
    bool lastFailedLoginExists = false;
    
    while (query.next()) {
        QString columnName = query.value("name").toString();
        if (columnName == "failed_attempts") {
            failedAttemptsExists = true;
        } else if (columnName == "lockout_until") {
            lockoutUntilExists = true;
        } else if (columnName == "last_failed_login") {
            lastFailedLoginExists = true;
        }
    }
    
    // Добавляем колонку failed_attempts, если её нет
    if (!failedAttemptsExists) {
        QString addColumnQuery = "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0";
        if (!exec(addColumnQuery)) {
            qWarning() << "Не удалось добавить колонку failed_attempts:" << m_lastError;
            return false;
        }
        qDebug() << "Колонка failed_attempts добавлена в таблицу users";
    }
    
    // Добавляем колонку lockout_until, если её нет
    if (!lockoutUntilExists) {
        QString addColumnQuery = "ALTER TABLE users ADD COLUMN lockout_until DATETIME";
        if (!exec(addColumnQuery)) {
            qWarning() << "Не удалось добавить колонку lockout_until:" << m_lastError;
            return false;
        }
        qDebug() << "Колонка lockout_until добавлена в таблицу users";
    }
    
    // Добавляем колонку last_failed_login, если её нет
    if (!lastFailedLoginExists) {
        QString addColumnQuery = "ALTER TABLE users ADD COLUMN last_failed_login DATETIME";
        if (!exec(addColumnQuery)) {
            qWarning() << "Не удалось добавить колонку last_failed_login:" << m_lastError;
            return false;
        }
        qDebug() << "Колонка last_failed_login добавлена в таблицу users";
    }
    
    return true;
}

bool Database::ensureAuditLogTable()
{
    // Создаем таблицу audit_log для записи событий безопасности
    QString createAuditLogTable = R"(
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            event TEXT NOT NULL,
            detail TEXT,
            user_email TEXT
        )
    )";
    
    if (!exec(createAuditLogTable)) {
        qWarning() << "Не удалось создать таблицу audit_log:" << m_lastError;
        return false;
    }
    
    // Создаем индекс для быстрого поиска по timestamp
    QString createTimestampIndex = "CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)";
    if (!exec(createTimestampIndex)) {
        qDebug() << "Не удалось создать индекс для audit_log.timestamp:" << m_lastError;
    }
    
    // Создаем индекс для быстрого поиска по user_email
    QString createUserEmailIndex = "CREATE INDEX IF NOT EXISTS idx_audit_log_user_email ON audit_log(user_email)";
    if (!exec(createUserEmailIndex)) {
        qDebug() << "Не удалось создать индекс для audit_log.user_email:" << m_lastError;
    }
    
    qDebug() << "Таблица audit_log создана успешно";
    return true;
}

bool Database::incrementFailedAttempts(const QString &email)
{
    if (email.isEmpty()) {
        m_lastError = "Email не может быть пустым";
        return false;
    }
    
    // Увеличиваем счётчик неудачных попыток и обновляем время последней неудачной попытки
    QString query = R"(
        UPDATE users 
        SET failed_attempts = failed_attempts + 1,
            last_failed_login = ?
        WHERE email = ?
    )";
    
    QVariantList params;
    params << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss") << email;
    
    return exec(query, params);
}

bool Database::resetFailedAttempts(const QString &email)
{
    if (email.isEmpty()) {
        m_lastError = "Email не может быть пустым";
        return false;
    }
    
    // Сбрасываем счётчик неудачных попыток и время блокировки
    QString query = R"(
        UPDATE users 
        SET failed_attempts = 0,
            lockout_until = NULL
        WHERE email = ?
    )";
    
    QVariantList params;
    params << email;
    
    return exec(query, params);
}

bool Database::setLockoutUntil(const QString &email, const QDateTime &lockoutUntil)
{
    if (email.isEmpty()) {
        m_lastError = "Email не может быть пустым";
        return false;
    }
    
    QString query;
    QVariantList params;
    
    if (lockoutUntil.isValid()) {
        query = "UPDATE users SET lockout_until = ? WHERE email = ?";
        params << lockoutUntil.toString("yyyy-MM-dd HH:mm:ss") << email;
    } else {
        // Устанавливаем NULL для сброса блокировки и сбрасываем счетчик неудачных попыток
        query = "UPDATE users SET lockout_until = NULL, failed_attempts = 0 WHERE email = ?";
        params << email;
    }
    
    return exec(query, params);
}

bool Database::isLockedOut(const QString &email, QDateTime &lockoutUntil)
{
    if (email.isEmpty()) {
        m_lastError = "Email не может быть пустым";
        return false;
    }
    
    QString query = "SELECT lockout_until FROM users WHERE email = ?";
    QVariantList params;
    params << email;
    
    QSqlQuery sqlQuery = select(query, params);
    
    if (sqlQuery.next()) {
        QVariant lockoutVar = sqlQuery.value("lockout_until");
        if (lockoutVar.isNull() || !lockoutVar.isValid()) {
            return false; // Не заблокирован
        }
        
        lockoutUntil = lockoutVar.toDateTime();
        QDateTime now = QDateTime::currentDateTime();
        
        // Если время блокировки прошло, сбрасываем блокировку
        if (lockoutUntil < now || !lockoutUntil.isValid()) {
            setLockoutUntil(email, QDateTime()); // Сбрасываем блокировку
            return false;
        }
        
        return true; // Заблокирован
    }
    
    return false; // Пользователь не найден
}

bool Database::logFailedLogin(const QString &email, const QString &reason)
{
    if (email.isEmpty()) {
        m_lastError = "Email не может быть пустым";
        return false;
    }
    
    QString query = R"(
        INSERT INTO audit_log(timestamp, event, detail, user_email)
        VALUES(?, ?, ?, ?)
    )";
    
    QVariantList params;
    params << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
           << "failed_login"
           << reason
           << email;
    
    return exec(query, params);
}

bool Database::logSuccessfulRegistration(const QString &email)
{
    if (email.isEmpty()) {
        m_lastError = "Email не может быть пустым";
        return false;
    }
    
    QString query = R"(
        INSERT INTO audit_log(timestamp, event, detail, user_email)
        VALUES(?, ?, ?, ?)
    )";
    
    QVariantList params;
    params << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
           << "successful_registration"
           << "Пользователь успешно зарегистрирован"
           << email;
    
    return exec(query, params);
}
