#ifndef USER_H
#define USER_H

#include <QString>
#include <QDateTime>

/**
 * @brief Класс User представляет модель пользователя в системе аутентификации
 * 
 * Содержит основную информацию о пользователе: email, хеш пароля,
 * дату создания и статус активации аккаунта.
 */
class User
{
public:
    User();
    User(const QString &email, const QString &passwordHash);
    
    // Геттеры
    int getId() const { return m_id; }
    QString getEmail() const { return m_email; }
    QString getPasswordHash() const { return m_passwordHash; }
    QString getTOTPSecret() const { return m_totpSecret; }
    QDateTime getCreatedAt() const { return m_createdAt; }
    bool isActive() const { return m_isActive; }
    QString getRole() const { return m_role; }
    bool isAdmin() const { return m_role == "admin"; }
    
    // Сеттеры
    void setId(int id) { m_id = id; }
    void setEmail(const QString &email) { m_email = email; }
    void setPasswordHash(const QString &passwordHash) { m_passwordHash = passwordHash; }
    void setTOTPSecret(const QString &totpSecret) { m_totpSecret = totpSecret; }
    void setCreatedAt(const QDateTime &createdAt) { m_createdAt = createdAt; }
    void setActive(bool active) { m_isActive = active; }
    void setRole(const QString &role) { m_role = role; }
    
    // Валидация
    bool isValid() const;
    static bool isValidEmail(const QString &email);
    static bool isValidPassword(const QString &password);
    
    // Утилиты
    QString toString() const;

private:
    int m_id;
    QString m_email;
    QString m_passwordHash;
    QString m_totpSecret;
    QDateTime m_createdAt;
    bool m_isActive;
    QString m_role;  // "user" или "admin"
};

#endif // USER_H
