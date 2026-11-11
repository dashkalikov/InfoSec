#include "user.h"
#include <QRegularExpression>
#include <QDebug>

User::User()
    : m_id(-1)
    , m_email("")
    , m_passwordHash("")
    , m_totpSecret("")
    , m_createdAt(QDateTime::currentDateTime())
    , m_isActive(true)
    , m_role("user")
{
}

User::User(const QString &email, const QString &passwordHash)
    : m_id(-1)
    , m_email(email)
    , m_passwordHash(passwordHash)
    , m_totpSecret("")
    , m_createdAt(QDateTime::currentDateTime())
    , m_isActive(true)
    , m_role("user")
{
}

bool User::isValid() const
{
    return isValidEmail(m_email) && !m_passwordHash.isEmpty();
}

bool User::isValidEmail(const QString &email)
{
    // Простая валидация email с использованием регулярного выражения
    QRegularExpression emailRegex(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
    return emailRegex.match(email).hasMatch();
}

bool User::isValidPassword(const QString &password)
{
    // Минимальные требования к паролю:
    // - Длина не менее 8 символов
    // - Содержит хотя бы одну заглавную букву
    // - Содержит хотя бы одну строчную букву
    // - Содержит хотя бы одну цифру
    
    if (password.length() < 8) {
        return false;
    }
    
    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    
    for (const QChar &ch : password) {
        if (ch.isUpper()) hasUpper = true;
        if (ch.isLower()) hasLower = true;
        if (ch.isDigit()) hasDigit = true;
    }
    
    return hasUpper && hasLower && hasDigit;
}

QString User::toString() const
{
    return QString("User{id: %1, email: %2, totpSecret: %3, created: %4, active: %5, role: %6}")
           .arg(m_id)
           .arg(m_email)
           .arg(m_totpSecret.isEmpty() ? "not set" : "set")
           .arg(m_createdAt.toString())
           .arg(m_isActive ? "true" : "false")
           .arg(m_role);
}
