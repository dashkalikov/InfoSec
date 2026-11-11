#include "rbacguard.h"
#include "user.h"
#include <QSqlQuery>
#include <QSqlError>
#include <QDebug>

bool RBACGuard::isAdmin(const User &user)
{
    return user.isAdmin();
}

bool RBACGuard::isAdmin(const QString &role)
{
    return role == "admin";
}

bool RBACGuard::isAdmin(QSqlDatabase *db, int userId)
{
    if (!db || !db->isOpen() || userId <= 0) {
        return false;
    }
    
    QString role = getUserRole(db, userId);
    return isAdmin(role);
}

bool RBACGuard::hasAccess(int userId, int ownerId, const QString &userRole)
{
    // Доступ разрешен, если пользователь является владельцем ресурса
    // или если пользователь является администратором
    return (userId == ownerId) || isAdmin(userRole);
}

bool RBACGuard::hasAccess(QSqlDatabase *db, int userId, int ownerId)
{
    if (!db || !db->isOpen() || userId <= 0 || ownerId <= 0) {
        return false;
    }
    
    // Если пользователь является владельцем, доступ разрешен
    if (userId == ownerId) {
        return true;
    }
    
    // Проверяем, является ли пользователь администратором
    return isAdmin(db, userId);
}

QString RBACGuard::getUserRole(QSqlDatabase *db, int userId)
{
    if (!db || !db->isOpen() || userId <= 0) {
        return QString();
    }
    
    QString role;
    {
    QSqlQuery query(*db);
    query.prepare("SELECT role FROM users WHERE id = ?");
    query.addBindValue(userId);
    
    if (!query.exec()) {
        qWarning() << "RBACGuard: Failed to get user role:" << query.lastError().text();
            query.finish(); // Явно завершаем запрос
        return QString();
    }
    
    if (query.next()) {
            role = query.value(0).toString();
        }
        query.finish(); // Явно завершаем запрос
        // query уничтожится при выходе из блока
    }
    
        return role.isEmpty() ? "user" : role; // По умолчанию "user"
}

