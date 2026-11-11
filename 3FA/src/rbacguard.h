#ifndef RBACGUARD_H
#define RBACGUARD_H

#include <QString>
#include <QSqlDatabase>

class User;

/**
 * @brief RBACGuard - централизованный механизм контроля доступа на основе ролей
 * 
 * Предоставляет единый интерфейс для проверки прав доступа пользователей
 * на основе их ролей (user/admin).
 */
class RBACGuard
{
public:
    /**
     * @brief Проверяет, является ли пользователь администратором
     * @param user Объект пользователя
     * @return true если пользователь является администратором
     */
    static bool isAdmin(const User &user);
    
    /**
     * @brief Проверяет, является ли пользователь администратором по его роли
     * @param role Роль пользователя ("user" или "admin")
     * @return true если роль равна "admin"
     */
    static bool isAdmin(const QString &role);
    
    /**
     * @brief Проверяет, является ли пользователь администратором по его ID в базе данных
     * @param db Подключение к базе данных пользователей
     * @param userId ID пользователя
     * @return true если пользователь является администратором
     */
    static bool isAdmin(QSqlDatabase *db, int userId);
    
    /**
     * @brief Проверяет доступ пользователя к ресурсу
     * @param userId ID пользователя, запрашивающего доступ
     * @param ownerId ID владельца ресурса
     * @param userRole Роль пользователя
     * @return true если доступ разрешен (пользователь является владельцем или администратором)
     */
    static bool hasAccess(int userId, int ownerId, const QString &userRole);
    
    /**
     * @brief Проверяет доступ пользователя к ресурсу через базу данных
     * @param db Подключение к базе данных пользователей
     * @param userId ID пользователя, запрашивающего доступ
     * @param ownerId ID владельца ресурса
     * @return true если доступ разрешен (пользователь является владельцем или администратором)
     */
    static bool hasAccess(QSqlDatabase *db, int userId, int ownerId);
    
    /**
     * @brief Получает роль пользователя из базы данных
     * @param db Подключение к базе данных пользователей
     * @param userId ID пользователя
     * @return Роль пользователя ("user" или "admin"), или пустая строка при ошибке
     */
    static QString getUserRole(QSqlDatabase *db, int userId);

private:
    RBACGuard() = delete; // Статический класс, не должен быть инстанцирован
};

#endif // RBACGUARD_H

