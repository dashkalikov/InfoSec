#ifndef REQUESTCONTEXT_H
#define REQUESTCONTEXT_H

#include <QString>
#include <QSqlDatabase>

/**
 * @brief RequestContext - контекст HTTP запроса
 * 
 * Содержит информацию о пользователе, извлеченную из сессии
 * через middleware.
 */
struct RequestContext {
    int userId;
    QString userEmail;
    QString userRole;
    QSqlDatabase *userDb;
    bool isValid;
    
    RequestContext()
        : userId(-1)
        , userDb(nullptr)
        , isValid(false)
    {
    }
    
    RequestContext(int uid, const QString &email, const QString &role, QSqlDatabase *db)
        : userId(uid)
        , userEmail(email)
        , userRole(role)
        , userDb(db)
        , isValid(true)
    {
    }
};

#endif // REQUESTCONTEXT_H


