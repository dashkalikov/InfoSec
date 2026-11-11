#ifndef HTTPMIDDLEWARE_H
#define HTTPMIDDLEWARE_H

#include <string>
#include <map>
#include <functional>
#include "requestcontext.h"
#include "sessionmanager.h"

class QSqlDatabase;

/**
 * @brief HTTPMiddleware - middleware для HTTP сервера
 * 
 * Предоставляет функции для извлечения сессии из запроса
 * и подгрузки пользователя в контекст запроса.
 */
class HTTPMiddleware
{
public:
    /**
     * @brief Извлекает токен сессии из HTTP заголовков
     * @param headers HTTP заголовки запроса
     * @return Токен сессии или пустая строка
     */
    static std::string extractSessionToken(const std::string &headers);

    /**
     * @brief Извлекает токен сессии из Authorization заголовка
     * @param headers HTTP заголовки запроса
     * @return Токен сессии или пустая строка
     */
    static std::string extractTokenFromAuthorization(const std::string &headers);

    /**
     * @brief Извлекает токен сессии из Cookie заголовка
     * @param headers HTTP заголовки запроса
     * @return Токен сессии или пустая строка
     */
    static std::string extractTokenFromCookie(const std::string &headers);

    /**
     * @brief Загружает пользователя в контекст запроса из сессии
     * @param token Токен сессии
     * @param sessionManager Менеджер сессий
     * @param rootDir Корневая директория проекта
     * @return Контекст запроса с информацией о пользователе
     */
    static RequestContext loadUserContext(const std::string &token, 
                                          SessionManager *sessionManager,
                                          const std::string &rootDir);

    /**
     * @brief Создает HTTP ответ с ошибкой аутентификации
     * @param statusCode HTTP статус код
     * @param message Сообщение об ошибке
     * @return HTTP ответ
     */
    static std::string createErrorResponse(int statusCode, const std::string &message);
};

#endif // HTTPMIDDLEWARE_H


