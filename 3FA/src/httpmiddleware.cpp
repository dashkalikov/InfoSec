#include "httpmiddleware.h"
#include "rbacguard.h"
#include "sessionmanager.h"
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QString>
#include <QDir>
#include <QCoreApplication>
#include <QDebug>
#include <algorithm>
#include <cctype>
#include <sstream>

// Forward declaration
static QSqlDatabase* userDbOpen(const std::string &rootDir);

std::string HTTPMiddleware::extractSessionToken(const std::string &headers)
{
    // Сначала пробуем извлечь из Authorization заголовка
    std::string token = extractTokenFromAuthorization(headers);
    if (!token.empty()) {
        return token;
    }
    
    // Затем пробуем извлечь из Cookie
    token = extractTokenFromCookie(headers);
    if (!token.empty()) {
        return token;
    }
    
    return std::string();
}

std::string HTTPMiddleware::extractTokenFromAuthorization(const std::string &headers)
{
    // Ищем "Authorization: Bearer <token>"
    std::string authHeader = "Authorization:";
    size_t authPos = headers.find(authHeader);
    if (authPos == std::string::npos) {
        // Пробуем case-insensitive поиск
        std::string headersLower = headers;
        std::transform(headersLower.begin(), headersLower.end(), headersLower.begin(), ::tolower);
        std::string authHeaderLower = "authorization:";
        authPos = headersLower.find(authHeaderLower);
        if (authPos == std::string::npos) {
            return std::string();
        }
    }
    
    // Находим начало значения после "Authorization:"
    size_t valueStart = authPos + authHeader.length();
    while (valueStart < headers.length() && std::isspace(headers[valueStart])) {
        valueStart++;
    }
    
    // Проверяем наличие "Bearer "
    std::string bearer = "Bearer ";
    if (headers.substr(valueStart, bearer.length()) != bearer) {
        // Пробуем case-insensitive
        std::string bearerLower = "bearer ";
        std::string valueLower = headers.substr(valueStart, bearerLower.length());
        std::transform(valueLower.begin(), valueLower.end(), valueLower.begin(), ::tolower);
        if (valueLower != bearerLower) {
            return std::string();
        }
        valueStart += bearerLower.length();
    } else {
        valueStart += bearer.length();
    }
    
    // Находим конец токена (до конца строки или пробела)
    size_t valueEnd = valueStart;
    while (valueEnd < headers.length() && headers[valueEnd] != '\r' && headers[valueEnd] != '\n' && !std::isspace(headers[valueEnd])) {
        valueEnd++;
    }
    
    if (valueEnd > valueStart) {
        return headers.substr(valueStart, valueEnd - valueStart);
    }
    
    return std::string();
}

std::string HTTPMiddleware::extractTokenFromCookie(const std::string &headers)
{
    // Ищем "Cookie: session_token=<token>"
    std::string cookieHeader = "Cookie:";
    size_t cookiePos = headers.find(cookieHeader);
    if (cookiePos == std::string::npos) {
        // Пробуем case-insensitive поиск
        std::string headersLower = headers;
        std::transform(headersLower.begin(), headersLower.end(), headersLower.begin(), ::tolower);
        std::string cookieHeaderLower = "cookie:";
        cookiePos = headersLower.find(cookieHeaderLower);
        if (cookiePos == std::string::npos) {
            return std::string();
        }
    }
    
    // Находим начало значения после "Cookie:"
    size_t valueStart = cookiePos + cookieHeader.length();
    while (valueStart < headers.length() && std::isspace(headers[valueStart])) {
        valueStart++;
    }
    
    // Ищем "session_token=" в оригинальных заголовках (case-insensitive)
    std::string cookieValue = headers.substr(valueStart);
    std::string cookieValueLower = cookieValue;
    std::transform(cookieValueLower.begin(), cookieValueLower.end(), cookieValueLower.begin(), ::tolower);
    
    std::string tokenKey = "session_token=";
    std::string tokenKeyLower = "session_token=";
    size_t tokenKeyPos = cookieValueLower.find(tokenKeyLower);
    
    if (tokenKeyPos == std::string::npos) {
        return std::string();
    }
    
    // Находим начало токена (используем оригинальный cookieValue)
    size_t tokenStart = tokenKeyPos + tokenKey.length();
    
    // Находим конец токена (до ';', пробела или конца строки)
    size_t tokenEnd = tokenStart;
    while (tokenEnd < cookieValue.length() && 
           cookieValue[tokenEnd] != ';' && 
           cookieValue[tokenEnd] != '\r' && 
           cookieValue[tokenEnd] != '\n' && 
           !std::isspace(cookieValue[tokenEnd])) {
        tokenEnd++;
    }
    
    if (tokenEnd > tokenStart) {
        return cookieValue.substr(tokenStart, tokenEnd - tokenStart);
    }
    
    return std::string();
}

RequestContext HTTPMiddleware::loadUserContext(const std::string &token, 
                                                SessionManager *sessionManager,
                                                const std::string &rootDir)
{
    if (token.empty() || !sessionManager) {
        return RequestContext();
    }
    
    // Проверяем валидность токена
    QString qToken = QString::fromStdString(token);
    if (!sessionManager->isValidSession(qToken)) {
        return RequestContext();
    }
    
    // Получаем информацию о пользователе из сессии
    int userId = sessionManager->getUserIdFromToken(qToken);
    QString userEmail = sessionManager->getUserEmailFromToken(qToken);
    
    if (userId <= 0 || userEmail.isEmpty()) {
        return RequestContext();
    }
    
    // Открываем базу данных пользователей
    QSqlDatabase *userDb = userDbOpen(rootDir);
    if (!userDb || !userDb->isOpen()) {
        return RequestContext();
    }
    
    // Получаем роль пользователя через RBACGuard
    QString userRole = RBACGuard::getUserRole(userDb, userId);
    if (userRole.isEmpty()) {
        userRole = "user"; // По умолчанию
    }
    
    return RequestContext(userId, userEmail, userRole, userDb);
}

std::string HTTPMiddleware::createErrorResponse(int statusCode, const std::string &message)
{
    std::ostringstream response;
    response << "HTTP/1.1 " << statusCode;
    
    switch (statusCode) {
        case 401:
            response << " Unauthorized";
            break;
        case 403:
            response << " Forbidden";
            break;
        case 400:
            response << " Bad Request";
            break;
        default:
            response << " Error";
            break;
    }
    
    response << "\r\n";
    response << "Content-Type: text/plain\r\n";
    response << "Content-Length: " << message.length() << "\r\n";
    response << "\r\n";
    response << message;
    
    return response.str();
}

// Helper function to open user database (from minica.cpp)
static QSqlDatabase* userDbOpen(const std::string &rootDir)
{
    static int connectionCounter = 0;
    QString connectionName = QString("user_db_middleware_%1").arg(++connectionCounter);
    
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", connectionName);
    QDir rootDirObj(QString::fromStdString(rootDir));
    QString dbPath = rootDirObj.absoluteFilePath("databases/3fa_users.db");
    db.setDatabaseName(dbPath);
    
    if (!db.open()) {
        qWarning() << "HTTPMiddleware: Failed to open user database:" << db.lastError().text();
        QSqlDatabase::removeDatabase(connectionName);
        return nullptr;
    }
    
    QSqlDatabase* dbPtr = new QSqlDatabase(QSqlDatabase::database(connectionName));
    return dbPtr;
}

