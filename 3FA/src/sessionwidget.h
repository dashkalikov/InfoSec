#ifndef SESSIONWIDGET_H
#define SESSIONWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QHeaderView>
#include <QProgressBar>
#include "database.h"
#include "authservice.h"

/**
 * @brief Виджет для управления активными сессиями пользователя
 * 
 * Показывает таблицу со всеми активными сессиями пользователя.
 * Пользователь может просматривать свои сессии и завершать их по запросу.
 */
class SessionWidget : public QWidget
{
    Q_OBJECT

public:
    explicit SessionWidget(Database *database, AuthService *authService, QWidget *parent = nullptr);
    ~SessionWidget();
    
    void refreshData();
    void setDatabase(Database *database) { m_database = database; }
    void setAuthService(AuthService *authService) { m_authService = authService; }

signals:
    void backToMenu();

private slots:
    void onBackClicked();
    void onRefreshClicked();
    void onTerminateSessionClicked(const QString &token);

private:
    void setupUI();
    void populateTable();
    void fillTableWithData(const QList<QMap<QString, QVariant>> &sessions);
    QString formatDateTime(const QDateTime &dateTime) const;
    QString formatToken(const QString &token) const;
    
    Database *m_database;
    AuthService *m_authService;
    QTableWidget *m_tableWidget;
    QPushButton *m_refreshButton;
    QPushButton *m_backButton;
    QLabel *m_statusLabel;
    QProgressBar *m_progressBar;
    QList<QMap<QString, QVariant>> m_allSessions; // Храним все данные для фильтрации
};

#endif // SESSIONWIDGET_H

