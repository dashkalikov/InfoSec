#ifndef ADMINFILESWIDGET_H
#define ADMINFILESWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QHeaderView>
#include <QFileDialog>
#include <QProgressBar>
#include <QLineEdit>
#include <QCompleter>
#include <QTabWidget>
#include <QComboBox>
#include "database.h"
#include "user.h"

/**
 * @brief Виджет для администратора для просмотра файлов и управления пользователями
 * 
 * Показывает таблицу со всеми пользователями и их PDF файлами.
 * Администратор может скачивать любой файл любого пользователя.
 * Также позволяет управлять пользователями: изменять роли и блокировать/разблокировать.
 */
class AdminFilesWidget : public QWidget
{
    Q_OBJECT

public:
    explicit AdminFilesWidget(Database *database, QWidget *parent = nullptr);
    ~AdminFilesWidget();
    
    void refreshData();
    void setDatabase(Database *database) { m_database = database; }
    void setCurrentUserEmail(const QString &email) { m_currentUserEmail = email; }

signals:
    void backToMenu();

private slots:
    void onDownloadClicked();
    void onRefreshClicked();
    void onBackClicked();
    void onFilterTextChanged(const QString &text);
    void onClearFilterClicked();
    void onUserRoleChanged(int index);
    void onUserRoleChanged(const QString &email, const QString &role);
    void onUserBlockedToggled(bool blocked);
    void onUserBlockedToggled(const QString &email, bool blocked);
    void onDeleteUserClicked(int userId, const QString &email);
    void onRefreshUsersClicked();

private:
    void setupUI();
    void setupFilesTab();
    void setupUsersTab();
    void populateTable();
    void populateUsersTable();
    void fillTableWithData(const QList<QMap<QString, QVariant>> &pdfs);
    void fillUsersTableWithData(const QList<User> &users);
    void filterTable(const QString &emailFilter);
    QString formatDateTime(const QDateTime &dateTime) const;
    
    Database *m_database;
    QTabWidget *m_tabWidget;
    QWidget *m_filesTab;
    QWidget *m_usersTab;
    QTableWidget *m_tableWidget;
    QTableWidget *m_usersTableWidget;
    QPushButton *m_downloadButton;
    QPushButton *m_refreshButton;
    QPushButton *m_refreshUsersButton;
    QPushButton *m_backButton;
    QLabel *m_statusLabel;
    QLabel *m_usersStatusLabel;
    QProgressBar *m_progressBar;
    QLineEdit *m_filterEdit;
    QPushButton *m_clearFilterButton;
    QList<QMap<QString, QVariant>> m_allPdfs; // Храним все данные для фильтрации
    QList<User> m_allUsers; // Храним все данные пользователей
    int m_savedSortColumn; // Сохраняем столбец сортировки
    Qt::SortOrder m_savedSortOrder; // Сохраняем направление сортировки
    QString m_currentUserEmail; // Email текущего пользователя для выделения его файлов
};

#endif // ADMINFILESWIDGET_H

