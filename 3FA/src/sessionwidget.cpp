#include "sessionwidget.h"
#include "apptheme.h"
#include "user.h"
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include "appmessage.h"
#include <QPalette>
#include <QColor>
#include <QAbstractButton>
#include <QClipboard>
#include <QHeaderView>
#include <QApplication>
#include <QDir>

SessionWidget::SessionWidget(Database *database, AuthService *authService, QWidget *parent)
    : QWidget(parent)
    , m_database(database)
    , m_authService(authService)
    , m_tableWidget(nullptr)
    , m_refreshButton(nullptr)
    , m_backButton(nullptr)
    , m_statusLabel(nullptr)
    , m_progressBar(nullptr)
{
    setupUI();
    if (m_database && m_authService) {
        populateTable();
    }
}

SessionWidget::~SessionWidget()
{
}

void SessionWidget::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    AppTheme::margins(mainLayout, 24, 24, 24, 24);

    // Создаем карточку в современном стиле - адаптивную по размеру окна
    QFrame *card = new QFrame();
    card->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    AppTheme::dimension(card, "maximumWidth", 1140);
    AppTheme::role(card, "card");

    QVBoxLayout *cardLayout = new QVBoxLayout(card);
    AppTheme::margins(cardLayout, 25, 25, 25, 25);
    AppTheme::spacing(cardLayout, 15);

    // Заголовок в современном стиле
    QLabel *titleLabel = new QLabel("Активные сессии");
    titleLabel->setAlignment(Qt::AlignCenter);
    AppTheme::role(titleLabel, "title");
    cardLayout->addWidget(titleLabel);

    // Статус-лейбл
    m_statusLabel = new QLabel("Готово");
    m_statusLabel->setAlignment(Qt::AlignCenter);
    AppTheme::role(m_statusLabel, "muted");
    cardLayout->addWidget(m_statusLabel);

    // Прогресс-бар
    m_progressBar = new QProgressBar();
    m_progressBar->setVisible(false);
    cardLayout->addWidget(m_progressBar);

    // Таблица сессий
    m_tableWidget = AppTheme::createAdminTable();
    m_tableWidget->setColumnCount(5);
    QStringList headers;
    headers << "Токен" << "Email" << "Создана" << "Истекает" << "Действия";
    m_tableWidget->setHorizontalHeaderLabels(headers);

    m_tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(m_tableWidget, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (const auto *email = m_tableWidget->item(row, 1)) {
            QApplication::clipboard()->setText(email->text());
        }
    });
    m_tableWidget->setSortingEnabled(true);
    m_tableWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_tableWidget->setWordWrap(false);

    QHeaderView *header = m_tableWidget->horizontalHeader();
    header->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(1, QHeaderView::Stretch); // Email - растягиваем
    header->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    header->setSectionsClickable(true);
    header->setSortIndicatorShown(true);

    cardLayout->addWidget(m_tableWidget, 1);

    // Кнопки управления
    QHBoxLayout *buttonsLayout = new QHBoxLayout();
    AppTheme::spacing(buttonsLayout, 15);

    // Кнопка обновления
    m_refreshButton = new QPushButton("Обновить");
    AppTheme::buttonIcon(m_refreshButton, "refresh");
    m_refreshButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    connect(m_refreshButton, &QPushButton::clicked, this, &SessionWidget::onRefreshClicked);
    buttonsLayout->addWidget(m_refreshButton);

    // Кнопка "Назад"
    m_backButton = new QPushButton("Назад");
    AppTheme::buttonIcon(m_backButton, "back");
    m_backButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    AppTheme::role(m_backButton, "quiet");
    connect(m_backButton, &QPushButton::clicked, this, &SessionWidget::onBackClicked);
    buttonsLayout->addWidget(m_backButton);

    cardLayout->addLayout(buttonsLayout);

    AppTheme::centerBlock(mainLayout, card);
}

void SessionWidget::populateTable()
{
    if (!m_database || !m_authService) {
        if (m_statusLabel) {
            m_statusLabel->setText("База данных или сервис аутентификации не подключены");
            AppTheme::role(m_statusLabel, "error");
        }
        return;
    }

    if (m_statusLabel) {
        m_statusLabel->setText("Загрузка данных...");
        AppTheme::role(m_statusLabel, "muted");
    }

    if (m_progressBar) {
        m_progressBar->setVisible(true);
        m_progressBar->setRange(0, 0); // Неопределенный прогресс
    }

    // Получаем текущего пользователя
    User currentUser = m_authService->getCurrentUser();
    if (!currentUser.isValid()) {
        if (m_statusLabel) {
            m_statusLabel->setText("Пользователь не авторизован");
            AppTheme::role(m_statusLabel, "error");
        }
        if (m_progressBar) {
            m_progressBar->setVisible(false);
        }
        return;
    }

    // Если пользователь - админ, показываем все сессии, иначе - только свои
    if (currentUser.isAdmin()) {
        m_allSessions = m_authService->getAllSessions();
    } else {
        m_allSessions = m_authService->getUserSessions(currentUser.getId());
    }

    fillTableWithData(m_allSessions);

    if (m_progressBar) {
        m_progressBar->setVisible(false);
    }

    if (m_statusLabel) {
        m_statusLabel->setText(QString("Загружено активных сессий: %1").arg(m_allSessions.size()));
        AppTheme::role(m_statusLabel, "success");
    }
}

void SessionWidget::fillTableWithData(const QList<QMap<QString, QVariant>> &sessions)
{
    if (!m_tableWidget) {
        return;
    }

    // Отключаем сортировку перед заполнением
    m_tableWidget->setSortingEnabled(false);

    // Очищаем таблицу
    int currentRowCount = m_tableWidget->rowCount();
    for (int i = currentRowCount - 1; i >= 0; --i) {
        m_tableWidget->removeRow(i);
    }
    m_tableWidget->clearContents();
    m_tableWidget->setRowCount(0);

    m_tableWidget->setRowCount(sessions.size());

    // Получаем токен текущей сессии для выделения
    QString currentSessionToken;
    if (m_authService) {
        currentSessionToken = m_authService->getCurrentSessionToken();
    }

    for (int i = 0; i < sessions.size(); ++i) {
        const QMap<QString, QVariant> &session = sessions[i];

        // Токен (первые 16 символов)
        QString token = session["token"].toString();
        QString tokenDisplay = formatToken(token);
        QTableWidgetItem *tokenItem = new QTableWidgetItem(tokenDisplay);
        tokenItem->setToolTip(token); // Полный токен в tooltip
        m_tableWidget->setItem(i, 0, tokenItem);

        // Email
        QString email = session["user_email"].toString();
        QTableWidgetItem *emailItem = new QTableWidgetItem(email);
        emailItem->setToolTip(email);
        m_tableWidget->setItem(i, 1, emailItem);

        // Дата создания
        QDateTime createdAt = session["created_at"].toDateTime();
        QString createdAtStr = formatDateTime(createdAt);
        QTableWidgetItem *createdItem = new QTableWidgetItem(createdAtStr);
        createdItem->setToolTip(createdAtStr);
        m_tableWidget->setItem(i, 2, createdItem);

        // Дата истечения
        QDateTime expiresAt = session["expires_at"].toDateTime();
        QString expiresAtStr = formatDateTime(expiresAt);
        QTableWidgetItem *expiresItem = new QTableWidgetItem(expiresAtStr);
        expiresItem->setToolTip(expiresAtStr);
        m_tableWidget->setItem(i, 3, expiresItem);

        // Выделяем текущую сессию светлым цветом
        bool isCurrentSession = (token == currentSessionToken);

        if (isCurrentSession) { QFont font = emailItem->font(); font.setBold(true); emailItem->setFont(font); }

        // Действия - кнопка завершения сессии
        QPushButton *terminateButton = new QPushButton("Завершить");
        AppTheme::buttonIcon(terminateButton, "close");
        AppTheme::role(terminateButton, "danger");
        connect(terminateButton, &QPushButton::clicked, this, [this, token]() {
            onTerminateSessionClicked(token);
        });
        AppTheme::setTableCell(m_tableWidget, i, 4, terminateButton);
    }

    // Включаем сортировку обратно
    m_tableWidget->setSortingEnabled(true);

    // Сортируем по дате создания по умолчанию (по убыванию)
    QHeaderView *header = m_tableWidget->horizontalHeader();
    header->setSortIndicator(2, Qt::DescendingOrder);
    m_tableWidget->sortItems(2, Qt::DescendingOrder);

    // Сбрасываем выделение строки (чтобы не было фиолетового выделения при первом открытии)
    m_tableWidget->clearSelection();
    m_tableWidget->setCurrentItem(nullptr);
}

void SessionWidget::onBackClicked()
{
    emit backToMenu();
}

void SessionWidget::onRefreshClicked()
{
    populateTable();
}

void SessionWidget::onTerminateSessionClicked(const QString &token)
{
    if (!m_authService) {
        AppMessage::warning(this, "Ошибка", "Сервис аутентификации не подключен");
        return;
    }

    // Показываем диалог подтверждения
    if (!AppMessage::confirm(
        this,
        "Подтверждение завершения сессии",
        QString("Вы уверены, что хотите завершить эту сессию?\n\n"
                "После завершения сессии потребуется повторная авторизация."),
        "Завершить сессию")) {
        return;
    }

    // Завершаем сессию
    if (m_authService->terminateSession(token)) {
        if (m_statusLabel) {
            m_statusLabel->setText("Сессия успешно завершена");
            AppTheme::role(m_statusLabel, "success");
        }
        // Обновляем таблицу
        populateTable();
        AppMessage::information(this, "Успех", "Сессия успешно завершена.");
    } else {
        AppMessage::critical(this, "Ошибка",
            QString("Не удалось завершить сессию:\n%1").arg(m_authService->getLastError()));
    }
}

QString SessionWidget::formatDateTime(const QDateTime &dateTime) const
{
    return dateTime.toString("dd.MM.yyyy HH:mm:ss");
}

QString SessionWidget::formatToken(const QString &token) const
{
    if (token.length() <= 16) {
        return token;
    }
    return token.left(16) + "...";
}

void SessionWidget::refreshData()
{
    populateTable();
}

