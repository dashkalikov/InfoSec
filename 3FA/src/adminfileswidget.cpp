#include "adminfileswidget.h"
#include "apptheme.h"
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QFileDialog>
#include <QStandardPaths>
#include "appmessage.h"
#include <QPalette>
#include <QColor>
#include <QAbstractButton>
#include <QLineEdit>
#include <QCompleter>
#include <QTimer>
#include <QHeaderView>
#include <QComboBox>
#include <QCheckBox>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QMetaType>
#include <QApplication>
#include <QDir>
#include "user.h"
#include <algorithm>

AdminFilesWidget::AdminFilesWidget(Database *database, QWidget *parent)
    : QWidget(parent)
    , m_database(database)
    , m_tabWidget(nullptr)
    , m_filesTab(nullptr)
    , m_usersTab(nullptr)
    , m_tableWidget(nullptr)
    , m_usersTableWidget(nullptr)
    , m_downloadButton(nullptr)
    , m_refreshButton(nullptr)
    , m_refreshUsersButton(nullptr)
    , m_backButton(nullptr)
    , m_statusLabel(nullptr)
    , m_usersStatusLabel(nullptr)
    , m_progressBar(nullptr)
    , m_filterEdit(nullptr)
    , m_clearFilterButton(nullptr)
    , m_savedSortColumn(-1)
    , m_savedSortOrder(Qt::AscendingOrder)
{
    setupUI();
    if (m_database) {
        populateTable();
        populateUsersTable();
    }
}

AdminFilesWidget::~AdminFilesWidget()
{
}

void AdminFilesWidget::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    AppTheme::margins(mainLayout, 24, 20, 24, 20);
    mainLayout->setSizeConstraint(QLayout::SetMinimumSize);

    // Создаем карточку в современном стиле - адаптивную по размеру окна
    QFrame *card = new QFrame();
    card->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred); // Expanding по ширине, Preferred по высоте
    AppTheme::dimension(card, "maximumWidth", 1140);
    AppTheme::dimension(card, "minimumHeight", 450); // Уменьшенная минимальная высота карточки
    AppTheme::dimension(card, "maximumHeight", 680); // Уменьшенная максимальная высота для ограничения
    AppTheme::role(card, "card");

    QVBoxLayout *cardLayout = new QVBoxLayout(card);
    AppTheme::margins(cardLayout, 24, 22, 24, 20);
    AppTheme::spacing(cardLayout, 8);
    cardLayout->setSizeConstraint(QLayout::SetMinimumSize); // Ограничиваем минимальный размер

    // Заголовок в современном стиле
    QLabel *titleLabel = new QLabel("Панель администратора");
    titleLabel->setAlignment(Qt::AlignCenter);
    AppTheme::role(titleLabel, "title");
    cardLayout->addWidget(titleLabel);

    // Создаем вкладки
    m_tabWidget = new QTabWidget();

    setupFilesTab();
    setupUsersTab();

    m_tabWidget->addTab(m_filesTab, "Файлы пользователей");
    m_tabWidget->addTab(m_usersTab, "Управление пользователями");

    for (auto *table : {m_tableWidget, m_usersTableWidget}) {
        connect(table, &QTableWidget::cellDoubleClicked, this, [this, table](int row, int) {
            const auto *emailItem = table->item(row, 1);
            if (!emailItem) return;
            const auto email = emailItem->text();
            m_tabWidget->setCurrentWidget(m_filesTab);
            m_filterEdit->setText(email);
            m_filterEdit->setFocus();
        });
    }

    cardLayout->addWidget(m_tabWidget, 0); // Убираем stretch factor, чтобы вкладки не растягивались

    // Кнопка "Назад" для возврата в главное меню
    m_backButton = new QPushButton("Назад");
    AppTheme::buttonIcon(m_backButton, "back");
    m_backButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    AppTheme::role(m_backButton, "quiet");
    connect(m_backButton, &QPushButton::clicked, this, &AdminFilesWidget::onBackClicked);
    cardLayout->addWidget(m_backButton);

    AppTheme::centerBlock(mainLayout, card);
}

void AdminFilesWidget::setupFilesTab()
{
    m_filesTab = new QWidget();
    QVBoxLayout *filesLayout = new QVBoxLayout(m_filesTab);
    AppTheme::margins(filesLayout, 10, 8, 10, 8);
    AppTheme::spacing(filesLayout, 8);
    filesLayout->setSizeConstraint(QLayout::SetMinimumSize); // Ограничиваем минимальный размер

    // Прогресс-бар
    m_progressBar = new QProgressBar();
    m_progressBar->setVisible(false);
    m_progressBar->setRange(0, 0);
    filesLayout->addWidget(m_progressBar);

    // Статус-лейбл
    m_statusLabel = new QLabel("Готово");
    m_statusLabel->setAlignment(Qt::AlignCenter);
    AppTheme::role(m_statusLabel, "muted");
    filesLayout->addWidget(m_statusLabel);

    // Поле фильтрации по email пользователя
    QHBoxLayout *filterLayout = new QHBoxLayout();
    AppTheme::spacing(filterLayout, 10);

    QLabel *filterLabel = new QLabel("Фильтр по email:");
    filterLayout->addWidget(filterLabel);

    m_filterEdit = new QLineEdit();
    m_filterEdit->setPlaceholderText("Введите email пользователя для фильтрации...");
    connect(m_filterEdit, &QLineEdit::textChanged, this, &AdminFilesWidget::onFilterTextChanged);
    filterLayout->addWidget(m_filterEdit, 1); // Растягиваем поле фильтра

    m_clearFilterButton = new QPushButton("Очистить");
    AppTheme::buttonIcon(m_clearFilterButton, "close");
    AppTheme::role(m_clearFilterButton, "quiet");
    connect(m_clearFilterButton, &QPushButton::clicked, this, &AdminFilesWidget::onClearFilterClicked);
    filterLayout->addWidget(m_clearFilterButton);

    filesLayout->addLayout(filterLayout);

    // Таблица
    m_tableWidget = AppTheme::createAdminTable();
    m_tableWidget->setColumnCount(6);
    QStringList headers;
    headers << "ID" << "Email пользователя" << "Имя файла" << "Алгоритм" << "Операция" << "Дата создания";
    m_tableWidget->setHorizontalHeaderLabels(headers);

    m_tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tableWidget->setSortingEnabled(true);
    m_tableWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::MinimumExpanding); // MinimumExpanding для правильной работы
    AppTheme::dimension(m_tableWidget, "minimumHeight", 180); // Увеличенная минимальная высота
    AppTheme::dimension(m_tableWidget, "maximumHeight", 350); // Увеличенная максимальная высота таблицы
    m_tableWidget->setWordWrap(false); // Отключаем перенос текста, чтобы высота ячеек не увеличивалась

    QHeaderView *header = m_tableWidget->horizontalHeader();
    header->setSectionResizeMode(0, QHeaderView::ResizeToContents); // ID
    header->setSectionResizeMode(1, QHeaderView::Stretch); // Email - возвращаем растягивание
    header->setSectionResizeMode(2, QHeaderView::Stretch); // Имя файла
    header->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    header->setSectionsClickable(true); // Разрешаем клик по заголовкам для сортировки
    header->setSortIndicatorShown(true); // Показываем индикаторы сортировки (стрелки)

    connect(m_tableWidget, &QTableWidget::itemSelectionChanged, this, [this]() {
        bool hasSelection = m_tableWidget->currentRow() >= 0;
        m_downloadButton->setEnabled(hasSelection);
    });

    filesLayout->addWidget(m_tableWidget);

    // Кнопки управления - перемещены вниз под таблицу, растянуты на всю ширину
    QHBoxLayout *buttonsLayout = new QHBoxLayout();
    AppTheme::spacing(buttonsLayout, 10);
    AppTheme::margins(buttonsLayout, 0, 0, 0, 0);

    m_refreshButton = new QPushButton("Обновить");
    AppTheme::buttonIcon(m_refreshButton, "refresh");
    m_refreshButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    AppTheme::dimension(m_refreshButton, "minimumWidth", 0);
    connect(m_refreshButton, &QPushButton::clicked, this, &AdminFilesWidget::onRefreshClicked);
    buttonsLayout->addWidget(m_refreshButton);

    m_downloadButton = new QPushButton("Скачать выбранный файл");
    AppTheme::buttonIcon(m_downloadButton, "download");
    m_downloadButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    AppTheme::dimension(m_downloadButton, "minimumWidth", 0);
    m_downloadButton->setEnabled(false);
    connect(m_downloadButton, &QPushButton::clicked, this, &AdminFilesWidget::onDownloadClicked);
    buttonsLayout->addWidget(m_downloadButton);

    filesLayout->addLayout(buttonsLayout);
}

void AdminFilesWidget::setupUsersTab()
{
    m_usersTab = new QWidget();
    QVBoxLayout *usersLayout = new QVBoxLayout(m_usersTab);
    AppTheme::margins(usersLayout, 12, 10, 12, 10);
    AppTheme::spacing(usersLayout, 10);
    usersLayout->setSizeConstraint(QLayout::SetMinimumSize); // Ограничиваем минимальный размер

    // Статус-лейбл для пользователей
    m_usersStatusLabel = new QLabel("Готово");
    m_usersStatusLabel->setAlignment(Qt::AlignCenter);
    AppTheme::role(m_usersStatusLabel, "muted");
    usersLayout->addWidget(m_usersStatusLabel);

    // Таблица пользователей
    m_usersTableWidget = AppTheme::createAdminTable();
    m_usersTableWidget->setColumnCount(6);
    QStringList headers;
    headers << "ID" << "Email" << "Роль" << "Статус" << "Дата создания" << "Действия";
    m_usersTableWidget->setHorizontalHeaderLabels(headers);

    m_usersTableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_usersTableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    m_usersTableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_usersTableWidget->setSortingEnabled(true);
    m_usersTableWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::MinimumExpanding); // MinimumExpanding для правильной работы
    AppTheme::dimension(m_usersTableWidget, "minimumHeight", 180); // Увеличенная минимальная высота
    AppTheme::dimension(m_usersTableWidget, "maximumHeight", 350); // Увеличенная максимальная высота таблицы
    m_usersTableWidget->setWordWrap(false);

    QHeaderView *header = m_usersTableWidget->horizontalHeader();
    header->setSectionResizeMode(0, QHeaderView::ResizeToContents); // ID - по содержимому
    header->setSectionResizeMode(1, QHeaderView::Stretch); // Email - растягиваем
    header->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    header->setSectionsClickable(true);
    header->setSortIndicatorShown(true);

    // Добавляем таблицу без stretch factor, чтобы она не растягивалась
    usersLayout->addWidget(m_usersTableWidget);

    // Кнопка обновления
    m_refreshUsersButton = new QPushButton("Обновить список пользователей");
    AppTheme::buttonIcon(m_refreshUsersButton, "refresh");
    m_refreshUsersButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    AppTheme::dimension(m_refreshUsersButton, "minimumWidth", 0);
    connect(m_refreshUsersButton, &QPushButton::clicked, this, &AdminFilesWidget::onRefreshUsersClicked);
    usersLayout->addWidget(m_refreshUsersButton);
}

void AdminFilesWidget::populateTable()
{
    if (!m_database) {
        m_statusLabel->setText("База данных не подключена");
        AppTheme::role(m_statusLabel, "error");
        return;
    }

    m_progressBar->setVisible(true);
    m_statusLabel->setText("Загрузка данных...");
    AppTheme::role(m_statusLabel, "muted");

    m_allPdfs = m_database->getAllUserPdfs(); // Сохраняем все данные для фильтрации

    // Применяем текущий фильтр, если он есть
    QString currentFilter = m_filterEdit ? m_filterEdit->text().trimmed() : QString();
    if (!currentFilter.isEmpty()) {
        filterTable(currentFilter);
    } else {
        fillTableWithData(m_allPdfs);
    }

    m_progressBar->setVisible(false);
    m_statusLabel->setText(QString("Загружено файлов: %1").arg(m_allPdfs.size()));
    AppTheme::role(m_statusLabel, "muted");
}

void AdminFilesWidget::refreshData()
{
    if (m_database) {
    populateTable();
    populateUsersTable();
    } else {
        qWarning() << "AdminFilesWidget: Database is null, cannot refresh data";
    }
}

void AdminFilesWidget::fillTableWithData(const QList<QMap<QString, QVariant>> &pdfs)
{
    // Сохраняем текущее состояние сортировки перед очисткой
    QHeaderView *header = m_tableWidget->horizontalHeader();
    if (header->sortIndicatorSection() >= 0) {
        m_savedSortColumn = header->sortIndicatorSection();
        m_savedSortOrder = header->sortIndicatorOrder();
    }

    // Отключаем сортировку перед заполнением, чтобы избежать автоматической сортировки
    m_tableWidget->setSortingEnabled(false);

    // Полностью очищаем таблицу перед заполнением
    // Сначала удаляем все строки, затем очищаем содержимое
    int currentRowCount = m_tableWidget->rowCount();
    for (int i = currentRowCount - 1; i >= 0; --i) {
        m_tableWidget->removeRow(i);
    }
    m_tableWidget->clearContents();
    m_tableWidget->setRowCount(0);

    // Фильтруем только валидные записи (с обязательными полями)
    QList<QMap<QString, QVariant>> validPdfs;
    for (const QMap<QString, QVariant> &pdf : pdfs) {
        // Проверяем, что есть все обязательные поля
        if (pdf.contains("id") && pdf["id"].toInt() > 0 &&
            pdf.contains("user_email") && !pdf["user_email"].toString().isEmpty() &&
            pdf.contains("filename") && !pdf["filename"].toString().isEmpty()) {
            validPdfs.append(pdf);
        }
    }

    m_tableWidget->setRowCount(validPdfs.size());

    // Цвет для выделения файлов текущего пользователя (как в сессиях)

    for (int i = 0; i < validPdfs.size(); ++i) {
        const QMap<QString, QVariant> &pdf = validPdfs[i];

        // Email пользователя - проверяем принадлежность текущему пользователю
        QString email = pdf["user_email"].toString();
        bool isCurrentUserFile = (!m_currentUserEmail.isEmpty() && email == m_currentUserEmail);

        // ID - устанавливаем числовое значение для правильной сортировки
        int id = pdf["id"].toInt();
        QTableWidgetItem *idItem = new QTableWidgetItem();
        idItem->setData(Qt::DisplayRole, id); // Устанавливаем числовое значение для правильной сортировки
        idItem->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
        m_tableWidget->setItem(i, 0, idItem);

        // Email пользователя
        QTableWidgetItem *emailItem = new QTableWidgetItem(email);
        emailItem->setToolTip(email); // Tooltip с полным текстом
        if (isCurrentUserFile) { QFont font = emailItem->font(); font.setBold(true); emailItem->setFont(font); }
        m_tableWidget->setItem(i, 1, emailItem);

        // Имя файла
        QString filename = pdf["filename"].toString();
        QTableWidgetItem *filenameItem = new QTableWidgetItem(filename);
        filenameItem->setToolTip(filename); // Tooltip с полным текстом
        m_tableWidget->setItem(i, 2, filenameItem);

        // Алгоритм
        QString algorithm = pdf["algorithm"].toString();
        if (algorithm == "Kuznechik") algorithm = "Кузнечик";
        QTableWidgetItem *algorithmItem = new QTableWidgetItem(algorithm);
        algorithmItem->setToolTip(algorithm);
        m_tableWidget->setItem(i, 3, algorithmItem);

        // Операция
        QString operation = pdf["operation"].toString();
        if (operation == "encrypt") operation = "Шифрование";
        else if (operation == "decrypt") operation = "Расшифровка";
        QTableWidgetItem *operationItem = new QTableWidgetItem(operation);
        operationItem->setToolTip(operation);
        m_tableWidget->setItem(i, 4, operationItem);

        // Дата создания
        QString dateTime = formatDateTime(pdf["created_at"].toDateTime());
        QTableWidgetItem *dateItem = new QTableWidgetItem(dateTime);
        dateItem->setToolTip(dateTime);
        m_tableWidget->setItem(i, 5, dateItem);
    }

    // Включаем сортировку и восстанавливаем сохраненную сортировку
    // ВАЖНО: Включаем сортировку только после того, как все ячейки заполнены
    if (validPdfs.size() > 0) {
        m_tableWidget->setSortingEnabled(true);
        if (m_savedSortColumn >= 0 && m_savedSortColumn < m_tableWidget->columnCount()) {
            // Восстанавливаем сохраненную сортировку
            header->setSortIndicator(m_savedSortColumn, m_savedSortOrder);
            m_tableWidget->sortItems(m_savedSortColumn, m_savedSortOrder);
        } else {
            // Если сортировка не была сохранена (первое открытие), сортируем по ID по умолчанию
            header->setSortIndicator(0, Qt::DescendingOrder); // ID - по убыванию (новые сверху)
            m_tableWidget->sortItems(0, Qt::DescendingOrder);
            m_savedSortColumn = 0;
            m_savedSortOrder = Qt::DescendingOrder;
        }
    } else {
        // Если нет данных, просто включаем сортировку без применения
        m_tableWidget->setSortingEnabled(true);
    }

    // Обновляем статус с учетом фильтрации
    if (m_filterEdit && !m_filterEdit->text().trimmed().isEmpty()) {
        m_statusLabel->setText(QString("Показано файлов: %1 из %2").arg(validPdfs.size()).arg(m_allPdfs.size()));
        AppTheme::role(m_statusLabel, "muted");
    } else {
        m_statusLabel->setText(QString("Загружено файлов: %1").arg(validPdfs.size()));
        AppTheme::role(m_statusLabel, "muted");
    }
}

void AdminFilesWidget::filterTable(const QString &emailFilter)
{
    if (emailFilter.trimmed().isEmpty()) {
        fillTableWithData(m_allPdfs);
        return;
    }

    QString filterLower = emailFilter.trimmed().toLower();
    QList<QMap<QString, QVariant>> filteredPdfs;

    for (const QMap<QString, QVariant> &pdf : m_allPdfs) {
        QString email = pdf["user_email"].toString().toLower();
        if (email.contains(filterLower)) {
            filteredPdfs.append(pdf);
        }
    }

    fillTableWithData(filteredPdfs);
}

void AdminFilesWidget::onFilterTextChanged(const QString &text)
{
    filterTable(text);
}

void AdminFilesWidget::onClearFilterClicked()
{
    if (m_filterEdit) {
        m_filterEdit->clear();
        filterTable(QString()); // Очищаем фильтр
    }
}

void AdminFilesWidget::onRefreshClicked()
{
    refreshData();
}

void AdminFilesWidget::onDownloadClicked()
{
    int currentRow = m_tableWidget->currentRow();
    if (currentRow < 0) {
        AppMessage::warning(this, "Ошибка", "Выберите файл для скачивания");
        return;
    }

    QTableWidgetItem *idItem = m_tableWidget->item(currentRow, 0);
    QTableWidgetItem *filenameItem = m_tableWidget->item(currentRow, 2);

    if (!idItem || !filenameItem) {
        AppMessage::warning(this, "Ошибка", "Не удалось получить данные о файле");
        return;
    }

    int pdfId = idItem->text().toInt();
    QString filename = filenameItem->text();

    if (!m_database) {
        AppMessage::critical(this, "Ошибка", "База данных не подключена");
        return;
    }

    m_progressBar->setVisible(true);
    m_statusLabel->setText("Загрузка файла...");

    QByteArray pdfData = m_database->getPdfByIdForAdmin(pdfId);

    m_progressBar->setVisible(false);

    if (pdfData.isEmpty()) {
        AppMessage::critical(this, "Ошибка",
            QString("Не удалось загрузить файл:\n%1").arg(m_database->getLastError()));
        m_statusLabel->setText("Ошибка загрузки файла");
        AppTheme::role(m_statusLabel, "error");
        return;
    }

    // Предлагаем сохранить файл (аналогично KuznechikWidget)
    const QString defaultDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (QWidget *w = window()) { w->raise(); w->activateWindow(); }

    QFileDialog saveDialog(this, "Сохранить файл", defaultDir + "/" + filename, "PDF файлы (*.pdf);;Все файлы (*)");
    saveDialog.setAcceptMode(QFileDialog::AcceptSave);
    saveDialog.setFileMode(QFileDialog::AnyFile);
    saveDialog.setWindowModality(Qt::ApplicationModal);
    saveDialog.setNameFilter("PDF файлы (*.pdf);;Все файлы (*)");
    saveDialog.setDefaultSuffix("pdf");
    saveDialog.setDirectory(defaultDir);
    saveDialog.selectFile(filename);

    QString savePath;
    if (saveDialog.exec() == QDialog::Accepted) {
        const QStringList files = saveDialog.selectedFiles();
        if (!files.isEmpty()) savePath = files.first();
    }

    if (savePath.isEmpty()) {
        qDebug() << "Скачивание файла отменено пользователем";
        // Не показываем сообщение об отмене, просто выходим
        return;
    }

    // Сохраняем файл
    QFile file(savePath);
    if (!file.open(QIODevice::WriteOnly)) {
        AppMessage::critical(this, "Ошибка", "Не удалось сохранить файл");
        m_statusLabel->setText("Ошибка сохранения файла");
        AppTheme::role(m_statusLabel, "error");
        return;
    }

    file.write(pdfData);
    file.close();

    m_statusLabel->setText(QString("Файл сохранён: %1").arg(QFileInfo(savePath).fileName()));
    AppTheme::role(m_statusLabel, "success");

    AppMessage::information(this, "Успех", QString("Файл успешно сохранён:\n%1").arg(savePath));
}

QString AdminFilesWidget::formatDateTime(const QDateTime &dateTime) const
{
    return dateTime.toString("dd.MM.yyyy HH:mm:ss");
}

void AdminFilesWidget::onBackClicked()
{
    emit backToMenu();
}

void AdminFilesWidget::populateUsersTable()
{
    if (!m_database) {
        if (m_usersStatusLabel) {
            m_usersStatusLabel->setText("База данных не подключена");
            AppTheme::role(m_usersStatusLabel, "error");
        }
        return;
    }

    if (m_usersStatusLabel) {
        m_usersStatusLabel->setText("Загрузка данных...");
    }

    // Загружаем всех пользователей (включая заблокированных) для админ-панели
    QList<User> allUsers;
    QSqlQuery sqlQuery = m_database->select("SELECT * FROM users ORDER BY created_at DESC");

    if (!sqlQuery.isActive()) {
        qDebug() << "Ошибка выполнения запроса пользователей:" << m_database->getLastError();
        if (m_usersStatusLabel) {
            m_usersStatusLabel->setText("Ошибка загрузки данных: " + m_database->getLastError());
            AppTheme::role(m_usersStatusLabel, "error");
        }
        return;
    }

    while (sqlQuery.next()) {
        User user;
        QSqlRecord record = sqlQuery.record();
        user.setId(record.value("id").toInt());
        user.setEmail(record.value("email").toString());
        user.setPasswordHash(record.value("password_hash").toString());
        user.setTOTPSecret(record.value("totp_secret").toString());

        // Парсим дату создания - может быть как DATETIME, так и строка
        QVariant createdAtVar = record.value("created_at");
        if (createdAtVar.typeId() == QMetaType::QDateTime) {
            user.setCreatedAt(createdAtVar.toDateTime());
        } else {
            // Пытаемся распарсить строку
            QString dateStr = createdAtVar.toString();
            QDateTime dateTime = QDateTime::fromString(dateStr, "yyyy-MM-dd HH:mm:ss");
            if (!dateTime.isValid()) {
                dateTime = QDateTime::fromString(dateStr, Qt::ISODate);
            }
            if (!dateTime.isValid()) {
                dateTime = QDateTime::currentDateTime(); // Используем текущую дату, если не удалось распарсить
            }
            user.setCreatedAt(dateTime);
        }

        user.setActive(record.value("is_active").toBool());
        if (record.indexOf("role") >= 0) {
            user.setRole(record.value("role").toString());
        } else {
            user.setRole("user");
        }
        allUsers.append(user);
        // Убрано логирование каждого пользователя - слишком много сообщений
        // qDebug() << "Загружен пользователь:" << user.getEmail() << "ID:" << user.getId() << "Активен:" << user.isActive();
    }

    m_allUsers = allUsers;
    fillUsersTableWithData(m_allUsers);

    if (m_usersStatusLabel) {
        m_usersStatusLabel->setText(QString("Загружено пользователей: %1").arg(m_allUsers.size()));
        AppTheme::role(m_usersStatusLabel, "success");
    }
}

void AdminFilesWidget::fillUsersTableWithData(const QList<User> &users)
{
    if (!m_usersTableWidget) {
        return;
    }

    // Отключаем сортировку перед заполнением
    m_usersTableWidget->setSortingEnabled(false);

    // Очищаем таблицу
    int currentRowCount = m_usersTableWidget->rowCount();
    for (int i = currentRowCount - 1; i >= 0; --i) {
        m_usersTableWidget->removeRow(i);
    }
    m_usersTableWidget->clearContents();
    m_usersTableWidget->setRowCount(0);

    m_usersTableWidget->setRowCount(users.size());

    const auto activeAdmins = std::count_if(users.cbegin(), users.cend(), [](const User &user) {
        return user.isAdmin() && user.isActive();
    });

    for (int i = 0; i < users.size(); ++i) {
        const User &user = users[i];

        // Проверяем, является ли это текущим пользователем
        bool isCurrentUser = (!m_currentUserEmail.isEmpty() && user.getEmail() == m_currentUserEmail);

        // ID
        QTableWidgetItem *idItem = new QTableWidgetItem();
        idItem->setData(Qt::DisplayRole, user.getId());
        idItem->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
        m_usersTableWidget->setItem(i, 0, idItem);

        // Email
        QTableWidgetItem *emailItem = new QTableWidgetItem(user.getEmail());
        emailItem->setToolTip(user.getEmail());
        if (isCurrentUser) { QFont font = emailItem->font(); font.setBold(true); emailItem->setFont(font); }
        m_usersTableWidget->setItem(i, 1, emailItem);

        const bool protectedAdmin = activeAdmins == 1 && user.isAdmin() && user.isActive();
        const QString protectedHint = "Последний активный администратор";

        auto *roleCombo = new QComboBox;
        roleCombo->addItem("Пользователь", "user");
        roleCombo->addItem("Администратор", "admin");
        roleCombo->setCurrentIndex(user.isAdmin() ? 1 : 0);
        roleCombo->setEnabled(!protectedAdmin);
        if (protectedAdmin) roleCombo->setToolTip(protectedHint);
        connect(roleCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, [this, email = user.getEmail(), roleCombo](int index) {
            onUserRoleChanged(email, roleCombo->itemData(index).toString());
        });
        AppTheme::setTableCell(m_usersTableWidget, i, 2, roleCombo, roleCombo->currentText());

        auto *activeCheck = new QCheckBox(user.isActive() ? "Активен" : "Заблокирован");
        activeCheck->setChecked(user.isActive());
        activeCheck->setEnabled(!protectedAdmin);
        if (protectedAdmin) activeCheck->setToolTip(protectedHint);
        connect(activeCheck, &QCheckBox::toggled, this, [this, email = user.getEmail()](bool active) {
            onUserBlockedToggled(email, !active);
        });
        AppTheme::setTableCell(m_usersTableWidget, i, 3, activeCheck, activeCheck->text());

        // Дата создания
        QString dateTime = formatDateTime(user.getCreatedAt());
        QTableWidgetItem *dateItem = new QTableWidgetItem(dateTime);
        dateItem->setToolTip(dateTime);
        m_usersTableWidget->setItem(i, 4, dateItem);

        auto *deleteButton = new QPushButton("Удалить");
        AppTheme::buttonIcon(deleteButton, "delete");
        AppTheme::role(deleteButton, "danger");
        deleteButton->setEnabled(!protectedAdmin);
        if (protectedAdmin) deleteButton->setToolTip(protectedHint);
        connect(deleteButton, &QPushButton::clicked, this, [this, user]() {
            onDeleteUserClicked(user.getId(), user.getEmail());
        });
        AppTheme::setTableCell(m_usersTableWidget, i, 5, deleteButton);
    }

    // Включаем сортировку обратно
    m_usersTableWidget->setSortingEnabled(true);

    // Сортируем по ID по умолчанию (по убыванию)
    QHeaderView *header = m_usersTableWidget->horizontalHeader();
    header->setSortIndicator(0, Qt::DescendingOrder);
    m_usersTableWidget->sortItems(0, Qt::DescendingOrder);
}

void AdminFilesWidget::onUserRoleChanged(int index)
{
    // Этот метод будет вызываться из lambda, но нам нужен email пользователя
    // Поэтому используем другой подход - передаем email напрямую
}

void AdminFilesWidget::onUserRoleChanged(const QString &email, const QString &role)
{
    if (!m_database) {
        AppMessage::warning(this, "Ошибка", "База данных не подключена");
        return;
    }

    if (m_database->updateUserRole(email, role)) {
        if (m_usersStatusLabel) {
            m_usersStatusLabel->setText(QString("Роль пользователя %1 изменена на %2").arg(email).arg(role));
            AppTheme::role(m_usersStatusLabel, "success");
        }
        // Обновляем таблицу
        populateUsersTable();
    } else {
        AppMessage::critical(this, "Ошибка",
            QString("Не удалось изменить роль пользователя:\n%1").arg(m_database->getLastError()));
        populateUsersTable();
    }
}

void AdminFilesWidget::onUserBlockedToggled(bool blocked)
{
    // Этот метод будет вызываться из lambda, но нам нужен email пользователя
    // Поэтому используем другой подход - передаем email напрямую
}

void AdminFilesWidget::onUserBlockedToggled(const QString &email, bool blocked)
{
    if (!m_database) {
        AppMessage::warning(this, "Ошибка", "База данных не подключена");
        return;
    }

    if (m_database->setUserBlocked(email, blocked)) {
        if (m_usersStatusLabel) {
            m_usersStatusLabel->setText(QString("Пользователь %1 %2").arg(email).arg(blocked ? "заблокирован" : "разблокирован"));
            AppTheme::role(m_usersStatusLabel, "success");
        }
        // Обновляем таблицу
        populateUsersTable();
    } else {
        AppMessage::critical(this, "Ошибка",
            QString("Не удалось изменить статус блокировки:\n%1").arg(m_database->getLastError()));
        populateUsersTable();
    }
}

void AdminFilesWidget::onDeleteUserClicked(int userId, const QString &email)
{
    if (!m_database) {
        AppMessage::warning(this, "Ошибка", "База данных не подключена");
        return;
    }

    // Показываем диалог подтверждения
    if (!AppMessage::confirm(
        this,
        "Подтверждение удаления",
        QString("Вы уверены, что хотите удалить пользователя %1?\n\n"
                "Это действие удалит:\n"
                "- Все сессии пользователя\n"
                "- Все записи в audit_log\n"
                "- Все face embeddings\n"
                "- Все PDF документы\n"
                "- Самого пользователя\n\n"
                "Это действие необратимо!").arg(email),
        "Удалить пользователя")) {
        return;
    }

    // Выполняем удаление
    if (m_database->deleteUserPermanently(userId)) {
        if (m_usersStatusLabel) {
            m_usersStatusLabel->setText(QString("Пользователь %1 успешно удален").arg(email));
            AppTheme::role(m_usersStatusLabel, "success");
        }
        // Обновляем таблицу
        refreshData();
        AppMessage::information(this, "Успех", QString("Пользователь %1 успешно удален со всеми связанными данными.").arg(email));
    } else {
        AppMessage::critical(this, "Ошибка",
            QString("Не удалось удалить пользователя:\n%1").arg(m_database->getLastError()));
    }
}

void AdminFilesWidget::onRefreshUsersClicked()
{
    populateUsersTable();
}

