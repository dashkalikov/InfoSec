#include "mainwindow.h"
#include "apptheme.h"
#include "loginmemory.h"
#include <QGridLayout>
#include <QStackedLayout>
#include "rbacguard.h"
#include <QApplication>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QCheckBox>
#include <QCloseEvent>
#include <QClipboard>
#include <QCoreApplication>
#include <QDir>
#include <QFormLayout>
#include <QFrame>
#include <QGraphicsOpacityEffect>
#include <QImage>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QTimer>
#include <QRegularExpression>
#include <QScrollArea>
#include <QScrollBar>
#include <QDebug>
#include <QStandardPaths>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPixmap>
#include <QPainterPath>
#include <QPointer>
#include <QPropertyAnimation>
#include <QPalette>
#include <QBrush>
#include <QResizeEvent>
#include <QWheelEvent>
#include <QWindow>
#include <algorithm>
#include <iterator>

MainWindow::MainWindow(QWidget *parent, Qt::WindowFlags flags)
    : QMainWindow(parent, flags | Qt::FramelessWindowHint)
    , m_stackedWidget(nullptr)
    , m_database(nullptr)
    , m_authService(nullptr)
    , m_totpService(nullptr)
    , m_faceAuthService(nullptr)
    , m_factor2Widget(nullptr)
    , m_faceAuthWidget(nullptr)
    , m_factor3Widget(nullptr)
    , m_kuznechikWidget(nullptr)
    , m_kuznechikWidgetContent(nullptr)
    , m_adminFilesWidget(nullptr)
    , m_adminFilesWidgetContent(nullptr)
    , m_sessionWidget(nullptr)
    , m_sessionWidgetContent(nullptr)
    , m_forgotPasswordWidget(nullptr)
    , m_forgotPasswordWidgetContent(nullptr)
    , m_enrollingFace(false)
    , m_registerCameraWidget(nullptr)
    , m_signServerProcess(nullptr)
    , m_sessionCheckTimer(nullptr)
{
    AppTheme::restore();

    // Инициализируем базу данных и сервис аутентификации
    m_database = new Database(this);
    // m_caDatabase = new CaDatabase(this); // ЗАКОММЕНТИРОВАНО
    m_authService = new AuthService(m_database, this);
    m_totpService = new TOTPService(this);
    m_totpService->setPageDark(AppTheme::isDark());
    m_faceAuthService = new FaceAuthService(m_database, this);

    const QString faceModelDir = QDir(QCoreApplication::applicationDirPath()).filePath("resources/face");
    if (!m_faceAuthService->initialize(faceModelDir)) {
        qWarning() << "Не удалось инициализировать сервис распознавания лиц. Проверьте модели в" << faceModelDir;
    }

    // Подключаемся к базе данных пользователей
    if (!m_database->connect()) {
        AppMessage::persistent(this, "Ошибка", "Не удалось подключиться к базе данных: " + m_database->getLastError(), AppMessage::Kind::Error);
        return;
    }

    // Подключаемся к базе данных сертификатов - ЗАКОММЕНТИРОВАНО
    // if (!m_caDatabase->connect()) {
    //     qWarning() << "Не удалось подключиться к базе данных сертификатов: " << m_caDatabase->getLastError();
    // } else {
    //     // Инициализируем и запускаем воркер для управления сертификатами
    //     m_certificateWorker = new CertificateWorker(m_caDatabase, this);
    //     m_certificateWorker->startWorker();
    //     qDebug() << "CertificateWorker: Воркер инициализирован и запущен";
    // }

    // Инициализируем и запускаем воркер для автоматической разблокировки истекших аккаунтов - ЗАКОММЕНТИРОВАНО
    // m_lockoutCleanupWorker = new LockoutCleanupWorker(m_database, this);
    // m_lockoutCleanupWorker->startWorker();
    // qDebug() << "LockoutCleanupWorker: Воркер инициализирован и запущен";

    setupUI();
    setupStatusBar();

    connectSignals();

    // Инициализируем таймер для периодической проверки истечения сессии
    m_sessionCheckTimer = new QTimer(this);
    m_sessionCheckTimer->setInterval(10000); // Проверяем каждые 10 секунд для быстрой реакции на удаление сессии
    connect(m_sessionCheckTimer, &QTimer::timeout, this, &MainWindow::checkSessionExpiration);

    // Очищаем истекшие сессии из БД при старте приложения
    m_authService->cleanupExpiredSessions();

    // Пытаемся восстановить состояние из активной сессии
    qDebug() << "MainWindow: Checking for active session to restore...";
    if (m_authService->restoreFromSession()) {
        // Сессия восстановлена - показываем главное меню
        qDebug() << "MainWindow: Session restored, showing main menu";
        showMainMenuAfterAuth();
        // Запускаем таймер проверки истечения сессии
        m_sessionCheckTimer->start();
    } else {
        // Нет активной сессии - показываем форму входа
        qDebug() << "MainWindow: No active session found, showing login form";
        showLoginForm();
    }

    setWindowTitle("3FA — Безопасность");
    setMinimumSize(680, 480);
    resizeAndCenter(1040, 750);

    // Запускаем сервер подписи в фоне
    startSignServer();
}

MainWindow::~MainWindow()
{
    // Останавливаем воркер сертификатов перед закрытием - ЗАКОММЕНТИРОВАНО
    // if (m_certificateWorker) {
    //     qDebug() << "MainWindow: Остановка CertificateWorker...";
    //     m_certificateWorker->stopWorker();
    //
    //     // Ждем завершения потока с таймаутом
    //     if (!m_certificateWorker->wait(5000)) { // Ждем до 5 секунд
    //         qWarning() << "MainWindow: CertificateWorker не завершился в течение 5 секунд";
    //     }
    //
    //     qDebug() << "MainWindow: CertificateWorker остановлен";
    // }

    // Останавливаем воркер разблокировки аккаунтов - ЗАКОММЕНТИРОВАНО
    // if (m_lockoutCleanupWorker) {
    //     qDebug() << "MainWindow: Остановка LockoutCleanupWorker...";
    //     m_lockoutCleanupWorker->stopWorker();
    //
    //     // Ждем завершения потока с таймаутом
    //     if (!m_lockoutCleanupWorker->wait(3000)) { // Ждем до 3 секунд
    //         qWarning() << "MainWindow: LockoutCleanupWorker не завершился в течение 3 секунд";
    //     }
    //
    //     qDebug() << "MainWindow: LockoutCleanupWorker остановлен";
    // }

    // НЕ вызываем logout() при закрытии приложения - сессии должны сохраняться
    // для восстановления состояния при следующем запуске
    // logout() вызывается только при явном выходе пользователя (кнопка "Выйти")

    // Останавливаем сервер подписи
    stopSignServer();
}

namespace {
constexpr int zoomSteps[] = {75, 80, 90, 100, 110, 125, 150, 175, 200};
constexpr int zoomPreviewMs = 1150;
constexpr int zoomFadeMs = 180;
constexpr int gripWidth = 5;

class PageStack final : public QStackedWidget
{
public:
    QSize sizeHint() const override { return currentWidget() ? currentWidget()->sizeHint() : QSize(); }
    QSize minimumSizeHint() const override { return currentWidget() ? currentWidget()->minimumSizeHint() : QSize(); }
    bool hasHeightForWidth() const override { return currentWidget() && currentWidget()->hasHeightForWidth(); }
    int heightForWidth(int width) const override
    {
        return hasHeightForWidth() ? currentWidget()->heightForWidth(width) : minimumSizeHint().height();
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter painter(this);
        painter.fillRect(rect(), palette().alternateBase());
    }
};

class GlassZoomPanel final : public QFrame
{
public:
    GlassZoomPanel(QWidget *parent, QWidget *backdrop) : QFrame(parent), m_backdrop(backdrop)
    {
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QImage sample(size(), QImage::Format_ARGB32_Premultiplied);
        sample.fill(palette().color(QPalette::Window));
        if (m_backdrop && m_backdrop->isVisible()) {
            const QPoint origin = m_backdrop->mapFromGlobal(mapToGlobal(QPoint(0, 0)));
            QPainter snapshot(&sample);
            m_backdrop->render(&snapshot, QPoint(0, 0), QRegion(QRect(origin, size())));
        }
        const auto softened = sample.scaled(qMax(1, width() / 9), qMax(1, height() / 9),
                                            Qt::IgnoreAspectRatio, Qt::SmoothTransformation);

        const bool dark = AppTheme::isDark();
        const QRectF bounds = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
        QPainterPath shape;
        shape.addRoundedRect(bounds, 16, 16);
        QLinearGradient tint(bounds.topLeft(), bounds.bottomLeft());
        tint.setColorAt(0, dark ? QColor(44, 50, 63, 218) : QColor(255, 255, 255, 224));
        tint.setColorAt(1, dark ? QColor(25, 29, 37, 224) : QColor(235, 242, 253, 192));

        QPainter painter(this);
        painter.setRenderHints(QPainter::Antialiasing | QPainter::SmoothPixmapTransform);
        painter.save();
        painter.setClipPath(shape);
        painter.drawImage(rect(), softened);
        painter.fillPath(shape, tint);
        painter.restore();

        QLinearGradient rim(bounds.topLeft(), bounds.bottomLeft());
        rim.setColorAt(0, dark ? QColor(216, 231, 255, 62) : QColor(255, 255, 255, 226));
        rim.setColorAt(1, dark ? QColor(143, 162, 202, 35) : QColor(112, 137, 174, 62));
        painter.setPen(QPen(rim, 1));
        painter.drawPath(shape);
    }

private:
    QPointer<QWidget> m_backdrop;
};

class CaptionButton final : public QPushButton
{
public:
    CaptionButton() { setAttribute(Qt::WA_Hover); }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        const auto circle = QRectF(rect()).adjusted(1, 1, -1, -1);
        if (underMouse() || isDown()) {
            QColor tint = palette().color(QPalette::Link);
            tint.setAlpha(isDown() ? 78 : 51);
            painter.setPen(Qt::NoPen);
            painter.setBrush(tint);
            painter.drawEllipse(circle);
        }
        if (hasFocus()) {
            painter.setBrush(Qt::NoBrush);
            painter.setPen(QPen(palette().link().color(), 1));
            painter.drawEllipse(circle);
        }
        QRect glyph(QPoint(0, 0), iconSize());
        glyph.moveCenter(rect().center());
        icon().paint(&painter, glyph, Qt::AlignCenter, isEnabled() ? QIcon::Normal : QIcon::Disabled);
    }
};

class ResizeGrip final : public QWidget
{
public:
    ResizeGrip(QWidget *parent, Qt::Edges edges, Qt::CursorShape cursor)
        : QWidget(parent), m_edges(edges)
    {
        setCursor(cursor);
    }

protected:
    void mousePressEvent(QMouseEvent *event) override
    {
        if (event->button() == Qt::LeftButton && window()->windowHandle()) {
            window()->windowHandle()->startSystemResize(m_edges);
            event->accept();
        }
    }

private:
    Qt::Edges m_edges;
};

QLabel *textLabel(const QString &text, const char *role = "muted")
{
    auto *label = new QLabel(text);
    AppTheme::role(label, role);
    return label;
}

QLabel *wrappedLabel(const QString &text, const char *role = "muted")
{
    auto *label = textLabel(text, role);
    label->setWordWrap(true);
    return label;
}

void fieldLabel(QVBoxLayout *layout, const QString &caption, QWidget *field)
{
    auto *label = textLabel(caption, "section");
    label->setBuddy(field);
    layout->addWidget(label);
}
}

void MainWindow::setupUI()
{
    auto *shell = new QWidget;
    shell->setObjectName("appShell");
    auto *layout = new QVBoxLayout(shell);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    auto *header = new QFrame;
    header->setObjectName("appTitleBar");
    header->setFixedHeight(54);
    auto *headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(16, 0, 12, 0);
    headerLayout->setSpacing(10);
    m_titleDrag = new QWidget;
    auto *brandLayout = new QHBoxLayout(m_titleDrag);
    brandLayout->setContentsMargins(0, 0, 0, 0);
    brandLayout->setSpacing(12);
    auto *logo = new QLabel;
    logo->setPixmap(AppTheme::logo().pixmap(QSize(28, 28)));
    brandLayout->addWidget(logo);
    brandLayout->addWidget(textLabel("3FA", "brand"));
    brandLayout->addWidget(textLabel("Безопасность и криптография"));
    brandLayout->addStretch();
    for (auto *label : m_titleDrag->findChildren<QLabel *>()) label->setAttribute(Qt::WA_TransparentForMouseEvents);
    headerLayout->addWidget(m_titleDrag, 1);

    auto *themeToggle = new QPushButton;
    themeToggle->setObjectName("themeToggle");
    themeToggle->setFixedSize(124, 32);
    themeToggle->setFocusPolicy(Qt::TabFocus);
    themeToggle->setProperty("fixedChromeIcon", true);
    AppTheme::role(themeToggle, "glassTool");
    const auto updateThemeButton = [themeToggle] {
        const bool dark = AppTheme::isDark();
        themeToggle->setText(dark ? "Светлая тема" : "Тёмная тема");
        AppTheme::buttonIcon(themeToggle, dark ? "sun" : "moon");
    };
    updateThemeButton();
    connect(themeToggle, &QPushButton::clicked, this, [this, updateThemeButton] {
        AppTheme::setDark(!AppTheme::isDark());
        m_totpService->setPageDark(AppTheme::isDark());
        updateThemeButton();
    });
    headerLayout->addWidget(themeToggle);
    auto *windowControls = new QFrame;
    windowControls->setObjectName("windowControls");
    windowControls->setFixedHeight(38);
    auto *captionLayout = new QHBoxLayout(windowControls);
    captionLayout->setContentsMargins(3, 3, 3, 3);
    captionLayout->setSpacing(3);
    headerLayout->addWidget(windowControls);
    const auto captionButton = [captionLayout](const char *name, const QString &label, const char *glyph) {
        auto *button = new CaptionButton;
        button->setObjectName(name);
        button->setAccessibleName(label);
        button->setToolTip(label);
        button->setFixedSize(32, 32);
        button->setFocusPolicy(Qt::TabFocus);
        button->setProperty("fixedChromeIcon", true);
        AppTheme::role(button, "caption");
        AppTheme::buttonIcon(button, glyph);
        captionLayout->addWidget(button);
        return button;
    };
    connect(captionButton("windowMinimize", "Свернуть окно", "minimize"), &QPushButton::clicked, this, &QWidget::showMinimized);
    m_maximizeButton = captionButton("windowMaximize", "Развернуть окно", "maximize");
    connect(m_maximizeButton, &QPushButton::clicked, this, &MainWindow::toggleMaximized);
    connect(captionButton("windowClose", "Закрыть окно", "close"), &QPushButton::clicked, this, &QWidget::close);
    layout->addWidget(header);

    auto *pageScroll = new QScrollArea;
    pageScroll->setObjectName("pageScroll");
    pageScroll->setFrameShape(QFrame::NoFrame);
    pageScroll->setWidgetResizable(true);
    m_stackedWidget = new PageStack;
    m_stackedWidget->setObjectName("mainPages");
    m_stackedWidget->layout()->setSizeConstraint(QLayout::SetNoConstraint);
    pageScroll->setWidget(m_stackedWidget);
    connect(m_stackedWidget, &QStackedWidget::currentChanged, pageScroll, [this, pageScroll] {
        adjustPageLayouts();
        m_stackedWidget->updateGeometry();
        pageScroll->horizontalScrollBar()->setValue(0);
        pageScroll->verticalScrollBar()->setValue(0);
    });
    layout->addWidget(pageScroll, 1);
    setCentralWidget(shell);
    setupZoomPanel(shell, pageScroll->viewport());
    auto *titleMenu = new QMenu(header);
    auto *zoomAction = titleMenu->addAction("Масштаб…", this, &MainWindow::showZoomPanel);
    zoomAction->setObjectName("showZoomPanel");
    header->setContextMenuPolicy(Qt::CustomContextMenu);
    m_titleDrag->setToolTip("Правый щелчок — меню окна");
    connect(header, &QWidget::customContextMenuRequested, this, [header, titleMenu](const QPoint &point) {
        titleMenu->popup(header->mapToGlobal(point));
    });
    for (auto *scrollBar : {pageScroll->horizontalScrollBar(), pageScroll->verticalScrollBar()}) {
        connect(scrollBar, &QScrollBar::valueChanged, m_zoomPanel, qOverload<>(&QWidget::update));
    }
    connect(m_stackedWidget, &QStackedWidget::currentChanged, m_zoomPanel, qOverload<>(&QWidget::update));
    m_resizeGrips = {
        new ResizeGrip(this, Qt::TopEdge, Qt::SizeVerCursor),
        new ResizeGrip(this, Qt::BottomEdge, Qt::SizeVerCursor),
        new ResizeGrip(this, Qt::LeftEdge, Qt::SizeHorCursor),
        new ResizeGrip(this, Qt::RightEdge, Qt::SizeHorCursor),
        new ResizeGrip(this, Qt::TopEdge | Qt::LeftEdge, Qt::SizeFDiagCursor),
        new ResizeGrip(this, Qt::TopEdge | Qt::RightEdge, Qt::SizeBDiagCursor),
        new ResizeGrip(this, Qt::BottomEdge | Qt::LeftEdge, Qt::SizeBDiagCursor),
        new ResizeGrip(this, Qt::BottomEdge | Qt::RightEdge, Qt::SizeFDiagCursor)
    };
    qApp->installEventFilter(this);

    setupLoginForm();
    setupRegisterForm();
    setupFactor2Form();
    setupFactor3Form();
    setupForgotPasswordWidget();
    setupMainMenu();
    setupKuznechikWidget();
    adjustPageLayouts();
}

void MainWindow::setupZoomPanel(QWidget *shell, QWidget *backdrop)
{
    auto *layer = new QFrame(shell);
    layer->setObjectName("zoomPanel");
    layer->setFixedSize(260, 72);
    auto *panel = new GlassZoomPanel(layer, backdrop);
    panel->setFixedSize(236, 48);
    panel->move(12, 8);
    auto *row = new QHBoxLayout(panel);
    row->setContentsMargins(14, 7, 8, 7);
    row->setSpacing(4);
    m_zoomPanel = layer;
    m_zoomLabel = new QLabel;
    m_zoomLabel->setAccessibleName("Текущий масштаб");
    row->addWidget(m_zoomLabel);
    row->addStretch();
    const auto control = [row](const char *name, const QString &text, const QString &description, int width) {
        auto *button = new QPushButton(text);
        button->setObjectName(name);
        button->setToolTip(description);
        button->setAccessibleName(description);
        button->setFixedSize(width, 32);
        button->setFocusPolicy(Qt::TabFocus);
        row->addWidget(button);
        return button;
    };
    m_zoomOut = control("zoomOut", "−", "Уменьшить масштаб", 32);
    m_zoomIn = control("zoomIn", "+", "Увеличить масштаб", 32);
    auto *reset = control("zoomReset", "Сброс", "Вернуть 100%", 62);
    connect(m_zoomOut, &QPushButton::clicked, this, [this] { stepZoom(-1, true); });
    connect(m_zoomIn, &QPushButton::clicked, this, [this] { stepZoom(1, true); });
    connect(reset, &QPushButton::clicked, this, [this] { setZoom(100, true); });
    auto *opacity = new QGraphicsOpacityEffect(layer);
    opacity->setOpacity(1);
    layer->setGraphicsEffect(opacity);
    m_zoomFade = new QPropertyAnimation(opacity, "opacity", this);
    m_zoomFade->setDuration(zoomFadeMs);
    m_zoomFade->setEndValue(0.0);
    connect(m_zoomFade, &QPropertyAnimation::finished, layer, &QWidget::hide);
    m_zoomTimer = new QTimer(this);
    m_zoomTimer->setSingleShot(true);
    connect(m_zoomTimer, &QTimer::timeout, this, [this] {
        if (!m_zoomPanel->underMouse()) fadeZoomPanel();
    });
    layer->hide();
    setZoom(AppTheme::zoomPercent());
}

void MainWindow::showZoomPanel()
{
    m_zoomFade->stop();
    m_zoomFade->targetObject()->setProperty("opacity", 1.0);
    m_zoomPanel->show();
    placeWindowControls();
    m_zoomTimer->start(zoomPreviewMs);
}

void MainWindow::fadeZoomPanel()
{
    if (!m_zoomPanel->isVisible() || m_zoomFade->state() == QAbstractAnimation::Running) return;
    m_zoomTimer->stop();
    m_zoomFade->setStartValue(m_zoomFade->targetObject()->property("opacity"));
    m_zoomFade->start();
}

void MainWindow::setZoom(int percent, bool preview)
{
    AppTheme::setZoomPercent(percent);
    adjustPageLayouts();
    refreshQrPixmap();
    const int zoom = AppTheme::zoomPercent();
    const QString label = QString::number(zoom) + '%';
    m_zoomLabel->setText(label);
    m_zoomOut->setEnabled(zoom > zoomSteps[0]);
    m_zoomIn->setEnabled(zoom < zoomSteps[std::size(zoomSteps) - 1]);
    if (preview) showZoomPanel();
    else placeWindowControls();
}

void MainWindow::stepZoom(int direction, bool preview)
{
    const int zoom = AppTheme::zoomPercent();
    if (direction > 0) {
        const auto next = std::upper_bound(std::begin(zoomSteps), std::end(zoomSteps), zoom);
        setZoom(next == std::end(zoomSteps) ? zoom : *next, preview);
    } else {
        const auto next = std::lower_bound(std::begin(zoomSteps), std::end(zoomSteps), zoom);
        setZoom(next == std::begin(zoomSteps) ? zoom : *std::prev(next), preview);
    }
}

void MainWindow::placeWindowControls()
{
    if (m_zoomPanel && m_zoomPanel->isVisible()) {
        const int headerBottom = m_titleDrag->parentWidget()->height();
        m_zoomPanel->move(qMax(0, centralWidget()->width() - m_zoomPanel->width() - 4), headerBottom + 2);
        m_zoomPanel->raise();
    }
    const bool resizable = !isFullScreen() && !isMaximized();
    const int edge = gripWidth;
    const int right = width() - edge;
    const int bottom = height() - edge;
    const QRect grips[] = {
        {edge, 0, width() - 2 * edge, edge}, {edge, bottom, width() - 2 * edge, edge},
        {0, edge, edge, height() - 2 * edge}, {right, edge, edge, height() - 2 * edge},
        {0, 0, edge, edge}, {right, 0, edge, edge}, {0, bottom, edge, edge}, {right, bottom, edge, edge}
    };
    for (size_t i = 0; i < m_resizeGrips.size(); ++i) {
        if (auto *grip = m_resizeGrips[i]) {
            grip->setGeometry(grips[i]);
            grip->setVisible(resizable);
            if (resizable) grip->raise();
        }
    }
}

void MainWindow::toggleMaximized()
{
    if (isFullScreen()) toggleFullscreen();
    else if (isMaximized()) showNormal();
    else showMaximized();
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    adjustPageLayouts();
    placeWindowControls();
}

void MainWindow::adjustPageLayouts()
{
    if (!m_stackedWidget) return;
    const auto placeColumns = [this](QBoxLayout *layout, int threshold) {
        if (layout) layout->setDirection(width() < AppTheme::pixels(threshold) ? QBoxLayout::TopToBottom : QBoxLayout::LeftToRight);
    };
    placeColumns(m_loginLinks, 430);
    placeColumns(m_registerColumns, 820);
    placeColumns(m_totpColumns, 690);

    const bool compact = width() < AppTheme::pixels(520);
    for (auto *layout : m_stackedWidget->findChildren<QVBoxLayout *>("centeredPageLayout")) {
        AppTheme::margins(layout, compact ? 10 : 20, 22, compact ? 10 : 20, 22);
    }
    for (auto *layout : m_stackedWidget->findChildren<QVBoxLayout *>("centeredCardLayout")) {
        AppTheme::margins(layout, compact ? 16 : 32, 30, compact ? 16 : 32, 30);
    }
}

void MainWindow::changeEvent(QEvent *event)
{
    QMainWindow::changeEvent(event);
    if (event->type() == QEvent::WindowStateChange && m_maximizeButton) {
        const bool restore = isMaximized() || isFullScreen();
        const QString label = restore ? "Восстановить размер окна" : "Развернуть окно";
        m_maximizeButton->setAccessibleName(label);
        m_maximizeButton->setToolTip(label);
        AppTheme::buttonIcon(m_maximizeButton, restore ? "restore" : "maximize");
        QTimer::singleShot(0, this, &MainWindow::adjustPageLayouts);
        placeWindowControls();
    }
}

bool MainWindow::eventFilter(QObject *watched, QEvent *event)
{
    auto *widget = qobject_cast<QWidget *>(watched);
    if (!widget || widget->window() != this) return false;

    if (event->type() == QEvent::KeyPress || event->type() == QEvent::ShortcutOverride) {
        auto *key = static_cast<QKeyEvent *>(event);
        const int code = key->key();
        const bool dismiss = code == Qt::Key_Escape && m_zoomPanel->isVisible();
        const bool zoomKey = key->modifiers().testFlag(Qt::ControlModifier) &&
            !(key->modifiers() & (Qt::AltModifier | Qt::MetaModifier)) &&
            (code == Qt::Key_Plus || code == Qt::Key_Equal || code == Qt::Key_Minus || code == Qt::Key_0);
        if (dismiss || zoomKey) {
            if (event->type() == QEvent::KeyPress) {
                if (dismiss) fadeZoomPanel();
                else if (code == Qt::Key_0) setZoom(100, true);
                else stepZoom(code == Qt::Key_Minus ? -1 : 1, true);
            }
            event->accept();
            return true;
        }
    } else if (event->type() == QEvent::Wheel) {
        auto *wheel = static_cast<QWheelEvent *>(event);
        if (wheel->modifiers().testFlag(Qt::ControlModifier) && wheel->angleDelta().y()) {
            m_zoomWheelDelta += wheel->angleDelta().y();
            if (qAbs(m_zoomWheelDelta) >= 120) {
                stepZoom(m_zoomWheelDelta > 0 ? 1 : -1, true);
                m_zoomWheelDelta %= 120;
            }
            event->accept();
            return true;
        }
        m_zoomWheelDelta = 0;
    } else if (event->type() == QEvent::MouseButtonPress) {
        if (!m_zoomPanel->isAncestorOf(widget) && widget != m_zoomPanel) fadeZoomPanel();
        if (widget == m_titleDrag) m_titlePress = static_cast<QMouseEvent *>(event)->position().toPoint();
    } else if (widget == m_zoomPanel && event->type() == QEvent::Leave && m_zoomPanel->isVisible() &&
               m_zoomFade->state() != QAbstractAnimation::Running) {
        m_zoomTimer->start(zoomPreviewMs);
    }

    if (widget == m_titleDrag) {
        if (event->type() == QEvent::MouseButtonDblClick && static_cast<QMouseEvent *>(event)->button() == Qt::LeftButton) {
            toggleMaximized();
            return true;
        }
        if (event->type() == QEvent::MouseMove && !isFullScreen() && windowHandle()) {
            auto *mouse = static_cast<QMouseEvent *>(event);
            if (mouse->buttons().testFlag(Qt::LeftButton) &&
                (mouse->position().toPoint() - m_titlePress).manhattanLength() >= QApplication::startDragDistance()) {
                return windowHandle()->startSystemMove();
            }
        }
    }
    return QMainWindow::eventFilter(watched, event);
}

void MainWindow::setupStatusBar()
{
    auto *bar = statusBar();
    bar->setSizeGripEnabled(false);
    m_statusLabel = textLabel("Готово к работе");
    m_statusLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_statusLabel->setTextFormat(Qt::PlainText);
    m_statusLabel->setContentsMargins(14, 4, 14, 4);
    bar->addWidget(m_statusLabel, 1);
}

void MainWindow::setupLoginForm()
{
    m_loginWidget = new QWidget;
    m_loginWidget->setObjectName("loginPage");
    auto *card = AppTheme::centeredCard(m_loginWidget, 504);
    auto *steps = new QHBoxLayout;
    AppTheme::spacing(steps, 10);
    steps->addWidget(textLabel("01  Пароль", "badge"));
    steps->addWidget(textLabel("02  Код"));
    steps->addWidget(textLabel("03  Лицо"));
    steps->addStretch();
    card->addLayout(steps);
    card->addWidget(wrappedLabel("Вход в систему", "title"));
    card->addWidget(wrappedLabel("Введите данные вашего аккаунта."));
    card->addSpacing(4);

    m_loginEmailEdit = new QLineEdit;
    m_loginEmailEdit->setPlaceholderText("Введите адрес почты");
    m_loginEmailEdit->setInputMethodHints(Qt::ImhEmailCharactersOnly);
    auto *email = new QVBoxLayout;
    AppTheme::spacing(email, 7);
    fieldLabel(email, "Электронная почта", m_loginEmailEdit);
    email->addWidget(m_loginEmailEdit);
    card->addLayout(email);

    m_loginPasswordEdit = new QLineEdit;
    m_loginPasswordEdit->setEchoMode(QLineEdit::Password);
    m_loginPasswordEdit->setPlaceholderText("Введите пароль");
    auto *password = new QVBoxLayout;
    AppTheme::spacing(password, 7);
    fieldLabel(password, "Пароль", m_loginPasswordEdit);
    password->addWidget(m_loginPasswordEdit);
    card->addLayout(password);
    connect(m_loginPasswordEdit, &QLineEdit::returnPressed, this, &MainWindow::onLoginClicked);
    connect(m_loginPasswordEdit, &QLineEdit::textEdited, this, [this] { m_prefilledLoginPassword = false; });
    connect(m_loginEmailEdit, &QLineEdit::textChanged, this, [this] {
        if (!m_prefilledLoginPassword) return;
        m_prefilledLoginPassword = false;
        m_loginPasswordEdit->clear();
        m_rememberPassword->setChecked(false);
    });
    m_rememberPassword = new QCheckBox("Запомнить пароль на этом устройстве");
    m_rememberPassword->setObjectName("rememberLoginPassword");
    m_rememberPassword->setToolTip("Настройка применяется после успешного входа");
    if (!LoginMemory::canSavePassword()) m_rememberPassword->hide();
    card->addWidget(m_rememberPassword);

    m_loginButton = new QPushButton("Продолжить");
    m_loginButton->setDefault(true);
    AppTheme::role(m_loginButton, "primary");
    AppTheme::buttonIcon(m_loginButton, "enter");
    card->addSpacing(4);
    card->addWidget(m_loginButton);

    auto *links = new QHBoxLayout;
    m_loginLinks = links;
    m_showRegisterButton = new QPushButton("Создать аккаунт");
    m_forgotPasswordButton = new QPushButton("Забыли пароль?");
    AppTheme::role(m_showRegisterButton, "quiet");
    AppTheme::role(m_forgotPasswordButton, "quiet");
    links->addWidget(m_showRegisterButton);
    links->addStretch();
    links->addWidget(m_forgotPasswordButton);
    card->addLayout(links);
    m_stackedWidget->addWidget(m_loginWidget);
}

void MainWindow::setupRegisterForm()
{
    m_registerWidget = new QWidget;
    m_registerWidget->setObjectName("registerPage");
    auto *card = AppTheme::centeredCard(m_registerWidget, 864);
    card->addWidget(textLabel("АККАУНТ", "eyebrow"));
    card->addWidget(wrappedLabel("Регистрация", "title"));
    card->addWidget(wrappedLabel("Создайте аккаунт и добавьте образец лица для входа."));
    card->addSpacing(6);

    auto *columns = new QHBoxLayout;
    m_registerColumns = columns;
    AppTheme::spacing(columns, 32);
    auto *account = new QVBoxLayout;
    AppTheme::spacing(account, 12);
    auto *biometrics = new QVBoxLayout;
    AppTheme::spacing(biometrics, 12);
    columns->addLayout(account, 1);
    columns->addLayout(biometrics, 1);
    card->addLayout(columns);

    m_registerEmailEdit = new QLineEdit;
    m_registerEmailEdit->setPlaceholderText("Введите адрес почты");
    m_registerEmailEdit->setInputMethodHints(Qt::ImhEmailCharactersOnly);
    fieldLabel(account, "Электронная почта", m_registerEmailEdit);
    account->addWidget(m_registerEmailEdit);
    m_registerPasswordEdit = new QLineEdit;
    m_registerConfirmPasswordEdit = new QLineEdit;
    const auto addPassword = [account](const QString &caption, QLineEdit *field, QPushButton *&toggle) {
        field->setEchoMode(QLineEdit::Password);
        fieldLabel(account, caption, field);
        auto *row = new QHBoxLayout;
        AppTheme::spacing(row, 6);
        toggle = new QPushButton;
        toggle->setToolTip("Показать или скрыть пароль");
        toggle->setAccessibleName(toggle->toolTip());
        AppTheme::fixedSize(toggle, 36, 34);
        AppTheme::role(toggle, "tool");
        AppTheme::buttonIcon(toggle, "eye");
        row->addWidget(field, 1);
        row->addWidget(toggle);
        account->addLayout(row);
    };
    addPassword("Пароль", m_registerPasswordEdit, m_passwordToggleButton);
    addPassword("Подтвердите пароль", m_registerConfirmPasswordEdit, m_confirmPasswordToggleButton);
    connect(m_registerPasswordEdit, &QLineEdit::textChanged, this, &MainWindow::validatePassword);

    auto *requirements = new QGridLayout;
    m_passwordLengthCheck = textLabel("От 8 символов");
    m_passwordLowercaseCheck = textLabel("Строчная буква");
    m_passwordUppercaseCheck = textLabel("Заглавная буква");
    m_passwordDigitCheck = textLabel("Цифра");
    requirements->addWidget(m_passwordLengthCheck, 0, 0);
    requirements->addWidget(m_passwordLowercaseCheck, 0, 1);
    requirements->addWidget(m_passwordUppercaseCheck, 1, 0);
    requirements->addWidget(m_passwordDigitCheck, 1, 1);
    account->addLayout(requirements);

    m_registerButton = new QPushButton("Создать аккаунт");
    AppTheme::role(m_registerButton, "primary");
    AppTheme::buttonIcon(m_registerButton, "plus");
    account->addSpacing(4);
    account->addWidget(m_registerButton);
    m_showLoginButton = new QPushButton("Уже есть аккаунт? Войти");
    AppTheme::role(m_showLoginButton, "quiet");
    account->addWidget(m_showLoginButton, 0, Qt::AlignLeft);
    account->addStretch();

    biometrics->addWidget(textLabel("Образец лица", "section"));
    auto *cameraFrame = new QFrame;
    AppTheme::role(cameraFrame, "inset");
    auto *cameraLayout = new QStackedLayout(cameraFrame);
    AppTheme::margins(cameraLayout, 6, 6, 6, 6);
    cameraLayout->setStackingMode(QStackedLayout::StackAll);
    m_registerCameraWidget = new CameraCaptureWidget;
    m_registerCameraLabel = textLabel("Создайте аккаунт, чтобы записать образец лица", "camera");
    m_registerCameraLabel->setAlignment(Qt::AlignCenter);
    m_registerCameraLabel->setWordWrap(true);
    cameraLayout->addWidget(m_registerCameraWidget);
    cameraLayout->addWidget(m_registerCameraLabel);
    cameraLayout->setCurrentWidget(m_registerCameraLabel);
    biometrics->addWidget(cameraFrame);
    m_registerStatusLabel = textLabel("");
    m_registerStatusLabel->setWordWrap(true);
    biometrics->addWidget(m_registerStatusLabel);
    m_registerFaceButton = new QPushButton("Зарегистрировать лицо");
    AppTheme::buttonIcon(m_registerFaceButton, "camera");
    m_registerFaceButton->setEnabled(false);
    biometrics->addWidget(m_registerFaceButton);
    biometrics->addStretch();
    connect(m_registerCameraWidget, &CameraCaptureWidget::registrationCompleted, this, &MainWindow::onRegisterFaceVerified);
    connect(m_registerCameraWidget, &CameraCaptureWidget::registrationFailed, this, &MainWindow::onRegisterFaceFailed);
    connect(m_registerCameraWidget, &CameraCaptureWidget::statusUpdate, this, &MainWindow::onRegisterStatusUpdate);
    m_stackedWidget->addWidget(m_registerWidget);
}

void MainWindow::setupFactor2Form()
{
    m_factor2Widget = new QWidget;
    m_factor2Widget->setObjectName("totpPage");
    auto *card = AppTheme::centeredCard(m_factor2Widget, 780);
    card->addWidget(textLabel("ЭТАП 2 ИЗ 3", "eyebrow"));
    card->addWidget(wrappedLabel("Одноразовый код", "title"));
    auto *instructions = textLabel("Откройте QR камерой телефона. Используйте ту же локальную сеть.");
    instructions->setWordWrap(true);
    card->addWidget(instructions);

    auto *columns = new QHBoxLayout;
    m_totpColumns = columns;
    AppTheme::spacing(columns, 28);
    auto *scan = new QVBoxLayout;
    auto *verify = new QVBoxLayout;
    AppTheme::spacing(scan, 12);
    AppTheme::spacing(verify, 16);
    columns->addLayout(scan, 1);
    columns->addLayout(verify, 2);
    card->addLayout(columns);

    m_qrCodeLabel = textLabel("", "qr");
    AppTheme::fixedSize(m_qrCodeLabel, 224, 224);
    m_qrCodeLabel->setAlignment(Qt::AlignCenter);
    scan->addWidget(m_qrCodeLabel, 0, Qt::AlignHCenter);
    verify->addStretch();
    verify->addWidget(textLabel("Код подтверждения", "section"));
    m_factor2InstructionsLabel = textLabel("Введите 6 цифр с открывшейся страницы.");
    m_factor2InstructionsLabel->setWordWrap(true);
    verify->addWidget(m_factor2InstructionsLabel);
    m_totpCodeWidget = new TOTPInputWidget;
    verify->addWidget(m_totpCodeWidget, 0, Qt::AlignLeft);
    auto *actions = new QHBoxLayout;
    m_factor2BackButton = new QPushButton("Назад");
    AppTheme::role(m_factor2BackButton, "quiet");
    AppTheme::buttonIcon(m_factor2BackButton, "back");
    m_factor2VerifyButton = new QPushButton("Проверить код");
    AppTheme::role(m_factor2VerifyButton, "primary");
    AppTheme::buttonIcon(m_factor2VerifyButton, "check");
    actions->addWidget(m_factor2BackButton);
    auto *copyLink = new QPushButton("Копировать ссылку");
    AppTheme::role(copyLink, "quiet");
    connect(copyLink, &QPushButton::clicked, this, [this] {
        if (!m_factor2PageUrl.isEmpty()) {
            QApplication::clipboard()->setText(m_factor2PageUrl);
            m_statusLabel->setText("Ссылка на страницу кода скопирована");
        }
    });
    scan->addWidget(copyLink, 0, Qt::AlignHCenter);
    actions->addStretch();
    actions->addWidget(m_factor2VerifyButton);
    verify->addLayout(actions);
    verify->addStretch();
    m_stackedWidget->addWidget(m_factor2Widget);
}

void MainWindow::setupFactor3Form()
{
    if (!m_faceAuthService) {
        return;
    }

    m_factor3Widget = new QWidget();
    m_factor3Widget->setObjectName("facePage");
    QVBoxLayout *layout = new QVBoxLayout(m_factor3Widget);
    AppTheme::margins(layout, 0, 0, 0, 0);

    m_faceAuthWidget = new FaceAuthWidget(m_faceAuthService, m_factor3Widget);
    layout->addWidget(m_faceAuthWidget);

    connect(m_faceAuthWidget, &FaceAuthWidget::faceVerified, this, &MainWindow::onFaceFactorVerified);
    connect(m_faceAuthWidget, &FaceAuthWidget::verificationFailed, this, &MainWindow::onFaceFactorFailed);

    m_stackedWidget->addWidget(m_factor3Widget);
}

void MainWindow::setupKuznechikWidget()
{
    m_kuznechikWidgetContent = new KuznechikWidget;
    m_kuznechikWidget = m_kuznechikWidgetContent;

    connect(m_kuznechikWidgetContent, &KuznechikWidget::backToMenu, this, &MainWindow::showMainMenuAfterAuth);
    connect(m_kuznechikWidgetContent, &KuznechikWidget::logoutRequested, this, &MainWindow::onUserLoggedOut);

    m_stackedWidget->addWidget(m_kuznechikWidget);
}

void MainWindow::setupAdminFilesWidget()
{
    m_adminFilesWidget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(m_adminFilesWidget);
    AppTheme::margins(layout, 0, 0, 0, 0);

    m_adminFilesWidgetContent = new AdminFilesWidget(m_database, m_adminFilesWidget);
    layout->addWidget(m_adminFilesWidgetContent);

    connect(m_adminFilesWidgetContent, &AdminFilesWidget::backToMenu, this, &MainWindow::showMainMenuAfterAuth);

    m_stackedWidget->addWidget(m_adminFilesWidget);
}

void MainWindow::setupForgotPasswordWidget()
{
    m_forgotPasswordWidget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(m_forgotPasswordWidget);
    AppTheme::margins(layout, 0, 0, 0, 0);

    m_forgotPasswordWidgetContent = new ForgotPasswordWidget(m_database, m_authService, m_forgotPasswordWidget);
    layout->addWidget(m_forgotPasswordWidgetContent);

    connect(m_forgotPasswordWidgetContent, &ForgotPasswordWidget::backToLogin, this, &MainWindow::showLoginForm);
    connect(m_forgotPasswordWidgetContent, &ForgotPasswordWidget::passwordResetSuccess, this, &MainWindow::showLoginForm);

    m_stackedWidget->addWidget(m_forgotPasswordWidget);
}

void MainWindow::showAdminFilesWidget()
{
    if (!m_adminFilesWidget) {
        setupAdminFilesWidget();
    }

    if (m_stackedWidget->indexOf(m_adminFilesWidget) == -1) {
        m_stackedWidget->addWidget(m_adminFilesWidget);
    }

    if (m_adminFilesWidgetContent) {
        m_adminFilesWidgetContent->setDatabase(m_database);
        // Передаём email текущего пользователя для выделения его файлов
        if (m_authService) {
            const User user = m_authService->getCurrentUser();
            if (!user.getEmail().isEmpty()) {
                m_adminFilesWidgetContent->setCurrentUserEmail(user.getEmail());
            }
        }
        m_adminFilesWidgetContent->refreshData();
    }

    m_stackedWidget->setCurrentWidget(m_adminFilesWidget);
}

void MainWindow::setupSessionWidget()
{
    m_sessionWidget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(m_sessionWidget);
    AppTheme::margins(layout, 0, 0, 0, 0);

    m_sessionWidgetContent = new SessionWidget(m_database, m_authService, m_sessionWidget);
    layout->addWidget(m_sessionWidgetContent);

    connect(m_sessionWidgetContent, &SessionWidget::backToMenu, this, &MainWindow::showMainMenuAfterAuth);

    m_stackedWidget->addWidget(m_sessionWidget);
}

void MainWindow::showSessionWidget()
{
    if (!m_sessionWidget) {
        setupSessionWidget();
    }

    if (m_stackedWidget->indexOf(m_sessionWidget) == -1) {
        m_stackedWidget->addWidget(m_sessionWidget);
    }

    if (m_sessionWidgetContent) {
        m_sessionWidgetContent->setDatabase(m_database);
        m_sessionWidgetContent->setAuthService(m_authService);
        m_sessionWidgetContent->refreshData();
    }

    m_stackedWidget->setCurrentWidget(m_sessionWidget);
}

void MainWindow::showKuznechikWidget()
{
    if (!m_kuznechikWidget) {
        setupKuznechikWidget();
    }

    // Проверяем, что виджет действительно добавлен в stack
    if (m_stackedWidget->indexOf(m_kuznechikWidget) == -1) {
        qWarning() << "Kuznechik widget not in stack, adding it";
        m_stackedWidget->addWidget(m_kuznechikWidget);
    }

    // Перед показом пробросим email и ID текущего пользователя в виджет
    if (m_authService && m_kuznechikWidgetContent) {
        const User user = m_authService->getCurrentUser();
        if (!user.getEmail().isEmpty()) {
            m_kuznechikWidgetContent->setUserEmail(user.getEmail());
            m_kuznechikWidgetContent->setUserId(user.getId());
        }
        if (m_database) {
            m_kuznechikWidgetContent->setDatabase(m_database);
        }
    }

    m_stackedWidget->setCurrentWidget(m_kuznechikWidget);

}

void MainWindow::startFaceCapture(const User &user, bool enroll)
{
    if (!m_faceAuthService || !m_faceAuthService->isReady()) {
        showMessage("Ошибка", "Распознавание лица недоступно. Проверьте модели и повторите вход.", AppMessage::Kind::Warning);
        showLoginForm();
        return;
    }

    if (!m_faceAuthWidget) {
        setupFactor3Form();
    }

    m_pendingFaceUser = user;
    m_enrollingFace = enroll;

    m_faceAuthWidget->setUser(user);
    if (enroll) {
        m_faceAuthWidget->setEnrollmentMode(true);
    }
    m_stackedWidget->setCurrentWidget(m_factor3Widget);
    if (!enroll) {
        QTimer::singleShot(300, m_faceAuthWidget, &FaceAuthWidget::startVerification);
    }
}

void MainWindow::setupMainMenu()
{
    m_mainMenuWidget = new QWidget;
    m_mainMenuWidget->setObjectName("workspacePage");
    auto *workspace = AppTheme::centeredCard(m_mainMenuWidget, 808);
    workspace->addWidget(textLabel("РАБОЧЕЕ ПРОСТРАНСТВО", "eyebrow"));
    m_welcomeLabel = wrappedLabel("Панель управления", "title");
    workspace->addWidget(m_welcomeLabel);
    workspace->addWidget(wrappedLabel("Инструменты шифрования и параметры аккаунта."));
    workspace->addSpacing(6);
    auto *tools = new QVBoxLayout;
    auto *account = new QVBoxLayout;
    AppTheme::spacing(tools, 12);
    AppTheme::spacing(account, 12);
    workspace->addLayout(tools);
    workspace->addSpacing(8);
    workspace->addLayout(account);
    tools->addWidget(textLabel("Инструменты", "section"));

    const auto tool = [this, tools](const QString &caption, const char *glyph, void (MainWindow::*action)()) {
        auto *button = new QPushButton(caption);
        AppTheme::role(button, "nav");
        AppTheme::buttonIcon(button, glyph);
        tools->addWidget(button);
        connect(button, &QPushButton::clicked, this, action);
        return button;
    };
    m_kuznechikButton = tool("Шифрование · Кузнечик / RSA", "lock", &MainWindow::showKuznechikWidget);
    m_adminFilesButton = tool("Файлы и пользователи", "users", &MainWindow::showAdminFilesWidget);
    m_sessionsButton = tool("Активные сессии", "clock", &MainWindow::showSessionWidget);
    m_adminFilesButton->hide();
    m_sessionsButton->hide();

    account->addWidget(textLabel("Текущий аккаунт", "section"));
    m_userInfoText = new QTextEdit;
    m_userInfoText->setReadOnly(true);
    AppTheme::fixedHeight(m_userInfoText, 144);
    account->addWidget(m_userInfoText);
    m_logoutButton = new QPushButton("Выйти");
    AppTheme::role(m_logoutButton, "quiet");
    AppTheme::buttonIcon(m_logoutButton, "exit");
    account->addWidget(m_logoutButton, 0, Qt::AlignLeft);
    m_stackedWidget->addWidget(m_mainMenuWidget);
}

void MainWindow::connectSignals()
{
    // Подключаем сигналы кнопок
    connect(m_loginButton, &QPushButton::clicked, this, &MainWindow::onLoginClicked);
    connect(m_showRegisterButton, &QPushButton::clicked, this, &MainWindow::showRegisterForm);
    connect(m_forgotPasswordButton, &QPushButton::clicked, this, &MainWindow::showForgotPasswordForm);

    connect(m_registerButton, &QPushButton::clicked, this, &MainWindow::onRegisterClicked);
    connect(m_registerFaceButton, &QPushButton::clicked, this, &MainWindow::onRegisterFaceClicked);
    connect(m_showLoginButton, &QPushButton::clicked, this, &MainWindow::showLoginForm);
    connect(m_passwordToggleButton, &QPushButton::clicked, this, &MainWindow::togglePasswordVisibility);
    connect(m_confirmPasswordToggleButton, &QPushButton::clicked, this, &MainWindow::toggleConfirmPasswordVisibility);

    connect(m_factor2VerifyButton, &QPushButton::clicked, this, &MainWindow::onFactor2VerifyClicked);
    connect(m_factor2BackButton, &QPushButton::clicked, this, &MainWindow::onFactor2BackClicked);

    // Автоматическая проверка при завершении ввода кода
    connect(m_totpCodeWidget, &TOTPInputWidget::codeCompleted, this, &MainWindow::onFactor2VerifyClicked);

    connect(m_logoutButton, &QPushButton::clicked, this, &MainWindow::onUserLoggedOut);

    // Подключаем сигналы сервиса аутентификации
    connect(m_authService, &AuthService::userRegistered, this, &MainWindow::onUserRegistered);
    connect(m_authService, &AuthService::userLoggedIn, this, &MainWindow::onUserLoggedIn);
    connect(m_authService, &AuthService::userLoggedOut, this, &MainWindow::onUserLoggedOut);
    // Убрано подключение сигнала authenticationFailed - сообщение об ошибке показывается в onLoginClicked
    // connect(m_authService, &AuthService::authenticationFailed, this, &MainWindow::onAuthenticationFailed);
    connect(m_authService, &AuthService::errorOccurred, this, &MainWindow::onErrorOccurred);
}

void MainWindow::onRegisterClicked()
{
    QString email = m_registerEmailEdit->text().trimmed();
    QString password = m_registerPasswordEdit->text();
    QString confirmPassword = m_registerConfirmPasswordEdit->text();

    // Проверяем совпадение паролей
    if (password != confirmPassword) {
        showMessage("Ошибка", "Пароли не совпадают", AppMessage::Kind::Warning);
        return;
    }

    // Прогресс-бар не используется (скрыт)
    // if (m_progressBar) {
    //     m_progressBar->setVisible(true);
    //     m_progressBar->setRange(0, 0);
    // }

    // Регистрируем пользователя
    if (m_authService->registerUser(email, password)) {
        showMessage("Успех", "Пользователь успешно зарегистрирован! Теперь зарегистрируйте ваше лицо.", AppMessage::Kind::Information);

        // Блокируем левую часть регистрации
        if (m_registerEmailEdit) m_registerEmailEdit->setEnabled(false);
        if (m_registerPasswordEdit) m_registerPasswordEdit->setEnabled(false);
        if (m_registerConfirmPasswordEdit) m_registerConfirmPasswordEdit->setEnabled(false);
        if (m_registerButton) m_registerButton->setEnabled(false);

        // Блокируем кнопки "глазки"
        if (m_passwordToggleButton) m_passwordToggleButton->setEnabled(false);
        if (m_confirmPasswordToggleButton) m_confirmPasswordToggleButton->setEnabled(false);

        // Блокируем кнопку входа
        if (m_showLoginButton) {
            m_showLoginButton->setEnabled(false);
        }

        // Разблокируем кнопку регистрации лица
        m_registerFaceButton->setEnabled(true);
        m_registerCameraLabel->setText("Нажмите «Зарегистрировать лицо», чтобы включить камеру");

        User newUser = m_database->findUserByEmail(email);
        if (newUser.isValid() && newUser.getId() >= 0) {
            // Сохраняем пользователя для регистрации лица
            m_pendingFaceUser = newUser;

            // Передаем пользователя и сервис в CameraCaptureWidget
            if (m_registerCameraWidget) {
                m_registerCameraWidget->setUserAndService(m_pendingFaceUser, m_faceAuthService);
            }

        } else {
            showMessage("Информация", "Не удалось получить данные пользователя для регистрации лица. Войдите и добавьте лицо позже.", AppMessage::Kind::Warning);
            showLoginForm();
        }
    } else {
        showMessage("Ошибка", m_authService->getLastError(), AppMessage::Kind::Error);
    }

    // Прогресс-бар не используется
    // if (m_progressBar) m_progressBar->setVisible(false);
}

void MainWindow::onLoginClicked()
{
    QString email = m_loginEmailEdit->text().trimmed();
    QString password = m_loginPasswordEdit->text();

    // Прогресс-бар не используется
    // if (m_progressBar) {
    //     m_progressBar->setVisible(true);
    //     m_progressBar->setRange(0, 0);
    // }

    // Входим в систему
    if (m_authService->loginUser(email, password)) {
        m_pendingLoginPassword = m_rememberPassword->isChecked() ? password : QString();
        showMessage("Успех", "Первый фактор пройден! Переходим ко второму...", AppMessage::Kind::Information);
        clearForms();
        showFactor2Form();
    } else {
        showMessage("Ошибка", m_authService->getLastError(), AppMessage::Kind::Error);
    }

    // Прогресс-бар не используется
    // if (m_progressBar) m_progressBar->setVisible(false);
}

void MainWindow::showForgotPasswordForm()
{
    if (!m_forgotPasswordWidget) {
        setupForgotPasswordWidget();
    }

    if (m_stackedWidget->indexOf(m_forgotPasswordWidget) == -1) {
        m_stackedWidget->addWidget(m_forgotPasswordWidget);
    }

    // Получаем email из поля ввода на форме входа
    QString email = m_loginEmailEdit->text().trimmed();

    if (m_forgotPasswordWidgetContent) {
        m_forgotPasswordWidgetContent->setDatabase(m_database);
        m_forgotPasswordWidgetContent->setAuthService(m_authService);
        m_forgotPasswordWidgetContent->setEmail(email);
        m_forgotPasswordWidgetContent->resetForm();
    }

    m_stackedWidget->setCurrentWidget(m_forgotPasswordWidget);
}

void MainWindow::showLoginForm()
{
    if (m_kuznechikWidgetContent) m_kuznechikWidgetContent->setUserId(-1);
    // Останавливаем камеру регистрации если она работает
    // Это нужно делать при явном переходе на форму входа (например, при нажатии кнопки "Войти" на форме регистрации)
    // Закрываем камеру полностью, так как выходим из окна регистрации
    if (m_registerCameraWidget) {
        m_registerCameraWidget->stopCapture(true);  // true = закрыть камеру
        m_registerCameraWidget->resetState();
    }

    // Останавливаем камеру третьего фактора если она работает
    if (m_faceAuthWidget) {
        m_faceAuthWidget->stopCapture();
    }

    m_pendingLoginPassword.reset();
    m_prefilledLoginPassword = false;
    const auto saved = LoginMemory::restore();
    m_loginEmailEdit->setText(saved.email);
    m_loginPasswordEdit->setText(saved.password);
    m_prefilledLoginPassword = !saved.password.isEmpty();
    m_rememberPassword->setChecked(m_prefilledLoginPassword);

    m_stackedWidget->setCurrentWidget(m_loginWidget);
    (saved.email.isEmpty() ? m_loginEmailEdit : m_loginPasswordEdit)->setFocus();
}

void MainWindow::showRegisterForm()
{
    // Сбрасываем состояние формы регистрации
    m_registerEmailEdit->clear();
    m_registerEmailEdit->setEnabled(true);
    m_registerPasswordEdit->clear();
    m_registerPasswordEdit->setEnabled(true);
    m_registerConfirmPasswordEdit->clear();
    m_registerConfirmPasswordEdit->setEnabled(true);
    m_registerButton->setEnabled(true);
    m_registerButton->setText("Создать аккаунт");
    m_passwordToggleButton->setEnabled(true);
    m_confirmPasswordToggleButton->setEnabled(true);
    m_showLoginButton->setEnabled(true);

    // Сбрасываем кнопку регистрации лица
    m_registerFaceButton->setEnabled(false);
    m_registerFaceButton->setText("Зарегистрировать лицо");

    // Скрываем статусное сообщение регистрации лица
    if (m_registerStatusLabel) {
        m_registerStatusLabel->setVisible(false);
    }

    m_registerCameraWidget->resetState();
    if (m_registerCameraLabel) {
        m_registerCameraLabel->setVisible(true);
        m_registerCameraLabel->setText("Создайте аккаунт, чтобы записать образец лица");
    }

    // Очищаем сохраненные данные
    m_pendingFaceUser = User();

    m_stackedWidget->setCurrentWidget(m_registerWidget);
    m_registerEmailEdit->setFocus();
}

void MainWindow::showMainMenu()
{
    // Останавливаем камеру регистрации если она работает
    // Закрываем камеру полностью, так как переходим на главное меню
    if (m_registerCameraWidget) {
        m_registerCameraWidget->stopCapture(true);  // true = закрыть камеру
    }

    // Останавливаем камеру третьего фактора если она работает
    if (m_faceAuthWidget) {
        m_faceAuthWidget->stopCapture();
    }

    qDebug() << "🎉 Показываем главное меню...";

    User currentUser = m_authService->getCurrentUser();
    rememberSuccessfulLogin(currentUser);
    qDebug() << "Текущий пользователь:" << currentUser.getEmail();

    // Обновляем информацию о пользователе
    m_welcomeLabel->setText("Панель управления");

    QString userInfo = QString(
        "Email: %1\n"
        "Дата регистрации: %2\n"
        "Статус: %3\n\n"
        "Уровень аутентификации: 3 фактора\n"
        "Многофакторная аутентификация завершена!\n\n"
        "Пройденные факторы:\n"
        "• Пароль (первый фактор)\n"
        "• TOTP код (второй фактор)\n"
        "• Распознавание лица (третий фактор)"
    ).arg(currentUser.getEmail())
     .arg(currentUser.getCreatedAt().toString("dd.MM.yyyy HH:mm"))
     .arg(currentUser.isActive() ? "Активен" : "Неактивен");

    m_userInfoText->setPlainText(userInfo);

    // Получаем пользователя из БД для получения роли
    User userFromDB = m_database->findUserByEmail(currentUser.getEmail());

    // Показываем/скрываем кнопку админа в зависимости от роли через RBACGuard - ЗАГЛУШКА
    if (m_adminFilesButton) {
        m_adminFilesButton->setVisible(RBACGuard::isAdmin(userFromDB));
    }

    qDebug() << "Переключаемся на главное меню...";
    m_stackedWidget->setCurrentWidget(m_mainMenuWidget);
    qDebug() << "[OK] Главное меню показано успешно!";
}

void MainWindow::showMainMenuAfterAuth()
{
    qDebug() << "🎉 Показываем главное меню после аутентификации...";

    // Сохраняем сессию в БД после успешной аутентификации
    m_authService->saveSessionToDb();

    // Запускаем таймер проверки истечения сессии, если он еще не запущен
    if (m_sessionCheckTimer && !m_sessionCheckTimer->isActive()) {
        m_sessionCheckTimer->start();
    }

    User currentUser = m_authService->getCurrentUser();
    rememberSuccessfulLogin(currentUser);
    qDebug() << "Текущий пользователь:" << currentUser.getEmail();

    // Получаем пользователя из БД для получения роли
    User userFromDB = m_database->findUserByEmail(currentUser.getEmail());

    // Обновляем информацию о пользователе
    m_welcomeLabel->setText("Панель управления");

    QString roleText = RBACGuard::isAdmin(userFromDB) ? "Администратор" : "Пользователь";
    QString userInfo = QString(
        "Email: %1\n"
        "Дата регистрации: %2\n"
        "Статус: %3\n"
        "Роль: %4\n"
        "Уровень аутентификации: 3 фактора"
    ).arg(userFromDB.getEmail())
     .arg(userFromDB.getCreatedAt().toString("dd.MM.yyyy HH:mm"))
     .arg(userFromDB.isActive() ? "Активен" : "Неактивен")
     .arg(roleText);

    m_userInfoText->setPlainText(userInfo);

    // Показываем/скрываем кнопку админа в зависимости от роли через RBACGuard - ЗАГЛУШКА
    if (m_adminFilesButton) {
        m_adminFilesButton->setVisible(RBACGuard::isAdmin(userFromDB));
        qDebug() << "Роль пользователя:" << userFromDB.getRole() << ", isAdmin:" << RBACGuard::isAdmin(userFromDB);
    }

    // Показываем/скрываем кнопку "Активные сессии" только для админа - ЗАГЛУШКА
    if (m_sessionsButton) {
        m_sessionsButton->setVisible(RBACGuard::isAdmin(userFromDB));
    }

    qDebug() << "Переключаемся на главное меню после аутентификации...";
    m_stackedWidget->setCurrentWidget(m_mainMenuWidget);
    qDebug() << "[OK] Главное меню показано успешно!";
}

void MainWindow::showFactor2Form()
{
    // Получаем текущего пользователя из AuthService
    User currentUser = m_authService->getCurrentUser();

    qDebug() << "Current user email:" << currentUser.getEmail();
    qDebug() << "Current user valid:" << currentUser.isValid();

    // Проверяем, что пользователь валиден
    if (!currentUser.isValid() || currentUser.getEmail().isEmpty()) {
        showMessage("Ошибка", "Пользователь не найден. Пожалуйста, войдите заново.", AppMessage::Kind::Error);
        showLoginForm();
        return;
    }

    // Генерируем новый секрет если его нет
    QString secret = currentUser.getTOTPSecret();
    if (secret.isEmpty()) {
        secret = m_totpService->generateSecret();
        currentUser.setTOTPSecret(secret);
        // Сохраняем секрет в текущем пользователе AuthService (но не в БД)
        // Секрет будет сохранен в БД только после успешной проверки первого кода
        m_authService->updateCurrentUser(currentUser);
        qDebug() << "TOTP секрет сгенерирован и сохранен в текущем пользователе:" << secret;
    }

    // Генерируем QR-код с веб-страницей (без запуска таймера)
    m_qrPixmap = m_totpService->generateQRCode(secret, currentUser.getEmail(), "3FA Security", false, &m_factor2PageUrl);
    if (m_qrPixmap.isNull()) {
        showMessage("Страница кода недоступна", "Проверьте настройки сети и повторите вход.", AppMessage::Kind::Error);
        showLoginForm();
        return;
    }

    qDebug() << "Generated secret:" << secret;

    refreshQrPixmap();

    // Обновляем инструкции с секретным ключом
    const QString instructions = QStringLiteral("Введите 6 цифр с открывшейся страницы.");
    m_factor2InstructionsLabel->setText(instructions);

    // Останавливаем камеру регистрации если она работает
    // Закрываем камеру полностью, так как переходим на второй фактор
    if (m_registerCameraWidget) {
        m_registerCameraWidget->stopCapture(true);  // true = закрыть камеру
    }

    // Очищаем поле ввода
    m_totpCodeWidget->clear();

    m_stackedWidget->setCurrentWidget(m_factor2Widget);
    m_totpCodeWidget->setFocus();
}

void MainWindow::refreshQrPixmap()
{
    if (m_qrPixmap.isNull()) return;
    const int size = AppTheme::pixels(196);
    m_qrCodeLabel->setPixmap(m_qrPixmap.scaled(size, size, Qt::KeepAspectRatio, Qt::FastTransformation));
}

void MainWindow::showFactor3Form()
{
    User currentUser = m_authService->getCurrentUser();
    if (!currentUser.isValid() || currentUser.getId() < 0) {
        showMessage("Ошибка", "Пользователь не найден. Войдите заново.", AppMessage::Kind::Error);
        showLoginForm();
        return;
    }

    const auto hasFace = m_database->hasUserFaceEmbedding(currentUser.getId());
    if (!hasFace) {
        showMessage("Ошибка", "Не удалось проверить, есть ли сохранённый образец лица. Повторите вход.", AppMessage::Kind::Error);
        showLoginForm();
        return;
    }
    startFaceCapture(currentUser, !*hasFace);
}

void MainWindow::onFactor2VerifyClicked()
{
    QString totpCode = m_totpCodeWidget->getCode();

    if (totpCode.length() != 6) {
        showMessage("Ошибка", "Введите 6-значный код", AppMessage::Kind::Warning);
        return;
    }

    User currentUser = m_authService->getCurrentUser();

    // Получаем секрет из базы данных или из текущего пользователя (если еще не сохранен)
    User userFromDB = m_database->findUserByEmail(currentUser.getEmail());
    QString secret = userFromDB.getTOTPSecret();

    // Если секрет не в БД, берем из currentUser (для первого сканирования)
    if (secret.isEmpty()) {
        secret = currentUser.getTOTPSecret();
    }

    if (secret.isEmpty()) {
        showMessage("Ошибка", "TOTP секрет не найден. Пожалуйста, обновите страницу.", AppMessage::Kind::Error);
        return;
    }

    // Генерируем текущий код для сравнения
    QString currentCode = m_totpService->generateTOTPCode(secret);
    qDebug() << "Введенный код:" << totpCode;
    qDebug() << "Текущий код сервера:" << currentCode;
    // Не логируем секрет в консоль, чтобы избежать утечек

    // Проверяем TOTP код
    if (m_totpService->verifyTOTPCode(secret, totpCode)) {
        qDebug() << "[OK] Второй фактор аутентификации пройден!";

        // Если секрет еще не сохранен в БД (первое сканирование), сохраняем его
        if (userFromDB.getTOTPSecret().isEmpty() || userFromDB.getTOTPSecret() != secret) {
            if (!m_database->updateUserTOTPSecret(currentUser.getEmail(), secret)) {
                qWarning() << "Не удалось сохранить TOTP секрет после подтверждения";
            } else {
                qDebug() << "TOTP секрет сохранен в БД после успешного сканирования";
                // Теперь запускаем таймер обновления кода, так как секрет подтвержден
                QString currentCode = m_totpService->generateTOTPCode(secret);
                m_totpService->startCodeUpdateTimer(secret, currentCode);
            }
        }

        if (m_faceAuthService && m_faceAuthService->isReady()) {
            showFactor3Form();
        } else {
            showMessage("Успех", "Второй фактор пройден! Распознавание лица недоступно, выполняем вход.", AppMessage::Kind::Information);
            // Сохраняем сессию в БД после успешной аутентификации (без 3-го фактора)
            m_authService->saveSessionToDb();
            showMainMenu();
        }
    } else {
        showMessage("Ошибка", "Неверный код. Попробуйте еще раз.", AppMessage::Kind::Warning);
        m_totpCodeWidget->clear();
        m_totpCodeWidget->setFocus();
    }
}

void MainWindow::onFactor2BackClicked()
{
    m_statusLabel->setText("Готово к работе");
    showLoginForm();
}

void MainWindow::onFaceFactorVerified()
{
    if (m_stackedWidget->currentWidget() != m_factor3Widget || !m_pendingFaceUser.isValid() ||
        m_pendingFaceUser.getId() != m_authService->getCurrentUser().getId()) {
        return;
    }
    const bool enrolled = m_enrollingFace;
    m_enrollingFace = false;
    m_pendingFaceUser = User();
    m_statusLabel->setText(enrolled ? "Образец лица сохранён" : "Пользователь прошёл распознавание лица");
    showMessage("Успех", enrolled ? "Образец лица сохранён. Вход выполнен."
                                  : "Третий фактор аутентификации пройден! Доступ к системе открыт.",
                AppMessage::Kind::Information);
    showMainMenuAfterAuth();
}

void MainWindow::onFaceFactorFailed(const QString &reason)
{
    showMessage("Ошибка", reason, AppMessage::Kind::Warning);
    if (m_enrollingFace) {
        m_enrollingFace = false;
        m_pendingFaceUser = User();
        showLoginForm();
    }
}

void MainWindow::onRegisterFaceClicked()
{
    qDebug() << "[REGISTER] onRegisterFaceClicked() вызван";

    if (!m_pendingFaceUser.isValid()) {
        qWarning() << "[REGISTER] m_pendingFaceUser не валиден!";
        showMessage("Ошибка", "Нет данных пользователя для регистрации лица", AppMessage::Kind::Error);
        return;
    }

    qDebug() << "[REGISTER] m_pendingFaceUser валиден, продолжаем...";

    // Освобождаем место для предпросмотра камеры
    m_registerCameraLabel->setVisible(false);

    // Показываем статусную надпись (если она была скрыта)
    if (m_registerStatusLabel) {
        m_registerStatusLabel->setVisible(true);
        m_registerStatusLabel->setText("Расположите лицо в центре круга.");
    }

    // Запускаем регистрацию с таймером
    qDebug() << "[REGISTER] Проверяем m_registerCameraWidget:" << (m_registerCameraWidget ? "exists" : "null");
    if (m_registerCameraWidget) {
        // Проверяем, запущена ли камера, и запускаем только если не запущена
        // Это предотвращает лишние перезапуски, которые вызывают мигание индикатора
        qDebug() << "[REGISTER] Проверяем состояние камеры...";
        // startCapture() сам проверяет, запущена ли камера, но лучше не вызывать его лишний раз
        m_registerCameraWidget->startCapture();
        qDebug() << "[REGISTER] Камера проверена/запущена";

        qDebug() << "[REGISTER] Вызываем startFaceRegistration()...";
        m_registerCameraWidget->startFaceRegistration();
        qDebug() << "[REGISTER] Регистрация запущена";
    } else {
        qWarning() << "[REGISTER] Камера регистрации недоступна";
    }

    // Отключаем кнопку во время регистрации
    m_registerFaceButton->setEnabled(false);
    m_registerFaceButton->setText("Записываем образец лица");
}

void MainWindow::onRegisterFaceVerified()
{
    // Регистрация завершена - шаблон уже сохранен в CameraCaptureWidget::registrationCompleted
    showMessage("Успех", "Регистрация завершена! Теперь можно войти в систему.", AppMessage::Kind::Information);

    // Восстанавливаем кнопку входа
    if (m_showLoginButton) {
        m_showLoginButton->setEnabled(true);
    }

    // Восстанавливаем кнопки "глазки"
    if (m_passwordToggleButton) m_passwordToggleButton->setEnabled(true);
    if (m_confirmPasswordToggleButton) m_confirmPasswordToggleButton->setEnabled(true);

    // Отключаем кнопку регистрации на форме регистрации
    m_registerFaceButton->setEnabled(false);
    m_registerFaceButton->setText("Регистрация завершена");
    m_registerCameraLabel->setText("Регистрация\nзавершена!");
    m_registerCameraLabel->setVisible(true);
    m_pendingFaceUser = User();

    // Возвращаемся на экран входа
    showLoginForm();
}

void MainWindow::onRegisterStatusUpdate(const QString &message, bool error)
{
    m_registerStatusLabel->setText(message);
    AppTheme::role(m_registerStatusLabel, error ? "error" : "muted");
}

void MainWindow::onRegisterFaceFailed(const QString &reason)
{
    onRegisterStatusUpdate(reason, true);
    m_registerFaceButton->setText("Повторить");
    m_registerFaceButton->setEnabled(m_pendingFaceUser.isValid());
}

void MainWindow::onUserRegistered(const QString &email)
{
    m_statusLabel->setText(QString("Пользователь %1 зарегистрирован").arg(email));
}

void MainWindow::onUserLoggedIn(const User &user)
{
    m_statusLabel->setText(QString("Пользователь %1 вошел в систему").arg(user.getEmail()));
}

void MainWindow::onUserLoggedOut()
{
    // Останавливаем камеру регистрации при выходе
    // Закрываем камеру полностью, так как пользователь выходит из системы
    if (m_registerCameraWidget) {
        m_registerCameraWidget->stopCapture(true);  // true = закрыть камеру
        m_registerCameraWidget->resetState();
    }

    // Останавливаем таймер проверки истечения сессии
    if (m_sessionCheckTimer && m_sessionCheckTimer->isActive()) {
        m_sessionCheckTimer->stop();
    }

    m_authService->logout();
    showLoginForm();
    m_statusLabel->setText("Пользователь вышел из системы");
}

void MainWindow::checkSessionExpiration()
{
    if (!m_authService->checkSessionExpiration()) {
        // Сессия истекла - показываем сообщение и форму входа
        showMessage("Сессия истекла", "Ваша сессия истекла. Пожалуйста, войдите в систему снова.", AppMessage::Kind::Warning);
        showLoginForm();
        m_statusLabel->setText("Сессия истекла. Требуется повторная авторизация.");
    }
}

void MainWindow::onAuthenticationFailed(const QString &reason)
{
    showMessage("Ошибка аутентификации", reason, AppMessage::Kind::Warning);
}

void MainWindow::onErrorOccurred(const QString &error)
{
    showMessage("Ошибка", error, AppMessage::Kind::Error);
}

void MainWindow::clearForms()
{
    m_loginEmailEdit->clear();
    m_loginPasswordEdit->clear();
    m_registerEmailEdit->clear();
    m_registerPasswordEdit->clear();
    m_registerConfirmPasswordEdit->clear();
}

void MainWindow::rememberSuccessfulLogin(const User &user)
{
    if (user.isValid()) LoginMemory::remember(user.getEmail(), m_pendingLoginPassword);
    m_pendingLoginPassword.reset();
}

void MainWindow::showMessage(const QString &title, const QString &message, AppMessage::Kind kind)
{
    AppMessage::show(this, title, message, kind);
}

void MainWindow::resizeAndCenter(int width, int height)
{
    // Получаем размер экрана
    QScreen *screen = QApplication::primaryScreen();
    if (!screen) {
        resize(width, height);
        return;
    }

    QRect screenGeometry = screen->availableGeometry();  // Доступная область (без панели задач)

    // Корректируем размер окна, чтобы оно помещалось на экране
    // Оставляем отступ 50 пикселей от краев
    int maxWidth = screenGeometry.width() - 100;
    int maxHeight = screenGeometry.height() - 100;

    int finalWidth = qMin(width, maxWidth);
    int finalHeight = qMin(height, maxHeight);

    // Устанавливаем размер
    resize(finalWidth, finalHeight);

    // Центрируем окно на экране
    QPoint center = screenGeometry.center();
    QRect frameGeometry = this->frameGeometry();
    frameGeometry.moveCenter(center);
    move(frameGeometry.topLeft());
}

void MainWindow::toggleFullscreen()
{
    if (isFullScreen()) {
        if (m_wasMaximizedBeforeFullscreen) {
            showMaximized();
        } else {
            showNormal();
        }
        return;
    }
    m_wasMaximizedBeforeFullscreen = isMaximized();
    showFullScreen();
}

void MainWindow::togglePasswordVisibility()
{
    if (m_registerPasswordEdit->echoMode() == QLineEdit::Password) {
        m_registerPasswordEdit->setEchoMode(QLineEdit::Normal);
        AppTheme::buttonIcon(m_passwordToggleButton, "eye-off"); // Глаз закрыт
    } else {
        m_registerPasswordEdit->setEchoMode(QLineEdit::Password);
        AppTheme::buttonIcon(m_passwordToggleButton, "eye"); // Глаз открыт
    }
}

void MainWindow::toggleConfirmPasswordVisibility()
{
    if (m_registerConfirmPasswordEdit->echoMode() == QLineEdit::Password) {
        m_registerConfirmPasswordEdit->setEchoMode(QLineEdit::Normal);
        AppTheme::buttonIcon(m_confirmPasswordToggleButton, "eye-off"); // Глаз закрыт
    } else {
        m_registerConfirmPasswordEdit->setEchoMode(QLineEdit::Password);
        AppTheme::buttonIcon(m_confirmPasswordToggleButton, "eye"); // Глаз открыт
    }
}

void MainWindow::validatePassword(const QString &password)
{
    bool lower = false;
    bool upper = false;
    bool digit = false;
    for (const auto character : password) {
        lower |= character.isLower();
        upper |= character.isUpper();
        digit |= character.isDigit();
    }
    AppTheme::role(m_passwordLengthCheck, password.size() >= 8 ? "success" : "muted");
    AppTheme::role(m_passwordLowercaseCheck, lower ? "success" : "muted");
    AppTheme::role(m_passwordUppercaseCheck, upper ? "success" : "muted");
    AppTheme::role(m_passwordDigitCheck, digit ? "success" : "muted");
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    // Останавливаем воркер сертификатов перед закрытием окна - ЗАКОММЕНТИРОВАНО
    // if (m_certificateWorker && m_certificateWorker->isRunning()) {
    //     qDebug() << "MainWindow: Остановка CertificateWorker при закрытии окна...";
    //     m_certificateWorker->stopWorker();
    //
    //     // Ждем завершения потока с таймаутом (не блокируем UI слишком долго)
    //     if (!m_certificateWorker->wait(3000)) { // Ждем до 3 секунд
    //         qWarning() << "MainWindow: CertificateWorker не завершился в течение 3 секунд, продолжаем закрытие";
    //     }
    //
    //     qDebug() << "MainWindow: CertificateWorker остановлен";
    // }

    // Останавливаем воркер разблокировки аккаунтов - ЗАКОММЕНТИРОВАНО
    // if (m_lockoutCleanupWorker && m_lockoutCleanupWorker->isRunning()) {
    //     qDebug() << "MainWindow: Остановка LockoutCleanupWorker при закрытии окна...";
    //     m_lockoutCleanupWorker->stopWorker();
    //
    //     // Ждем завершения потока с таймаутом (не блокируем UI слишком долго)
    //     if (!m_lockoutCleanupWorker->wait(2000)) { // Ждем до 2 секунд
    //         qWarning() << "MainWindow: LockoutCleanupWorker не завершился в течение 2 секунд, продолжаем закрытие";
    //     }
    //
    //     qDebug() << "MainWindow: LockoutCleanupWorker остановлен";
    // }

    // Останавливаем все камеры перед закрытием приложения
    // Закрываем камеры полностью при закрытии приложения
    if (m_registerCameraWidget) {
        m_registerCameraWidget->stopCapture(true);  // true = закрыть камеру
    }

    if (m_faceAuthWidget) {
        m_faceAuthWidget->stopCapture();
    }

    if (m_totpService) {
        m_totpService->closeWebPage();
    }

    // Останавливаем сервер подписи - ЗАКОММЕНТИРОВАНО
    // stopSignServer();

    QMainWindow::closeEvent(event);
}

void MainWindow::keyPressEvent(QKeyEvent *event)
{
    // F11 или Cmd+Ctrl+F для переключения полноэкранного режима
    if (event->key() == Qt::Key_F11 ||
        (event->modifiers() == (Qt::ControlModifier | Qt::MetaModifier) && event->key() == Qt::Key_F)) {
        toggleFullscreen();
        return;
    }

    // Escape для выхода из полноэкранного режима
    if (event->key() == Qt::Key_Escape && isFullScreen()) {
        toggleFullscreen();
        return;
    }

    QMainWindow::keyPressEvent(event);
}

void MainWindow::startSignServer()
{
    // Определяем путь к minica (ищем относительно директории приложения)
    QDir appDir(QCoreApplication::applicationDirPath());
    QString minicaPath;

    // Пробуем разные варианты путей
    QStringList pathsToTry = {
        appDir.absoluteFilePath("minica"),                                    // В директории приложения
        appDir.absoluteFilePath("../../minica"),                              // build/minica (из Contents/MacOS)
        appDir.absoluteFilePath("../../../minica"),                           // корень проекта (из build/)
        QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/3FA/build/minica"  // альтернатива
    };

    for (const QString &path : pathsToTry) {
#ifdef Q_OS_WIN
        QString tryPath = path + ".exe";
#else
        QString tryPath = path;
#endif
        if (QFile::exists(tryPath)) {
            minicaPath = tryPath;
            break;
        }
    }

    if (minicaPath.isEmpty()) {
        qWarning() << "minica not found, PDF signing will be unavailable";
        qWarning() << "Searched in:" << pathsToTry;
        return;
    }

    // Определяем директорию CA (используем директорию проекта)
    QDir projectDir = appDir;
    // Поднимаемся от Contents/MacOS до корня проекта
    while (!projectDir.exists("CMakeLists.txt") && projectDir.cdUp()) {
        if (projectDir.isRoot()) break;
    }

    QString rootDir = projectDir.absolutePath();
    QString caDir = rootDir + "/ca";
    QDir().mkpath(caDir);

    // Если нет базы CA, создаем её автоматически с 3FA-Signer
    QString caDbPath = rootDir + "/databases/ca.db";
    if (!QFile::exists(caDbPath)) {
        qDebug() << "Creating root CA certificate for 3FA-Signer...";
        QProcess *initProcess = new QProcess(this);
        initProcess->start(minicaPath, {"init-ca", rootDir, "/CN=3FA-Signer Root CA/O=3FA Security/C=RU"});
        if (!initProcess->waitForFinished(10000)) {
            qWarning() << "Failed to create root CA certificate";
            initProcess->kill();
        }
        initProcess->deleteLater();
    }

    m_signServerProcess = new QProcess(this);
    m_signServerProcess->setProcessChannelMode(QProcess::MergedChannels);

    // Connect to readyRead to log server output
    connect(m_signServerProcess, &QProcess::readyReadStandardOutput, [this]() {
        QByteArray data = m_signServerProcess->readAllStandardOutput();
        qDebug() << "Sign server:" << data;
    });
    connect(m_signServerProcess, &QProcess::readyReadStandardError, [this]() {
        QByteArray data = m_signServerProcess->readAllStandardError();
        qWarning() << "Sign server error:" << data;
    });

    // Load CA configuration from file (if exists)
    QString serverBindAddr = "127.0.0.1";
    int serverPort = 9090;

    QFile configFile(rootDir + "/config/ca.json");
    if (configFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QString json = QString::fromUtf8(configFile.readAll());
        configFile.close();

        if (!json.isEmpty()) {
            QJsonParseError parseError;
            QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8(), &parseError);

            if (parseError.error != QJsonParseError::NoError) {
                qWarning() << "MainWindow: [КОНФИГ] JSON parse error at position" << parseError.offset
                           << ":" << parseError.errorString() << ", используются значения по умолчанию";
            } else if (!doc.isNull() && doc.isObject()) {
                qDebug() << "MainWindow: [КОНФИГ] Загружаем конфигурацию из config/ca.json";
                QJsonObject obj = doc.object();

                // Server settings
                QJsonObject serverObj = obj["server"].toObject();
                if (!serverObj.isEmpty()) {
                    if (serverObj.contains("bind_addr")) {
                        QJsonValue bindAddrVal = serverObj["bind_addr"];
                        if (bindAddrVal.isString()) {
                            serverBindAddr = bindAddrVal.toString();
                            qDebug() << "MainWindow: [КОНФИГ] server.bind_addr из JSON:" << serverBindAddr;
                        }
                    }
                    if (serverObj.contains("port")) {
                        QJsonValue portVal = serverObj["port"];
                        if (portVal.isDouble()) {
                            int port = portVal.toInt();
                            if (port > 0 && port < 65536) {
                                serverPort = port;
                                qDebug() << "MainWindow: [КОНФИГ] server.port из JSON:" << serverPort;
                            } else {
                                qWarning() << "MainWindow: [КОНФИГ] Invalid server port value:" << port << "(must be 1-65535), используется значение по умолчанию";
                            }
                        }
                    }
                }
                qDebug() << "MainWindow: [КОНФИГ] Конфигурация загружена из JSON. Сервер:" << serverBindAddr << ":" << serverPort;
            }
        } else {
            qWarning() << "MainWindow: [КОНФИГ] Файл config/ca.json пуст, используются значения по умолчанию";
        }
    } else {
        qDebug() << "MainWindow: [КОНФИГ] Файл config/ca.json не найден, используются значения по умолчанию:" << serverBindAddr << ":" << serverPort;
    }

    m_signServerProcess->start(minicaPath, {"serve-sign", rootDir, serverBindAddr, QString::number(serverPort)});

    if (!m_signServerProcess->waitForStarted(3000)) {
        qWarning() << "Failed to start sign server:" << m_signServerProcess->errorString();
        delete m_signServerProcess;
        m_signServerProcess = nullptr;
        return;
    }

    qDebug() << "Sign server started on" << serverBindAddr << ":" << serverPort << "using root dir:" << rootDir;
}

void MainWindow::stopSignServer()
{
    if (m_signServerProcess && m_signServerProcess->state() == QProcess::Running) {
        m_signServerProcess->terminate();
        if (!m_signServerProcess->waitForFinished(3000)) {
            m_signServerProcess->kill();
        }
    }
}
