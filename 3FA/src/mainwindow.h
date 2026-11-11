#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <optional>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QGroupBox>
#include "appmessage.h"
#include <QStatusBar>
#include <QProgressBar>
#include <QLabel>
#include <QPainter>
#include "authservice.h"
#include "database.h"
#include "user.h"
#include "totpservice.h"
#include "faceauthservice.h"
#include "faceauthwidget.h"
#include "cameracapturewidget.h"
#include "totpinputwidget.h"
#include "kuznechikwidget.h"
#include "adminfileswidget.h"
#include "sessionwidget.h"
#include "forgotpasswordwidget.h"
// #include "certificateworker.h"
// #include "cadatabase.h"
// #include "lockoutcleanupworker.h"
// #include <QProcess>
#include <QTimer>
#include <array>

class QPropertyAnimation;

QT_BEGIN_NAMESPACE
class QAction;
class QMenu;
QT_END_NAMESPACE

/**
 * @brief Главное окно приложения 3FA
 * 
 * Предоставляет интерфейс для регистрации и входа в систему
 * с использованием первого фактора аутентификации (email + пароль).
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr, Qt::WindowFlags flags = Qt::WindowFlags());
    ~MainWindow();

private slots:
    // Слоты для регистрации
    void onRegisterClicked();
    void onRegisterFaceClicked();
    void togglePasswordVisibility();
    void toggleConfirmPasswordVisibility();
    void validatePassword(const QString &password);
    
    // Слоты для входа
    void onLoginClicked();
    
    // Слоты для навигации
    void showLoginForm();
    void showRegisterForm();
    void showForgotPasswordForm();
    void showMainMenu();
    void showFactor2Form();
    void showFactor3Form();
    void showKuznechikWidget();
    void showAdminFilesWidget();
    void showSessionWidget();
    void showMainMenuAfterAuth();
    
    // Слоты для полноэкранного режима
    void toggleFullscreen();
    
    // Слоты для второго фактора
    void onFactor2VerifyClicked();
    void onFactor2BackClicked();
    void onFaceFactorVerified();
    void onFaceFactorFailed(const QString &reason);
    void onRegisterFaceVerified();
    void onRegisterFaceFailed(const QString &reason);
    void onRegisterStatusUpdate(const QString &message, bool error = false);
    
    // Слоты для аутентификации
    void onUserRegistered(const QString &email);
    void onUserLoggedIn(const User &user);
    void onUserLoggedOut();
    void onAuthenticationFailed(const QString &reason);
    void onErrorOccurred(const QString &error);
    
    // Слот для проверки истечения сессии
    void checkSessionExpiration();

private:
    void setupUI();
    void setupZoomPanel(QWidget *shell, QWidget *backdrop);
    void showZoomPanel();
    void fadeZoomPanel();
    void setZoom(int percent, bool preview = false);
    void stepZoom(int direction, bool preview = false);
    void placeWindowControls();
    void adjustPageLayouts();
    void toggleMaximized();
    void refreshQrPixmap();
    void setupStatusBar();
    void setupLoginForm();
    void setupRegisterForm();
    void setupFactor2Form();
    void setupFactor3Form();
    void setupKuznechikWidget();
    void setupAdminFilesWidget();
    void setupSessionWidget();
    void setupForgotPasswordWidget();
    void startFaceCapture(const User &user, bool enroll);
    void setupMainMenu();
    void connectSignals();
    void clearForms();
    void rememberSuccessfulLogin(const User &user);
    void showMessage(const QString &title, const QString &message, AppMessage::Kind kind = AppMessage::Kind::Information);
    void resizeAndCenter(int width, int height);  // Безопасное изменение размера окна с учетом экрана
    void startSignServer();
    void stopSignServer();
    
    // Обработчики событий
    void keyPressEvent(QKeyEvent *event) override;
    bool eventFilter(QObject *watched, QEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    void changeEvent(QEvent *event) override;
    void closeEvent(QCloseEvent *event) override;
    
    // UI компоненты
    QStackedWidget *m_stackedWidget;
    QWidget *m_titleDrag = nullptr;
    QPushButton *m_maximizeButton = nullptr;
    std::array<QWidget *, 8> m_resizeGrips{};
    QPoint m_titlePress;
    QWidget *m_zoomPanel = nullptr;
    QLabel *m_zoomLabel = nullptr;
    QPushButton *m_zoomOut = nullptr;
    QPushButton *m_zoomIn = nullptr;
    QTimer *m_zoomTimer = nullptr;
    QPropertyAnimation *m_zoomFade = nullptr;
    int m_zoomWheelDelta = 0;
    QBoxLayout *m_loginLinks = nullptr;
    QBoxLayout *m_registerColumns = nullptr;
    QBoxLayout *m_totpColumns = nullptr;
    
    // Форма входа
    QWidget *m_loginWidget;
    QLineEdit *m_loginEmailEdit;
    QLineEdit *m_loginPasswordEdit;
    class QCheckBox *m_rememberPassword = nullptr;
    std::optional<QString> m_pendingLoginPassword;
    bool m_prefilledLoginPassword = false;
    QPushButton *m_loginButton;
    QPushButton *m_showRegisterButton;
    QPushButton *m_forgotPasswordButton;
    
    // Форма регистрации
    QWidget *m_registerWidget;
    QLineEdit *m_registerEmailEdit;
    QLineEdit *m_registerPasswordEdit;
    QLineEdit *m_registerConfirmPasswordEdit;
    QPushButton *m_passwordToggleButton;
    QPushButton *m_confirmPasswordToggleButton;
    QLabel *m_passwordLengthCheck;
    QLabel *m_passwordLowercaseCheck;
    QLabel *m_passwordUppercaseCheck;
    QLabel *m_passwordDigitCheck;
    QPushButton *m_registerButton;
    QPushButton *m_registerFaceButton;
    QPushButton *m_showLoginButton;
    QLabel *m_registerCameraLabel;
    QLabel *m_registerStatusLabel;
    CameraCaptureWidget *m_registerCameraWidget;
    
    // Форма второго фактора
    QWidget *m_factor2Widget;
    QLabel *m_qrCodeLabel;
    QPixmap m_qrPixmap;
    TOTPInputWidget *m_totpCodeWidget;
    QPushButton *m_factor2VerifyButton;
    QPushButton *m_factor2BackButton;
    QLabel *m_factor2InstructionsLabel;
    QString m_factor2PageUrl;

    QWidget *m_factor3Widget;
    FaceAuthWidget *m_faceAuthWidget;

    // Виджет шифрования Кузнечик
    QWidget *m_kuznechikWidget;
    KuznechikWidget *m_kuznechikWidgetContent;
    
    // Виджет просмотра файлов для админа
    QWidget *m_adminFilesWidget;
    AdminFilesWidget *m_adminFilesWidgetContent;
    
    // Виджет управления сессиями
    QWidget *m_sessionWidget;
    SessionWidget *m_sessionWidgetContent;
    
    // Виджет восстановления пароля
    QWidget *m_forgotPasswordWidget;
    ForgotPasswordWidget *m_forgotPasswordWidgetContent;

    // Главное меню
    QWidget *m_mainMenuWidget;
    QLabel *m_welcomeLabel;
    QPushButton *m_logoutButton;
    QPushButton *m_kuznechikButton;
    QPushButton *m_adminFilesButton;
    QPushButton *m_sessionsButton;
    QTextEdit *m_userInfoText;
    
    // Статус бар
    QLabel *m_statusLabel;
    
    // Сервисы
    Database *m_database;
    // CaDatabase *m_caDatabase; // ЗАКОММЕНТИРОВАНО
    AuthService *m_authService;
    TOTPService *m_totpService;
    FaceAuthService *m_faceAuthService;
    // CertificateWorker *m_certificateWorker; // ЗАКОММЕНТИРОВАНО
    // LockoutCleanupWorker *m_lockoutCleanupWorker; // ЗАКОММЕНТИРОВАНО
    User m_pendingFaceUser;
    bool m_enrollingFace;
    QProcess *m_signServerProcess;
    bool m_wasMaximizedBeforeFullscreen = false;
    QTimer *m_sessionCheckTimer; // Таймер для периодической проверки истечения сессии
};

#endif // MAINWINDOW_H
