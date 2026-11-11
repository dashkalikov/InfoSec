#ifndef FORGOTPASSWORDWIDGET_H
#define FORGOTPASSWORDWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QTimer>
#include "authservice.h"
#include "database.h"
#include "emailservice.h"
#include "totpinputwidget.h"

/**
 * @brief Виджет для восстановления пароля
 * 
 * Позволяет пользователю восстановить пароль через верификацию.
 * Процесс включает:
 * 1. Ввод email
 * 2. Верификацию пользователя (код по email или другой способ)
 * 3. Ввод нового пароля
 */
class ForgotPasswordWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ForgotPasswordWidget(Database *database, AuthService *authService, QWidget *parent = nullptr);
    ~ForgotPasswordWidget();
    
    void setEmail(const QString &email);
    void setDatabase(Database *database) { m_database = database; }
    void setAuthService(AuthService *authService) { m_authService = authService; }
    void resetForm();

signals:
    void backToLogin();
    void passwordResetSuccess();

private slots:
    void onBackClicked();
    void onSendCodeClicked();
    void onVerifyCodeClicked();
    void onResendCodeClicked();
    void onResetPasswordClicked();
    void onCodeTimerTimeout();
    void toggleNewPasswordVisibility();
    void toggleConfirmPasswordVisibility();
    void validatePassword(const QString &password);

private:
    void setupUI();
    void showStep(int step); // 1 - ввод email, 2 - ввод кода, 3 - новый пароль
    bool validateEmail(const QString &email);
    bool validatePasswordFormat(const QString &password);
    QString generateVerificationCode();
    bool sendVerificationCode(const QString &email, const QString &code);
    void loadEmailConfig(); // Загрузка конфигурации email из файла
    void setupTimer(); // Настройка таймера обратного отсчета
    void updateTimerLabel(); // Обновление метки таймера
    
    Database *m_database;
    AuthService *m_authService;
    EmailService *m_emailService;
    
    // UI элементы
    QLabel *m_titleLabel;
    QLabel *m_subtitleLabel;
    
    // Шаг 1: Ввод email
    QWidget *m_step1Widget;
    QLineEdit *m_emailEdit;
    QPushButton *m_sendCodeButton;
    
    // Шаг 2: Ввод кода верификации
    QWidget *m_step2Widget;
    TOTPInputWidget *m_verificationCodeWidget;
    QPushButton *m_verifyCodeButton;
    QPushButton *m_resendCodeButton;
    QLabel *m_codeHintLabel;
    QLabel *m_timerLabel;
    
    // Шаг 3: Новый пароль
    QWidget *m_step3Widget;
    QLineEdit *m_newPasswordEdit;
    QLineEdit *m_confirmPasswordEdit;
    QPushButton *m_newPasswordToggleButton;
    QPushButton *m_confirmPasswordToggleButton;
    QPushButton *m_resetPasswordButton;
    QLabel *m_passwordLengthCheck;
    QLabel *m_passwordLowercaseCheck;
    QLabel *m_passwordUppercaseCheck;
    QLabel *m_passwordDigitCheck;
    
    // Кнопка "Назад"
    QPushButton *m_backButton;
    
    // Состояние
    int m_currentStep;
    QString m_currentEmail;
    QString m_verificationCode;
    bool m_codeVerified;
    
    // Таймер обратного отсчета
    QTimer *m_codeTimer;
    int m_codeExpirySeconds; // Время жизни кода в секундах (по умолчанию 10 минут)
};

#endif // FORGOTPASSWORDWIDGET_H

