#include "forgotpasswordwidget.h"
#include "apptheme.h"
#include "user.h"
#include "emailservice.h"
#include <QDebug>
#include "appmessage.h"
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QRandomGenerator>
#include <QDateTime>
#include <QFile>
#include <QDir>
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>
#include <QApplication>

ForgotPasswordWidget::ForgotPasswordWidget(Database *database, AuthService *authService, QWidget *parent)
    : QWidget(parent)
    , m_database(database)
    , m_authService(authService)
    , m_emailService(new EmailService(this))
    , m_currentStep(1)
    , m_codeVerified(false)
    , m_verificationCodeWidget(nullptr)
    , m_resendCodeButton(nullptr)
    , m_timerLabel(nullptr)
    , m_newPasswordToggleButton(nullptr)
    , m_confirmPasswordToggleButton(nullptr)
    , m_backButton(nullptr)
    , m_passwordLengthCheck(nullptr)
    , m_passwordLowercaseCheck(nullptr)
    , m_passwordUppercaseCheck(nullptr)
    , m_passwordDigitCheck(nullptr)
    , m_codeTimer(new QTimer(this))
    , m_codeExpirySeconds(600) // 10 минут по умолчанию
{
    setupUI();
    loadEmailConfig();
    setupTimer();
}

ForgotPasswordWidget::~ForgotPasswordWidget()
{
}

void ForgotPasswordWidget::setupUI()
{
    auto *cardLayout = AppTheme::centeredCard(this, 504);

    // Заголовок
    m_titleLabel = new QLabel("Восстановление пароля");
    m_titleLabel->setAlignment(Qt::AlignCenter);
    m_titleLabel->setWordWrap(true);
    AppTheme::role(m_titleLabel, "title");
    cardLayout->addWidget(m_titleLabel);

    m_subtitleLabel = new QLabel("Введите email для восстановления пароля");
    m_subtitleLabel->setAlignment(Qt::AlignCenter);
    m_subtitleLabel->setWordWrap(true);
    AppTheme::role(m_subtitleLabel, "muted");
    cardLayout->addWidget(m_subtitleLabel);

    // Шаг 1: Ввод email
    m_step1Widget = new QWidget();
    QVBoxLayout *step1Layout = new QVBoxLayout(m_step1Widget);
    AppTheme::margins(step1Layout, 0, 0, 0, 0);
    AppTheme::spacing(step1Layout, 16);

    m_emailEdit = new QLineEdit();
    m_emailEdit->setPlaceholderText("Адрес электронной почты");
    step1Layout->addWidget(m_emailEdit);

    m_sendCodeButton = new QPushButton("Отправить код");
    AppTheme::buttonIcon(m_sendCodeButton, "enter");
    AppTheme::dimension(m_sendCodeButton, "minimumHeight", 52);
    AppTheme::role(m_sendCodeButton, "primary");
    step1Layout->addWidget(m_sendCodeButton);
    cardLayout->addWidget(m_step1Widget);

    // Шаг 2: Ввод кода верификации
    m_step2Widget = new QWidget();
    QVBoxLayout *step2Layout = new QVBoxLayout(m_step2Widget);
    AppTheme::margins(step2Layout, 0, 0, 0, 0);
    AppTheme::spacing(step2Layout, 16);

    m_codeHintLabel = new QLabel("Код отправлен на email");
    m_codeHintLabel->setAlignment(Qt::AlignCenter);
    step2Layout->addWidget(m_codeHintLabel);

    // Таймер обратного отсчета
    m_timerLabel = new QLabel("Код действителен: 10:00");
    m_timerLabel->setAlignment(Qt::AlignCenter);
    step2Layout->addWidget(m_timerLabel);

    // Инструкция
    QLabel *instructionLabel = new QLabel("Введите 6-значный код:");
    instructionLabel->setAlignment(Qt::AlignCenter);
    step2Layout->addWidget(instructionLabel);

    // Поле ввода кода - используем TOTPInputWidget
    m_verificationCodeWidget = new TOTPInputWidget();
    step2Layout->addWidget(m_verificationCodeWidget, 0, Qt::AlignCenter);

    m_verifyCodeButton = new QPushButton("Проверить код");
    AppTheme::buttonIcon(m_verifyCodeButton, "check");
    AppTheme::dimension(m_verifyCodeButton, "minimumHeight", 52);
    AppTheme::role(m_verifyCodeButton, "primary");
    step2Layout->addWidget(m_verifyCodeButton);

    // Кнопка "Выслать код повторно"
    m_resendCodeButton = new QPushButton("Выслать код повторно");
    AppTheme::buttonIcon(m_resendCodeButton, "refresh");
    AppTheme::dimension(m_resendCodeButton, "minimumHeight", 46);
    m_resendCodeButton->setFlat(true);
    AppTheme::role(m_resendCodeButton, "quiet");
    step2Layout->addWidget(m_resendCodeButton);
    m_step2Widget->setVisible(false);
    cardLayout->addWidget(m_step2Widget);

    // Шаг 3: Новый пароль
    m_step3Widget = new QWidget();
    QVBoxLayout *step3Layout = new QVBoxLayout(m_step3Widget);
    AppTheme::margins(step3Layout, 0, 0, 0, 0);
    AppTheme::spacing(step3Layout, 16);

    // Контейнер для нового пароля с кнопкой просмотра
    QWidget *newPasswordContainer = new QWidget();
    QHBoxLayout *newPasswordLayout = new QHBoxLayout(newPasswordContainer);
    AppTheme::margins(newPasswordLayout, 0, 0, 0, 0);
    AppTheme::spacing(newPasswordLayout, 10);

    m_newPasswordEdit = new QLineEdit();
    m_newPasswordEdit->setEchoMode(QLineEdit::Password);
    m_newPasswordEdit->setPlaceholderText("Новый пароль");
    newPasswordLayout->addWidget(m_newPasswordEdit, 1);

    // Кнопка показа/скрытия нового пароля
    m_newPasswordToggleButton = new QPushButton("");
    AppTheme::buttonIcon(m_newPasswordToggleButton, "eye");
    AppTheme::fixedSize(m_newPasswordToggleButton, 52, 52);
    AppTheme::role(m_newPasswordToggleButton, "tool");
    newPasswordLayout->addWidget(m_newPasswordToggleButton);
    step3Layout->addWidget(newPasswordContainer);

    // Подключаем сигнал изменения пароля для валидации
    connect(m_newPasswordEdit, &QLineEdit::textChanged, this, &ForgotPasswordWidget::validatePassword);

    // Контейнер для валидации пароля
    QWidget *validationContainer = new QWidget();
    AppTheme::dimension(validationContainer, "minimumHeight", 100);
    AppTheme::dimension(validationContainer, "minimumWidth", 0);
    AppTheme::dimension(validationContainer, "maximumWidth", 430);
    QVBoxLayout *validationLayout = new QVBoxLayout(validationContainer);
    AppTheme::margins(validationLayout, 15, 10, 15, 10);
    AppTheme::spacing(validationLayout, 5);

    // Две строки по два критерия в каждой
    QHBoxLayout *row1 = new QHBoxLayout();
    AppTheme::spacing(row1, 10);
    QHBoxLayout *row2 = new QHBoxLayout();
    AppTheme::spacing(row2, 10);

    // Фон контейнера
    AppTheme::role(validationContainer, "inset");

    // Виджеты валидации пароля
    m_passwordLengthCheck = new QLabel("Минимум 8 символов");
    m_passwordLowercaseCheck = new QLabel("Строчные буквы");
    m_passwordUppercaseCheck = new QLabel("Заглавные буквы");
    m_passwordDigitCheck = new QLabel("Цифры");

    // Фиксируем ширину меток для выравнивания

    // Стили для меток валидации

    AppTheme::role(m_passwordLengthCheck, "muted");
    AppTheme::role(m_passwordLowercaseCheck, "muted");
    AppTheme::role(m_passwordUppercaseCheck, "muted");
    AppTheme::role(m_passwordDigitCheck, "muted");

    // Первая строка: длина и строчные буквы
    row1->addWidget(m_passwordLengthCheck);
    row1->addWidget(m_passwordLowercaseCheck);

    // Вторая строка: заглавные буквы и цифры
    row2->addWidget(m_passwordUppercaseCheck);
    row2->addWidget(m_passwordDigitCheck);

    validationLayout->addLayout(row1);
    validationLayout->addLayout(row2);

    step3Layout->addWidget(validationContainer);

    // Контейнер для подтверждения пароля с кнопкой просмотра
    QWidget *confirmPasswordContainer = new QWidget();
    QHBoxLayout *confirmPasswordLayout = new QHBoxLayout(confirmPasswordContainer);
    AppTheme::margins(confirmPasswordLayout, 0, 0, 0, 0);
    AppTheme::spacing(confirmPasswordLayout, 10);

    m_confirmPasswordEdit = new QLineEdit();
    m_confirmPasswordEdit->setEchoMode(QLineEdit::Password);
    m_confirmPasswordEdit->setPlaceholderText("Подтвердите пароль");
    confirmPasswordLayout->addWidget(m_confirmPasswordEdit, 1);

    // Кнопка показа/скрытия подтверждения пароля
    m_confirmPasswordToggleButton = new QPushButton("");
    AppTheme::buttonIcon(m_confirmPasswordToggleButton, "eye");
    AppTheme::fixedSize(m_confirmPasswordToggleButton, 52, 52);
    AppTheme::role(m_confirmPasswordToggleButton, "tool");
    confirmPasswordLayout->addWidget(m_confirmPasswordToggleButton);
    step3Layout->addWidget(confirmPasswordContainer);

    m_resetPasswordButton = new QPushButton("Сбросить пароль");
    AppTheme::buttonIcon(m_resetPasswordButton, "key");
    AppTheme::dimension(m_resetPasswordButton, "minimumHeight", 52);
    AppTheme::role(m_resetPasswordButton, "primary");
    step3Layout->addWidget(m_resetPasswordButton);
    m_step3Widget->setVisible(false);
    cardLayout->addWidget(m_step3Widget);

    // Кнопка "Назад"
    m_backButton = new QPushButton("Назад");
    AppTheme::buttonIcon(m_backButton, "back");
    AppTheme::dimension(m_backButton, "minimumHeight", 48);
    AppTheme::role(m_backButton, "quiet");
    cardLayout->addWidget(m_backButton);

    // Подключаем сигналы
    connect(m_backButton, &QPushButton::clicked, this, &ForgotPasswordWidget::onBackClicked);
    connect(m_sendCodeButton, &QPushButton::clicked, this, &ForgotPasswordWidget::onSendCodeClicked);
    connect(m_verifyCodeButton, &QPushButton::clicked, this, &ForgotPasswordWidget::onVerifyCodeClicked);
    connect(m_resendCodeButton, &QPushButton::clicked, this, &ForgotPasswordWidget::onResendCodeClicked);
    connect(m_resetPasswordButton, &QPushButton::clicked, this, &ForgotPasswordWidget::onResetPasswordClicked);
    if (m_verificationCodeWidget) {
        connect(m_verificationCodeWidget, &TOTPInputWidget::codeCompleted, this, &ForgotPasswordWidget::onVerifyCodeClicked);
    }
    connect(m_newPasswordToggleButton, &QPushButton::clicked, this, &ForgotPasswordWidget::toggleNewPasswordVisibility);
    connect(m_confirmPasswordToggleButton, &QPushButton::clicked, this, &ForgotPasswordWidget::toggleConfirmPasswordVisibility);
    connect(m_confirmPasswordEdit, &QLineEdit::returnPressed, this, &ForgotPasswordWidget::onResetPasswordClicked);


}

void ForgotPasswordWidget::setEmail(const QString &email)
{
    if (m_emailEdit) {
        m_emailEdit->setText(email);
        // Если email передан, делаем поле read-only для подтверждения
        if (!email.isEmpty()) {
            m_emailEdit->setReadOnly(true);
        } else {
            m_emailEdit->setReadOnly(false);
        }
    }
}

void ForgotPasswordWidget::resetForm()
{
    m_currentStep = 1;
    m_codeVerified = false;
    m_currentEmail.clear();
    m_verificationCode.clear();

    // Останавливаем таймер
    if (m_codeTimer) {
        m_codeTimer->stop();
    }

    // Не очищаем email, если он был установлен (read-only)
    // if (m_emailEdit) m_emailEdit->clear();
    if (m_verificationCodeWidget) m_verificationCodeWidget->clear();
    if (m_newPasswordEdit) m_newPasswordEdit->clear();
    if (m_confirmPasswordEdit) m_confirmPasswordEdit->clear();

    // Сбрасываем метки валидации пароля
    if (m_passwordLengthCheck) {
        m_passwordLengthCheck->setText("Минимум 8 символов");
        AppTheme::role(m_passwordLengthCheck, "muted");
    }
    if (m_passwordLowercaseCheck) {
        m_passwordLowercaseCheck->setText("Строчные буквы");
        AppTheme::role(m_passwordLowercaseCheck, "muted");
    }
    if (m_passwordUppercaseCheck) {
        m_passwordUppercaseCheck->setText("Заглавные буквы");
        AppTheme::role(m_passwordUppercaseCheck, "muted");
    }
    if (m_passwordDigitCheck) {
        m_passwordDigitCheck->setText("Цифры");
        AppTheme::role(m_passwordDigitCheck, "muted");
    }

    // Сбрасываем таймер
    m_codeExpirySeconds = 600;
    if (m_timerLabel) {
        m_timerLabel->setText("Код действителен: 10:00");
    }

    if (m_resendCodeButton) {
        m_resendCodeButton->setEnabled(true);
    }

    showStep(1);
}

void ForgotPasswordWidget::showStep(int step)
{
    m_currentStep = step;

    // Если email уже передан и это шаг 1, скрываем поле email и сразу показываем кнопку отправки
    bool emailPreFilled = !m_emailEdit->text().isEmpty();

    if (m_step1Widget) {
        m_step1Widget->setVisible(step == 1);
        // Если email уже есть, скрываем поле ввода email
        if (m_emailEdit) {
            m_emailEdit->setVisible(!emailPreFilled || step != 1);
        }
    }
    if (m_step2Widget) m_step2Widget->setVisible(step == 2);
    if (m_step3Widget) m_step3Widget->setVisible(step == 3);

    // Скрываем кнопку "Назад" на шаге 2 (верификация)
    if (m_backButton) {
        m_backButton->setVisible(step != 2);
    }

    // Обновляем заголовки
    if (m_titleLabel) {
        switch (step) {
            case 1:
                m_titleLabel->setText("Восстановление пароля");
                break;
            case 2:
                m_titleLabel->setText("Верификация");
                break;
            case 3:
                m_titleLabel->setText("Новый пароль");
                break;
        }
    }

    if (m_subtitleLabel) {
        switch (step) {
            case 1:
                // Если email уже есть, показываем его в подзаголовке
                if (emailPreFilled) {
                    m_subtitleLabel->setText(QString("Восстановление пароля для: %1").arg(m_emailEdit->text()));
                } else {
                    m_subtitleLabel->setText("Введите email для восстановления пароля");
                }
                break;
            case 2:
                m_subtitleLabel->setText(QString("Код отправлен на %1").arg(m_currentEmail));
                break;
            case 3:
                m_subtitleLabel->setText("Введите новый пароль");
                break;
        }
    }
}

void ForgotPasswordWidget::onBackClicked()
{
    if (m_currentStep > 1) {
        m_currentStep--;
        showStep(m_currentStep);
    } else {
        emit backToLogin();
    }
}

void ForgotPasswordWidget::onSendCodeClicked()
{
    QString email = m_emailEdit->text().trimmed();

    if (!validateEmail(email)) {
        AppMessage::warning(this, "Ошибка", "Введите корректный email адрес");
        return;
    }

    // Проверяем, существует ли пользователь
    if (!m_database || !m_database->userExists(email)) {
        AppMessage::warning(this, "Ошибка", "Пользователь с таким email не найден");
        return;
    }

    // Генерируем код верификации
    m_verificationCode = generateVerificationCode();
    m_currentEmail = email;

    // Отправляем код по email
    if (sendVerificationCode(email, m_verificationCode)) {
        // Если email сервис настроен, показываем простое сообщение
        if (m_emailService && m_emailService->isConfigured()) {
            AppMessage::information(this, "Код отправлен",
                QString("Код верификации отправлен на %1\n\nПроверьте вашу почту.").arg(email));
        }
        // Иначе код уже показан в sendVerificationCode

        showStep(2);

        // Запускаем таймер обратного отсчета
        m_codeExpirySeconds = 600; // 10 минут
        m_codeTimer->start();
        updateTimerLabel();

        // Очищаем поле ввода и устанавливаем фокус
        if (m_verificationCodeWidget) {
            m_verificationCodeWidget->clear();
            m_verificationCodeWidget->setFocus();
        }

        // Отключаем кнопку "Выслать код повторно" до истечения таймера
        if (m_resendCodeButton) {
            m_resendCodeButton->setEnabled(false);
        }
    } else {
        AppMessage::critical(this, "Ошибка", "Не удалось отправить код верификации");
    }
}

void ForgotPasswordWidget::setupTimer()
{
    // Настраиваем таймер обратного отсчета
    m_codeTimer->setSingleShot(false);
    m_codeTimer->setInterval(1000); // Обновляем каждую секунду
    connect(m_codeTimer, &QTimer::timeout, this, &ForgotPasswordWidget::onCodeTimerTimeout);
}

void ForgotPasswordWidget::onResendCodeClicked()
{
    // Повторно отправляем код
    if (m_currentEmail.isEmpty()) {
        AppMessage::warning(this, "Ошибка", "Email не указан");
        return;
    }

    // Генерируем новый код
    m_verificationCode = generateVerificationCode();

    // Отправляем код по email
    if (sendVerificationCode(m_currentEmail, m_verificationCode)) {
        // Если email сервис настроен, показываем простое сообщение
        if (m_emailService && m_emailService->isConfigured()) {
            AppMessage::information(this, "Код отправлен",
                QString("Код верификации повторно отправлен на %1\n\nПроверьте вашу почту.").arg(m_currentEmail));
        }

        // Сбрасываем таймер
        m_codeExpirySeconds = 600; // 10 минут
        m_codeTimer->start();
        updateTimerLabel();

        // Отключаем кнопку "Выслать код повторно" до истечения таймера
        if (m_resendCodeButton) {
            m_resendCodeButton->setEnabled(false);
        }

        // Очищаем поле ввода
        if (m_verificationCodeWidget) {
            m_verificationCodeWidget->clear();
            m_verificationCodeWidget->setFocus();
        }
    } else {
        AppMessage::critical(this, "Ошибка", "Не удалось отправить код верификации");
    }
}

void ForgotPasswordWidget::onCodeTimerTimeout()
{
    m_codeExpirySeconds--;
    updateTimerLabel();

    if (m_codeExpirySeconds <= 0) {
        m_codeTimer->stop();
        // Делаем код недействительным при истечении времени
        // Очищаем код, чтобы он не мог быть использован после истечения
        m_verificationCode.clear();
        m_codeExpirySeconds = 0; // Убеждаемся, что значение точно 0

        // Активируем кнопку "Выслать код повторно" когда таймер истечет
        if (m_resendCodeButton) {
            m_resendCodeButton->setEnabled(true);
        }
        if (m_timerLabel) {
            m_timerLabel->setText("Код истек. Запросите новый код.");
        }
    }
}

void ForgotPasswordWidget::updateTimerLabel()
{
    if (!m_timerLabel) return;

    int minutes = m_codeExpirySeconds / 60;
    int seconds = m_codeExpirySeconds % 60;

    QString timeText = QString("Код действителен: %1:%2")
        .arg(minutes, 2, 10, QChar('0'))
        .arg(seconds, 2, 10, QChar('0'));

    m_timerLabel->setText(timeText);

    // Меняем цвет в зависимости от оставшегося времени
    if (m_codeExpirySeconds <= 60) {
    } else if (m_codeExpirySeconds <= 180) {
    } else {
    }
}

void ForgotPasswordWidget::onVerifyCodeClicked()
{
    QString code = m_verificationCodeWidget ? m_verificationCodeWidget->getCode() : QString();

    if (code.length() != 6) {
        AppMessage::warning(this, "Ошибка", "Код должен содержать 6 цифр");
        return;
    }

    // Проверяем, не истекло ли время действия кода или не очищен ли код
    if (m_codeExpirySeconds <= 0 || m_verificationCode.isEmpty()) {
        AppMessage::warning(this, "Код истек",
            "Время действия кода истекло. Пожалуйста, запросите новый код.");
        if (m_verificationCodeWidget) {
            m_verificationCodeWidget->clear();
            m_verificationCodeWidget->setFocus();
        }
        // Активируем кнопку "Выслать код повторно"
        if (m_resendCodeButton) {
            m_resendCodeButton->setEnabled(true);
        }
        return;
    }

    if (code == m_verificationCode) {
        m_codeVerified = true;

        // Останавливаем таймер
        if (m_codeTimer) {
            m_codeTimer->stop();
        }

        AppMessage::information(this, "Успех", "Код верификации подтвержден");
        showStep(3);
        if (m_newPasswordEdit) {
            m_newPasswordEdit->clear();
            m_newPasswordEdit->setFocus();
        }
    } else {
        AppMessage::warning(this, "Ошибка", "Неверный код верификации");
        if (m_verificationCodeWidget) {
            m_verificationCodeWidget->clear();
            m_verificationCodeWidget->setFocus();
        }
    }
}

void ForgotPasswordWidget::onResetPasswordClicked()
{
    if (!m_codeVerified) {
        AppMessage::warning(this, "Ошибка", "Сначала подтвердите код верификации");
        return;
    }

    QString newPassword = m_newPasswordEdit->text();
    QString confirmPassword = m_confirmPasswordEdit->text();

    if (!validatePasswordFormat(newPassword)) {
        AppMessage::warning(this, "Ошибка",
            "Пароль должен содержать:\n"
            "• Минимум 8 символов\n"
            "• Хотя бы одну заглавную букву\n"
            "• Хотя бы одну строчную букву\n"
            "• Хотя бы одну цифру");
        return;
    }

    if (newPassword != confirmPassword) {
        AppMessage::warning(this, "Ошибка", "Пароли не совпадают");
        return;
    }

    // Сбрасываем пароль через AuthService
    if (!m_authService) {
        AppMessage::critical(this, "Ошибка", "Сервис аутентификации не подключен");
        return;
    }

    if (m_authService->resetPassword(m_currentEmail, newPassword)) {
        AppMessage::information(this, "Успех",
            QString("Пароль успешно изменен для %1\n\nТеперь вы можете войти с новым паролем.").arg(m_currentEmail));
        emit passwordResetSuccess();
    } else {
        AppMessage::critical(this, "Ошибка",
            QString("Не удалось сбросить пароль:\n%1").arg(m_authService->getLastError()));
    }
}

bool ForgotPasswordWidget::validateEmail(const QString &email)
{
    QRegularExpression emailRegex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    return emailRegex.match(email).hasMatch();
}

bool ForgotPasswordWidget::validatePasswordFormat(const QString &password)
{
    return User::isValidPassword(password);
}

void ForgotPasswordWidget::validatePassword(const QString &password)
{

    // Проверка длины (минимум 8 символов)
    if (password.length() >= 8) {
        m_passwordLengthCheck->setText("Минимум 8 символов");
        AppTheme::role(m_passwordLengthCheck, "success");
    } else {
        m_passwordLengthCheck->setText("Минимум 8 символов");
        AppTheme::role(m_passwordLengthCheck, "muted");
    }

    // Проверка наличия строчных букв
    if (password.contains(QRegularExpression("[a-z]"))) {
        m_passwordLowercaseCheck->setText("Строчные буквы");
        AppTheme::role(m_passwordLowercaseCheck, "success");
    } else {
        m_passwordLowercaseCheck->setText("Строчные буквы");
        AppTheme::role(m_passwordLowercaseCheck, "muted");
    }

    // Проверка наличия заглавных букв
    if (password.contains(QRegularExpression("[A-Z]"))) {
        m_passwordUppercaseCheck->setText("Заглавные буквы");
        AppTheme::role(m_passwordUppercaseCheck, "success");
    } else {
        m_passwordUppercaseCheck->setText("Заглавные буквы");
        AppTheme::role(m_passwordUppercaseCheck, "muted");
    }

    // Проверка наличия цифр
    if (password.contains(QRegularExpression("[0-9]"))) {
        m_passwordDigitCheck->setText("Цифры");
        AppTheme::role(m_passwordDigitCheck, "success");
    } else {
        m_passwordDigitCheck->setText("Цифры");
        AppTheme::role(m_passwordDigitCheck, "muted");
    }
}

QString ForgotPasswordWidget::generateVerificationCode()
{
    // Генерируем 6-значный код
    QString code;
    for (int i = 0; i < 6; ++i) {
        code += QString::number(QRandomGenerator::global()->bounded(10));
    }
    return code;
}

void ForgotPasswordWidget::loadEmailConfig()
{
    // Загружаем конфигурацию email из файла config/email.json (если существует)
    // Определяем корень проекта аналогично totpservice.cpp и kuznechikwidget.cpp
    QString appDir = QCoreApplication::applicationDirPath();
    QDir projectRootDir(appDir);

    // macOS bundle: <project>/build/3FA.app/Contents/MacOS
    if (appDir.contains("/Contents/MacOS")) {
        projectRootDir = QDir(projectRootDir.absoluteFilePath("../../../../")); // поднимаемся до корня проекта
    } else {
        // Обычный случай: бинарь в build/ → поднимаемся на один уровень к корню проекта, если виден CMakeLists.txt
        QDir tryBuildParent(projectRootDir.absoluteFilePath(".."));
        if (tryBuildParent.exists("CMakeLists.txt")) {
            projectRootDir = tryBuildParent;
        } else {
            // Поднимаемся до корня проекта, ища CMakeLists.txt
            while (!projectRootDir.exists("CMakeLists.txt") && projectRootDir.cdUp()) {
                if (projectRootDir.isRoot()) break;
            }
        }
    }

    QString projectRoot = projectRootDir.absolutePath();
    QString configPath = QDir(projectRoot).absoluteFilePath("config/email.json");
    QFile configFile(configPath);

    qDebug() << "EmailService: Ищем конфигурацию в" << configPath;
    qDebug() << "EmailService: Корень проекта:" << projectRoot;

    if (configFile.exists()) {
        qDebug() << "EmailService: Файл конфигурации найден:" << configPath;

        if (configFile.open(QIODevice::ReadOnly)) {
            QByteArray data = configFile.readAll();
            configFile.close();

            qDebug() << "EmailService: Размер файла:" << data.size() << "байт";
            qDebug() << "EmailService: Содержимое файла:" << QString::fromUtf8(data);

            QJsonParseError parseError;
            QJsonDocument doc = QJsonDocument::fromJson(data, &parseError);

            if (parseError.error != QJsonParseError::NoError) {
                qWarning() << "EmailService: Ошибка парсинга JSON:" << parseError.errorString() << "в позиции" << parseError.offset;
                qWarning() << "EmailService: Содержимое файла:" << QString::fromUtf8(data);
            } else if (doc.isObject()) {
                QJsonObject obj = doc.object();
                qDebug() << "EmailService: JSON успешно распарсен, объект содержит ключи:" << obj.keys();

                // Проверяем, есть ли настройки API (SendGrid, Mailgun и т.д.)
                if (obj.contains("api")) {
                    QJsonObject api = obj["api"].toObject();
                    QString apiUrl = api["url"].toString();
                    QString apiKey = api["key"].toString();

                    qDebug() << "EmailService: Найдена секция API, url:" << apiUrl << "key:" << (apiKey.isEmpty() ? "пусто" : "заполнено");

                    if (!apiUrl.isEmpty() && !apiKey.isEmpty()) {
                        m_emailService->setApiConfig(apiUrl, apiKey);
                        qDebug() << "EmailService: Загружена конфигурация API из" << configPath;
                        qDebug() << "EmailService: Конфигурация применена, isConfigured:" << m_emailService->isConfigured();
                        return;
                    }
                }

                // Проверяем, есть ли настройки SMTP
                if (obj.contains("smtp")) {
                    QJsonObject smtp = obj["smtp"].toObject();
                    QString host = smtp["host"].toString();
                    int port = smtp["port"].toInt(587);
                    QString username = smtp["username"].toString();
                    QString password = smtp["password"].toString();
                    bool useSsl = smtp["use_ssl"].toBool(true);

                    qDebug() << "EmailService: Найдена секция SMTP, host:" << host << "username:" << username;
                    qDebug() << "EmailService: port:" << port << "use_ssl:" << useSsl << "password:" << (password.isEmpty() ? "пусто" : "заполнено");

                    if (!host.isEmpty() && !username.isEmpty()) {
                        m_emailService->setSmtpConfig(host, port, username, password, useSsl);
                        qDebug() << "EmailService: Загружена конфигурация SMTP из" << configPath;
                        qDebug() << "EmailService: Конфигурация применена, isConfigured:" << m_emailService->isConfigured();
                        return;
                    } else {
                        qWarning() << "EmailService: SMTP секция найдена, но host или username пустые";
                    }
                } else {
                    qWarning() << "EmailService: Секция 'smtp' не найдена в JSON объекте";
                }
            } else {
                qWarning() << "EmailService: JSON документ не является объектом";
            }
        } else {
            qWarning() << "EmailService: Не удалось открыть файл для чтения:" << configFile.errorString();
        }
    } else {
        qWarning() << "EmailService: Файл конфигурации не существует:" << configPath;
    }

    // Если конфигурация не найдена, используем значения по умолчанию или показываем предупреждение
    qWarning() << "EmailService: Конфигурация email не найдена в" << configPath;
    qWarning() << "EmailService: Создайте файл config/email.json с настройками SMTP или API";
}

void ForgotPasswordWidget::toggleNewPasswordVisibility()
{
    if (m_newPasswordEdit->echoMode() == QLineEdit::Password) {
        m_newPasswordEdit->setEchoMode(QLineEdit::Normal);
        AppTheme::buttonIcon(m_newPasswordToggleButton, "eye-off"); // Глаз закрыт
    } else {
        m_newPasswordEdit->setEchoMode(QLineEdit::Password);
        AppTheme::buttonIcon(m_newPasswordToggleButton, "eye"); // Глаз открыт
    }
}

void ForgotPasswordWidget::toggleConfirmPasswordVisibility()
{
    if (m_confirmPasswordEdit->echoMode() == QLineEdit::Password) {
        m_confirmPasswordEdit->setEchoMode(QLineEdit::Normal);
        AppTheme::buttonIcon(m_confirmPasswordToggleButton, "eye-off"); // Глаз закрыт
    } else {
        m_confirmPasswordEdit->setEchoMode(QLineEdit::Password);
        AppTheme::buttonIcon(m_confirmPasswordToggleButton, "eye"); // Глаз открыт
    }
}

bool ForgotPasswordWidget::sendVerificationCode(const QString &email, const QString &code)
{
    if (!m_emailService) {
        qWarning() << "EmailService не инициализирован";
        return false;
    }

    // Если email сервис не настроен, показываем код в сообщении (для тестирования)
    if (!m_emailService->isConfigured()) {
        qWarning() << "EmailService не настроен, показываем код в сообщении";
        AppMessage::persistent(this, "Код верификации",
            QString("Email сервис не настроен.\n\nКод верификации: %1\n\nДля настройки email создайте файл config/email.json").arg(code));
        return true; // Возвращаем true для продолжения процесса
    }

    // Отправляем код через EmailService
    if (m_emailService->sendVerificationCode(email, code)) {
        qDebug() << "Код верификации отправлен на" << email;
        return true;
    } else {
        QString error = m_emailService->getLastError();
        qWarning() << "Не удалось отправить код верификации:" << error;
        // Показываем код в сообщении как fallback
        AppMessage::warning(this, "Ошибка отправки email",
            QString("Не удалось отправить код по email:\n%1\n\nКод верификации: %2\n\nИспользуйте этот код для продолжения.").arg(error).arg(code));
        return true; // Возвращаем true, чтобы пользователь мог продолжить
    }
}

