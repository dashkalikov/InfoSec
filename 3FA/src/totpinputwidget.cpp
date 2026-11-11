#include "totpinputwidget.h"
#include "apptheme.h"
#include <QApplication>
#include <QClipboard>
#include <QDebug>

TOTPInputWidget::TOTPInputWidget(QWidget *parent)
    : QWidget(parent)
    , m_layout(nullptr)
{
    setupInputs();
    setupConnections();
}

TOTPInputWidget::~TOTPInputWidget()
{
    // Qt автоматически удалит дочерние виджеты
}

void TOTPInputWidget::setupInputs()
{
    m_layout = new QHBoxLayout(this);
    AppTheme::margins(m_layout, 0, 0, 0, 0);
    AppTheme::spacing(m_layout, 7);
    m_layout->setAlignment(Qt::AlignCenter); // Выравниваем по центру

    // Создаем 6 полей ввода
    for (int i = 0; i < 6; ++i) {
        m_inputs[i] = new QLineEdit();
        m_inputs[i]->setMaxLength(1);
        m_inputs[i]->setInputMethodHints(Qt::ImhDigitsOnly);
        m_inputs[i]->setAlignment(Qt::AlignCenter);
        m_inputs[i]->installEventFilter(this);

        // Стилизация каждого поля
        AppTheme::role(m_inputs[i], "otp");
        AppTheme::fixedSize(m_inputs[i], 40, 46);

        m_layout->addWidget(m_inputs[i]);
    }

    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
}

void TOTPInputWidget::setupConnections()
{
    // Подключаем сигналы для каждого поля
    for (int i = 0; i < 6; ++i) {
        connect(m_inputs[i], &QLineEdit::textChanged, this, &TOTPInputWidget::onTextChanged);
        connect(m_inputs[i], &QLineEdit::textEdited, this, &TOTPInputWidget::onTextEdited);
    }
}

QString TOTPInputWidget::getCode() const
{
    QString code;
    for (int i = 0; i < 6; ++i) {
        code += m_inputs[i]->text();
    }
    return code;
}

void TOTPInputWidget::setCode(const QString &code)
{
    // Блокируем сигналы во время установки
    for (int i = 0; i < 6; ++i) {
        m_inputs[i]->blockSignals(true);
    }

    // Устанавливаем код
    for (int i = 0; i < 6 && i < code.length(); ++i) {
        m_inputs[i]->setText(code.at(i));
    }

    // Разблокируем сигналы
    for (int i = 0; i < 6; ++i) {
        m_inputs[i]->blockSignals(false);
    }

    updateCode();
}

void TOTPInputWidget::clear()
{
    for (int i = 0; i < 6; ++i) {
        m_inputs[i]->clear();
    }
    m_inputs[0]->setFocus();
}

void TOTPInputWidget::setFocus()
{
    m_inputs[0]->setFocus();
}

void TOTPInputWidget::onTextChanged(const QString &text)
{
    QLineEdit *sender = qobject_cast<QLineEdit*>(QObject::sender());
    if (!sender) return;

    // Находим индекс отправителя
    int currentIndex = -1;
    for (int i = 0; i < 6; ++i) {
        if (m_inputs[i] == sender) {
            currentIndex = i;
            break;
        }
    }

    if (currentIndex == -1) return;

    // Если введен символ, переходим к следующему полю
    if (!text.isEmpty() && isValidDigit(text)) {
        moveToNext(currentIndex);
    }

    updateCode();
}

void TOTPInputWidget::onTextEdited(const QString &text)
{
    QLineEdit *sender = qobject_cast<QLineEdit*>(QObject::sender());
    if (!sender) return;

    // Находим индекс отправителя
    int currentIndex = -1;
    for (int i = 0; i < 6; ++i) {
        if (m_inputs[i] == sender) {
            currentIndex = i;
            break;
        }
    }

    if (currentIndex == -1) return;

    // Если поле очищено, НЕ переходим к предыдущему - остаемся в текущем
    // Это позволяет пользователю заменить значение в текущем поле

    updateCode();
}

void TOTPInputWidget::moveToNext(int currentIndex)
{
    if (currentIndex < 5) {
        m_inputs[currentIndex + 1]->setFocus();
    }
}

void TOTPInputWidget::moveToPrevious(int currentIndex)
{
    if (currentIndex > 0) {
        m_inputs[currentIndex - 1]->setFocus();
    }
}

void TOTPInputWidget::updateCode()
{
    QString code = getCode();
    emit codeChanged(code);

    // Если код полный, отправляем сигнал завершения
    if (code.length() == 6) {
        emit codeCompleted(code);
    }
}

bool TOTPInputWidget::isValidDigit(const QString &text) const
{
    if (text.isEmpty()) return true;
    if (text.length() > 1) return false;

    QChar ch = text.at(0);
    return ch.isDigit();
}

bool TOTPInputWidget::eventFilter(QObject *obj, QEvent *event)
{
    QLineEdit *input = qobject_cast<QLineEdit*>(obj);
    if (!input) return QWidget::eventFilter(obj, event);

    // Находим индекс поля
    int currentIndex = -1;
    for (int i = 0; i < 6; ++i) {
        if (m_inputs[i] == input) {
            currentIndex = i;
            break;
        }
    }

    if (currentIndex == -1) return QWidget::eventFilter(obj, event);

    if (event->type() == QEvent::KeyPress) {
        QKeyEvent *keyEvent = static_cast<QKeyEvent*>(event);

        switch (keyEvent->key()) {
        case Qt::Key_Backspace:
            // Если поле пустое, переходим к предыдущему и очищаем его
            if (input->text().isEmpty() && currentIndex > 0) {
                m_inputs[currentIndex - 1]->setFocus();
                m_inputs[currentIndex - 1]->clear();
                return true; // Поглощаем событие
            }
            // Если поле не пустое, просто очищаем его (стандартное поведение)
            break;

        case Qt::Key_Left:
            // Переход к предыдущему полю
            if (currentIndex > 0) {
                m_inputs[currentIndex - 1]->setFocus();
                return true;
            }
            break;

        case Qt::Key_Right:
            // Переход к следующему полю
            if (currentIndex < 5) {
                m_inputs[currentIndex + 1]->setFocus();
                return true;
            }
            break;

        case Qt::Key_Delete:
            // Очищаем текущее поле
            input->clear();
            return true;

        case Qt::Key_V:
            // Обработка Ctrl+V для вставки из буфера обмена
            if (keyEvent->modifiers() & Qt::ControlModifier) {
                QString clipboardText = QApplication::clipboard()->text();
                if (clipboardText.length() == 6 && clipboardText.toInt() > 0) {
                    setCode(clipboardText);
                    return true;
                }
            }
            break;

        default:
            // Если это цифра, заменяем содержимое поля
            if (keyEvent->text().length() == 1 && keyEvent->text().at(0).isDigit()) {
                input->setText(keyEvent->text());
                moveToNext(currentIndex);
                return true;
            }
            break;
        }
    }

    return QWidget::eventFilter(obj, event);
}

void TOTPInputWidget::keyPressEvent(QKeyEvent *event)
{
    // Обработка глобальных горячих клавиш
    switch (event->key()) {
    case Qt::Key_Escape:
        clear();
        break;

    case Qt::Key_Return:
    case Qt::Key_Enter:
        // Если код полный, отправляем сигнал завершения
        if (getCode().length() == 6) {
            emit codeCompleted(getCode());
        }
        break;

    default:
        QWidget::keyPressEvent(event);
        break;
    }
}
