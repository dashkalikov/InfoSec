#ifndef TOTPINPUTWIDGET_H
#define TOTPINPUTWIDGET_H

#include <QWidget>
#include <QLineEdit>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QFocusEvent>

class TOTPInputWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TOTPInputWidget(QWidget *parent = nullptr);
    ~TOTPInputWidget();

    // Получение и установка значения
    QString getCode() const;
    void setCode(const QString &code);
    void clear();
    void setFocus();

signals:
    void codeChanged(const QString &code);
    void codeCompleted(const QString &code);

private slots:
    void onTextChanged(const QString &text);
    void onTextEdited(const QString &text);

private:
    // Массив из 6 полей ввода
    QLineEdit *m_inputs[6];
    QHBoxLayout *m_layout;
    
    // Вспомогательные методы
    void setupInputs();
    void setupConnections();
    void moveToNext(int currentIndex);
    void moveToPrevious(int currentIndex);
    void updateCode();
    bool isValidDigit(const QString &text) const;
    
    // Обработка событий
    bool eventFilter(QObject *obj, QEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
};

#endif // TOTPINPUTWIDGET_H
