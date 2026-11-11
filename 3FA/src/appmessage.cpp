#include "appmessage.h"
#include "apptheme.h"

#include <QApplication>
#include <QDialog>
#include <QEvent>
#include <QFrame>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QMainWindow>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScreen>
#include <QScrollArea>
#include <QStyle>
#include <QTimer>
#include <QVBoxLayout>

namespace {
using Kind = AppMessage::Kind;

QWidget *messageHost(QWidget *parent)
{
    auto *window = parent ? parent->window() : QApplication::activeWindow();
    if (auto *main = qobject_cast<QMainWindow *>(window); main && main->centralWidget()) return main->centralWidget();
    return window;
}

QPoint topCenter(const QWidget *host, int width)
{
    const auto *header = host->findChild<QWidget *>("appTitleBar", Qt::FindDirectChildrenOnly);
    const int top = header && !header->isHidden() ? header->geometry().bottom() + 1 : 0;
    return {qMax(0, (host->width() - width) / 2), top + 12};
}

QIcon messageIcon(Kind kind)
{
    if (kind == Kind::Error) return AppTheme::statusIcon("error-circle", "error");
    if (kind == Kind::Warning) return AppTheme::statusIcon("alert", "warning");
    return AppTheme::statusIcon("info", "eyebrow");
}

QLabel *messageText(const QString &text)
{
    auto *label = new QLabel(text);
    label->setTextFormat(Qt::PlainText);
    label->setWordWrap(true);
    return label;
}

class Toast final : public QFrame
{
public:
    Toast(QWidget *parent, const QString &title, const QString &text, Kind kind, bool persistent)
        : QFrame(parent), m_kind(kind), m_persistent(persistent), m_title(title), m_text(text),
          m_opacity(new QGraphicsOpacityEffect(this)), m_fade(m_opacity, "opacity")
    {
        setObjectName("appToast");
        setAccessibleName(title);
        m_opacity->setOpacity(0);
        setGraphicsEffect(m_opacity);
        m_timer.setSingleShot(true);
        connect(&m_timer, &QTimer::timeout, this, &Toast::dismiss);
        connect(&m_fade, &QPropertyAnimation::finished, this, [this] {
            if (m_dismissing) {
                hide();
                deleteLater();
            } else {
                armTimer();
            }
        });

        auto *row = new QHBoxLayout(this);
        AppTheme::margins(row, 12, 10, 10, 10);
        AppTheme::spacing(row, 9);
        m_icon = new QLabel;
        AppTheme::fixedSize(m_icon, 18, 18);
        row->addWidget(m_icon, 0, Qt::AlignTop);

        auto *copy = new QVBoxLayout;
        AppTheme::spacing(copy, 3);
        m_caption = messageText(title);
        m_caption->setObjectName("toastTitle");
        m_caption->setAlignment(Qt::AlignTop | Qt::AlignLeft);
        m_caption->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
        copy->addWidget(m_caption);
        m_body = messageText(text);
        m_body->setObjectName("toastBody");
        m_body->setTextInteractionFlags(Qt::TextSelectableByMouse);
        m_body->setAlignment(Qt::AlignTop | Qt::AlignLeft);
        m_body->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        m_scroll = new QScrollArea;
        m_scroll->setObjectName("toastBodyScroll");
        m_scroll->setFrameShape(QFrame::NoFrame);
        m_scroll->setFocusPolicy(Qt::NoFocus);
        m_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        m_scroll->setWidgetResizable(true);
        m_scroll->setWidget(m_body);
        copy->addWidget(m_scroll);
        row->addLayout(copy, 1);

        m_close = new QPushButton;
        m_close->setObjectName("toastClose");
        m_close->setAccessibleName(tr("Закрыть уведомление"));
        m_close->setToolTip(m_close->accessibleName());
        m_close->setFocusPolicy(Qt::TabFocus);
        AppTheme::fixedSize(m_close, 24, 24);
        AppTheme::buttonIcon(m_close, "close");
        row->addWidget(m_close, 0, Qt::AlignTop);
        connect(m_close, &QPushButton::clicked, this, &Toast::dismiss);
    }

    bool matches(const QString &title, const QString &text, Kind kind, bool persistent) const
    {
        return !m_dismissing && m_kind == kind && m_persistent == persistent && m_title == title && m_text == text;
    }

    bool persistentWithTitle(const QString &title) const { return m_persistent && m_title == title; }
    bool isPersistent() const { return m_persistent; }

    void dismissWith(QWidget *source)
    {
        source->installEventFilter(this);
        connect(source, &QObject::destroyed, this, &Toast::dismiss);
    }

    void fit(int width, int windowHeight)
    {
        ensurePolished();
        m_caption->ensurePolished();
        m_body->ensurePolished();
        setFixedWidth(width);
        m_icon->setPixmap(messageIcon(m_kind).pixmap(m_icon->size(), devicePixelRatioF()));
        const auto margins = layout()->contentsMargins();
        const int bodyWidth = qMax(24, width - margins.left() - margins.right() - m_icon->width() -
                                      m_close->width() - 2 * layout()->spacing());
        const int captionHeight = qMax(m_caption->fontMetrics().height(), m_caption->heightForWidth(bodyWidth));
        m_caption->setFixedHeight(captionHeight);
        const int limit = qMin(AppTheme::pixels(96), qMax(36, windowHeight / 5));
        int bodyHeight = qMax(m_body->fontMetrics().height(), m_body->heightForWidth(bodyWidth));
        if (bodyHeight > limit) {
            const int scrollbar = m_scroll->style()->pixelMetric(QStyle::PM_ScrollBarExtent);
            bodyHeight = qMax(bodyHeight, m_body->heightForWidth(qMax(24, bodyWidth - scrollbar)));
        }
        m_body->setMinimumHeight(bodyHeight);
        const int visibleBody = qMin(limit, bodyHeight);
        m_scroll->setFixedHeight(visibleBody);
        const int textHeight = captionHeight + AppTheme::pixels(3) + visibleBody;
        const int rowHeight = qMax(textHeight, qMax(m_icon->height(), m_close->height()));
        setFixedHeight(margins.top() + rowHeight + margins.bottom());
    }

protected:
    bool eventFilter(QObject *watched, QEvent *event) override
    {
        if (event->type() == QEvent::Hide && !event->spontaneous()) dismiss();
        return QFrame::eventFilter(watched, event);
    }

    void showEvent(QShowEvent *event) override
    {
        QFrame::showEvent(event);
        if (!m_started) {
            m_started = true;
            fadeTo(1, 180);
        } else if (m_fade.state() != QAbstractAnimation::Running) {
            armTimer();
        }
    }

    void hideEvent(QHideEvent *event) override
    {
        m_timer.stop();
        QFrame::hideEvent(event);
    }

    void enterEvent(QEnterEvent *event) override
    {
        m_timer.stop();
        QFrame::enterEvent(event);
    }

    void leaveEvent(QEvent *event) override
    {
        armTimer();
        QFrame::leaveEvent(event);
    }

private:
    void armTimer()
    {
        if (m_persistent || m_dismissing || !isVisible() || underMouse()) return;
        const int base = m_kind == Kind::Error ? 7200 : m_kind == Kind::Warning ? 5600 : 4300;
        m_timer.start(base + int(qBound(qsizetype{0}, (m_text.size() - 80) * 15, qsizetype{3000})));
    }

    void dismiss()
    {
        if (m_dismissing) return;
        m_dismissing = true;
        m_timer.stop();
        fadeTo(0, 260);
    }

    void fadeTo(qreal target, int duration)
    {
        m_fade.stop();
        m_fade.setDuration(duration);
        m_fade.setStartValue(m_opacity->opacity());
        m_fade.setEndValue(target);
        m_fade.setEasingCurve(QEasingCurve::InOutSine);
        m_fade.start();
    }

    Kind m_kind;
    bool m_persistent;
    QString m_title;
    QString m_text;
    QGraphicsOpacityEffect *m_opacity;
    QPropertyAnimation m_fade;
    QTimer m_timer;
    QLabel *m_icon;
    QLabel *m_caption;
    QLabel *m_body;
    QScrollArea *m_scroll;
    QPushButton *m_close;
    bool m_started = false;
    bool m_dismissing = false;
};

class ToastArea final : public QWidget
{
public:
    explicit ToastArea(QWidget *host) : QWidget(host), m_stack(new QVBoxLayout(this))
    {
        setObjectName("appToastArea");
        m_stack->setContentsMargins(0, 0, 0, 0);
        m_stack->setSpacing(8);
        host->installEventFilter(this);
    }

    void push(const QString &title, const QString &text, Kind kind, bool persistent, QWidget *source)
    {
        for (int index = m_stack->count() - 1; index >= 0; --index) {
            auto *toast = static_cast<Toast *>(m_stack->itemAt(index)->widget());
            if (toast->matches(title, text, kind, persistent)) return;
            if (persistent && toast->persistentWithTitle(title)) removeToast(toast);
        }
        if (m_stack->count() >= 3) {
            for (int index = m_stack->count() - 1; index >= 0; --index) {
                auto *toast = static_cast<Toast *>(m_stack->itemAt(index)->widget());
                if (!toast->isPersistent()) {
                    removeToast(toast);
                    break;
                }
            }
            if (m_stack->count() >= 3) removeToast(static_cast<Toast *>(m_stack->itemAt(2)->widget()));
        }

        auto *toast = new Toast(this, title, text, kind, persistent);
        if (persistent && source && source != parentWidget()->window()) toast->dismissWith(source);
        connect(toast, &QObject::destroyed, this, [this] { reflow(); }, Qt::QueuedConnection);
        m_stack->insertWidget(0, toast);
        toast->show();
        reflow();
        show();
        raise();
    }

protected:
    bool eventFilter(QObject *watched, QEvent *event) override
    {
        if (event->type() == QEvent::Resize || event->type() == QEvent::Show) reflow();
        if (event->type() == QEvent::StyleChange) QTimer::singleShot(0, this, [this] { reflow(); });
        return QWidget::eventFilter(watched, event);
    }

private:
    void removeToast(Toast *toast)
    {
        m_stack->removeWidget(toast);
        toast->hide();
        toast->deleteLater();
    }

    void reflow()
    {
        if (!m_stack->count()) {
            hide();
            return;
        }
        const auto *host = parentWidget();
        const int width = qMin(AppTheme::pixels(344), qMax(120, host->width() - 24));
        for (int index = 0; index < m_stack->count(); ++index)
            static_cast<Toast *>(m_stack->itemAt(index)->widget())->fit(width, host->height());
        m_stack->activate();
        setFixedSize(width, m_stack->sizeHint().height());
        move(topCenter(host, width));
    }

    QVBoxLayout *m_stack;
};

int displayDialog(QWidget *parent, const QString &title, const QString &text, Kind kind, const QString &action = {})
{
    QDialog dialog(parent ? parent->window() : nullptr, Qt::Dialog | Qt::FramelessWindowHint);
    dialog.setObjectName(QStringLiteral("appMessage"));
    dialog.setWindowTitle(title);
    dialog.setWindowModality(Qt::WindowModal);
    dialog.setAttribute(Qt::WA_TranslucentBackground);

    const bool confirmation = !action.isEmpty();
    const auto translate = [](const char *text) { return QDialog::tr(text); };

    auto *outer = new QVBoxLayout(&dialog);
    outer->setContentsMargins(0, 0, 0, 0);
    auto *card = new QFrame;
    AppTheme::role(card, "message");
    outer->addWidget(card);
    auto *contents = new QVBoxLayout(card);
    AppTheme::margins(contents, 16, 14, 16, 14);
    AppTheme::spacing(contents, 10);

    auto *heading = new QHBoxLayout;
    heading->setSpacing(10);
    auto *icon = new QLabel;
    const int iconSize = AppTheme::pixels(18);
    icon->setPixmap(messageIcon(kind).pixmap(iconSize, iconSize));
    auto *caption = messageText(title);
    AppTheme::role(caption, "section");
    heading->addWidget(icon);
    heading->addWidget(caption, 1);
    contents->addLayout(heading);

    const auto available = dialog.screen()->availableGeometry();
    const auto *host = messageHost(parent);
    const int width = qMin(AppTheme::pixels(364), (host ? qMin(available.width(), host->width()) : available.width()) - 24);
    auto *body = messageText(text);
    body->setTextInteractionFlags(Qt::TextSelectableByMouse);
    body->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    AppTheme::role(body, "muted");
    const int bodyHeight = qMax(body->fontMetrics().height(), body->heightForWidth(width - AppTheme::pixels(32)));
    const int bodyLimit = qMin(AppTheme::pixels(150), available.height() / 2);
    if (bodyHeight <= bodyLimit) {
        contents->addWidget(body);
    } else {
        auto *scroll = new QScrollArea;
        scroll->setFrameShape(QFrame::NoFrame);
        scroll->setWidgetResizable(true);
        scroll->setFixedHeight(bodyLimit);
        body->setMinimumHeight(bodyHeight);
        scroll->setWidget(body);
        contents->addWidget(scroll);
    }

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(8);
    buttons->addStretch();
    auto *accept = new QPushButton(confirmation ? action : translate("Понятно"));
    AppTheme::role(accept, confirmation ? "destructive" : "primary");
    QObject::connect(accept, &QPushButton::clicked, &dialog, &QDialog::accept);
    if (confirmation) {
        auto *cancel = new QPushButton(translate("Отмена"));
        QObject::connect(cancel, &QPushButton::clicked, &dialog, &QDialog::reject);
        accept->setAutoDefault(false);
        cancel->setDefault(true);
        buttons->addWidget(cancel);
        cancel->setFocus();
    } else {
        accept->setDefault(true);
        accept->setFocus();
    }
    buttons->addWidget(accept);
    contents->addLayout(buttons);
    dialog.setFixedWidth(width);
    dialog.adjustSize();
    if (host) dialog.move(host->mapToGlobal(topCenter(host, width)));
    else dialog.move(available.center().x() - width / 2, available.top() + 12);
    return dialog.exec();
}

void notify(QWidget *parent, const QString &title, const QString &text, Kind kind, bool persistent)
{
    auto *host = messageHost(parent);
    if (!host) {
        displayDialog(parent, title, text, kind);
        return;
    }
    auto *area = static_cast<ToastArea *>(host->findChild<QWidget *>("appToastArea", Qt::FindDirectChildrenOnly));
    if (!area) area = new ToastArea(host);
    area->push(title, text, kind, persistent, parent);
}
}

namespace AppMessage {
void show(QWidget *parent, const QString &title, const QString &text, Kind kind)
{
    notify(parent, title, text, kind, false);
}

void persistent(QWidget *parent, const QString &title, const QString &text, Kind kind)
{
    notify(parent, title, text, kind, true);
}

void information(QWidget *parent, const QString &title, const QString &text)
{
    show(parent, title, text);
}

void warning(QWidget *parent, const QString &title, const QString &text)
{
    show(parent, title, text, Kind::Warning);
}

void critical(QWidget *parent, const QString &title, const QString &text)
{
    show(parent, title, text, Kind::Error);
}

bool confirm(QWidget *parent, const QString &title, const QString &text, const QString &action)
{
    return displayDialog(parent, title, text, Kind::Warning, action) == QDialog::Accepted;
}
}
