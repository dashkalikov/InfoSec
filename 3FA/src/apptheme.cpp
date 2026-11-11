#include "apptheme.h"

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QFont>
#include <QFrame>
#include <QHash>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QKeySequence>
#include <QVBoxLayout>
#include <QLayout>
#include <QMargins>
#include <QMenu>
#include <QPainter>
#include <QPainterPath>
#include <QProxyStyle>
#include <QRawFont>
#include <QRegularExpression>
#include <QSettings>
#include <QStyle>
#include <QStyleHints>
#include <QStyleOption>
#include <QStyledItemDelegate>
#include <QTableWidget>

namespace {
int zoom = 100;
QFont baseFont;

class AdminTableDelegate final : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override
    {
        auto rowOption = option;
        rowOption.state &= ~QStyle::State_HasFocus;
        QStyledItemDelegate::paint(painter, rowOption, index);
    }

    void updateEditorGeometry(QWidget *editor, const QStyleOptionViewItem &option,
                              const QModelIndex &) const override
    {
        editor->setGeometry(option.rect);
    }
};

QString tableCellText(const QTableWidget *table, int row, int column)
{
    const auto *item = table->item(row, column);
    if (!item) return {};
    const auto copyText = item->data(Qt::UserRole);
    return copyText.isValid() ? copyText.toString() : item->text();
}

QString tableRowText(const QTableWidget *table, int row)
{
    if (row < 0) return {};
    QStringList cells;
    for (int column = 0; column < table->columnCount(); ++column) {
        cells.append(tableCellText(table, row, column));
    }
    return cells.join(u'\t');
}

void copyTableText(const QString &text)
{
    if (!text.isEmpty()) QApplication::clipboard()->setText(text);
}

void enableTableCopy(QTableWidget *table)
{
    auto *copyCell = new QAction(QObject::tr("Копировать ячейку"), table);
    copyCell->setShortcuts(QKeySequence::Copy);
    copyCell->setShortcutContext(Qt::WidgetShortcut);
    table->addAction(copyCell);
    QObject::connect(copyCell, &QAction::triggered, table, [table] {
        copyTableText(tableCellText(table, table->currentRow(), table->currentColumn()));
    });

    auto *copyRow = new QAction(QObject::tr("Копировать строку"), table);
    copyRow->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C));
    copyRow->setShortcutContext(Qt::WidgetShortcut);
    table->addAction(copyRow);
    QObject::connect(copyRow, &QAction::triggered, table, [table] {
        copyTableText(tableRowText(table, table->currentRow()));
    });

    table->setContextMenuPolicy(Qt::CustomContextMenu);
    QObject::connect(table, &QTableWidget::customContextMenuRequested, table,
                     [table, copyCell, copyRow](const QPoint &point) {
        const auto index = table->indexAt(point);
        if (!index.isValid()) return;
        table->setCurrentCell(index.row(), index.column());

        const auto cell = tableCellText(table, index.row(), index.column());
        const auto email = tableCellText(table, index.row(), 1);
        const auto row = tableRowText(table, index.row());
        QMenu menu(table);
        menu.addAction(copyCell->text(), &menu, [cell] { copyTableText(cell); })->setEnabled(!cell.isEmpty());
        menu.addAction(QObject::tr("Копировать email"), &menu, [email] { copyTableText(email); })->setEnabled(!email.isEmpty());
        menu.addAction(copyRow->text(), &menu, [row] { copyTableText(row); });
        menu.exec(table->viewport()->mapToGlobal(point));
    });
}

class AppStyle final : public QProxyStyle
{
public:
    AppStyle() : QProxyStyle(QStringLiteral("Fusion")) {}

    int pixelMetric(PixelMetric metric, const QStyleOption *option, const QWidget *widget) const override
    {
        if (metric == PM_IndicatorWidth || metric == PM_IndicatorHeight ||
            metric == PM_ExclusiveIndicatorWidth || metric == PM_ExclusiveIndicatorHeight) return AppTheme::pixels(18);
        return QProxyStyle::pixelMetric(metric, option, widget);
    }

    void drawPrimitive(PrimitiveElement element, const QStyleOption *option, QPainter *painter,
                       const QWidget *widget) const override
    {
        if (element == PE_IndicatorRadioButton) {
            drawRadioIndicator(option, painter);
            return;
        }
        if (element != PE_IndicatorCheckBox) {
            QProxyStyle::drawPrimitive(element, option, painter, widget);
            return;
        }

        const auto state = option->state;
        const bool checked = state.testAnyFlags(State_On | State_NoChange);
        const bool enabled = state.testFlag(State_Enabled);
        const QRectF square = QRectF(option->rect).adjusted(0.6, 0.6, -0.6, -0.6);
        const QColor blue = AppTheme::primaryColor();
        const QColor rim = option->palette.mid().color();
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing);
        painter->setPen(checked ? Qt::NoPen : QPen(rim, 1.2));
        painter->setBrush(checked ? (enabled ? blue : option->palette.mid().color()) : option->palette.base().color());
        const qreal side = square.width();
        painter->drawRoundedRect(square, side * .25, side * .25);
        if (checked) {
            const auto point = [&](qreal x, qreal y) { return square.topLeft() + QPointF(side * x, side * y); };
            QPainterPath mark;
            mark.moveTo(point(.25, .52));
            if (state & State_NoChange) {
                mark.lineTo(point(.75, .52));
            } else {
                mark.lineTo(point(.43, .69));
                mark.lineTo(point(.76, .32));
            }
            painter->setBrush(Qt::NoBrush);
            painter->setPen(QPen(Qt::white, side * .13, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            painter->drawPath(mark);
        }
        painter->restore();
    }

private:
    static void drawRadioIndicator(const QStyleOption *option, QPainter *painter)
    {
        const auto state = option->state;
        const bool checked = state.testFlag(State_On);
        const bool dark = AppTheme::isDark();
        const QColor blue = AppTheme::primaryColor();
        const QColor rim(dark ? "#8190a5" : "#8793a4");
        const QColor ink = !state.testFlag(State_Enabled) ? option->palette.color(QPalette::Disabled, QPalette::WindowText)
            : checked || state.testFlag(State_MouseOver) ? blue : rim;
        const QRectF bounds(option->rect);
        const qreal radius = qMin(bounds.width(), bounds.height()) / 2 - .8;
        const qreal stroke = checked ? radius * .56 : qMax(1.0, radius * .16);
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing);
        painter->setPen(QPen(ink, stroke));
        painter->setBrush(Qt::NoBrush);
        painter->drawEllipse(bounds.center(), radius - stroke / 2, radius - stroke / 2);
        painter->restore();
    }
};

struct Colors {
    const char *canvas;
    const char *panel;
    const char *field;
    const char *hover;
    const char *border;
    const char *text;
    const char *muted;
    const char *disabled;
    const char *accent;
    const char *primary;
    const char *primaryHover;
    const char *selected;
    const char *error;
    const char *success;
    const char *warning;
    const char *glassTop;
    const char *glassBottom;
    const char *glassRim;
    const char *glassHover;
};

// Surface and accent colors are adapted from the VS Code 2026 themes.
constexpr Colors darkColors{"#121314", "#191a1b", "#202122", "#292b2d", "#343637",
                            "#e8e9ea", "#a7a9ad", "#73777b", "#60b2d4", "#236b8a",
                            "#2a7899", "#234454", "#f48771", "#72c892", "#e9ba69",
                            "#282d37", "#1a1e25", "#39414f", "#343e50"};
constexpr Colors lightColors{"#ffffff", "#fafafd", "#ffffff", "#eef2f6", "#dce0e5",
                             "#202020", "#5c6067", "#727781", "#0069cc", "#0063be",
                             "#0055a5", "#dcecff", "#ad2929", "#246b43", "#855300",
                             "#ffffff", "#edf2fb", "#dce4f1", "#e3ebf8"};

const Colors &colors()
{
    return AppTheme::isDark() ? darkColors : lightColors;
}

class TableOutline final : public QWidget
{
public:
    explicit TableOutline(QWidget *parent) : QWidget(parent)
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        const QRectF bounds(rect());
        const int radius = AppTheme::pixels(12);
        QPainterPath outline;
        outline.addRoundedRect(bounds.adjusted(.5, .5, -.5, -.5), radius, radius);

        QPainterPath corners;
        corners.addRect(bounds);
        corners.addPath(outline);

        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.fillPath(corners, QColor(colors().panel));
        painter.setPen(QColor(colors().glassRim));
        painter.drawPath(outline);
    }
};

class AdminTable final : public QTableWidget
{
public:
    AdminTable() : m_outline(new TableOutline(this)) {}

protected:
    void resizeEvent(QResizeEvent *event) override
    {
        QTableWidget::resizeEvent(event);
        m_outline->setGeometry(rect());
        m_outline->raise();
    }

    void paintEvent(QPaintEvent *event) override
    {
        QTableWidget::paintEvent(event);

        const int firstEmptyY = qMax(0, verticalHeader()->length() - verticalOffset());
        const int bottom = viewport()->rect().bottom();
        if (firstEmptyY > bottom) return;

        QPainter painter(viewport());
        painter.setPen(QColor(colors().glassRim));
        const int lastColumnEdge = horizontalHeader()->length() - horizontalOffset() - 1;
        for (int column = 0; column < columnCount(); ++column) {
            if (isColumnHidden(column)) continue;
            const int x = columnViewportPosition(column) + columnWidth(column) - 1;
            if (x >= 0 && x < lastColumnEdge && x < viewport()->width()) {
                painter.drawLine(x, firstEmptyY, x, bottom);
            }
        }
    }

private:
    TableOutline *m_outline;
};

QString sheet(const Colors &c)
{
    QString qss = QStringLiteral(R"QSS(
QMainWindow, QWidget#appShell { background: @panel; }
QDialog { background: @canvas; }
QDialog#appMessage { background: transparent; }
QFrame#appToast { background: @panel; border: 1px solid @glassRim; border-radius: 12px; }
QLabel#toastTitle { font-size: 14px; font-weight: 650; }
QLabel#toastBody { color: @muted; font-size: 12px; }
QScrollArea#toastBodyScroll, QScrollArea#toastBodyScroll QWidget { background: transparent; border: 0; }
QWidget { color: @text; }
QWidget:disabled { color: @disabled; }
QStatusBar { background: @panel; border-top: 1px solid @glassRim; }
QStatusBar::item { border: 0; }
QFrame[ui="card"] { background: @panel; border: 1px solid @glassRim; border-radius: 20px; }
QFrame[ui="message"] { background: @panel; border: 1px solid @glassRim; border-radius: 16px; }
QFrame[ui="inset"], QLabel[ui="camera"] { background: @field; border: 1px solid @border; border-radius: 8px; }
QLabel { background: transparent; }
QLabel[ui="brand"] { font-size: 17px; font-weight: 700; }
QLabel[ui="eyebrow"] { color: @accent; font-size: 11px; font-weight: 700; }
QLabel[ui="title"] { font-size: 26px; font-weight: 700; }
QLabel[ui="section"] { font-size: 15px; font-weight: 650; }
QLabel[ui="muted"] { color: @muted; }
QLabel[ui="error"] { color: @error; }
QLabel[ui="warning"] { color: @warning; }
QDialog#appMessage QLabel[ui="warning"], QDialog#appMessage QLabel[ui="error"] { font-size: 11px; font-weight: 700; }
QLabel[ui="success"] { color: @success; }
QLabel[ui="qr"] { background: #ffffff; border: 1px solid @border; border-radius: 8px; padding: 12px; }
QLabel[ui="badge"] { color: @accent; background: @selected; padding: 5px 9px; border-radius: 5px; font-weight: 650; }

QPushButton {
    background: @field; color: @text; border: 1px solid @border; border-radius: 9px;
    padding: 8px 14px; min-height: 20px; font-weight: 600;
}
QPushButton:hover { background: @hover; }
QPushButton:pressed { background: @selected; }
QPushButton:focus { border-color: @accent; }
QPushButton[ui="primary"] { background: @primary; color: #ffffff; border-color: @primary; }
QPushButton[ui="primary"]:hover { background: @primaryHover; border-color: @primaryHover; }
QPushButton[ui="primary"]:focus { border-color: @accent; }
QPushButton[ui="quiet"] { background: transparent; border-color: transparent; color: @accent; }
QPushButton[ui="quiet"]:hover { background: @hover; }
QPushButton[ui="quiet"]:focus { border-color: @accent; }
QPushButton[ui="danger"] { color: @error; }
QPushButton[ui="destructive"] { color: @error; border-color: @error; }
QPushButton[ui="destructive"]:focus { border-color: @accent; }
QPushButton[ui="tool"] { padding: 3px; }
QPushButton[ui="nav"] { text-align: left; padding: 10px 14px; }
QPushButton#toastClose { background: transparent; border: 1px solid transparent; border-radius: 7px; padding: 0; min-height: 0; }
QPushButton#toastClose:hover { background: @glassHover; }
QPushButton#toastClose:focus { border-color: @accent; }
QPushButton:disabled, QPushButton[ui="primary"]:disabled, QPushButton[ui="quiet"]:disabled,
QPushButton[ui="danger"]:disabled { background: @panel; color: @disabled; border-color: @border; }

QFrame#algorithmSwitch QPushButton {
    background: transparent; color: transparent; border: 0; padding: 4px 10px; min-height: 24px;
}

QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
    background: @field; color: @text; border: 1px solid @border; border-radius: 9px;
    padding: 8px 12px; selection-background-color: @selected; selection-color: @text;
}
QLineEdit, QSpinBox, QComboBox { min-height: 20px; }
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus { border-color: @accent; }
QLineEdit[ui="invalid"] { border-color: @error; }
QLineEdit:disabled, QTextEdit:disabled, QPlainTextEdit:disabled, QSpinBox:disabled, QComboBox:disabled {
    color: @disabled; background: @panel;
}
QLineEdit[ui="otp"] { font-size: 20px; font-weight: 650; padding: 0; }
QComboBox { padding-right: 22px; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: top right; width: 23px; border: 0; }
QComboBox QAbstractItemView { background: @field; border: 1px solid @border; padding: 3px; selection-background-color: @selected; }
QComboBox QAbstractItemView::item { min-height: 24px; padding: 4px 8px; }
QRadioButton, QCheckBox { spacing: 7px; }

QGroupBox { border: 1px solid @border; border-radius: 8px; margin-top: 12px; padding: 10px 8px 7px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: @muted; }
QTabWidget::pane { border: 1px solid @border; border-radius: 6px; background: @panel; }
QTabBar::tab { color: @muted; padding: 9px 14px; border-bottom: 2px solid transparent; }
QTabBar::tab:hover { color: @text; background: @hover; }
QTabBar::tab:selected { color: @text; border-bottom-color: @accent; }
QTableView { background: @canvas; alternate-background-color: @panel; border: 1px solid @border;
             gridline-color: @border; selection-background-color: @selected; selection-color: @text; }
QTableWidget[ui="adminTable"] { border: 0; gridline-color: @glassRim; }
QTableWidget[ui="adminTable"]::item { padding: 0 10px; }
QTableWidget[ui="adminTable"] QHeaderView::section {
    background: @field; color: @text; padding: 0 10px; font-weight: 600;
    border: 0; border-bottom: 1px solid @glassRim; border-right: 1px solid @glassRim;
}
QTableWidget[ui="adminTable"] QHeaderView::section:last { border-right: 0; }
QTableWidget[ui="adminTable"] QPushButton[ui="danger"] {
    background: transparent; border-color: transparent; padding: 4px 8px;
}
QTableWidget[ui="adminTable"] QPushButton[ui="danger"]:enabled:hover { background: @hover; }
QTableWidget[ui="adminTable"] QPushButton[ui="danger"]:disabled { color: @disabled; }
QTableWidget[ui="adminTable"] QComboBox { padding-top: 4px; padding-bottom: 4px; }
QHeaderView::section { background: @panel; color: @muted; border: 0; border-bottom: 1px solid @border;
                      padding: 8px 9px; font-weight: 600; }
QTableCornerButton::section { background: @panel; border: 0; }
QScrollArea { border: 0; background: transparent; }
QScrollBar { background: transparent; }
QScrollBar:vertical { width: 10px; }
QScrollBar:horizontal { height: 10px; }
QScrollBar::handle { background: @border; border-radius: 4px; }
QScrollBar::handle:vertical { min-height: 28px; }
QScrollBar::handle:horizontal { min-width: 28px; }
QScrollBar::handle:hover { background: @disabled; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QProgressBar { background: @field; border: 1px solid @border; border-radius: 4px; text-align: center; }
QProgressBar::chunk { background: @primary; border-radius: 3px; }
QToolTip { background: @panel; color: @text; border: 1px solid @border; padding: 5px; }
)QSS");
    static const QRegularExpression pixelValue(QStringLiteral("(\\d+)px"));
    QString scaled;
    qsizetype position = 0;
    for (auto matches = pixelValue.globalMatch(qss); matches.hasNext();) {
        const auto match = matches.next();
        scaled += qss.mid(position, match.capturedStart() - position);
        scaled += QString::number(AppTheme::pixels(match.captured(1).toInt())) + QStringLiteral("px");
        position = match.capturedEnd();
    }
    scaled += qss.mid(position);
    qss = scaled + QStringLiteral(R"QSS(
QFrame#appTitleBar {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 @glassTop, stop:1 @glassBottom);
    border-bottom: 1px solid @glassRim;
}
QFrame#appTitleBar QLabel { font-size: 13px; }
QFrame#appTitleBar QLabel[ui="brand"] { font-size: 17px; }
QFrame#appTitleBar QPushButton, QFrame#zoomPanel QPushButton {
    font-size: 13px; padding: 0 9px; min-height: 0; border-width: 1px; border-radius: 16px;
}
QFrame#appTitleBar QPushButton[ui="glassTool"], QFrame#windowControls {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @glassTop, stop:1 @glassBottom);
    border: 1px solid @glassRim;
}
QFrame#windowControls { border-radius: 19px; }
QFrame#appTitleBar QPushButton[ui="glassTool"]:hover { background: @glassHover; }
QFrame#appTitleBar QPushButton[ui="caption"] { padding: 0; border: 0; background: transparent; }
QFrame#appTitleBar QPushButton[ui="glassTool"]:focus { border-color: @accent; }
QFrame#zoomPanel QLabel { font-size: 13px; font-weight: 700; }
QFrame#zoomPanel QPushButton { background: @glassBottom; border-color: @glassRim; }
QFrame#zoomPanel QPushButton:hover { background: @glassHover; }
QFrame#zoomPanel QPushButton:focus { border-color: @accent; }
QFrame#zoomPanel QPushButton#zoomIn, QFrame#zoomPanel QPushButton#zoomOut {
    background: transparent; border-color: transparent; font-size: 18px; padding: 0;
}
QFrame#zoomPanel QPushButton#zoomIn:hover, QFrame#zoomPanel QPushButton#zoomOut:hover { background: @glassHover; }
QFrame#zoomPanel QPushButton#zoomIn:focus, QFrame#zoomPanel QPushButton#zoomOut:focus { border-color: @accent; }
)QSS");
    return qss.replace("@canvas", c.canvas).replace("@panel", c.panel).replace("@field", c.field)
        .replace("@hover", c.hover).replace("@border", c.border).replace("@text", c.text)
        .replace("@muted", c.muted).replace("@disabled", c.disabled).replace("@accent", c.accent)
        .replace("@primaryHover", c.primaryHover).replace("@primary", c.primary)
        .replace("@selected", c.selected).replace("@error", c.error).replace("@success", c.success)
        .replace("@warning", c.warning).replace("@glassTop", c.glassTop).replace("@glassBottom", c.glassBottom)
        .replace("@glassRim", c.glassRim).replace("@glassHover", c.glassHover);
}

QPainterPath materialGlyph(const QString &name)
{
    static const QRawFont font(QStringLiteral(":/3fa/material-symbols/MaterialSymbolsRounded.ttf"), 24, QFont::PreferNoHinting);
    static const QHash<QString, ushort> codepoints{
        {"alert", 0xf083}, {"back", 0xe5c4}, {"camera", 0xe412}, {"check", 0xe668},
        {"clock", 0xefd6}, {"close", 0xe5cd}, {"delete", 0xe92e}, {"download", 0xf090},
        {"enter", 0xea77}, {"error-circle", 0xf8b6}, {"exit", 0xe9ba}, {"eye", 0xe8f4},
        {"eye-off", 0xe8f5}, {"file", 0xe873}, {"info", 0xe88e}, {"key", 0xe73c},
        {"lock", 0xe899}, {"maximize", 0xe3c6}, {"minimize", 0xe15b}, {"moon", 0xe51c},
        {"plus", 0xe145}, {"refresh", 0xe5d5}, {"restore", 0xe3e0}, {"shield", 0xf013},
        {"sun", 0xe518}, {"unlock", 0xe898}, {"users", 0xea21},
    };
    if (!font.isValid()) return {};
    const auto character = QChar(codepoints.value(name, 0xe668));
    const auto glyphs = font.glyphIndexesForString(QString(character));
    auto path = font.pathForGlyph(glyphs.value(0));
    path.translate(QPointF(12, 12) - path.boundingRect().center());
    return path;
}

QIcon drawIcon(const QString &name, const QColor &color, bool brand = false, qreal verticalOffset = 0)
{
    const auto glyph = materialGlyph(name);
    QIcon icon;
    for (int size : {16, 24, 32, 48, 64, 128, 256}) {
        QPixmap pixmap(size, size);
        pixmap.fill(Qt::transparent);
        QPainter painter(&pixmap);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.scale(size / 24.0, size / 24.0);
        painter.setPen(Qt::NoPen);
        if (brand) {
            painter.setBrush(QColor("#236b8a"));
            painter.drawRoundedRect(QRectF(0.5, 0.5, 23, 23), 5, 5);
            painter.translate(2, 2);
            painter.scale(20.0 / 24, 20.0 / 24);
        }
        painter.translate(0, verticalOffset);
        painter.setBrush(color);
        painter.drawPath(glyph);
        painter.end();
        icon.addPixmap(pixmap);
    }
    return icon;
}

void refreshStyle()
{
    auto font = baseFont;
    if (font.pointSizeF() > 0) font.setPointSizeF(font.pointSizeF() * zoom / 100.0);
    else if (font.pixelSize() > 0) font.setPixelSize(AppTheme::pixels(font.pixelSize()));
    QApplication::setFont(font);
    qApp->setStyleSheet(sheet(colors()));
    for (auto *widget : QApplication::allWidgets()) {
        if (auto *button = qobject_cast<QAbstractButton *>(widget)) {
            const auto name = button->property("glyph").toByteArray();
            if (!name.isEmpty()) AppTheme::buttonIcon(button, name.constData());
        }
    }
}
}

namespace AppTheme {
void restore()
{
    QApplication::setStyle(new AppStyle);
    static const QFont defaultFont = QApplication::font();
    auto font = defaultFont;
#ifdef Q_OS_WIN
    font.setFamily(QStringLiteral("Segoe UI"));
#endif
    if (font.pointSizeF() > 0 && font.pointSizeF() < 10) {
        font.setPointSize(10);
    }
    baseFont = font;
    zoom = qBound(75, QSettings().value("appearance/zoom", 100).toInt(), 200);
    setDark(QSettings().value("appearance/theme", "dark").toString() != "light");
    QApplication::setWindowIcon(logo());
}

bool isDark()
{
    return qApp->property("appearanceDark").toBool();
}

QColor primaryColor()
{
    return QColor(colors().primary);
}

void setDark(bool dark)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 8, 0)
    QApplication::styleHints()->setColorScheme(dark ? Qt::ColorScheme::Dark : Qt::ColorScheme::Light);
#endif
    qApp->setProperty("appearanceDark", dark);
    QSettings().setValue("appearance/theme", dark ? "dark" : "light");
    const auto &c = colors();
    QPalette palette;
    palette.setColor(QPalette::Window, QColor(c.canvas));
    palette.setColor(QPalette::WindowText, QColor(c.text));
    palette.setColor(QPalette::Base, QColor(c.field));
    palette.setColor(QPalette::AlternateBase, QColor(c.panel));
    palette.setColor(QPalette::Button, QColor(c.field));
    palette.setColor(QPalette::ButtonText, QColor(c.text));
    palette.setColor(QPalette::Text, QColor(c.text));
    palette.setColor(QPalette::PlaceholderText, QColor(c.muted));
    palette.setColor(QPalette::Highlight, QColor(c.selected));
    palette.setColor(QPalette::HighlightedText, QColor(c.text));
    palette.setColor(QPalette::Link, QColor(c.accent));
    palette.setColor(QPalette::Mid, QColor(c.glassRim));
    palette.setColor(QPalette::Disabled, QPalette::Text, QColor(c.disabled));
    palette.setColor(QPalette::Disabled, QPalette::WindowText, QColor(c.disabled));
    palette.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(c.disabled));
    QApplication::setPalette(palette);
    refreshStyle();
}

int zoomPercent()
{
    return zoom;
}

int pixels(int value)
{
    return value > 0 ? qMax(1, qRound(value * zoom / 100.0)) : value;
}

void dimension(QWidget *widget, const char *property, int value)
{
    auto dimensions = widget->property("uiDimensions").toMap();
    dimensions.insert(QString::fromLatin1(property), value);
    widget->setProperty("uiDimensions", dimensions);
    widget->setProperty(property, pixels(value));
}

void fixedWidth(QWidget *widget, int width)
{
    dimension(widget, "maximumWidth", width);
    dimension(widget, "minimumWidth", width);
}

void fixedHeight(QWidget *widget, int height)
{
    dimension(widget, "maximumHeight", height);
    dimension(widget, "minimumHeight", height);
}

void fixedSize(QWidget *widget, int width, int height)
{
    fixedWidth(widget, width);
    fixedHeight(widget, height);
}

void margins(QLayout *layout, int left, int top, int right, int bottom)
{
    layout->setProperty("uiMargins", QVariant::fromValue(QMargins(left, top, right, bottom)));
    layout->setContentsMargins(pixels(left), pixels(top), pixels(right), pixels(bottom));
}

void spacing(QLayout *layout, int value)
{
    layout->setProperty("uiSpacing", value);
    layout->setSpacing(pixels(value));
}

void centerBlock(QVBoxLayout *layout, QWidget *block)
{
    auto *row = new QHBoxLayout;
    row->setSpacing(0);
    row->addStretch();
    row->addWidget(block, 1);
    row->addStretch();
    layout->addStretch();
    layout->addLayout(row);
    layout->addStretch();
}

QVBoxLayout *centeredCard(QWidget *page, int width)
{
    auto *layout = new QVBoxLayout(page);
    layout->setObjectName("centeredPageLayout");
    AppTheme::margins(layout, 20, 22, 20, 22);
    auto *card = new QFrame;
    AppTheme::dimension(card, "maximumWidth", width);
    AppTheme::role(card, "card");
    auto *contents = new QVBoxLayout(card);
    contents->setObjectName("centeredCardLayout");
    AppTheme::margins(contents, 32, 30, 32, 30);
    AppTheme::spacing(contents, 16);
    centerBlock(layout, card);
    return contents;
}

void setZoomPercent(int percent)
{
    percent = qBound(75, percent, 200);
    if (zoom == percent) return;
    zoom = percent;
    QSettings().setValue("appearance/zoom", zoom);
    refreshStyle();
    for (auto *widget : QApplication::allWidgets()) {
        const auto dimensions = widget->property("uiDimensions").toMap();
        for (auto it = dimensions.cbegin(); it != dimensions.cend(); ++it) {
            widget->setProperty(it.key().toLatin1().constData(), pixels(it.value().toInt()));
        }
    }
    for (auto *window : QApplication::topLevelWidgets()) {
        for (auto *layout : window->findChildren<QLayout *>()) {
            const auto baseMargins = layout->property("uiMargins");
            if (baseMargins.isValid()) {
                const auto m = baseMargins.value<QMargins>();
                layout->setContentsMargins(pixels(m.left()), pixels(m.top()), pixels(m.right()), pixels(m.bottom()));
            }
            const auto baseSpacing = layout->property("uiSpacing");
            if (baseSpacing.isValid()) layout->setSpacing(pixels(baseSpacing.toInt()));
        }
    }
}

void role(QWidget *widget, const char *name)
{
    if (widget->property("ui").toByteArray() == name) return;
    widget->setProperty("ui", QByteArray(name));
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
    widget->update();
    auto *button = qobject_cast<QAbstractButton *>(widget);
    if (button) {
        const auto glyphName = button->property("glyph").toByteArray();
        if (!glyphName.isEmpty()) buttonIcon(button, glyphName.constData());
    }
}

QTableWidget *createAdminTable()
{
    auto *table = new AdminTable;
    role(table, "adminTable");
    table->setItemDelegate(new AdminTableDelegate(table));
    table->setShowGrid(true);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->hide();
    table->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    dimension(table->verticalHeader(), "defaultSectionSize", 46);
    table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    dimension(table->horizontalHeader(), "minimumSectionSize", 48);
    fixedHeight(table->horizontalHeader(), 38);
    enableTableCopy(table);

    return table;
}

void setTableCell(QTableWidget *table, int row, int column, QWidget *control,
                  const QString &copyText)
{
    auto *item = new QTableWidgetItem;
    item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
    if (!copyText.isEmpty()) item->setData(Qt::UserRole, copyText);
    table->setItem(row, column, item);

    auto *cell = new QWidget;
    cell->setAutoFillBackground(false);
    auto *layout = new QHBoxLayout(cell);
    margins(layout, 8, 4, 8, 4);
    layout->addWidget(control);
    table->setCellWidget(row, column, cell);
}

void buttonIcon(QAbstractButton *button, const char *name)
{
    button->setProperty("glyph", QByteArray(name));
    const auto role = button->property("ui").toByteArray();
    QColor color(colors().muted);
    if (role == "primary") color = Qt::white;
    else if (role == "caption") color = QColor(colors().text);
    button->setIcon(drawIcon(QString::fromLatin1(name), color, false, role == "danger" ? 1.5 : 0));
    const int size = button->property("fixedChromeIcon").toBool() ? (role == "caption" ? 18 : 16) : pixels(16);
    button->setIconSize(QSize(size, size));
}

QIcon logo()
{
    return drawIcon(QStringLiteral("shield"), QColor(Qt::white), true);
}

QIcon statusIcon(const char *name, const char *tone)
{
    const auto &c = colors();
    const QByteArray kind(tone);
    return drawIcon(QString::fromLatin1(name), QColor(kind == "error" ? c.error : kind == "warning" ? c.warning : c.accent));
}
}
