#include "facescanview.h"
#include "apptheme.h"

#include <QPainter>
#include <QPainterPath>
#include <cmath>
#include <utility>

FaceScanView::FaceScanView(QWidget *parent) : QWidget(parent)
{
    setObjectName("faceScanView");
    setAccessibleName(tr("Кадр камеры и ход сканирования лица"));
    setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    AppTheme::fixedHeight(this, 250);
    m_refresh.setInterval(16);
    m_refresh.setTimerType(Qt::PreciseTimer);
    connect(&m_refresh, &QTimer::timeout, this, [this] {
        m_displayedProgress += (qMax(0.0, m_progress) - m_displayedProgress) * .24;
        update();
    });
}

void FaceScanView::setFrame(QImage frame)
{
    m_frame = std::move(frame);
    update();
}

void FaceScanView::start()
{
    reset();
    m_motion.start();
    m_refresh.start();
}

void FaceScanView::setProgress(qreal fraction)
{
    m_progress = qBound(-1.0, fraction, 1.0);
}

void FaceScanView::reset()
{
    m_refresh.stop();
    m_frame = {};
    m_progress = -1;
    m_displayedProgress = 0;
    m_complete = false;
    update();
}

void FaceScanView::complete()
{
    reset();
    m_displayedProgress = 1;
    m_complete = true;
}

void FaceScanView::paintEvent(QPaintEvent *)
{
    const qreal diameter = qMin(width(), height()) - AppTheme::pixels(20);
    if (diameter <= 0) return;
    const QPointF center(width() / 2.0, height() / 2.0);
    const qreal outer = diameter / 2;
    const qreal radius = outer * .84;
    const QRectF lens(center - QPointF(radius, radius), QSizeF(radius * 2, radius * 2));

    QPainter painter(this);
    painter.setRenderHints(QPainter::Antialiasing | QPainter::SmoothPixmapTransform);
    painter.setPen(Qt::NoPen);
    QRadialGradient lensTint(center, radius);
    lensTint.setColorAt(0, palette().alternateBase().color());
    lensTint.setColorAt(1, palette().base().color());
    painter.setBrush(lensTint);
    painter.drawEllipse(lens);

    if (!m_frame.isNull()) {
        const qreal scale = lens.width() / qMin(m_frame.width(), m_frame.height());
        QTransform crop;
        crop.translate(center.x(), center.y());
        crop.scale(-scale, scale);
        crop.translate(-m_frame.width() / 2.0, -m_frame.height() / 2.0);
        QBrush preview(m_frame);
        preview.setTransform(crop);
        painter.setBrush(preview);
        painter.drawEllipse(lens);
    } else {
        const QColor ink = m_complete ? QColor(AppTheme::isDark() ? "#67e4b3" : "#097a57") : palette().link().color();
        painter.setPen(QPen(ink, outer * .026, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        painter.setBrush(Qt::NoBrush);
        const auto point = [&](qreal x, qreal y) { return center + QPointF(x * radius, y * radius); };
        QPainterPath glyph;
        if (m_complete) {
            glyph.moveTo(point(-.28, .02));
            glyph.lineTo(point(-.09, .21));
            glyph.lineTo(point(.31, -.22));
        } else {
            painter.drawEllipse(point(-.16, -.12), outer * .013, outer * .025);
            painter.drawEllipse(point(.16, -.12), outer * .013, outer * .025);
            glyph.moveTo(point(.02, -.06));
            glyph.lineTo(point(-.02, .08));
            glyph.lineTo(point(.06, .08));
            glyph.moveTo(point(-.17, .2));
            glyph.quadTo(point(0, .36), point(.17, .2));
            painter.drawRoundedRect(QRectF(point(-.41, -.41), point(.41, .41)), outer * .14, outer * .14);
        }
        painter.drawPath(glyph);
    }

    constexpr int ticks = 56;
    constexpr qreal fullTurn = 6.283185307179586;
    const QColor accent(AppTheme::isDark() ? "#67e4b3" : "#097a57");
    const QColor base = palette().mid().color();
    const bool scanning = m_refresh.isActive();
    const qreal head = scanning ? std::fmod(m_motion.elapsed() / 29.0, ticks) : 0;
    for (int i = 0; i < ticks; ++i) {
        const qreal angle = i * fullTurn / ticks;
        const QPointF direction(std::sin(angle), -std::cos(angle));
        qreal strength = qBound(0.0, m_displayedProgress * ticks - i, 1.0);
        if (scanning) {
            const qreal trail = std::fmod(head + ticks - i, ticks);
            strength = qMax(strength, qMax(0.0, 1 - trail / 11) * .85);
        }
        const auto blend = [strength](int from, int to) { return qRound(from + (to - from) * strength); };
        const QColor ink(blend(base.red(), accent.red()), blend(base.green(), accent.green()), blend(base.blue(), accent.blue()));
        painter.setPen(QPen(ink, qMax(1.2, outer * .018), Qt::SolidLine, Qt::RoundCap));
        painter.drawLine(center + direction * (outer * .91), center + direction * outer);
    }
}
