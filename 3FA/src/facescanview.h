#pragma once

#include <QElapsedTimer>
#include <QImage>
#include <QTimer>
#include <QWidget>

class FaceScanView final : public QWidget
{
public:
    explicit FaceScanView(QWidget *parent = nullptr);

    void setFrame(QImage frame);
    void start();
    void setProgress(qreal fraction);
    void reset();
    void complete();

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    QImage m_frame;
    QTimer m_refresh;
    QElapsedTimer m_motion;
    qreal m_progress = -1;
    qreal m_displayedProgress = 0;
    bool m_complete = false;
};
