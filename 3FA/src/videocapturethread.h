#ifndef VIDEOCAPTURETHREAD_H
#define VIDEOCAPTURETHREAD_H

#include <QThread>
#include <QMutex>
#include <QWaitCondition>
#include <opencv2/opencv.hpp>

class VideoCaptureThread : public QThread
{
    Q_OBJECT

public:
    explicit VideoCaptureThread(QObject *parent = nullptr);
    ~VideoCaptureThread();

    void startCapture();
    void stopCapture(bool closeCamera = false);
    bool isRunning() const { return m_running; }
    void enableMask(bool enable = true);

    // Получение текущего кадра
    cv::Mat getCurrentFrame() const;

signals:
    void frameReady(const cv::Mat &frame);

protected:
    void run() override;

private:
    mutable QMutex m_mutex;
    QWaitCondition m_condition;
    bool m_running;
    bool m_shouldStop;
    bool m_maskEnabled;
    
    cv::VideoCapture m_capture;
};

#endif // VIDEOCAPTURETHREAD_H

