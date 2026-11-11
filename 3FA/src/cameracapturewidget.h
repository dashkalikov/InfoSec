#ifndef CAMERACAPTUREWIDGET_H
#define CAMERACAPTUREWIDGET_H

#include <QWidget>
#include <QLabel>
#include <QTimer>
#include <QProcess>

#include <opencv2/videoio.hpp>
#include <opencv2/imgproc.hpp>
#include "registrationtimerthread.h"
#include "videocapturethread.h"
#include "faceauthservice.h"

class FaceScanView;

class CameraCaptureWidget : public QWidget
{
    Q_OBJECT
public:
    explicit CameraCaptureWidget(QWidget *parent = nullptr);
    ~CameraCaptureWidget() override;

    void startCapture();
    void stopCapture(bool closeCamera = false);
    void enableMask(bool enable = true);
    void startFaceRegistration();
    void setUserAndService(const User &user, FaceAuthService *service);
    void resetState();
    
    QLabel *m_statusLabel; // Публичный label для статусных сообщений

signals:
    void frameReady(const cv::Mat &frame);
    void registrationCompleted();
    void registrationFailed(const QString &message);
    void statusUpdate(const QString &message, bool error = false);

private slots:
    void processFrame(const cv::Mat &frame);
    void onMediaPipeDataReady();
    void onMediaPipeError(int exitCode, QProcess::ExitStatus exitStatus);
    void onRegistrationCompleted();

private:
    FaceScanView *m_scanView;
    VideoCaptureThread *m_videoThread;
    
    // MediaPipe integration
    QProcess *m_mediapipeProcess;
    bool m_mediapipeEnabled;
    QString m_mediapipeScriptPath;
    QString m_pythonPath;  // Путь к Python интерпретатору
    QByteArray m_mediapipeBuffer;
    cv::Mat m_lastProcessedFrame;
    bool m_maskEnabled;
    
    // Face registration timer (in separate thread)
    RegistrationTimerThread *m_registrationTimerThread;
    QTimer *m_scanTimeout;
    
    // Face registration
    FaceAuthService *m_faceAuthService;
    User m_user;
    std::vector<std::vector<float>> m_enrollmentSamples;
    int m_framesProcessed;
    int m_lastReportedStage = -1;  // 0 = нет лица, 1 = сканирование
    bool m_timerPaused = false;
    int m_faceCheckCounter = 0;
    bool m_faceWasLost = false;
    int m_mediapipeFrameCounter;  // Счетчик кадров для пропуска (отправляем каждый N-й кадр)

    QImage matToQImage(const cv::Mat &mat) const;
    void processFaceRegistration(const cv::Mat &frame);
    
    // MediaPipe methods
    bool initializeMediaPipe();
    void startMediaPipeProcess();
    void stopMediaPipeProcess();
    void sendFrameToMediaPipe(const cv::Mat &frame);
};

#endif // CAMERACAPTUREWIDGET_H

