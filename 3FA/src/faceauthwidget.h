#ifndef FACEAUTHWIDGET_H
#define FACEAUTHWIDGET_H

#include <QWidget>
#include "faceauthservice.h"

class CameraThread;
class FaceScanView;
class QLabel;
class QPushButton;
class QTimer;

class FaceAuthWidget : public QWidget
{
    Q_OBJECT
public:
    explicit FaceAuthWidget(FaceAuthService *service, QWidget *parent = nullptr);
    ~FaceAuthWidget() override;

    void setUser(const User &user);
    void setEnrollmentMode(bool isEnrollment = true);
    void startVerification();
    void stopCapture();

signals:
    void faceVerified();
    void verificationFailed(const QString &reason);

private slots:
    void onStartClicked();
    void onCancelClicked();
    void onFrameReady(const cv::Mat &frame);
    void onFaceVerified();
    void onEnrollmentCaptured(const std::vector<float> &embedding);
    void updateStatus(const QString &text, bool error = false);

private:
    enum class Mode { Verify, Enroll };

    FaceAuthService *m_service;
    User m_user;
    Mode m_mode = Mode::Verify;
    QLabel *m_title;
    FaceScanView *m_scanView;
    QLabel *m_statusLabel;
    QPushButton *m_startButton;
    QPushButton *m_cancelButton;
    CameraThread *m_cameraThread;
    QTimer *m_scanTimeout;
};

#endif
