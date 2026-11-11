#ifndef CAMERATHREAD_H
#define CAMERATHREAD_H

#include <QThread>
#include <QMutex>
#include <QWaitCondition>
#include <QTimer>
#include <QElapsedTimer>
#include <opencv2/opencv.hpp>
#include <vector>

class FaceAuthService;

class CameraThread : public QThread
{
    Q_OBJECT

public:
    explicit CameraThread(QObject *parent = nullptr);
    ~CameraThread();

    // Управление потоком
    void startCapture();
    void stopCapture();

    // Настройка параметров
    void setService(FaceAuthService *service);
    void setReferenceEmbedding(std::vector<float> embedding);
    void setMode(int mode); // 0 = Verify, 1 = Enrollment

    // Получение текущего кадра
    cv::Mat getCurrentFrame() const;

signals:
    void frameReady(const cv::Mat &frame);
    void faceVerified();
    void enrollmentCaptured(const std::vector<float> &embedding);
    void statusUpdate(const QString &message, bool error = false);
    void scanProgressChanged(qreal progress);

protected:
    void run() override;

private:
    // Состояние потока
    mutable QMutex m_mutex;
    QWaitCondition m_condition;
    bool m_running;
    bool m_shouldStop;

    // Камера и обработка
    cv::VideoCapture m_capture;
    cv::Mat m_currentFrame;
    mutable QMutex m_frameMutex;

    // Сервисы
    FaceAuthService *m_service;
    std::vector<float> m_referenceEmbedding;
    int m_mode;

    // Счетчики распознавания
    int m_successCounter;
    std::vector<std::vector<float>> m_enrollmentSamples;
    QElapsedTimer m_stabilizationTimer; // Таймер для отсчета времени стабилизации
    QString m_scanStatus;
    bool m_scanError = false;

    // Константы
    static constexpr int STABILIZATION_TIME_MS = 12000; // 12 секунд в миллисекундах
    static constexpr int FRAME_INTERVAL_MS = 33; // ~30 FPS
    static constexpr int VERIFICATION_MATCHES = 3;
    static constexpr int ENROLLMENT_SAMPLES = 10;
    static constexpr qreal STABILIZATION_PROGRESS = .8;

    // Вспомогательные методы
    bool initializeCamera();
    void cleanupCamera();
    void processFaceRecognition(const cv::Mat &frame);
    void reportScan(const QString &message, qreal progress, bool error = false);
    std::vector<float> averageSamples(const std::vector<std::vector<float>> &samples);
};

#endif // CAMERATHREAD_H
