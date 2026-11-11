#include "camerathread.h"
#include "faceauthservice.h"
#include <QDebug>
#include <QElapsedTimer>
#include <utility>

CameraThread::CameraThread(QObject *parent)
    : QThread(parent)
    , m_running(false)
    , m_shouldStop(false)
    , m_service(nullptr)
    , m_mode(0)
    , m_successCounter(0)
{
}

CameraThread::~CameraThread()
{
    stopCapture();
    wait(); // Ждем завершения потока
}

void CameraThread::startCapture()
{
    QMutexLocker locker(&m_mutex);

    if (m_running) {
        return;
    }

    m_shouldStop = false;
    m_successCounter = 0;
    m_enrollmentSamples.clear();
    m_stabilizationTimer.start(); // Запускаем таймер стабилизации
    m_scanStatus.clear();

    if (!initializeCamera()) {
        emit statusUpdate(tr("Не удалось открыть камеру. Проверьте подключение и разрешение на доступ."), true);
        return;
    }

    m_running = true;
    start(); // Запускаем поток
}

void CameraThread::stopCapture()
{
    QMutexLocker locker(&m_mutex);

    if (!m_running && !isRunning()) {
        return;
    }

    m_shouldStop = true;
    m_condition.wakeAll();

    const bool waitForThread = (QThread::currentThread() != this);
    locker.unlock();

    if (waitForThread) {
        wait(); // Ждем завершения потока только из внешних потоков
    }

    // Закрываем камеру только после полной остановки потока
    cleanupCamera();
}

void CameraThread::setService(FaceAuthService *service)
{
    QMutexLocker locker(&m_mutex);
    m_service = service;
}

void CameraThread::setReferenceEmbedding(std::vector<float> embedding)
{
    QMutexLocker locker(&m_mutex);
    m_referenceEmbedding = std::move(embedding);
}

void CameraThread::setMode(int mode)
{
    QMutexLocker locker(&m_mutex);
    m_mode = mode;
}

cv::Mat CameraThread::getCurrentFrame() const
{
    QMutexLocker locker(&m_frameMutex);
    return m_currentFrame.clone();
}

void CameraThread::run()
{
    QElapsedTimer frameTimer;
    frameTimer.start();

    while (true) {
        // Проверяем нужно ли остановиться
        {
            QMutexLocker locker(&m_mutex);
            if (m_shouldStop) {
                break;
            }
        }

        // Захватываем кадр
        cv::Mat frame;
        if (!m_capture.read(frame) || frame.empty()) {
            QThread::msleep(FRAME_INTERVAL_MS);
            continue;
        }

        // Сохраняем текущий кадр
        {
            QMutexLocker locker(&m_frameMutex);
            m_currentFrame = frame.clone();
        }

        // Обрабатываем распознавание лиц
        processFaceRecognition(frame);

        // Отправляем сигнал о готовности кадра
        emit frameReady(frame);

        // Контролируем частоту кадров
        int elapsed = frameTimer.elapsed();
        int sleepTime = FRAME_INTERVAL_MS - elapsed;
        if (sleepTime > 0) {
            QThread::msleep(sleepTime);
        }
        frameTimer.restart();
    }

    // НЕ закрываем камеру при завершении потока, чтобы избежать мигания индикатора
    // Камера будет закрыта только при явном вызове stopCapture() или в деструкторе
    // cleanupCamera();

    // Устанавливаем флаг завершения
    QMutexLocker locker(&m_mutex);
    m_running = false;
}

bool CameraThread::initializeCamera()
{
    // Проверяем, не открыта ли камера уже, чтобы избежать лишних переоткрытий
    if (m_capture.isOpened()) {
        qDebug() << "Камера уже открыта, пропускаем инициализацию";
        return true;
    }

    // Инициализация камеры
    m_capture.open(0);
    if (!m_capture.isOpened()) {
        qWarning() << "Не удалось открыть камеру";
        return false;
    }

    // Настройка параметров камеры
    m_capture.set(cv::CAP_PROP_FPS, 30);

    // Логируем разрешение камеры
    int width = static_cast<int>(m_capture.get(cv::CAP_PROP_FRAME_WIDTH));
    int height = static_cast<int>(m_capture.get(cv::CAP_PROP_FRAME_HEIGHT));
    qDebug() << "VideoCaptureThread: разрешение камеры" << width << "x" << height;

    return true;
}

void CameraThread::cleanupCamera()
{
    if (m_capture.isOpened()) {
        m_capture.release();
    }
}

void CameraThread::processFaceRecognition(const cv::Mat &frame)
{
    if (!m_service) {
        return;
    }

    // Извлекаем эмбеддинг лица из кадра
    cv::Rect faceRectCv;
    auto embeddingOpt = m_service->extractEmbedding(frame, nullptr, &faceRectCv);
    bool faceDetected = embeddingOpt.has_value();

    if (!faceDetected) {
        reportScan(tr("Расположите лицо в центре круга."), -1);
        return;
    }

    // Используем реальное время вместо подсчета кадров для точности
    int elapsedMs = m_stabilizationTimer.elapsed();
    if (elapsedMs < STABILIZATION_TIME_MS) {
        reportScan(tr("Смотрите прямо в камеру и держите голову неподвижно."),
                   STABILIZATION_PROGRESS * elapsedMs / STABILIZATION_TIME_MS);
        return;
    }

    const auto &embedding = embeddingOpt.value();

    if (m_mode == 0) { // Verify mode
        if (m_service->cosineSimilarity(m_referenceEmbedding, embedding) >= 0.6f) {
            ++m_successCounter;
            reportScan(tr("Подтверждаем лицо. Продолжайте смотреть в камеру."),
                       STABILIZATION_PROGRESS + (1 - STABILIZATION_PROGRESS) * m_successCounter / VERIFICATION_MATCHES);
            if (m_successCounter >= VERIFICATION_MATCHES) {
                stopCapture();
                emit statusUpdate(tr("Лицо подтверждено."));
                emit faceVerified();
            }
        } else {
            m_successCounter = 0;
            reportScan(tr("Лицо не совпало. Смотрите прямо в камеру."), STABILIZATION_PROGRESS, true);
        }
    } else { // Enrollment mode
        m_enrollmentSamples.push_back(embedding);
        reportScan(tr("Записываем образец лица. Держите голову неподвижно."),
                   STABILIZATION_PROGRESS + (1 - STABILIZATION_PROGRESS) * m_enrollmentSamples.size() / ENROLLMENT_SAMPLES);

        if (m_enrollmentSamples.size() >= ENROLLMENT_SAMPLES) {
            stopCapture();
            emit enrollmentCaptured(averageSamples(m_enrollmentSamples));
        }
    }
}

void CameraThread::reportScan(const QString &message, qreal progress, bool error)
{
    if (message != m_scanStatus || error != m_scanError) {
        m_scanStatus = message;
        m_scanError = error;
        emit statusUpdate(message, error);
    }
    emit scanProgressChanged(progress);
}

std::vector<float> CameraThread::averageSamples(const std::vector<std::vector<float>> &samples)
{
    if (samples.empty()) {
        return {};
    }

    std::vector<float> avg(samples.front().size(), 0.0f);
    for (const auto &vec : samples) {
        for (size_t i = 0; i < vec.size(); ++i) {
            avg[i] += vec[i];
        }
    }
    for (float &value : avg) {
        value /= static_cast<float>(samples.size());
    }

    // Нормализуем усредненный эмбеддинг (важно для корректного сравнения)
    float norm = 0.0f;
    for (float value : avg) {
        norm += value * value;
    }
    norm = std::sqrt(norm);
    if (norm > 0.0f) {
        for (float &value : avg) {
            value /= norm;
        }
    }

    return avg;
}
