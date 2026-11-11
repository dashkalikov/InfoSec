#include "videocapturethread.h"
#include <QDebug>

VideoCaptureThread::VideoCaptureThread(QObject *parent)
    : QThread(parent)
    , m_running(false)
    , m_shouldStop(false)
    , m_maskEnabled(false)
{
}

VideoCaptureThread::~VideoCaptureThread()
{
    stopCapture();
    
    // Закрываем камеру только в деструкторе (когда объект уничтожается)
    QMutexLocker locker(&m_mutex);
    if (m_capture.isOpened()) {
        m_capture.release();
        qDebug() << "VideoCaptureThread: камера закрыта в деструкторе";
    }
}

void VideoCaptureThread::startCapture()
{
    qDebug() << "VideoCaptureThread::startCapture() вызван";
    qDebug() << "  - QThread::isRunning():" << QThread::isRunning();
    qDebug() << "  - m_running:" << m_running;
    qDebug() << "  - m_capture.isOpened():" << m_capture.isOpened();
    
    // Проверяем, не запущен ли поток уже
    // Используем QThread::isRunning() как основной критерий
    if (QThread::isRunning()) {
        qDebug() << "VideoCaptureThread: поток уже запущен, пропускаем";
        return;
    }
    
    {
        QMutexLocker locker(&m_mutex);
        // Сбрасываем флаг остановки
        m_shouldStop = false;
    }
    
    // Запускаем поток (вне мьютекса, чтобы run() мог захватить его)
    start();
    qDebug() << "VideoCaptureThread: поток запущен успешно";
}

void VideoCaptureThread::stopCapture(bool closeCamera)
{
    QMutexLocker locker(&m_mutex);
    
    // Если поток не запущен, ничего не делаем (кроме закрытия камеры, если требуется)
    if (!m_running && !QThread::isRunning()) {
        if (closeCamera && m_capture.isOpened()) {
            m_capture.release();
            qDebug() << "VideoCaptureThread: камера закрыта (поток уже был остановлен)";
        } else {
            qDebug() << "VideoCaptureThread: поток уже остановлен";
        }
        return;
    }
    
    m_running = false;
    m_shouldStop = true;
    
    locker.unlock();
    
    // Ждем завершения потока
    if (QThread::isRunning()) {
        wait(5000);  // Увеличиваем время ожидания до 5 секунд
        if (QThread::isRunning()) {
            terminate();
            wait(1000);  // Ждем еще секунду после terminate
        }
    }
    
    // Закрываем камеру только если явно указано (при выходе из окна регистрации)
    // По умолчанию камера остается открытой для быстрого перезапуска без мигания
    if (closeCamera) {
        QMutexLocker locker(&m_mutex);
        if (m_capture.isOpened()) {
            m_capture.release();
            qDebug() << "VideoCaptureThread: поток остановлен, камера закрыта";
        }
    } else {
        qDebug() << "VideoCaptureThread: поток остановлен (камера остается открытой для быстрого перезапуска)";
    }
}

void VideoCaptureThread::enableMask(bool enable)
{
    QMutexLocker locker(&m_mutex);
    m_maskEnabled = enable;
}

cv::Mat VideoCaptureThread::getCurrentFrame() const
{
    // Этот метод не используется в новой архитектуре
    // Кадры эмитятся через сигнал frameReady
    return cv::Mat();
}

void VideoCaptureThread::run()
{
    {
        QMutexLocker locker(&m_mutex);
        
        // Устанавливаем m_running в true сразу в начале run(), чтобы избежать race condition
        // когда другой поток вызывает startCapture() пока мы открываем камеру
        m_running = true;
        
        // Проверяем, не открыта ли камера уже, чтобы избежать лишних переоткрытий
        // Это предотвращает мигание индикатора камеры при перезапуске потока
        if (!m_capture.isOpened()) {
            // Открываем камеру только если она не открыта
            qDebug() << "VideoCaptureThread: открываем камеру...";
            
            // Открываем камеру с параметрами для уменьшения задержки инициализации
            // Используем CAP_ANY чтобы OpenCV сам выбрал лучший backend
            if (!m_capture.open(0)) {
                qWarning() << "VideoCaptureThread: не удалось открыть камеру";
                m_running = false;
                return;
            }
            
            // НЕ меняем настройки камеры после открытия, чтобы избежать мигания
            // Используем разрешение по умолчанию, которое камера выбирает сама
            int actualWidth = static_cast<int>(m_capture.get(cv::CAP_PROP_FRAME_WIDTH));
            int actualHeight = static_cast<int>(m_capture.get(cv::CAP_PROP_FRAME_HEIGHT));
            qDebug() << "VideoCaptureThread: камера открыта, разрешение" << actualWidth << "x" << actualHeight;
        } else {
            qDebug() << "VideoCaptureThread: камера уже открыта, используем существующее подключение (без мигания)";
        }
    }
    
    // Основной цикл захвата видео
    while (true) {
        {
            QMutexLocker locker(&m_mutex);
            
            if (m_shouldStop) {
                break;
            }
            
            if (!m_capture.isOpened()) {
                break;
            }
            
            cv::Mat frame;
            bool success = m_capture.read(frame);
            
            // Отправляем кадр, если он успешно получен
            if (success && !frame.empty()) {
                emit frameReady(frame);
            }
        }
        
        // Небольшая задержка для управления FPS (~30 FPS)
        msleep(33);
    }
    
    // НЕ закрываем камеру при завершении потока, чтобы избежать мигания индикатора
    // Камера будет закрыта только при явном вызове stopCapture() или в деструкторе
    // {
    //     QMutexLocker locker(&m_mutex);
    //     if (m_capture.isOpened()) {
    //         m_capture.release();
    //     }
    // }
    
    {
        QMutexLocker locker(&m_mutex);
        m_running = false;
    }
    
    qDebug() << "VideoCaptureThread: поток завершен";
}

