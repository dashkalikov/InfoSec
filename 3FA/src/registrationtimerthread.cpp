#include "registrationtimerthread.h"
#include <QDebug>

RegistrationTimerThread::RegistrationTimerThread(QObject *parent)
    : QThread(parent)
    , m_secondsRemaining(0)
    , m_running(false)
    , m_paused(false)
{
}

void RegistrationTimerThread::startTimer(int seconds)
{
    if (m_running || isRunning()) {
        qWarning() << "RegistrationTimerThread: таймер уже запущен";
        return;
    }
    
    m_secondsRemaining = seconds;
    m_paused = false;
    m_running = true;
    start();
}

void RegistrationTimerThread::stopTimer()
{
    m_running = false;
    if (isRunning()) {
        wait(2000); // Ждем до 2 секунд
    }
    qDebug() << "RegistrationTimerThread: таймер остановлен";
}

void RegistrationTimerThread::pauseTimer()
{
    m_paused = true;
    qDebug() << "RegistrationTimerThread: таймер приостановлен";
}

void RegistrationTimerThread::resumeTimer()
{
    m_paused = false;
    qDebug() << "RegistrationTimerThread: таймер возобновлен";
}

void RegistrationTimerThread::run()
{
    qDebug() << "RegistrationTimerThread: поток запущен";
    
    while (m_running && m_secondsRemaining > 0) {
        emit progress(m_secondsRemaining);
        
        // Ждем 1 секунду
        sleep(1);
        
        // Если пауза, пропускаем уменьшение таймера
        if (m_paused) {
            continue;
        }
        
        if (m_running) {
            m_secondsRemaining--;
        }
    }
    
    if (m_running) {
        qDebug() << "RegistrationTimerThread: таймер завершен";
        emit completed();
    }
    
    m_running = false;
}

void RegistrationTimerThread::onTimeout()
{
    // Не используется, оставлено для совместимости
}

