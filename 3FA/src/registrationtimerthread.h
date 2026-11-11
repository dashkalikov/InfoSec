#ifndef REGISTRATIONTIMERTHREAD_H
#define REGISTRATIONTIMERTHREAD_H

#include <QThread>
#include <QTimer>
#include <atomic>

class RegistrationTimerThread : public QThread
{
    Q_OBJECT
public:
    explicit RegistrationTimerThread(QObject *parent = nullptr);
    
    void startTimer(int seconds);
    void stopTimer();
    void pauseTimer();
    void resumeTimer();

signals:
    void progress(int secondsRemaining);
    void completed();

protected:
    void run() override;

private slots:
    void onTimeout();

private:
    int m_secondsRemaining;
    std::atomic_bool m_running;
    std::atomic_bool m_paused;
};

#endif // REGISTRATIONTIMERTHREAD_H

