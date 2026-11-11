#include "lockoutcleanupworker.h"
#include "database.h"
#include <QDebug>
#include <QDateTime>
#include <QSqlQuery>

LockoutCleanupWorker::LockoutCleanupWorker(Database *database, QObject *parent)
    : QThread(parent)
    , m_database(database)
    , m_shouldStop(false)
{
    // Инициализация членов класса. Поток не запускается автоматически.
    
    // Проверяем валидность указателя database согласно принципам защитного программирования.
    // Раннее обнаружение проблемы упростит отладку и предотвратит краш в рантайме.
    if (!m_database) 
    {
        qCritical() << "LockoutCleanupWorker: указатель на Database равен null!";
    }
}

LockoutCleanupWorker::~LockoutCleanupWorker()
{
    // Автоматически останавливаем поток при уничтожении объекта
    stopWorker();
}

void LockoutCleanupWorker::startWorker()
{
    // Проверяем, не запущен ли поток уже
    if (isRunning()) 
    {
        qWarning() << "LockoutCleanupWorker: поток уже запущен";
        return;
    }
    
    // Сбрасываем флаг остановки под защитой мьютекса
    QMutexLocker locker(&m_mutex);
    m_shouldStop = false;
    locker.unlock();
    
    // Запускаем поток выполнения
    start();
    qDebug() << "LockoutCleanupWorker: поток запущен";
}

void LockoutCleanupWorker::stopWorker()
{
    // Устанавливаем флаг остановки и пробуждаем поток из ожидания
    QMutexLocker locker(&m_mutex);
    m_shouldStop = true;
    m_waitCondition.wakeAll();
    locker.unlock();
    
    // Ожидаем завершения потока с таймаутом 3 секунды
    if (isRunning()) 
    {
        wait(3000); // Ждем до 3 секунд
    }
    
    qDebug() << "LockoutCleanupWorker: поток остановлен";
}

bool LockoutCleanupWorker::isRunning() const
{
    // Просто возвращаем состояние базового класса QThread
    return QThread::isRunning();
}

void LockoutCleanupWorker::run()
{
    qDebug() << "LockoutCleanupWorker: поток запущен";
    
    // Основной цикл работы потока
    while (true) 
    {
        QMutexLocker locker(&m_mutex);
        
        // Проверяем, нужно ли остановить поток
        if (m_shouldStop) 
        {
            break;
        }
        
        locker.unlock();
        
        // Выполняем очистку истекших блокировок
        int unlockedCount = cleanupExpiredLockouts();
        
        // Если были разблокированы аккаунты, испускаем сигнал
        if (unlockedCount > 0) 
        {
            qDebug() << "LockoutCleanupWorker: разблокировано аккаунтов:" << unlockedCount;
            emit cleanupCompleted(unlockedCount);
        }
        
        // Ждем CHECK_INTERVAL_SECONDS секунд или до сигнала остановки
        locker.relock();
        if (!m_shouldStop)
        {
            m_waitCondition.wait(&m_mutex, CHECK_INTERVAL_SECONDS * 1000);
        }
    }
    
    qDebug() << "LockoutCleanupWorker: поток завершен";
}

int LockoutCleanupWorker::cleanupExpiredLockouts()
{
    // Проверяем валидность указателя и подключение к базе данных.
    // QPointer автоматически проверяет, не был ли объект удален извне.
    if (!m_database || !m_database->isConnected()) 
    {
        return 0;
    }
    
    // Получаем список всех заблокированных аккаунтов с истекшим временем блокировки
    QString query = R"(
        SELECT email, lockout_until 
        FROM users 
        WHERE lockout_until IS NOT NULL 
        AND lockout_until < ?
    )";
    
    // Подготавливаем параметры запроса с текущей датой и временем
    QVariantList params;
    params << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    
    // Выполняем SQL-запрос
    QSqlQuery sqlQuery = m_database->select(query, params);
    
    // Проверяем успешность выполнения запроса согласно документации Qt (QSqlQuery::lastError())
    // Всегда следует проверять наличие ошибок после выполнения запроса для раннего обнаружения
    // проблем с базой данных и улучшения диагностики. Уведомляем об ошибке через сигнал
    // errorOccurred для улучшения наблюдаемости системы.
    if (sqlQuery.lastError().isValid()) 
    {
        qWarning() << "LockoutCleanupWorker:" << sqlQuery.lastError().text();
        emit errorOccurred("Не удалось выполнить запрос истекших блокировок");
        return 0;
    }
    
    int unlockedCount = 0;
    QStringList unlockedEmails;
    
    // Начинаем транзакцию для обеспечения атомарности операций разблокировки.
    // Согласно принципам ACID (Atomicity, Consistency, Isolation, Durability),
    // групповые операции должны выполняться в транзакции. Транзакция гарантирует
    // атомарность операций: либо все аккаунты разблокируются, либо ни один.
    // Это предотвращает частичные обновления при ошибках и улучшает целостность данных.
    if (!m_database->beginTransaction()) 
    {
        qWarning() << "LockoutCleanupWorker: не удалось начать транзакцию";
        emit errorOccurred("Не удалось начать транзакцию для очистки блокировок");
        return 0;
    }
    
    bool transactionSuccess = true;
    
    // Обрабатываем результаты запроса в рамках транзакции.
    // Все операции разблокировки выполняются атомарно - либо все успешно, либо откат всех изменений.
    while (sqlQuery.next()) 
    {
        QString email = sqlQuery.value("email").toString();
        
        // Сбрасываем блокировку для каждого найденного аккаунта.
        // При ошибке разблокировки помечаем транзакцию как неуспешную для последующего отката.
        if (!m_database->setLockoutUntil(email, QDateTime())) 
        {
            qWarning() << "LockoutCleanupWorker: не удалось разблокировать аккаунт" << email;
            transactionSuccess = false;
            break;
        }
        
        unlockedEmails << email;
        unlockedCount++;
    }
    
    // Завершаем транзакцию: либо подтверждаем (commit), либо откатываем (rollback) при ошибке.
    // Это обеспечивает атомарность операций согласно принципам ACID.
    if (transactionSuccess) 
    {
        if (m_database->commit()) 
        {
            // Испускаем сигналы о разблокировке только после успешного коммита транзакции.
            // Это гарантирует, что сигналы отправляются только при реальном успешном завершении операций.
            for (const QString &email : unlockedEmails) 
            {
                emit accountUnlocked(email);
            }
        } 
        else 
        {
            qWarning() << "LockoutCleanupWorker: не удалось подтвердить транзакцию";
            emit errorOccurred("Не удалось подтвердить транзакцию очистки блокировок");
            m_database->rollback();
            unlockedCount = 0;
        }
    } 
    else 
    {
        // Откатываем транзакцию при ошибках разблокировки для предотвращения частичных обновлений.
        qWarning() << "LockoutCleanupWorker: откат транзакции из-за ошибок";
        emit errorOccurred("Транзакция откачена из-за ошибок разблокировки");
        m_database->rollback();
        unlockedCount = 0;
    }
    
    // Логируем результат, если были разблокированы аккаунты
    if (unlockedCount > 0) 
    {
        qDebug() << "LockoutCleanupWorker: автоматически разблокированы аккаунты:" << unlockedEmails.join(", ");
    }
    
    return unlockedCount;
}

