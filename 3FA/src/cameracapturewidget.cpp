#include "cameracapturewidget.h"
#include "apptheme.h"
#include "facescanview.h"

#include <QVBoxLayout>
#include <QDebug>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonArray>
#include <QCoreApplication>
#include <QDir>

#include <opencv2/imgcodecs.hpp>

namespace {
constexpr int registrationSeconds = 15;
}

CameraCaptureWidget::CameraCaptureWidget(QWidget *parent)
    : QWidget(parent)
    , m_statusLabel(new QLabel(this))
    , m_scanView(new FaceScanView(this))
    , m_videoThread(new VideoCaptureThread(this))
    , m_mediapipeProcess(nullptr)
    , m_mediapipeEnabled(false)
    , m_mediapipeScriptPath("")
    , m_pythonPath("")
    , m_maskEnabled(false)
    , m_registrationTimerThread(new RegistrationTimerThread(this))
    , m_scanTimeout(new QTimer(this))
    , m_faceAuthService(nullptr)
    , m_framesProcessed(0)
    , m_mediapipeFrameCounter(0)
{
    // Простой layout только с видео
    QVBoxLayout *layout = new QVBoxLayout(this);
    AppTheme::margins(layout, 0, 0, 0, 0);

    layout->addWidget(m_scanView);

    // Настройки для label статуса
    m_statusLabel->setAlignment(Qt::AlignCenter);
    AppTheme::role(m_statusLabel, "muted");
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setVisible(true); // Видима по умолчанию с начальным текстом

    layout->addWidget(m_statusLabel);

    // Подключаем поток видео
    connect(m_videoThread, &VideoCaptureThread::frameReady, this, &CameraCaptureWidget::processFrame);

    // Подключаем таймер регистрации (в отдельном потоке)
    connect(m_registrationTimerThread, &RegistrationTimerThread::progress, this, [this](int secondsRemaining) {
        if (m_scanTimeout->isActive() && m_lastReportedStage == 1 && !m_faceWasLost)
            m_scanView->setProgress(1.0 - qreal(secondsRemaining) / registrationSeconds);
    });
    connect(m_registrationTimerThread, &RegistrationTimerThread::completed,
            this, &CameraCaptureWidget::onRegistrationCompleted);
    m_scanTimeout->setObjectName("faceScanTimeout");
    m_scanTimeout->setSingleShot(true);
    m_scanTimeout->setTimerType(Qt::PreciseTimer);
    m_scanTimeout->setInterval(FaceAuthService::scanTimeoutMs);
    connect(m_scanTimeout, &QTimer::timeout, this, [this] {
        stopCapture(true);
        emit registrationFailed(tr("Не удалось записать лицо за отведённое время. Проверьте освещение и повторите попытку."));
    });

    // Инициализируем MediaPipe (но не запускаем процесс сразу - запустим когда включим маску)
    if (initializeMediaPipe()) {
        qDebug() << "[INFO] MediaPipe инициализирован для CameraCaptureWidget (процесс запустится при включении маски)";
        // НЕ запускаем процесс здесь - запустим когда enableMask(true) будет вызван
        // startMediaPipeProcess();
    } else {
        qWarning() << "[ERROR] Не удалось инициализировать MediaPipe для CameraCaptureWidget";
    }
}

CameraCaptureWidget::~CameraCaptureWidget()
{
    stopCapture();

    // Ждем завершения видео потока
    if (m_videoThread) {
        if (m_videoThread->isRunning()) {
            m_videoThread->wait(5000);  // Увеличиваем время ожидания до 5 секунд
            if (m_videoThread->isRunning()) {
                m_videoThread->terminate();
                m_videoThread->wait();
            }
        }
    }

    // Ждем завершения таймера регистрации
    if (m_registrationTimerThread) {
        if (m_registrationTimerThread->isRunning()) {
            m_registrationTimerThread->wait(2000);  // Увеличиваем время ожидания до 2 секунд
            if (m_registrationTimerThread->isRunning()) {
                m_registrationTimerThread->terminate();
                m_registrationTimerThread->wait();
            }
        }
    }

    stopMediaPipeProcess();
}

void CameraCaptureWidget::startCapture()
{
    if (m_videoThread) {
        // Проверяем, не запущен ли поток уже
        // VideoCaptureThread::startCapture() также делает эту проверку,
        // но проверяем здесь для логирования
        if (!m_videoThread->QThread::isRunning()) {
            m_videoThread->startCapture();
            qDebug() << "CameraCaptureWidget: запускаем камеру";
        } else {
            qDebug() << "CameraCaptureWidget: камера уже запущена, пропускаем";
        }
    }
}

void CameraCaptureWidget::stopCapture(bool closeCamera)
{
    m_scanTimeout->stop();
    if (m_videoThread) {
        m_videoThread->stopCapture(closeCamera);
    }

    if (m_registrationTimerThread && m_registrationTimerThread->isRunning()) {
        m_registrationTimerThread->stopTimer();
    }
    m_scanView->reset();
}

void CameraCaptureWidget::enableMask(bool enable)
{
    m_maskEnabled = enable;
    qDebug() << "[MASK] CameraCaptureWidget::enableMask(" << enable << ")";

    // Если включаем маску, проверяем что MediaPipe запущен
    if (enable) {
        qDebug() << "[MASK] Включаем маску, проверяем MediaPipe...";
        qDebug() << "[MASK] m_mediapipeEnabled:" << m_mediapipeEnabled;
        qDebug() << "[MASK] m_mediapipeProcess:" << (m_mediapipeProcess ? "exists" : "null");
        if (m_mediapipeProcess) {
            qDebug() << "[MASK] Process state:" << m_mediapipeProcess->state();
        }

        if (!m_mediapipeEnabled) {
            qWarning() << "[MASK] MediaPipe не инициализирован. Пытаемся инициализировать...";
            if (initializeMediaPipe()) {
                qDebug() << "[MASK] MediaPipe инициализирован, запускаем процесс...";
                startMediaPipeProcess();
            } else {
                qWarning() << "[MASK] Не удалось инициализировать MediaPipe!";
            }
        } else if (!m_mediapipeProcess || m_mediapipeProcess->state() != QProcess::Running) {
            qWarning() << "[MASK] MediaPipe процесс не запущен. Запускаем...";
            startMediaPipeProcess();
        } else {
            qDebug() << "[MASK] Маска включена, MediaPipe процесс уже работает";
        }
    } else {
        qDebug() << "[MASK] Маска выключена";
    }
}

void CameraCaptureWidget::resetState()
{
    m_scanTimeout->stop();
    m_enrollmentSamples.clear();
    m_framesProcessed = 0;
    m_lastReportedStage = -1;
    m_timerPaused = false;
    m_faceCheckCounter = 0;
    m_faceWasLost = false;

    // Останавливаем таймер если он работает
    if (m_registrationTimerThread && m_registrationTimerThread->isRunning()) {
        m_registrationTimerThread->stopTimer();
    }

    // Сбрасываем маску
    m_maskEnabled = false;
    m_lastProcessedFrame = cv::Mat();  // Очищаем обработанный кадр MediaPipe
    m_mediapipeFrameCounter = 0;  // Сбрасываем счетчик кадров MediaPipe
}

void CameraCaptureWidget::startFaceRegistration()
{
    if (m_scanTimeout->isActive() || m_registrationTimerThread->isRunning()) return;
    m_enrollmentSamples.clear();
    m_framesProcessed = 0;
    m_lastReportedStage = -1;
    m_timerPaused = false;
    m_faceCheckCounter = 0;
    m_faceWasLost = false;
    m_scanView->start();
    m_scanTimeout->start();
    m_registrationTimerThread->startTimer(registrationSeconds);
}

void CameraCaptureWidget::processFrame(const cv::Mat &frame)
{
    if (frame.empty() || !m_videoThread->QThread::isRunning()) {
        return;
    }

    // Обрабатываем распознавание лиц только если идет регистрация
    if (m_faceAuthService && m_registrationTimerThread && m_registrationTimerThread->isRunning()) {
        processFaceRegistration(frame);
    }

    // Отправляем кадр в MediaPipe если включен
    if (m_mediapipeEnabled && m_mediapipeProcess && m_mediapipeProcess->state() == QProcess::Running) {
        sendFrameToMediaPipe(frame);
    } else if (m_maskEnabled) {
        // Если маска включена, но MediaPipe не работает, пытаемся перезапустить
        static int retryCount = 0;
        if (retryCount++ < 3) {  // Пробуем только первые 3 раза
            qWarning() << "[MASK] Маска включена, но MediaPipe не работает. Состояние:"
                       << (m_mediapipeProcess ? m_mediapipeProcess->state() : QProcess::NotRunning)
                       << "m_mediapipeEnabled:" << m_mediapipeEnabled;
            if (initializeMediaPipe()) {
                startMediaPipeProcess();
            }
        }
    }

    // Выбираем какое изображение отображать
    cv::Mat displayFrame = frame;
    if (m_maskEnabled && !m_lastProcessedFrame.empty()) {
        displayFrame = m_lastProcessedFrame;
        static int maskFrameCount = 0;
        if (++maskFrameCount % 60 == 0) {  // Логируем каждые 60 кадров
            qDebug() << "[MASK] Используем обработанный кадр MediaPipe, размер:" << displayFrame.cols << "x" << displayFrame.rows;
        }
    } else if (m_maskEnabled) {
        static int emptyMaskCount = 0;
        if (++emptyMaskCount % 60 == 0) {  // Логируем каждые 60 кадров
            qWarning() << "[MASK] Маска включена, но m_lastProcessedFrame пуст! MediaPipe не работает?";
            qWarning() << "[MASK] m_mediapipeEnabled:" << m_mediapipeEnabled;
            qWarning() << "[MASK] Process state:" << (m_mediapipeProcess ? m_mediapipeProcess->state() : QProcess::NotRunning);
        }
    }

    m_scanView->setFrame(matToQImage(displayFrame));

    // Эмитируем сигнал с оригинальным кадром
    emit frameReady(frame);
}

QImage CameraCaptureWidget::matToQImage(const cv::Mat &mat) const
{
    if (mat.empty()) {
        return QImage();
    }

    cv::Mat rgbMat;
    cv::cvtColor(mat, rgbMat, cv::COLOR_BGR2RGB);

    QImage qimg(rgbMat.data, rgbMat.cols, rgbMat.rows, rgbMat.step, QImage::Format_RGB888);
    return qimg.copy();
}

bool CameraCaptureWidget::initializeMediaPipe()
{
    // Определяем корень проекта для поиска скрипта MediaPipe
    QString appDir = QCoreApplication::applicationDirPath();
    QDir projectRootDir(appDir);

    // macOS bundle: <project>/build/3FA.app/Contents/MacOS
    if (appDir.contains("/Contents/MacOS")) {
        projectRootDir = QDir(projectRootDir.absoluteFilePath("../../../../")); // поднимаемся до корня проекта
    } else {
        // Обычный случай: бинарь в build/ → поднимаемся на один уровень к корню проекта, если виден CMakeLists.txt
        QDir tryBuildParent(projectRootDir.absoluteFilePath(".."));
        if (tryBuildParent.exists("CMakeLists.txt")) {
            projectRootDir = tryBuildParent;
        } else {
            // Поднимаемся до корня проекта, ища CMakeLists.txt
            while (!projectRootDir.exists("CMakeLists.txt") && projectRootDir.cdUp()) {
                if (projectRootDir.isRoot()) break;
            }
        }
    }

    QString projectRoot = projectRootDir.absolutePath();
    m_mediapipeScriptPath = QDir(projectRoot).absoluteFilePath("scripts/mediapipe_simple.py");

    QFileInfo scriptFile(m_mediapipeScriptPath);
    qDebug() << "Проверяем скрипт MediaPipe:" << m_mediapipeScriptPath;
    qDebug() << "Скрипт существует:" << scriptFile.exists();
    if (!scriptFile.exists()) {
        qWarning() << "MediaPipe скрипт не найден:" << m_mediapipeScriptPath;
        return false;
    }

    // Определяем путь к Python: сначала пробуем виртуальное окружение, затем системный Python
    QString pythonPath;

        // Пробуем виртуальное окружение в корне проекта (без кириллицы в пути)
        QString venvPath = QDir(projectRoot).absoluteFilePath("venv_mediapipe");

#ifdef Q_OS_WIN
        // На Windows виртуальное окружение должно иметь структуру Scripts\python.exe
        QString winPythonPath = QDir(venvPath).absoluteFilePath("Scripts/python.exe");
        QFileInfo winPythonFile(winPythonPath);

        if (winPythonFile.exists()) {
            // Виртуальное окружение для Windows найдено
            pythonPath = winPythonPath;
            qDebug() << "Найдено виртуальное окружение Python (Windows):" << pythonPath;
        } else {
            // Виртуальное окружение не найдено - пробуем старое место
            QString oldVenvPath = QDir(projectRoot).absoluteFilePath("../468-Face-Landmarks-of-Face-with-MediaPippe-Google-s-Library-in-Python-OpenCV-main/venv311");
            QString oldWinPythonPath = QDir(oldVenvPath).absoluteFilePath("Scripts/python.exe");
            QString oldMacPythonPath = QDir(oldVenvPath).absoluteFilePath("bin/python");

            QFileInfo oldWinPythonFile(oldWinPythonPath);
            QFileInfo oldMacPythonFile(oldMacPythonPath);

            if (oldWinPythonFile.exists()) {
                pythonPath = oldWinPythonPath;
                qDebug() << "Найдено старое виртуальное окружение Python (Windows):" << pythonPath;
            } else if (oldMacPythonFile.exists()) {
                // Виртуальное окружение создано на Mac - не будет работать на Windows
                qWarning() << "Виртуальное окружение найдено, но создано на Mac (bin/python) - не работает на Windows";
                qWarning() << "Используем системный Python. Убедитесь, что MediaPipe установлен: pip install mediapipe";
                pythonPath = "python";  // Используем системный Python
            } else {
                // Виртуальное окружение не найдено
                qWarning() << "Виртуальное окружение не найдено. Используем системный Python.";
                qWarning() << "Убедитесь, что MediaPipe установлен: pip install mediapipe";
                pythonPath = "python";  // На Windows обычно "python"
            }
        }
#else
    // На Mac/Linux Python находится в bin/python
    pythonPath = QDir(venvPath).absoluteFilePath("bin/python");
    QFileInfo pythonFile(pythonPath);
    if (!pythonFile.exists()) {
        // Если виртуальное окружение не найдено, используем системный Python
        pythonPath = "python3"; // На Mac/Linux обычно "python3"
        qDebug() << "Виртуальное окружение не найдено, используем системный Python:" << pythonPath;
    } else {
        qDebug() << "Найдено виртуальное окружение Python:" << pythonPath;
    }
#endif

    // Сохраняем путь к Python для использования в startMediaPipeProcess
    m_pythonPath = pythonPath;

    m_mediapipeEnabled = true;
    return true;
}

void CameraCaptureWidget::startMediaPipeProcess()
{
    if (!m_mediapipeEnabled) {
        return;
    }

    // Используем сохраненный путь к Python из initializeMediaPipe
    QString pythonPath = m_pythonPath;
    if (pythonPath.isEmpty()) {
        // Если путь не был установлен, используем системный Python
#ifdef Q_OS_WIN
        pythonPath = "python";
#else
        pythonPath = "python3";
#endif
    }

    // Определяем рабочую директорию (корень проекта, где находится скрипт)
    QString appDir = QCoreApplication::applicationDirPath();
    QDir projectRootDir(appDir);
    if (appDir.contains("/Contents/MacOS")) {
        projectRootDir = QDir(projectRootDir.absoluteFilePath("../../../../"));
    } else {
        QDir tryBuildParent(projectRootDir.absoluteFilePath(".."));
        if (tryBuildParent.exists("CMakeLists.txt")) {
            projectRootDir = tryBuildParent;
        }
    }
    QString projectRoot = projectRootDir.absolutePath();

    m_mediapipeProcess = new QProcess(this);
    m_mediapipeProcess->setProcessChannelMode(QProcess::SeparateChannels); // Разделяем stdout и stderr для лучшей диагностики
    m_mediapipeProcess->setWorkingDirectory(projectRoot); // Устанавливаем рабочую директорию

    // Сбрасываем счетчик кадров при запуске процесса
    m_mediapipeFrameCounter = 0;

    connect(m_mediapipeProcess, &QProcess::readyReadStandardOutput, this, &CameraCaptureWidget::onMediaPipeDataReady);
    connect(m_mediapipeProcess, &QProcess::readyReadStandardError, this, [this]() {
        if (m_mediapipeProcess) {
            QByteArray errorData = m_mediapipeProcess->readAllStandardError();
            if (!errorData.isEmpty()) {
                qWarning() << "[MediaPipe stderr]:" << QString::fromUtf8(errorData);
            }
        }
    });
    connect(m_mediapipeProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &CameraCaptureWidget::onMediaPipeError);

    m_mediapipeProcess->start(pythonPath, QStringList() << m_mediapipeScriptPath);

    if (m_mediapipeProcess->waitForStarted(5000)) {
        qDebug() << "[OK] MediaPipe процесс запущен успешно для CameraCaptureWidget";
        qDebug() << "  Python:" << pythonPath;
        qDebug() << "  Скрипт:" << m_mediapipeScriptPath;
        qDebug() << "  Рабочая директория:" << projectRoot;
        qDebug() << "  PID:" << m_mediapipeProcess->processId();
    } else {
        QString errorStr = m_mediapipeProcess->errorString();
        qWarning() << "[ERROR] Не удалось запустить MediaPipe процесс для CameraCaptureWidget";
        qWarning() << "  Python путь:" << pythonPath;
        qWarning() << "  Скрипт:" << m_mediapipeScriptPath;
        qWarning() << "  Рабочая директория:" << projectRoot;
        qWarning() << "  Ошибка:" << errorStr;
        qWarning() << "  Вывод stderr:" << m_mediapipeProcess->readAllStandardError();
        qWarning() << "  Вывод stdout:" << m_mediapipeProcess->readAllStandardOutput();
        m_mediapipeEnabled = false;
    }
}

void CameraCaptureWidget::stopMediaPipeProcess()
{
    if (m_mediapipeProcess) {
        m_mediapipeProcess->terminate();
        if (!m_mediapipeProcess->waitForFinished(3000)) {
            m_mediapipeProcess->kill();
        }
        m_mediapipeProcess->deleteLater();
        m_mediapipeProcess = nullptr;
    }
}

void CameraCaptureWidget::sendFrameToMediaPipe(const cv::Mat &frame)
{
    if (!m_mediapipeProcess || m_mediapipeProcess->state() != QProcess::Running) {
        return;
    }

    // Пропускаем кадры: отправляем каждый 2-й кадр для повышения производительности
    ++m_mediapipeFrameCounter;
    if (m_mediapipeFrameCounter % 2 != 0) {
        return;  // Пропускаем нечетные кадры
    }

    // Уменьшаем размер изображения перед отправкой для ускорения обработки
    // MediaPipe хорошо работает с меньшими разрешениями
    cv::Mat resizedFrame;
    const int maxWidth = 640;  // Максимальная ширина
    const int maxHeight = 480; // Максимальная высота

    if (frame.cols > maxWidth || frame.rows > maxHeight) {
        double scale = std::min(static_cast<double>(maxWidth) / frame.cols,
                               static_cast<double>(maxHeight) / frame.rows);
        cv::Size newSize(static_cast<int>(frame.cols * scale),
                        static_cast<int>(frame.rows * scale));
        cv::resize(frame, resizedFrame, newSize, 0, 0, cv::INTER_LINEAR);
    } else {
        resizedFrame = frame;
    }

    // Конвертируем кадр в base64 с более низким качеством JPEG для уменьшения размера
    std::vector<uchar> buffer;
    std::vector<int> params;
    params.push_back(cv::IMWRITE_JPEG_QUALITY);
    params.push_back(85);  // Качество 85% (достаточно для маски, но меньше размер)
    cv::imencode(".jpg", resizedFrame, buffer, params);
    QByteArray imageData(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    QByteArray base64Data = imageData.toBase64();

    // Отправляем в MediaPipe
    QByteArray message = base64Data + "\n";
    qint64 written = m_mediapipeProcess->write(message);
    if (written < 0) {
        static int errorCount = 0;
        if (errorCount++ < 5) {  // Логируем только первые 5 ошибок
            qWarning() << "Ошибка отправки кадра в MediaPipe:" << m_mediapipeProcess->errorString();
        }
    }
    // QProcess::write() автоматически отправляет данные, flush() не нужен
}

void CameraCaptureWidget::onMediaPipeDataReady()
{
    if (!m_mediapipeProcess) {
        return;
    }

    QByteArray data = m_mediapipeProcess->readAllStandardOutput();
    m_mediapipeBuffer.append(data);

    // Ищем полные base64 строки (как в FaceAuthWidget)
    while (m_mediapipeBuffer.contains('\n')) {
        int newlinePos = m_mediapipeBuffer.indexOf('\n');
        QByteArray line = m_mediapipeBuffer.left(newlinePos);
        m_mediapipeBuffer.remove(0, newlinePos + 1);

        if (!line.isEmpty()) {
            try {
                // Декодируем base64 изображение (как в FaceAuthWidget)
                QByteArray imageData = QByteArray::fromBase64(line);
                std::vector<uchar> buffer(imageData.begin(), imageData.end());
                cv::Mat processedImage = cv::imdecode(buffer, cv::IMREAD_COLOR);

                if (!processedImage.empty()) {
                    m_lastProcessedFrame = processedImage.clone();
                    static int frameCount = 0;
                    if (++frameCount % 30 == 0) {  // Логируем каждые 30 кадров
                        qDebug() << "[OK] MediaPipe обработал кадр, размер:" << processedImage.cols << "x" << processedImage.rows;
                    }
                } else {
                    static int emptyCount = 0;
                    if (++emptyCount <= 3) {  // Логируем первые 3 пустых кадра
                        qWarning() << "[WARNING] MediaPipe вернул пустое изображение. Base64 длина:" << line.length();
                    }
                }
            } catch (const std::exception &e) {
                qWarning() << "CameraCaptureWidget: ошибка декодирования изображения:" << e.what();
            }
        }
    }
}

void CameraCaptureWidget::onMediaPipeError(int exitCode, QProcess::ExitStatus exitStatus)
{
    // Процесс MediaPipe завершился (может быть штатное завершение)
    qWarning() << "[ERROR] MediaPipe процесс завершился для CameraCaptureWidget";
    qWarning() << "  Exit code:" << exitCode;
    qWarning() << "  Exit status:" << (exitStatus == QProcess::NormalExit ? "Normal" : "Crash");

    // Читаем все оставшиеся данные для диагностики
    if (m_mediapipeProcess) {
        QByteArray stderrData = m_mediapipeProcess->readAllStandardError();
        QByteArray stdoutData = m_mediapipeProcess->readAllStandardOutput();

        if (!stderrData.isEmpty()) {
            qWarning() << "  stderr:" << QString::fromUtf8(stderrData);
        }
        if (!stdoutData.isEmpty()) {
            qWarning() << "  stdout:" << QString::fromUtf8(stdoutData);
        }
    }

    m_mediapipeEnabled = false;
}

void CameraCaptureWidget::setUserAndService(const User &user, FaceAuthService *service)
{
    m_user = user;
    m_faceAuthService = service;
}

void CameraCaptureWidget::processFaceRegistration(const cv::Mat &frame)
{
    if (!m_faceAuthService) {
        return;
    }

    // Проверяем лицо каждые 10 кадров (снижаем частоту проверки)
    ++m_faceCheckCounter;
    const int CHECK_FREQUENCY = 10;

    bool faceDetected = false;
    std::optional<std::vector<float>> embeddingOpt;

    if (m_faceCheckCounter >= CHECK_FREQUENCY) {
        m_faceCheckCounter = 0;

        // Извлекаем эмбеддинг лица из кадра
        cv::Rect faceRectCv;
        embeddingOpt = m_faceAuthService->extractEmbedding(frame, nullptr, &faceRectCv);
        faceDetected = embeddingOpt.has_value();

        // Проверяем изменение состояния лица
        if (!faceDetected && !m_faceWasLost) {
            // Лицо только что потеряли
            if (m_lastReportedStage != 0) {
                emit statusUpdate(tr("Расположите лицо в центре круга."));
                m_lastReportedStage = 0;
            }
            m_scanView->setProgress(-1);
            m_framesProcessed = 0;

            // Приостанавливаем таймер при потере лица (только если еще не на паузе)
            if (!m_timerPaused && m_registrationTimerThread && m_registrationTimerThread->isRunning()) {
                m_registrationTimerThread->pauseTimer();
                m_timerPaused = true;
            }
            m_faceWasLost = true;
        } else if (faceDetected && m_faceWasLost) {
            // Лицо вернулось
            // Возобновляем таймер при обнаружении лица (только если на паузе)
            if (m_timerPaused && m_registrationTimerThread && m_registrationTimerThread->isRunning()) {
                m_registrationTimerThread->resumeTimer();
                m_timerPaused = false;
            }
            m_faceWasLost = false;
        }

        // Если лицо не обнаружено, не обрабатываем дальше
        if (!faceDetected) {
            return;
        }
    } else {
        // Пропускаем проверку лица
        return;
    }

    // Возобновляем таймер при обнаружении лица (только если на паузе)
    if (m_timerPaused && m_registrationTimerThread && m_registrationTimerThread->isRunning()) {
        m_registrationTimerThread->resumeTimer();
        m_timerPaused = false;
    }

    ++m_framesProcessed;

    const int MIN_STABILIZATION_FRAMES = 30;
    if (m_framesProcessed < MIN_STABILIZATION_FRAMES) {
        if (m_lastReportedStage != 1) {
            emit statusUpdate(tr("Смотрите прямо в камеру и держите голову неподвижно."));
            m_lastReportedStage = 1;
        }
        const auto &embedding = embeddingOpt.value();
        m_enrollmentSamples.push_back(embedding);
        return;
    }

    // После стабилизации продолжаем собирать образцы без смены статуса
    const auto &embedding = embeddingOpt.value();
    m_enrollmentSamples.push_back(embedding);
}

void CameraCaptureWidget::onRegistrationCompleted()
{
    if (!m_scanTimeout->isActive()) return;
    stopCapture(true);
    qDebug() << "CameraCaptureWidget::onRegistrationCompleted - регистрация завершена";
    qDebug() << "  m_faceAuthService:" << (m_faceAuthService ? "set" : "null");
    qDebug() << "  m_enrollmentSamples.size():" << m_enrollmentSamples.size();
    qDebug() << "  m_user.isValid():" << m_user.isValid();

    // Таймер завершился - сохраняем усредненный шаблон
    if (m_faceAuthService && m_enrollmentSamples.size() >= 10 && m_user.isValid()) {
        // Усредняем образцы
        std::vector<float> averaged(m_enrollmentSamples[0].size(), 0.0f);
        for (const auto &sample : m_enrollmentSamples) {
            for (size_t i = 0; i < averaged.size() && i < sample.size(); ++i) {
                averaged[i] += sample[i];
            }
        }
        for (auto &val : averaged) {
            val /= m_enrollmentSamples.size();
        }

        // Нормализуем усредненный эмбеддинг (важно для корректного сравнения)
        float norm = 0.0f;
        for (float value : averaged) {
            norm += value * value;
        }
        norm = std::sqrt(norm);
        if (norm > 0.0f) {
            for (float &value : averaged) {
                value /= norm;
            }
        }

        // Сохраняем шаблон
        if (m_faceAuthService->storeEmbedding(m_user, averaged)) {
            m_scanView->complete();
            emit registrationCompleted();
        } else {
            emit registrationFailed(tr("Не удалось сохранить образец лица. Повторите попытку."));
        }
    } else {
        emit registrationFailed(tr("Не удалось получить достаточно кадров с лицом. Проверьте камеру и повторите попытку."));
    }
}

