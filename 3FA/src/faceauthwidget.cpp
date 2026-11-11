#include "faceauthwidget.h"
#include "apptheme.h"
#include "camerathread.h"
#include "facescanview.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QImage>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <utility>

FaceAuthWidget::FaceAuthWidget(FaceAuthService *service, QWidget *parent)
    : QWidget(parent)
    , m_service(service)
    , m_scanView(new FaceScanView)
    , m_statusLabel(new QLabel)
    , m_startButton(new QPushButton)
    , m_cancelButton(new QPushButton(tr("Отмена")))
    , m_cameraThread(new CameraThread(this))
    , m_scanTimeout(new QTimer(this))
{
    auto *contents = AppTheme::centeredCard(this, 502);
    auto *step = new QLabel(tr("ЭТАП 3 ИЗ 3"));
    AppTheme::role(step, "eyebrow");
    contents->addWidget(step);
    m_title = new QLabel;
    m_title->setWordWrap(true);
    AppTheme::role(m_title, "title");
    contents->addWidget(m_title);

    contents->addWidget(m_scanView);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setAlignment(Qt::AlignCenter);
    m_statusLabel->setObjectName("faceScanStatus");
    AppTheme::dimension(m_statusLabel, "minimumHeight", 40);
    contents->addWidget(m_statusLabel);

    auto *actions = new QHBoxLayout;
    AppTheme::role(m_startButton, "primary");
    AppTheme::buttonIcon(m_startButton, "camera");
    AppTheme::role(m_cancelButton, "quiet");
    m_cancelButton->setEnabled(false);
    actions->addWidget(m_cancelButton);
    actions->addStretch();
    actions->addWidget(m_startButton);
    contents->addLayout(actions);

    connect(m_cameraThread, &CameraThread::frameReady, this, &FaceAuthWidget::onFrameReady);
    connect(m_cameraThread, &CameraThread::faceVerified, this, &FaceAuthWidget::onFaceVerified);
    connect(m_cameraThread, &CameraThread::enrollmentCaptured, this, &FaceAuthWidget::onEnrollmentCaptured,
            Qt::QueuedConnection);
    connect(m_cameraThread, &CameraThread::statusUpdate, this, &FaceAuthWidget::updateStatus);
    connect(m_cameraThread, &CameraThread::scanProgressChanged, this, [this](qreal progress) {
        if (m_cancelButton->isEnabled()) m_scanView->setProgress(progress);
    });
    connect(m_startButton, &QPushButton::clicked, this, &FaceAuthWidget::onStartClicked);
    connect(m_cancelButton, &QPushButton::clicked, this, &FaceAuthWidget::onCancelClicked);
    m_scanTimeout->setObjectName("faceScanTimeout");
    m_scanTimeout->setSingleShot(true);
    m_scanTimeout->setTimerType(Qt::PreciseTimer);
    m_scanTimeout->setInterval(FaceAuthService::scanTimeoutMs);
    connect(m_scanTimeout, &QTimer::timeout, this, [this] {
        if (!m_cancelButton->isEnabled()) return;
        stopCapture();
        m_startButton->setText(tr("Повторить"));
        updateStatus(tr("Не удалось подтвердить лицо за отведённое время. Проверьте освещение и повторите попытку."), true);
    });
    setEnrollmentMode(false);
}

FaceAuthWidget::~FaceAuthWidget()
{
    m_cameraThread->stopCapture();
}

void FaceAuthWidget::setUser(const User &user)
{
    m_user = user;
    setEnrollmentMode(false);
}

void FaceAuthWidget::setEnrollmentMode(bool isEnrollment)
{
    m_mode = isEnrollment ? Mode::Enroll : Mode::Verify;
    m_title->setText(isEnrollment ? tr("Запись образца лица") : tr("Проверка лица"));
    m_startButton->setText(isEnrollment ? tr("Добавить лицо") : tr("Начать"));
    updateStatus(isEnrollment ? tr("Нажмите «Добавить лицо» и смотрите прямо в камеру.")
                              : tr("Расположите лицо в центре круга."));
}

void FaceAuthWidget::startVerification()
{
    onStartClicked();
}

void FaceAuthWidget::onStartClicked()
{
    if (m_cameraThread->isRunning()) return;

    if (!m_service || !m_service->isReady()) {
        updateStatus(tr("Распознавание недоступно. Проверьте модели в resources/face."), true);
        return;
    }

    std::vector<float> reference;
    if (m_mode == Mode::Verify) {
        auto stored = m_service->loadStoredEmbedding(m_user);
        if (!stored || stored->empty()) {
            updateStatus(tr("Не удалось загрузить сохранённый образец лица."), true);
            return;
        }
        reference = std::move(*stored);
    }

    m_cameraThread->setService(m_service);
    m_cameraThread->setReferenceEmbedding(std::move(reference));
    m_cameraThread->setMode(static_cast<int>(m_mode));
    m_cameraThread->startCapture();
    if (!m_cameraThread->isRunning()) return;

    m_startButton->setEnabled(false);
    m_cancelButton->setEnabled(true);
    m_scanView->start();
    m_scanTimeout->start();
    updateStatus(tr("Расположите лицо в центре круга и смотрите прямо в камеру."));
}

void FaceAuthWidget::onCancelClicked()
{
    const bool wasRunning = m_cancelButton->isEnabled();
    stopCapture();
    updateStatus(tr("Проверка отменена."));
    if (wasRunning) emit verificationFailed(tr("Проверка лица отменена."));
}

void FaceAuthWidget::stopCapture()
{
    m_scanTimeout->stop();
    m_cameraThread->stopCapture();
    m_startButton->setEnabled(true);
    m_cancelButton->setEnabled(false);
    m_scanView->reset();
}

void FaceAuthWidget::onFrameReady(const cv::Mat &frame)
{
    if (frame.empty() || !m_cancelButton->isEnabled()) return;
    const QImage preview(frame.data, frame.cols, frame.rows, static_cast<qsizetype>(frame.step),
                         QImage::Format_BGR888);
    m_scanView->setFrame(preview.copy());
}

void FaceAuthWidget::onFaceVerified()
{
    if (!m_cancelButton->isEnabled()) return;
    stopCapture();
    m_scanView->complete();
    emit faceVerified();
}

void FaceAuthWidget::onEnrollmentCaptured(const std::vector<float> &embedding)
{
    if (m_mode != Mode::Enroll || !m_cancelButton->isEnabled()) return;
    stopCapture();
    if (m_service->storeEmbedding(m_user, embedding)) {
        m_scanView->complete();
        emit faceVerified();
    } else {
        emit verificationFailed(tr("Не удалось сохранить новый образец лица. Войдите заново."));
    }
}

void FaceAuthWidget::updateStatus(const QString &text, bool error)
{
    AppTheme::role(m_statusLabel, error ? "error" : "muted");
    if (m_statusLabel->text() != text) m_statusLabel->setText(text);
}
