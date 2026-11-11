#include "faceauthservice.h"

#include <QDebug>
#include <QDir>
#include <QFile>
#include <QtMath>
#include <cstring>
#include <algorithm>
#include <cmath>

FaceAuthService::FaceAuthService(Database *database, QObject *parent)
    : QObject(parent)
    , m_database(database)
    , m_ready(false)
    , m_landmarkReady(false)
{
}

bool FaceAuthService::initialize(const QString &modelDirectory)
{
    m_modelDirectory = modelDirectory;

    const QString cascadePath = QDir(modelDirectory).filePath("haarcascade_frontalface_default.xml");
    const QString arcfacePath = QDir(modelDirectory).filePath("ms1mv3_arcface_r100.onnx");
    const QString landmarkPath = QDir(modelDirectory).filePath("2d106det.onnx");

    if (!QFile::exists(cascadePath) || !QFile::exists(arcfacePath)) {
        qWarning() << "FaceAuthService: модель или каскад не найдены в" << modelDirectory;
        m_ready = false;
        return false;
    }

    if (!m_faceCascade.load(cascadePath.toStdString())) {
        qWarning() << "FaceAuthService: не удалось загрузить каскад" << cascadePath;
        m_ready = false;
        return false;
    }

    try {
        m_faceNet = cv::dnn::readNetFromONNX(arcfacePath.toStdString());
    } catch (const cv::Exception &ex) {
        qWarning() << "FaceAuthService: ошибка загрузки ArcFace:" << ex.what();
        m_ready = false;
        return false;
    }

    if (m_faceNet.empty()) {
        qWarning() << "FaceAuthService: модель ArcFace пуста";
        m_ready = false;
        return false;
    }

    if (QFile::exists(landmarkPath)) {
        try {
            m_landmarkNet = cv::dnn::readNetFromONNX(landmarkPath.toStdString());
            m_landmarkReady = !m_landmarkNet.empty();
            if (m_landmarkReady) {
                qInfo() << "FaceAuthService: landmarks модель загружена из" << landmarkPath;
            } else {
                qWarning() << "FaceAuthService: landmarks модель загружена, но пуста:" << landmarkPath;
            }
        } catch (const cv::Exception &ex) {
            qWarning() << "FaceAuthService: ошибка загрузки landmarks модели:" << ex.what();
            m_landmarkReady = false;
        }
    } else {
        m_landmarkReady = false;
    }

    m_ready = true;
    return true;
}

bool FaceAuthService::hasStoredEmbedding(const User &user)
{
    if (!m_database || !m_database->isConnected()) {
        return false;
    }
    QByteArray blob = m_database->getUserFaceEmbedding(user.getId());
    return !blob.isEmpty();
}

bool FaceAuthService::storeEmbedding(const User &user, const std::vector<float> &embedding)
{
    if (!m_database || !m_database->isConnected()) {
        return false;
    }

    QByteArray blob = vectorToBlob(embedding);
    return m_database->saveUserFaceEmbedding(user.getId(), blob);
}

std::optional<std::vector<float>> FaceAuthService::loadStoredEmbedding(const User &user)
{
    if (!m_database || !m_database->isConnected()) {
        return std::nullopt;
    }
    QByteArray blob = m_database->getUserFaceEmbedding(user.getId());
    if (blob.isEmpty()) {
        return std::nullopt;
    }
    return blobToVector(blob);
}

std::optional<std::vector<float>> FaceAuthService::extractEmbedding(const cv::Mat &frame, cv::Mat *debugFace, cv::Rect *outFaceRect)
{
    if (!m_ready) {
        return std::nullopt;
    }

    cv::Rect faceRect;
    auto face = detectAndAlignFace(frame, &faceRect);
    if (!face.has_value()) {
        return std::nullopt;
    }

    cv::Mat faceMat = face.value();
    if (debugFace) {
        *debugFace = faceMat.clone();
    }

    if (outFaceRect) {
        *outFaceRect = faceRect;
    }

    cv::Mat blob = cv::dnn::blobFromImage(faceMat, 1.0 / 255.0, cv::Size(112, 112), cv::Scalar(), true, false);

    cv::Mat embedding;
    try {
        m_faceNet.setInput(blob);
        embedding = m_faceNet.forward();
    } catch (const cv::Exception &ex) {
        qWarning() << "FaceAuthService: ошибка во время инференса ArcFace:" << ex.what();
        return std::nullopt;
    }

    if (embedding.empty()) {
        return std::nullopt;
    }

    cv::Mat reshaped = embedding.reshape(1, 1);
    std::vector<float> vec = matToVector(reshaped);

    float norm = 0.0f;
    for (float value : vec) {
        norm += value * value;
    }
    norm = std::sqrt(norm);
    if (norm > 0.0f) {
        for (float &value : vec) {
            value /= norm;
        }
    }

    return vec;
}

float FaceAuthService::cosineSimilarity(const std::vector<float> &a, const std::vector<float> &b) const
{
    if (a.empty() || b.empty() || a.size() != b.size()) {
        return -1.0f;
    }

    float dot = 0.0f;
    float normA = 0.0f;
    float normB = 0.0f;
    for (size_t i = 0; i < a.size(); ++i) {
        dot += a[i] * b[i];
        normA += a[i] * a[i];
        normB += b[i] * b[i];
    }

    if (normA == 0.0f || normB == 0.0f) {
        return -1.0f;
    }

    return dot / (std::sqrt(normA) * std::sqrt(normB));
}

std::optional<std::vector<cv::Point2f>> FaceAuthService::estimateLandmarks(const cv::Mat &frame, const cv::Rect &faceRect)
{
    if (!m_landmarkReady) {
        return std::nullopt;
    }

    cv::Rect clippedRect = faceRect & cv::Rect(0, 0, frame.cols, frame.rows);
    if (clippedRect.width <= 0 || clippedRect.height <= 0) {
        return std::nullopt;
    }

    cv::Mat faceRoi = frame(clippedRect).clone();
    cv::cvtColor(faceRoi, faceRoi, cv::COLOR_BGR2RGB);

    cv::Mat blob = cv::dnn::blobFromImage(faceRoi, 1.0 / 255.0, cv::Size(192, 192), cv::Scalar(), true, false);

    cv::Mat preds;
    try {
        m_landmarkNet.setInput(blob);
        preds = m_landmarkNet.forward();
    } catch (const cv::Exception &ex) {
        qWarning() << "FaceAuthService: ошибка инференса landmarks:" << ex.what();
        return std::nullopt;
    }

    if (preds.empty() || preds.total() != 212) {
        return std::nullopt;
    }

    const float *data = preds.ptr<float>();
    std::vector<cv::Point2f> points;
    points.reserve(106);
    for (int i = 0; i < 106; ++i) {
        float x = data[2 * i];
        float y = data[2 * i + 1];

        float px = std::clamp(x, 0.0f, 1.0f) * faceRoi.cols;
        float py = std::clamp(y, 0.0f, 1.0f) * faceRoi.rows;

        points.emplace_back(clippedRect.x + px, clippedRect.y + py);
    }

    return points;
}

bool FaceAuthService::verifyEmbedding(const User &user, const std::vector<float> &embedding, float threshold)
{
    auto stored = loadStoredEmbedding(user);
    if (!stored.has_value()) {
        qDebug() << "FaceAuthService: сохраненный эмбеддинг не найден для пользователя" << user.getEmail();
        return false;
    }

    float similarity = cosineSimilarity(stored.value(), embedding);
    
    if (similarity < 0.0f) {
        qWarning() << "FaceAuthService: ошибка вычисления similarity";
        return false;
    }
    
    // Логируем только при успешной верификации или при очень низком similarity (возможная ошибка)
    static int logCounter = 0;
    if (similarity >= threshold) {
        if (logCounter % 10 == 0) {  // Логируем каждое 10-е успешное распознавание
            qDebug() << "FaceAuthService: ✅ Лицо распознано, similarity =" << similarity << "threshold =" << threshold;
        }
        logCounter++;
    } else if (similarity < 0.3f && logCounter % 50 == 0) {  // Логируем очень низкие значения реже
        qDebug() << "FaceAuthService: ⚠️ Низкое similarity =" << similarity << "threshold =" << threshold;
        logCounter++;
    } else {
        logCounter++;
    }
    
    return similarity >= threshold;
}

std::optional<cv::Mat> FaceAuthService::detectAndAlignFace(const cv::Mat &frame, cv::Rect *outRect)
{
    if (frame.empty()) {
        return std::nullopt;
    }

    cv::Mat gray;
    if (frame.channels() == 3) {
        cv::cvtColor(frame, gray, cv::COLOR_BGR2GRAY);
    } else {
        gray = frame.clone();
    }
    cv::equalizeHist(gray, gray);

    std::vector<cv::Rect> faces;
    m_faceCascade.detectMultiScale(gray, faces, 1.1, 3, 0, cv::Size(120, 120));
    if (faces.empty()) {
        return std::nullopt;
    }

    auto biggest = std::max_element(faces.begin(), faces.end(), [](const cv::Rect &a, const cv::Rect &b) {
        return a.area() < b.area();
    });

    cv::Rect faceRect = *biggest;
    int padX = static_cast<int>(faceRect.width * 0.15);
    int padY = static_cast<int>(faceRect.height * 0.20);
    faceRect.x = std::max(0, faceRect.x - padX);
    faceRect.y = std::max(0, faceRect.y - padY);
    faceRect.width = std::min(frame.cols - faceRect.x, faceRect.width + 2 * padX);
    faceRect.height = std::min(frame.rows - faceRect.y, faceRect.height + 2 * padY);

    if (outRect) {
        *outRect = faceRect;
    }

    cv::Mat face = frame(faceRect).clone();
    cv::cvtColor(face, face, cv::COLOR_BGR2RGB);
    cv::resize(face, face, cv::Size(112, 112));
    return face;
}

std::vector<float> FaceAuthService::matToVector(const cv::Mat &mat) const
{
    std::vector<float> vec(mat.total());
    std::memcpy(vec.data(), mat.ptr<float>(), mat.total() * sizeof(float));
    return vec;
}

QByteArray FaceAuthService::vectorToBlob(const std::vector<float> &vec) const
{
    QByteArray blob;
    blob.resize(static_cast<int>(vec.size() * sizeof(float)));
    std::memcpy(blob.data(), vec.data(), blob.size());
    return blob;
}

std::vector<float> FaceAuthService::blobToVector(const QByteArray &blob) const
{
    std::vector<float> vec(blob.size() / sizeof(float));
    std::memcpy(vec.data(), blob.constData(), blob.size());
    return vec;
}
