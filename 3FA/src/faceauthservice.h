#ifndef FACEAUTHSERVICE_H
#define FACEAUTHSERVICE_H

#include <QObject>
#include <QString>
#include <QByteArray>
#include <optional>
#include <vector>

#include <opencv2/core.hpp>
#include <opencv2/dnn.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/objdetect.hpp>

#include "database.h"
#include "user.h"

class FaceAuthService : public QObject
{
    Q_OBJECT
public:
    explicit FaceAuthService(Database *database, QObject *parent = nullptr);
    static constexpr int scanTimeoutMs = 30000;

    bool initialize(const QString &modelDirectory);
    bool isReady() const { return m_ready; }

    bool hasStoredEmbedding(const User &user);
    bool storeEmbedding(const User &user, const std::vector<float> &embedding);
    std::optional<std::vector<float>> loadStoredEmbedding(const User &user);

    std::optional<std::vector<float>> extractEmbedding(const cv::Mat &frame, cv::Mat *debugFace = nullptr, cv::Rect *outFaceRect = nullptr);
    std::optional<std::vector<cv::Point2f>> estimateLandmarks(const cv::Mat &frame, const cv::Rect &faceRect);
    float cosineSimilarity(const std::vector<float> &a, const std::vector<float> &b) const;
    bool verifyEmbedding(const User &user, const std::vector<float> &embedding, float threshold = 0.6f);

private:
    Database *m_database;
    cv::dnn::Net m_faceNet;
    cv::CascadeClassifier m_faceCascade;
    cv::dnn::Net m_landmarkNet;
    bool m_ready;
    bool m_landmarkReady;
    QString m_modelDirectory;

    std::optional<cv::Mat> detectAndAlignFace(const cv::Mat &frame, cv::Rect *outRect = nullptr);
    std::vector<float> matToVector(const cv::Mat &mat) const;
    QByteArray vectorToBlob(const std::vector<float> &vec) const;
    std::vector<float> blobToVector(const QByteArray &blob) const;
};

#endif // FACEAUTHSERVICE_H
