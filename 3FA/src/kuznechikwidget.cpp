#include "kuznechikwidget.h"
#include "apptheme.h"
#include <QDebug>
#include "appmessage.h"
#include <QApplication>
#include <QWidgetList>
#include <QTextOption>
#include <QFileDialog>
#include <QStandardPaths>
#include <QDateTime>
#include <QTextDocument>
#include <QtPrintSupport/QPrinter>
#include <QPageSize>
#include <QPageLayout>
#include <QFileInfo>
#include <QInputDialog>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrlQuery>
#include <QFile>
#include <QLockFile>
#include <QSaveFile>
#include <QSignalBlocker>
#include <QTemporaryDir>
#include <QUuid>
#include <QHttpMultiPart>
#include <QHttpPart>
#include <QUrl>
#include <QThread>
#include <QProcess>
#include <QDir>
#include <QRegularExpression>
#include <QProgressDialog>
#include <QTimer>
#include <QAbstractItemView>
#include <QEventLoop>
#include <QPalette>
#include <QColor>
#include <QFont>
#include <QIntValidator>
#include <QLocale>
#include <QTextStream>
#include <QMetaObject>
#include <QtConcurrent/QtConcurrent>
#include <openssl/bn.h>
#include <algorithm>
#include <future>
#include <memory>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCoreApplication>
#include <QVariantAnimation>
#include <QPainter>
#include <QPainterPath>
#include <QFocusEvent>

class AlgorithmSelector final : public QFrame
{
public:
    AlgorithmSelector()
        : m_buttons{new QPushButton("Кузнечик", this), new QPushButton("RSA", this)}
    {
        setObjectName("algorithmSwitch");
        setAccessibleName("Алгоритм шифрования");

        auto *row = new QHBoxLayout(this);
        AppTheme::margins(row, 4, 4, 4, 4);
        row->setSpacing(0);
        for (auto *button : m_buttons) {
            button->setCheckable(true);
            button->setAutoExclusive(true);
            button->setFocusPolicy(Qt::TabFocus);
            button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            row->addWidget(button, 1);
            button->installEventFilter(this);
        }
        m_buttons[0]->setChecked(true);

        m_slide.setDuration(220);
        m_slide.setEasingCurve(QEasingCurve::InOutSine);
        m_slide.setStartValue(0.0);
        m_slide.setEndValue(1.0);
        connect(&m_slide, &QVariantAnimation::valueChanged, this, [this](const QVariant &progress) {
            m_position = m_start + (m_active - m_start) * progress.toReal();
            update();
        });
    }

    QPushButton *button(int index) const { return m_buttons[index]; }

    void select(int index)
    {
        m_buttons[index]->setChecked(true);
        if (index == m_active) return;
        m_slide.stop();
        m_start = m_position;
        m_active = index;
        m_slide.setDuration(qRound(120 + 100 * qAbs(index - m_start)));
        m_slide.start();
    }

protected:
    bool eventFilter(QObject *watched, QEvent *event) override
    {
        if (event->type() == QEvent::FocusIn) {
            const auto reason = static_cast<QFocusEvent *>(event)->reason();
            m_keyboardFocus = reason == Qt::TabFocusReason || reason == Qt::BacktabFocusReason ||
                              reason == Qt::ShortcutFocusReason;
            update();
        } else if (event->type() == QEvent::FocusOut || event->type() == QEvent::MouseButtonPress) {
            m_keyboardFocus = false;
            update();
        }
        return QFrame::eventFilter(watched, event);
    }

    void paintEvent(QPaintEvent *) override
    {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.setPen(QPen(palette().mid().color(), 1));
        painter.setBrush(palette().base());
        const qreal radius = AppTheme::pixels(12);
        painter.drawRoundedRect(QRectF(rect()).adjusted(.5, .5, -.5, -.5), radius, radius);

        const QRectF left = m_buttons[0]->geometry();
        const QRectF right = m_buttons[1]->geometry();
        const QRectF thumb(left.x() + (right.x() - left.x()) * m_position, left.y(),
                           left.width() + (right.width() - left.width()) * m_position, left.height());
        auto blue = AppTheme::primaryColor();
        if (!isEnabled()) blue.setAlpha(150);
        QLinearGradient tint(thumb.topLeft(), thumb.bottomLeft());
        tint.setColorAt(0, blue.lighter(110));
        tint.setColorAt(1, blue);
        painter.setPen(Qt::NoPen);
        painter.setBrush(tint);
        const qreal thumbRadius = AppTheme::pixels(8);
        QPainterPath selected;
        selected.addRoundedRect(thumb.adjusted(.5, .5, -.5, -.5), thumbRadius, thumbRadius);
        painter.drawPath(selected);

        const auto drawLabels = [&] {
            for (const auto *button : m_buttons) {
                painter.setFont(button->font());
                painter.drawText(button->geometry(), Qt::AlignCenter, button->text());
            }
        };
        painter.setPen(palette().text().color());
        drawLabels();
        painter.save();
        painter.setClipPath(selected);
        painter.setPen(Qt::white);
        drawLabels();
        painter.restore();

        painter.setBrush(Qt::NoBrush);
        painter.setPen(QPen(palette().link().color(), 1));
        if (m_keyboardFocus) {
            for (const auto *button : m_buttons)
                if (button->hasFocus())
                    painter.drawRoundedRect(QRectF(button->geometry()).adjusted(1.5, 1.5, -1.5, -1.5),
                                            thumbRadius - 1, thumbRadius - 1);
        }
    }

private:
    QPushButton *m_buttons[2];
    QVariantAnimation m_slide;
    int m_active = 0;
    qreal m_start = 0;
    qreal m_position = 0;
    bool m_keyboardFocus = false;
};

namespace {
constexpr int maxRsaBits = 65536;
constexpr unsigned long rsaExponent = 65537;

bool writeKeyFile(const QString &path, const QByteArray &data)
{
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) return false;
#ifdef Q_OS_UNIX
    if (!file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)) return false;
#endif
    return file.write(data) == data.size() && file.commit();
}

QByteArray rsaKeyText(const BigInt &modulus, const BigInt &exponent, bool isPrivate)
{
    QByteArray text = isPrivate ? "# RSA Private Key\n" : "# RSA Public Key\n";
    text += "# Key Size: " + QByteArray::number(modulus.bitLength()) + " bits\n# Modulus (n):\n";
    text += QByteArray::fromStdString(BigIntConversion::gmpFastToDecimal(modulus));
    text += isPrivate ? "\n# Private Exponent (d):\n" : "\n# Public Exponent (e):\n";
    text += QByteArray::fromStdString(BigIntConversion::gmpFastToDecimal(exponent)) + '\n';
    return text;
}

QString keyFileStem(const QString &prefix)
{
    return prefix + '-' + QDateTime::currentDateTimeUtc().toString("yyyyMMdd-HHmmss-zzz") + '-' +
           QUuid::createUuid().toString(QUuid::Id128).left(8);
}

QString saveRsaPair(RSAKeyManager &keys, const QString &directory, const QString &name)
{
    if (directory.isEmpty() || !QDir().mkpath(directory)) return {};
    QTemporaryDir staging(QDir(directory).filePath(".pending-XXXXXX"));
    if (!staging.isValid()) return {};
    const auto [modulus, e] = keys.getPublicKey();
    const auto d = keys.getPrivateKey().second;
    const QString bits = QString::number(modulus.bitLength());
    const QString publicFile = name + "_public_" + bits + ".txt";
    const QString privateFile = name + "_private_" + bits + ".txt";
    if (!writeKeyFile(staging.filePath(publicFile), rsaKeyText(modulus, e, false)) ||
        !writeKeyFile(staging.filePath(privateFile), rsaKeyText(modulus, d, true))) return {};
    const QString published = QDir(directory).filePath(name);
    if (!QDir().rename(staging.path(), published)) return {};
    staging.setAutoRemove(false);
    return QDir(published).filePath(publicFile);
}

BigInt generateRsaPrime(int bits, std::atomic_bool &cancel)
{
    std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> prime(BN_new(), BN_clear_free);
    std::unique_ptr<BN_GENCB, decltype(&BN_GENCB_free)> callback(BN_GENCB_new(), BN_GENCB_free);
    if (!prime || !callback) throw std::runtime_error("OpenSSL could not allocate a prime generator");
    BN_GENCB_set(callback.get(), [](int, int, BN_GENCB *state) {
        return static_cast<std::atomic_bool *>(BN_GENCB_get_arg(state))->load() ? 0 : 1;
    }, &cancel);
    while (!cancel.load()) {
        if (BN_generate_prime_ex(prime.get(), bits, 0, nullptr, nullptr, callback.get()) != 1) break;
        const auto remainder = BN_mod_word(prime.get(), rsaExponent);
        if (remainder == static_cast<BN_ULONG>(-1)) break;
        if (remainder == 1) continue;
        std::vector<uint8_t> bytes(BN_num_bytes(prime.get()));
        if (BN_bn2lebinpad(prime.get(), bytes.data(), static_cast<int>(bytes.size())) < 0) break;
        return BigInt(bytes);
    }
    throw std::runtime_error("OpenSSL could not generate the RSA prime");
}

bool writeDefaultPrimes(const QString &directory)
{
    const QDir dir(directory);
    QLockFile lock(dir.filePath(".setup.lock"));
    if (!lock.tryLock(10000)) return false;

    std::atomic_bool cancel{false};
    try {
        for (const int bits : {1024, 1536}) {
            for (const QChar factor : {QChar('p'), QChar('q')}) {
                const auto path = dir.filePath(QString("rsa_%1_%2.txt").arg(factor).arg(bits));
                if (QFileInfo(path).isFile()) continue;
                const auto prime = generateRsaPrime(bits, cancel);
                const auto decimal = QByteArray::fromStdString(BigIntConversion::gmpFastToDecimal(prime));
                if (!writeKeyFile(path, decimal + '\n')) return false;
            }
        }
    } catch (const std::exception &error) {
        qWarning() << "Could not prepare RSA primes:" << error.what();
        return false;
    }
    return true;
}

int extractRsaKeyBitLength(const QString &keyPath)
{
    // Сначала пытаемся извлечь размер из имени файла
    // Формат: keyname_public_4096.txt или keyname_private_4096.txt
    QFileInfo fileInfo(keyPath);
    QString fileName = fileInfo.fileName();
    QRegularExpression fileNameRx("_public_(\\d+)\\.txt|_private_(\\d+)\\.txt");
    QRegularExpressionMatch fileNameMatch = fileNameRx.match(fileName);
    if (fileNameMatch.hasMatch()) {
        QString sizeStr = fileNameMatch.captured(1);
        if (sizeStr.isEmpty()) {
            sizeStr = fileNameMatch.captured(2);
        }
        if (!sizeStr.isEmpty()) {
            bool ok;
            int rsaSize = sizeStr.toInt(&ok);
            if (ok && rsaSize > 0) {
                // Размер в имени файла - это уже размер RSA (удвоенный размер простого числа)
                // Возвращаем размер простого числа (RSA / 2)
                return rsaSize / 2;
            }
        }
    }

    // Если не получилось из имени файла, пытаемся из файла
    QFile file(keyPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return 0;
    }
    QString content = file.readAll();
    file.close();

    const QStringList lines = content.split('\n');
    for (int i = 0; i < lines.size(); ++i) {
        const QString line = lines[i].trimmed();
        // Ищем комментарий с размером RSA
        if (line.contains("# RSA-", Qt::CaseInsensitive)) {
            QRegularExpression rx("RSA-(\\d+)");
            QRegularExpressionMatch match = rx.match(line);
            if (match.hasMatch()) {
                bool ok;
                int rsaSize = match.captured(1).toInt(&ok);
                if (ok && rsaSize > 0) {
                    // Размер в комментарии - это уже размер RSA (удвоенный размер простого числа)
                    // Возвращаем размер простого числа (RSA / 2)
                    return rsaSize / 2;
                }
            }
        }
        // Если не нашли комментарий, используем размер модуля как запасной вариант
        if (line.contains("# Modulus (n):", Qt::CaseInsensitive) && i + 1 < lines.size()) {
            const QString modulus = lines[i + 1].trimmed();
            if (!modulus.isEmpty()) {
                try {
                    BigInt n(modulus.toStdString(), true);
                    int modulusBits = n.bitLength();
                    // Модуль n = p * q, где p и q - простые числа одинакового размера
                    // Размер модуля примерно равен сумме размеров p и q
                    // Если p и q одинакового размера, то размер модуля примерно в два раза больше размера простого числа
                    // Возвращаем размер простого числа (модуль / 2)
                    return modulusBits / 2;
                } catch (...) {
                    return 0;
                }
            }
        }
    }

    return 0;
}

bool readPrimeFromFile(const QString &path, BigInt &prime, QString &error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        error = QString("Не удалось открыть файл %1").arg(path);
        return false;
    }

    QTextStream stream(&file);
    QString decimal = stream.readAll();
    file.close();

    decimal.remove(QRegularExpression("\\s+"));
    if (decimal.isEmpty()) {
        error = QString("Файл %1 пуст").arg(path);
        return false;
    }

    try {
        prime = BigInt(decimal.toStdString(), true); // true = десятичный формат
    } catch (const std::exception &ex) {
        error = QString("Ошибка чтения простого числа: %1").arg(ex.what());
        return false;
    }

    return true;
}
}

KuznechikWidget::KuznechikWidget(QWidget *parent)
    : QWidget(parent)
    , m_currentMode(TextMode)
    , m_cryptoFacade(new CryptoFacade())
    , m_rsaKeyManager(new RSAKeyManager())
    , m_primeFileManager(new PrimeFileManager())
    , m_networkManager(new QNetworkAccessManager(this))
    , m_primeGeneratorGroup(nullptr)
    , m_primeBitsEdit(nullptr)
    , m_generatePrimeButton(nullptr)
    , m_savePrimeButton(nullptr)
    , m_primeGenerationProgress(nullptr)
    , m_primeGenerationStatusLabel(nullptr)
    , m_generatedPrimeDecimal()
    , m_generatedPrimeHex()
    , m_generatedPrimeBits(0)
    , m_primeSelectionGroup(nullptr)
    , m_selectPrimesDirButton(nullptr)
    , m_primeFirstCombo(nullptr)
    , m_primeSecondCombo(nullptr)
    , m_primesStatusLabel(nullptr)
    , m_rsaKeyNameEdit(nullptr)
    , m_generateRsaKeysButton(nullptr)
    , m_saveRsaKeysButton(nullptr)
    , m_keyGenerationProgress(nullptr)
    , m_keyGenerationIndicator(nullptr)
    , m_rsaStatusLabel(nullptr)
    , m_primesDirectory()
    , m_selectedPrimePath1()
    , m_selectedPrimePath2()
    , m_selectedPrimeBits1(0)
    , m_selectedPrimeBits2(0)
    , m_generatedKeySize(0)
    , m_lastGeneratedKeyName()
    , m_keyGenerationWatcher(nullptr)
    , m_keySaveWatcher(nullptr)
    , m_primeGenerationWatcher(nullptr)
    , m_encryptDecryptWatcher(nullptr)
    , m_serverBindAddr("127.0.0.1")
    , m_serverPort(9090)
{
    // Load server configuration from JSON
    loadServerConfig();

    setupUI();
    ensureKeyGenerationWatcher();
    ensurePrimeGenerationWatcher();
    refreshPrimeSelections();
    updatePrimeControlsState();
    // Обновляем состояние кнопок шифрования/расшифрования после инициализации
    updateEncryptDecryptButtonsState();
}

void KuznechikWidget::loadServerConfig()
{
    // Определяем корневую директорию проекта
    QString appDir = QCoreApplication::applicationDirPath();
    QDir projectDir = QDir(appDir);

    // Поднимаемся от Contents/MacOS до корня проекта
    while (!projectDir.exists("CMakeLists.txt") && projectDir.cdUp()) {
        if (projectDir.isRoot()) break;
    }

    QString rootDir = projectDir.absolutePath();
    QFile configFile(rootDir + "/config/ca.json");

    if (configFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QString json = QString::fromUtf8(configFile.readAll());
        configFile.close();

        if (!json.isEmpty()) {
            QJsonParseError parseError;
            QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8(), &parseError);

            if (parseError.error != QJsonParseError::NoError) {
                qWarning() << "KuznechikWidget: [КОНФИГ] JSON parse error at position" << parseError.offset
                           << ":" << parseError.errorString() << ", используются значения по умолчанию";
            } else if (!doc.isNull() && doc.isObject()) {
                qDebug() << "KuznechikWidget: [КОНФИГ] Загружаем конфигурацию из config/ca.json";
                QJsonObject obj = doc.object();

                // Server settings
                QJsonObject serverObj = obj["server"].toObject();
                if (!serverObj.isEmpty()) {
                    if (serverObj.contains("bind_addr")) {
                        QJsonValue bindAddrVal = serverObj["bind_addr"];
                        if (bindAddrVal.isString()) {
                            m_serverBindAddr = bindAddrVal.toString();
                            qDebug() << "KuznechikWidget: [КОНФИГ] server.bind_addr из JSON:" << m_serverBindAddr;
                        }
                    }
                    if (serverObj.contains("port")) {
                        QJsonValue portVal = serverObj["port"];
                        if (portVal.isDouble()) {
                            int port = portVal.toInt();
                            if (port > 0 && port < 65536) {
                                m_serverPort = port;
                                qDebug() << "KuznechikWidget: [КОНФИГ] server.port из JSON:" << m_serverPort;
                            } else {
                                qWarning() << "KuznechikWidget: [КОНФИГ] Invalid server port value:" << port << "(must be 1-65535), используется значение по умолчанию";
                            }
                        }
                    }
                }
                qDebug() << "KuznechikWidget: [КОНФИГ] Конфигурация загружена из JSON. Сервер:" << m_serverBindAddr << ":" << m_serverPort;
            }
        } else {
            qWarning() << "KuznechikWidget: [КОНФИГ] Файл config/ca.json пуст, используются значения по умолчанию";
        }
    } else {
        qDebug() << "KuznechikWidget: [КОНФИГ] Файл config/ca.json не найден, используются значения по умолчанию:" << m_serverBindAddr << ":" << m_serverPort;
    }
}

KuznechikWidget::~KuznechikWidget()
{
    if (m_cancelRsa) m_cancelRsa->store(true);
    if (m_keyGenerationWatcher) {
        if (m_keyGenerationWatcher->isRunning()) {
            m_keyGenerationWatcher->cancel();
            m_keyGenerationWatcher->waitForFinished();
        }
        delete m_keyGenerationWatcher;
        m_keyGenerationWatcher = nullptr;
    }

    if (m_keySaveWatcher) {
        if (m_keySaveWatcher->isRunning()) {
            m_keySaveWatcher->cancel();
            m_keySaveWatcher->waitForFinished();
        }
        delete m_keySaveWatcher;
        m_keySaveWatcher = nullptr;
    }

    if (m_primeGenerationWatcher) {
        if (m_primeGenerationWatcher->isRunning()) {
            m_primeGenerationWatcher->cancel();
            m_primeGenerationWatcher->waitForFinished();
        }
        delete m_primeGenerationWatcher;
        m_primeGenerationWatcher = nullptr;
    }

    if (m_encryptDecryptWatcher) {
        if (m_encryptDecryptWatcher->isRunning()) {
            m_encryptDecryptWatcher->cancel();
            m_encryptDecryptWatcher->waitForFinished();
        }
        delete m_encryptDecryptWatcher;
        m_encryptDecryptWatcher = nullptr;
    }

    // Удаляем фасад
    if (m_cryptoFacade) {
        delete m_cryptoFacade;
        m_cryptoFacade = nullptr;
    }
}

void KuznechikWidget::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    AppTheme::margins(mainLayout, 24, 24, 24, 24);
    AppTheme::spacing(mainLayout, 10);
    mainLayout->setSizeConstraint(QLayout::SetMinimumSize);

    // Карточка в стиле проекта
    m_card = new QFrame();
    m_card->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    AppTheme::dimension(m_card, "maximumWidth", 1140);
    AppTheme::role(m_card, "card");

    QVBoxLayout *cardLayout = new QVBoxLayout(m_card);
    // Устанавливаем увеличенные отступы для Кузнечика (по умолчанию)
    AppTheme::margins(cardLayout, 20, 20, 20, 20); // Увеличенные отступы для Кузнечика
    AppTheme::spacing(cardLayout, 14); // Увеличенный spacing для Кузнечика

    // Заголовок
    m_titleLabel = new QLabel("Шифрование Кузнечик");
    m_titleLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    AppTheme::role(m_titleLabel, "title");
    m_titleLabel->setAlignment(Qt::AlignCenter);

    // Подзаголовок
    m_subtitleLabel = new QLabel("Алгоритм шифрования ГОСТ Р 34.12-2015");
    m_subtitleLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    AppTheme::role(m_subtitleLabel, "muted");
    m_subtitleLabel->setAlignment(Qt::AlignCenter);

    cardLayout->addWidget(m_titleLabel);
    cardLayout->addWidget(m_subtitleLabel);

    // ========== ВЫБОР АЛГОРИТМА (Кузнечик/RSA) ==========
    auto *algorithmLabel = new QLabel("Алгоритм");
    AppTheme::role(algorithmLabel, "section");
    algorithmLabel->setAlignment(Qt::AlignCenter);
    m_algorithmSwitch = new AlgorithmSelector;
    AppTheme::dimension(m_algorithmSwitch, "maximumWidth", 320);
    connect(m_algorithmSwitch->button(KuznechikAlgorithm), &QPushButton::clicked, this, [this] {
        onAlgorithmChanged(KuznechikAlgorithm);
    });
    connect(m_algorithmSwitch->button(RSAAlgorithm), &QPushButton::clicked, this, [this] {
        onAlgorithmChanged(RSAAlgorithm);
    });
    auto *algorithmRow = new QHBoxLayout;
    algorithmRow->addStretch();
    algorithmRow->addWidget(m_algorithmSwitch, 5);
    algorithmRow->addStretch();
    cardLayout->addWidget(algorithmLabel);
    cardLayout->addLayout(algorithmRow);

    // ========== ЛЕВАЯ ЧАСТЬ (кнопки и настройки) ==========
    QVBoxLayout *leftPanelLayout = new QVBoxLayout();
    AppTheme::spacing(leftPanelLayout, 8);
    AppTheme::margins(leftPanelLayout, 0, 0, 0, 0);

    // Метка для ключа
    m_keyLabel = new QLabel("Ключ (64 hex символа, 32 байта):");
    AppTheme::role(m_keyLabel, "section");
    leftPanelLayout->addWidget(m_keyLabel);

    // Поле ввода ключа
    m_keyEdit = new QLineEdit();
    m_keyEdit->setObjectName("kuznechikKey");
    m_keyEdit->setPlaceholderText("Форматы: 01234567..., 01 23 45..., 0x11 0x22..., 01-23-45..., 01:23:45...");
    leftPanelLayout->addWidget(m_keyEdit);

    m_kuznechikKeys = new MaterialComboBox;
    m_kuznechikKeys->setObjectName("kuznechikKeyLibrary");
    m_kuznechikKeys->setPlaceholderText("Сохранённые ключи");
    leftPanelLayout->addWidget(m_kuznechikKeys);
    connect(m_kuznechikKeys, &QComboBox::activated, this, &KuznechikWidget::selectKuznechikKey);

    // Кнопка генерации ключа
    m_generateKeyButton = new QPushButton("Создать и сохранить ключ");
    m_generateKeyButton->setObjectName("createKuznechikKey");
    AppTheme::buttonIcon(m_generateKeyButton, "key");
    m_generateKeyButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    AppTheme::dimension(m_generateKeyButton, "minimumHeight", 44);
    leftPanelLayout->addWidget(m_generateKeyButton);

    connect(m_generateKeyButton, &QPushButton::clicked, this, &KuznechikWidget::onGenerateKeyClicked);

    m_savedRsaGroup = new QGroupBox("Библиотека ключей RSA");
    auto *savedRsaLayout = new QVBoxLayout(m_savedRsaGroup);
    AppTheme::spacing(savedRsaLayout, 8);
    m_rsaKeyBits = new MaterialComboBox;
    m_rsaKeyBits->setObjectName("rsaKeyBits");
    for (int size : {2048, 3072, 4096, 8192, 16384, 32768, maxRsaBits})
        m_rsaKeyBits->addItem(QString("RSA · %1 бит").arg(QLocale().toString(size)), size);
    savedRsaLayout->addWidget(m_rsaKeyBits);
    m_createRsaPair = new QPushButton("Создать и сохранить пару");
    m_createRsaPair->setObjectName("createSavedRsaPair");
    AppTheme::buttonIcon(m_createRsaPair, "key");
    savedRsaLayout->addWidget(m_createRsaPair);
    connect(m_createRsaPair, &QPushButton::clicked, this, &KuznechikWidget::createSavedRsaPair);
    m_savedRsaStatus = new QLabel;
    m_savedRsaStatus->setWordWrap(true);
    AppTheme::role(m_savedRsaStatus, "muted");
    savedRsaLayout->addWidget(m_savedRsaStatus);
    m_savedRsaGroup->hide();
    leftPanelLayout->addWidget(m_savedRsaGroup);

    // Группа выбора простых чисел для RSA
    m_primeSelectionGroup = new QGroupBox("Генерация ключей RSA");
    m_primeSelectionGroup->setVisible(false);
    m_primeSelectionGroup->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    QVBoxLayout *primeLayout = new QVBoxLayout(m_primeSelectionGroup);
    AppTheme::spacing(primeLayout, 10);
    AppTheme::margins(primeLayout, 10, 6, 10, 8);
    m_primeSelectionGroup->setEnabled(false);

    m_selectPrimesDirButton = new QPushButton("Выбрать папку с простыми");
    AppTheme::buttonIcon(m_selectPrimesDirButton, "file");
    primeLayout->addWidget(m_selectPrimesDirButton);

    // Подключаем сигнал - используем прямое соединение
    connect(m_selectPrimesDirButton, &QPushButton::clicked,
            this, &KuznechikWidget::onSelectPrimesDirectory,
            Qt::DirectConnection);

    // Проверяем подключение
    qDebug() << "Кнопка 'Выбрать папку с простыми' создана, enabled:" << m_selectPrimesDirButton->isEnabled()
             << "visible:" << m_selectPrimesDirButton->isVisible();

    m_primeFirstCombo = new MaterialComboBox();
    m_primeFirstCombo->setEnabled(false);
    m_primeFirstCombo->setPlaceholderText("Выберите простое число p");
    AppTheme::fixedHeight(m_primeFirstCombo, 40);
    primeLayout->addWidget(m_primeFirstCombo);
    connect(m_primeFirstCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &KuznechikWidget::onPrimeSelectionChanged);

    m_primeSecondCombo = new MaterialComboBox();
    m_primeSecondCombo->setEnabled(false);
    m_primeSecondCombo->setPlaceholderText("Выберите простое число q");
    AppTheme::fixedHeight(m_primeSecondCombo, 40);
    primeLayout->addWidget(m_primeSecondCombo);
    connect(m_primeSecondCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &KuznechikWidget::onPrimeSelectionChanged);

    m_primesStatusLabel = new QLabel("Выберите два различных простых числа одинакового размера.");
    AppTheme::role(m_primesStatusLabel, "muted");
    m_primesStatusLabel->setWordWrap(true);
    primeLayout->addWidget(m_primesStatusLabel);

    QLabel *rsaKeyNameLabel = new QLabel("Имя для ключа:");
    primeLayout->addWidget(rsaKeyNameLabel);

    m_rsaKeyNameEdit = new QLineEdit();
    m_rsaKeyNameEdit->setPlaceholderText("secure_rsa_key");
    m_rsaKeyNameEdit->setEnabled(false);
    primeLayout->addWidget(m_rsaKeyNameEdit);
    connect(m_rsaKeyNameEdit, &QLineEdit::textChanged, this, &KuznechikWidget::onKeyNameChanged);

    QHBoxLayout *rsaButtonsLayout = new QHBoxLayout();
    AppTheme::spacing(rsaButtonsLayout, 8);
    AppTheme::margins(rsaButtonsLayout, 0, 0, 0, 0);

    m_generateRsaKeysButton = new QPushButton("Сгенерировать ключи");
    AppTheme::buttonIcon(m_generateRsaKeysButton, "key");
    m_generateRsaKeysButton->setEnabled(false);
    AppTheme::role(m_generateRsaKeysButton, "primary");
    rsaButtonsLayout->addWidget(m_generateRsaKeysButton);
    connect(m_generateRsaKeysButton, &QPushButton::clicked, this, &KuznechikWidget::onGenerateKeyPairClicked);

    m_saveRsaKeysButton = new QPushButton("Сохранить ключи");
    AppTheme::buttonIcon(m_saveRsaKeysButton, "download");
    m_saveRsaKeysButton->setEnabled(false);
    rsaButtonsLayout->addWidget(m_saveRsaKeysButton);
    connect(m_saveRsaKeysButton, &QPushButton::clicked, this, &KuznechikWidget::onSaveKeyPairClicked);

    primeLayout->addLayout(rsaButtonsLayout);

    m_keyGenerationIndicator = new QLabel("");
    m_keyGenerationIndicator->setAlignment(Qt::AlignCenter);
    m_keyGenerationIndicator->setVisible(false);
    primeLayout->addWidget(m_keyGenerationIndicator);

    m_keyGenerationProgress = new QProgressBar();
    m_keyGenerationProgress->setRange(0, 100);
    m_keyGenerationProgress->setValue(0); // Начальное значение - 0% (пустой прогресс)
    m_keyGenerationProgress->setVisible(false); // Скрыт по умолчанию, появляется только при генерации
    AppTheme::fixedHeight(m_keyGenerationProgress, 14); // Фиксированная высота для предотвращения расширения (уменьшено)
    m_keyGenerationProgress->setEnabled(false); // Изначально неактивен
    m_keyGenerationProgress->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    // Добавляем progress bar - отрицательный margin-left компенсирует padding layout
    primeLayout->addWidget(m_keyGenerationProgress);

    m_rsaStatusLabel = new QLabel();
    AppTheme::role(m_rsaStatusLabel, "muted");
    m_rsaStatusLabel->setWordWrap(true);
    primeLayout->addWidget(m_rsaStatusLabel);

    // ========== RSA КЛЮЧИ (скрыты по умолчанию) ==========
    // Метка для публичного ключа RSA
    m_publicKeyLabel = new QLabel("Публичный ключ:");
    m_publicKeyLabel->setVisible(false);
    leftPanelLayout->addWidget(m_publicKeyLabel);

    // Выпадающий список для публичного ключа RSA (MaterialComboBox)

    m_publicKeyCombo = new MaterialComboBox();
    m_publicKeyCombo->setObjectName("rsaPublicKey");
    m_publicKeyCombo->setPlaceholderText("Выберите открытый ключ");
    AppTheme::fixedHeight(m_publicKeyCombo, 40);
    m_publicKeyCombo->setVisible(false);
    leftPanelLayout->addWidget(m_publicKeyCombo);
    // Используем активацию, а не изменение индекса для предотвращения срабатывания при инициализации
    connect(m_publicKeyCombo, QOverload<int>::of(&QComboBox::activated), this, &KuznechikWidget::onPublicKeySelected);

    // Метка для приватного ключа RSA
    m_privateKeyLabel = new QLabel("Приватный ключ:");
    m_privateKeyLabel->setVisible(false);
    leftPanelLayout->addWidget(m_privateKeyLabel);

    // Выпадающий список для приватного ключа RSA (MaterialComboBox)
    m_privateKeyCombo = new MaterialComboBox();
    m_privateKeyCombo->setObjectName("rsaPrivateKey");
    m_privateKeyCombo->setPlaceholderText("Выберите закрытый ключ");
    AppTheme::fixedHeight(m_privateKeyCombo, 40);
    m_privateKeyCombo->setVisible(false);
    leftPanelLayout->addWidget(m_privateKeyCombo);
    // Используем активацию, а не изменение индекса для предотвращения срабатывания при инициализации
    connect(m_privateKeyCombo, QOverload<int>::of(&QComboBox::activated), this, &KuznechikWidget::onPrivateKeySelected);

    // Генерация простых чисел
    m_primeGeneratorGroup = new QGroupBox("Генерация простого числа");
    m_primeGeneratorGroup->setVisible(false);
    m_primeGeneratorGroup->setEnabled(false);
    QVBoxLayout *primeGenLayout = new QVBoxLayout(m_primeGeneratorGroup);
    AppTheme::spacing(primeGenLayout, 8);
    AppTheme::margins(primeGenLayout, 16, 12, 16, 12);

    QLabel *primeBitsLabel = new QLabel("Размер простого числа (бит):");
    primeGenLayout->addWidget(primeBitsLabel);

    m_primeBitsEdit = new QLineEdit("1024");
    m_primeBitsEdit->setEnabled(false);
    m_primeBitsEdit->setValidator(new QIntValidator(32, 32768, m_primeBitsEdit));
    AppTheme::role(m_primeBitsEdit, "input");
    primeGenLayout->addWidget(m_primeBitsEdit);
    connect(m_primeBitsEdit, &QLineEdit::textChanged, this, &KuznechikWidget::onPrimeBitSizeEdited);

    QHBoxLayout *primeGenButtonsLayout = new QHBoxLayout();
    AppTheme::spacing(primeGenButtonsLayout, 12);

    m_generatePrimeButton = new QPushButton("Сгенерировать простое");
    m_generatePrimeButton->setEnabled(false);
    AppTheme::role(m_generatePrimeButton, "primary");
    primeGenButtonsLayout->addWidget(m_generatePrimeButton);
    connect(m_generatePrimeButton, &QPushButton::clicked, this, &KuznechikWidget::onGeneratePrimeNumber);

    m_savePrimeButton = new QPushButton("Сохранить простое");
    AppTheme::buttonIcon(m_savePrimeButton, "download");
    m_savePrimeButton->setEnabled(false);
    primeGenButtonsLayout->addWidget(m_savePrimeButton);
    connect(m_savePrimeButton, &QPushButton::clicked, this, &KuznechikWidget::onSavePrimeNumber);

    primeGenLayout->addLayout(primeGenButtonsLayout);

    m_primeGenerationProgress = new QProgressBar();
    m_primeGenerationProgress->setRange(0, 0);
    m_primeGenerationProgress->setVisible(false);
    AppTheme::fixedHeight(m_primeGenerationProgress, 12);
    primeGenLayout->addWidget(m_primeGenerationProgress);

    m_primeGenerationStatusLabel = new QLabel("Введите значение, кратное 32 (например, 1024) и нажмите «Сгенерировать простое».");
    AppTheme::role(m_primeGenerationStatusLabel, "muted");
    m_primeGenerationStatusLabel->setWordWrap(true);
    primeGenLayout->addWidget(m_primeGenerationStatusLabel);

    leftPanelLayout->addWidget(m_primeGeneratorGroup);

    // Выбор режима шифрования (вертикально)
    QVBoxLayout *modeLayout = new QVBoxLayout();
    AppTheme::spacing(modeLayout, 8);
    AppTheme::margins(modeLayout, 0, 0, 0, 0);

    m_modeLabel = new QLabel("Режим:");
    AppTheme::role(m_modeLabel, "section");
    modeLayout->addWidget(m_modeLabel);

    m_modeGroup = new QButtonGroup(this);

    m_textModeRadio = new QRadioButton("Текст");
    m_textModeRadio->setChecked(true);
    m_modeGroup->addButton(m_textModeRadio, TextMode);

    m_hexModeRadio = new QRadioButton("Hex");
    m_modeGroup->addButton(m_hexModeRadio, HexMode);

    modeLayout->addWidget(m_textModeRadio);
    modeLayout->addWidget(m_hexModeRadio);

    leftPanelLayout->addLayout(modeLayout);
    connect(m_modeGroup, &QButtonGroup::idClicked, this, &KuznechikWidget::onModeChanged);

    // Режим для RSA (в одну строку)
    QHBoxLayout *rsaModeLayout = new QHBoxLayout();
    AppTheme::spacing(rsaModeLayout, 8);
    AppTheme::margins(rsaModeLayout, 0, 0, 0, 0);

    m_rsaModeLabel = new QLabel("Режим:");
    AppTheme::role(m_rsaModeLabel, "section");
    m_rsaModeLabel->setVisible(false);
    rsaModeLayout->addWidget(m_rsaModeLabel);

    m_rsaModeGroup = new QButtonGroup(this);

    m_rsaTextModeRadio = new QRadioButton("Текст");
    m_rsaTextModeRadio->setChecked(true);
    m_rsaTextModeRadio->setVisible(false);
    m_rsaModeGroup->addButton(m_rsaTextModeRadio, TextMode);

    m_rsaHexModeRadio = new QRadioButton("Hex");
    m_rsaHexModeRadio->setVisible(false);
    m_rsaModeGroup->addButton(m_rsaHexModeRadio, HexMode);

    rsaModeLayout->addWidget(m_rsaTextModeRadio);
    rsaModeLayout->addWidget(m_rsaHexModeRadio);
    rsaModeLayout->addStretch();

    leftPanelLayout->addLayout(rsaModeLayout);
    connect(m_rsaModeGroup, &QButtonGroup::idClicked, this, &KuznechikWidget::onModeChanged);

    // Убираем stretch для компактности
    // leftPanelLayout->addStretch();

    // Кнопки действий - создаем два контейнера (вертикальный для Кузнечика, горизонтальный для RSA)
    m_encryptDecryptVerticalContainer = new QWidget();
    m_encryptDecryptVerticalLayout = new QVBoxLayout(m_encryptDecryptVerticalContainer);
    AppTheme::spacing(m_encryptDecryptVerticalLayout, 6); // Уменьшен spacing между кнопками
    AppTheme::margins(m_encryptDecryptVerticalLayout, 0, 0, 0, 0);

    m_encryptDecryptHorizontalContainer = new QWidget();
    m_encryptDecryptHorizontalLayout = new QHBoxLayout(m_encryptDecryptHorizontalContainer);
    AppTheme::spacing(m_encryptDecryptHorizontalLayout, 6); // Уменьшен spacing между кнопками
    AppTheme::margins(m_encryptDecryptHorizontalLayout, 0, 0, 0, 0);

    // Создаем кнопки
    m_encryptButton = new QPushButton("Зашифровать");
    AppTheme::buttonIcon(m_encryptButton, "lock");
    AppTheme::role(m_encryptButton, "primary");
    m_encryptButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    m_decryptButton = new QPushButton("Расшифровать");
    AppTheme::buttonIcon(m_decryptButton, "unlock");
    m_decryptButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // Изначально кнопки активны (для Кузнечика), состояние будет обновлено при переключении алгоритма
    m_encryptButton->setEnabled(true);
    m_decryptButton->setEnabled(true);

    // Добавляем кнопки в вертикальный layout (по умолчанию для Кузнечика)
    m_encryptDecryptVerticalLayout->addWidget(m_encryptButton);
    m_encryptDecryptVerticalLayout->addWidget(m_decryptButton);

    // Добавляем оба контейнера в leftPanelLayout, но по умолчанию видим только вертикальный
    leftPanelLayout->addWidget(m_encryptDecryptVerticalContainer);
    m_encryptDecryptHorizontalContainer->setVisible(false); // Скрыт по умолчанию
    leftPanelLayout->addWidget(m_encryptDecryptHorizontalContainer);

    // Кнопка сохранения PDF (изначально не активна)
    m_savePdfButton = new QPushButton("Сохранить результат в PDF");
    AppTheme::buttonIcon(m_savePdfButton, "file");
    m_savePdfButton->setEnabled(false);
    m_savePdfButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    leftPanelLayout->addWidget(m_savePdfButton);

    m_backButton = new QPushButton("Назад");
    AppTheme::buttonIcon(m_backButton, "back");
    AppTheme::role(m_backButton, "quiet");
    m_backButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    leftPanelLayout->addWidget(m_backButton);

    // Горизонтальный layout для разделения на левую (кнопки) и правую (поля) части
    QHBoxLayout *mainContentLayout = new QHBoxLayout();
    AppTheme::spacing(mainContentLayout, 20);
    AppTheme::margins(mainContentLayout, 0, 0, 0, 0);

    // ========== ПРАВАЯ ЧАСТЬ (поля ввода и результата) ==========
    QFrame *rightPanelWidget = new QFrame();
    AppTheme::dimension(rightPanelWidget, "minimumWidth", 410);
    rightPanelWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    AppTheme::role(rightPanelWidget, "inset");
    rightPanelWidget->setContentsMargins(0, 0, 0, 0);

    QVBoxLayout *rightPanelLayout = new QVBoxLayout(rightPanelWidget);
    AppTheme::spacing(rightPanelLayout, 8);
    AppTheme::margins(rightPanelLayout, 14, 14, 14, 14);
    rightPanelLayout->addWidget(m_primeSelectionGroup);

    // Метка типа RSA под виджетом генерации ключей
    m_rsaTypeLabel = new QLabel("RSA - ");
    AppTheme::role(m_rsaTypeLabel, "muted");
    m_rsaTypeLabel->setAlignment(Qt::AlignLeft);
    m_rsaTypeLabel->setVisible(false); // Показывается только в режиме RSA
    rightPanelLayout->addWidget(m_rsaTypeLabel, 0, Qt::AlignLeft);

    // Поле ввода данных - метка
    m_inputLabel = new QLabel("Входные данные:");
    AppTheme::role(m_inputLabel, "section");
    rightPanelLayout->addWidget(m_inputLabel);

    // Поле ввода данных - текстовое поле
    m_inputTextEdit = new QTextEdit();
    m_inputTextEdit->setPlaceholderText("Введите данные для шифрования");
    m_inputTextEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    AppTheme::fixedHeight(m_inputTextEdit, 155); // Увеличена высота для удобства
    m_inputTextEdit->setLineWrapMode(QTextEdit::WidgetWidth);
    m_inputTextEdit->setWordWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
    m_inputTextEdit->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_inputTextEdit->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    rightPanelLayout->addWidget(m_inputTextEdit);

    // Поле вывода результата - метка
    m_outputLabel = new QLabel("Результат:");
    AppTheme::role(m_outputLabel, "section");
    rightPanelLayout->addWidget(m_outputLabel);

    // Поле вывода результата - текстовое поле
    m_outputTextEdit = new QTextEdit();
    m_outputTextEdit->setReadOnly(true);
    m_outputTextEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    AppTheme::fixedHeight(m_outputTextEdit, 155); // Увеличена высота для удобства
    m_outputTextEdit->setLineWrapMode(QTextEdit::WidgetWidth);
    m_outputTextEdit->setWordWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
    m_outputTextEdit->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_outputTextEdit->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_outputTextEdit->setPlaceholderText("Результат шифрования/расшифрования появится здесь");
    rightPanelLayout->addWidget(m_outputTextEdit);
    rightPanelLayout->addStretch();

    mainContentLayout->addLayout(leftPanelLayout, 4);
    mainContentLayout->addWidget(rightPanelWidget, 6);

    // Добавляем горизонтальный layout в карточку
    cardLayout->addLayout(mainContentLayout);

    AppTheme::centerBlock(mainLayout, m_card);

    // Подключаем сигналы
    connect(m_encryptButton, &QPushButton::clicked, this, &KuznechikWidget::onEncryptClicked);
    connect(m_decryptButton, &QPushButton::clicked, this, &KuznechikWidget::onDecryptClicked);
    connect(m_backButton, &QPushButton::clicked, this, &KuznechikWidget::onBackClicked);
    connect(m_savePdfButton, &QPushButton::clicked, this, &KuznechikWidget::onSavePdfClicked);

    // Подключаем сигнал изменения текста в поле ключа для обновления состояния кнопок
    if (m_keyEdit) {
        connect(m_keyEdit, &QLineEdit::textChanged, this, &KuznechikWidget::updateEncryptDecryptButtonsState);
    }
}

void KuznechikWidget::onModeChanged(int id)
{
    // Определяем высоту полей в зависимости от текущего алгоритма
    int inputHeight = (m_currentAlgorithm == RSAAlgorithm) ? 82 : 155;
    int outputHeight = (m_currentAlgorithm == RSAAlgorithm) ? 82 : 155;

    if (id == TextMode) {
        m_currentMode = TextMode;
        m_inputTextEdit->setPlaceholderText("Введите текст для шифрования (например: Hello World)");
        AppTheme::fixedHeight(m_inputTextEdit, inputHeight);
        AppTheme::fixedHeight(m_outputTextEdit, outputHeight);
    } else {
        m_currentMode = HexMode;
        m_inputTextEdit->setPlaceholderText("Форматы: 01234567, 01 23 45 67, 0x11 0x22 0x33, 01-23-45-67, 01:23:45:67");
        AppTheme::fixedHeight(m_inputTextEdit, inputHeight);
        AppTheme::fixedHeight(m_outputTextEdit, outputHeight);
    }
    m_outputTextEdit->clear();
}

void KuznechikWidget::onAlgorithmChanged(int id)
{
    if (id == m_currentAlgorithm || (m_encryptDecryptWatcher && m_encryptDecryptWatcher->isRunning())) return;
    m_currentAlgorithm = static_cast<AlgorithmType>(id);
    const bool rsa = m_currentAlgorithm == RSAAlgorithm;
    m_algorithmSwitch->select(id);
    m_savedRsaGroup->setVisible(rsa);
    m_kuznechikKeys->setVisible(!rsa);

    if (id == KuznechikAlgorithm) {
        // Обновляем заголовок для Кузнечик
        m_titleLabel->setText("Шифрование Кузнечик");
        m_subtitleLabel->setText("Алгоритм шифрования ГОСТ Р 34.12-2015");

        // Скрываем элементы для RSA
        m_publicKeyLabel->setVisible(false);
        m_publicKeyCombo->setVisible(false);
        m_privateKeyLabel->setVisible(false);
        m_privateKeyCombo->setVisible(false);
        m_rsaModeLabel->setVisible(false);
        m_rsaTextModeRadio->setVisible(false);
        m_rsaHexModeRadio->setVisible(false);
        if (m_primeSelectionGroup) {
            m_primeSelectionGroup->setVisible(false);
        }
        if (m_primeGeneratorGroup) {
            m_primeGeneratorGroup->setVisible(false);
            m_primeGeneratorGroup->setEnabled(false);
        }
        if (m_generateRsaKeysButton) {
            m_generateRsaKeysButton->setEnabled(false);
        }
        if (m_saveRsaKeysButton) {
            m_saveRsaKeysButton->setEnabled(false);
        }
        if (m_rsaStatusLabel) {
            m_rsaStatusLabel->clear();
        }
        if (m_rsaTypeLabel) {
            m_rsaTypeLabel->setVisible(false); // Скрываем тип RSA для Кузнечика
        }

        // Показываем элементы для Кузнечик
        m_modeLabel->setVisible(true);
        m_modeGroup->button(HexMode)->setVisible(true);
        m_modeGroup->button(TextMode)->setVisible(true);
        m_keyLabel->setVisible(true);
        m_keyEdit->setVisible(true);
        m_generateKeyButton->setVisible(true);
        if (m_primeBitsEdit) {
            m_primeBitsEdit->setEnabled(false);
        }
        if (m_generatePrimeButton) {
            m_generatePrimeButton->setEnabled(false);
        }
        if (m_savePrimeButton) {
            m_savePrimeButton->setEnabled(false);
        }

        // Переключаем layout кнопок: для Кузнечика - вертикальный
        if (m_encryptDecryptVerticalContainer && m_encryptDecryptHorizontalContainer) {
            m_encryptDecryptVerticalContainer->setVisible(true);
            m_encryptDecryptHorizontalContainer->setVisible(false);

            // Удаляем кнопки из горизонтального layout
            m_encryptDecryptHorizontalLayout->removeWidget(m_encryptButton);
            m_encryptDecryptHorizontalLayout->removeWidget(m_decryptButton);

            // Добавляем кнопки в вертикальный layout (если их там еще нет)
            if (m_encryptDecryptVerticalLayout->indexOf(m_encryptButton) < 0) {
                m_encryptDecryptVerticalLayout->addWidget(m_encryptButton);
            }
            if (m_encryptDecryptVerticalLayout->indexOf(m_decryptButton) < 0) {
                m_encryptDecryptVerticalLayout->addWidget(m_decryptButton);
            }
        }

        // Обновляем метку для ключа
        m_keyLabel->setText("Ключ (64 hex символа, 32 байта):");
        m_keyEdit->setPlaceholderText("Форматы: 01234567..., 01 23 45..., 0x11 0x22..., 01-23-45..., 01:23:45...");

        // Для Кузнечика - увеличиваем размеры карточки
        if (m_card) {
            QVBoxLayout *cardLayout = qobject_cast<QVBoxLayout*>(m_card->layout());
            if (cardLayout) {
                AppTheme::margins(cardLayout, 20, 20, 20, 20); // Еще больше увеличенные отступы для Кузнечика
                AppTheme::spacing(cardLayout, 14); // Еще больше увеличенный spacing для Кузнечика
            }
        }

        // Для Кузнечика - нормальная высота полей
        AppTheme::fixedHeight(m_inputTextEdit, 155); // Увеличена высота для удобства
        AppTheme::fixedHeight(m_outputTextEdit, 155); // Увеличена высота для удобства

        // Вызываем onModeChanged чтобы обновить поля согласно текущему режиму
        if (m_modeGroup) {
            onModeChanged(m_modeGroup->checkedId());
        }

        // Обновляем состояние кнопок шифрования/расшифрования
        updateEncryptDecryptButtonsState();
    } else {
        // Обновляем заголовок для RSA
        m_titleLabel->setText("Шифрование RSA");
        m_subtitleLabel->setText("Шифрование RSA с ключами до 65 536 бит");

        // Скрываем элементы для Кузнечик
        m_modeLabel->setVisible(false);
        m_modeGroup->button(HexMode)->setVisible(false);
        m_modeGroup->button(TextMode)->setVisible(false);
        m_keyLabel->setVisible(false);
        m_keyEdit->setVisible(false);
        m_generateKeyButton->setVisible(false);

        // Показываем элементы для RSA
        m_publicKeyLabel->setVisible(true);
        m_publicKeyCombo->setVisible(true);
        m_privateKeyLabel->setVisible(true);
        m_privateKeyCombo->setVisible(true);
        // Показываем режим для RSA (в одну строку)
        m_rsaModeLabel->setVisible(true);
        m_rsaTextModeRadio->setVisible(true);
        m_rsaHexModeRadio->setVisible(true);
        if (m_primeSelectionGroup) {
            m_primeSelectionGroup->setVisible(true);
        }
        if (m_primeGeneratorGroup) {
            m_primeGeneratorGroup->setVisible(true);
        }
        if (m_rsaTypeLabel) {
            m_rsaTypeLabel->setVisible(true); // Показываем тип RSA для RSA режима
        }
        refreshPrimeSelections();
        prepareDefaultPrimes();

        // Загружаем ключи из папки
        loadRSAKeysFromDirectory();

        // Обновляем тип RSA после загрузки ключей
        updateRsaTypeLabel();

        // Обновляем состояние кнопок шифрования/расшифрования
        updateEncryptDecryptButtonsState();

        // Переключаем layout кнопок: для RSA - горизонтальный
        if (m_encryptDecryptHorizontalContainer && m_encryptDecryptVerticalContainer) {
            m_encryptDecryptHorizontalContainer->setVisible(true);
            m_encryptDecryptVerticalContainer->setVisible(false);

            // Удаляем кнопки из вертикального layout
            m_encryptDecryptVerticalLayout->removeWidget(m_encryptButton);
            m_encryptDecryptVerticalLayout->removeWidget(m_decryptButton);

            // Добавляем кнопки в горизонтальный layout (если их там еще нет)
            if (m_encryptDecryptHorizontalLayout->indexOf(m_encryptButton) < 0) {
                m_encryptDecryptHorizontalLayout->addWidget(m_encryptButton);
            }
            if (m_encryptDecryptHorizontalLayout->indexOf(m_decryptButton) < 0) {
                m_encryptDecryptHorizontalLayout->addWidget(m_decryptButton);
            }
        }

        // Для RSA - уменьшаем размеры карточки
        if (m_card) {
            QVBoxLayout *cardLayout = qobject_cast<QVBoxLayout*>(m_card->layout());
            if (cardLayout) {
                AppTheme::margins(cardLayout, 20, 25, 20, 25); // Уменьшенные отступы для RSA
                AppTheme::spacing(cardLayout, 15); // Уменьшенный spacing для RSA
            }
        }

        // Для RSA - уменьшенная высота полей
        AppTheme::fixedHeight(m_inputTextEdit, 82);
        AppTheme::fixedHeight(m_outputTextEdit, 82);
    }

    m_outputTextEdit->clear();
    m_savePdfButton->setEnabled(false);
    updateEncryptDecryptButtonsState();
}

void KuznechikWidget::setUserId(int userId)
{
    if (m_userId == userId) return;
    if (m_cancelRsa) m_cancelRsa->store(true);
    m_userId = userId;
    m_primesDirectory.clear();
    m_generatedKeySize = 0;
    m_lastOperation = OpNone;
    m_lastKey.clear();
    m_lastInput.clear();
    m_lastOutput.clear();
    m_inputTextEdit->clear();
    m_outputTextEdit->clear();
    m_keyEdit->clear();
    m_savedRsaStatus->clear();
    m_rsaStatusLabel->clear();
    m_publicKeyCombo->setCurrentIndex(-1);
    m_privateKeyCombo->setCurrentIndex(-1);
    m_savePdfButton->setEnabled(false);
    loadKuznechikKeys();
    refreshPrimeSelections();
    if (m_currentAlgorithm == RSAAlgorithm) {
        loadRSAKeysFromDirectory();
        prepareDefaultPrimes();
    }
}

QString KuznechikWidget::managedKeyDirectory(const QString &algorithm) const
{
    if (m_userId <= 0) return {};
    return QDir(resolveRsaKeysDirectory()).filePath(QString("user-%1/%2").arg(m_userId).arg(algorithm));
}

void KuznechikWidget::loadKuznechikKeys()
{
    const QSignalBlocker blocker(m_kuznechikKeys);
    m_kuznechikKeys->clear();
    const QString directory = managedKeyDirectory("kuznechik");
    if (directory.isEmpty()) return;
    const auto files = QDir(directory).entryInfoList({"*.key"}, QDir::Files | QDir::NoSymLinks, QDir::Name | QDir::Reversed);
    for (const auto &file : files) m_kuznechikKeys->addItem(file.completeBaseName(), file.absoluteFilePath());
    if (!files.isEmpty()) {
        m_kuznechikKeys->setCurrentIndex(0);
        selectKuznechikKey(0);
    }
}

void KuznechikWidget::selectKuznechikKey(int index)
{
    if (index < 0) return;
    QFile file(m_kuznechikKeys->itemData(index).toString());
    if (!file.open(QIODevice::ReadOnly)) {
        AppMessage::warning(this, "Ключ недоступен", "Не удалось открыть сохранённый ключ.");
        return;
    }
    const auto key = file.read(128).trimmed();
    static const QRegularExpression format("\\A[0-9a-fA-F]{64}\\z");
    if (!file.atEnd() || !format.match(QString::fromLatin1(key)).hasMatch()) {
        AppMessage::warning(this, "Ключ недоступен", "Сохранённый ключ должен содержать 64 шестнадцатеричных символа.");
        return;
    }
    m_keyEdit->setText(QString::fromLatin1(key));
}

void KuznechikWidget::onGenerateKeyClicked()
{
    if (m_currentAlgorithm != KuznechikAlgorithm) {
        return;
    }

    const QString directory = managedKeyDirectory("kuznechik");
    const QString path = QDir(directory).filePath(keyFileStem("Kuznechik") + ".key");
    const auto key = m_cryptoFacade->generateKuznechikKey();
    if (directory.isEmpty() || key.size() != 32 || !QDir().mkpath(directory) || !writeKeyFile(path, key.toHex() + '\n')) {
        AppMessage::warning(this, "Ключ не сохранён", "Не удалось записать ключ в библиотеку аккаунта.");
        return;
    }
    loadKuznechikKeys();
    const int index = m_kuznechikKeys->findData(path);
    if (index >= 0 && index != m_kuznechikKeys->currentIndex()) {
        m_kuznechikKeys->setCurrentIndex(index);
        selectKuznechikKey(index);
    }
}

void KuznechikWidget::createSavedRsaPair()
{
    if (m_cancelRsa) {
        m_cancelRsa->store(true);
        m_createRsaPair->setEnabled(false);
        m_savedRsaStatus->setText("Отмена генерации…");
        return;
    }
    ensureKeyGenerationWatcher();
    if (m_keyGenerationWatcher->isRunning() || m_primeGenerationActive ||
        (m_keySaveWatcher && m_keySaveWatcher->isRunning())) return;
    const QString directory = managedKeyDirectory("rsa");
    if (directory.isEmpty() || !QDir().mkpath(directory)) {
        m_savedRsaStatus->setText("Не удалось открыть библиотеку ключей аккаунта.");
        return;
    }
    const int bits = m_rsaKeyBits->currentData().toInt();
    const int owner = m_userId;
    const QString name = keyFileStem(QString("RSA-%1").arg(bits));
    m_cancelRsa = std::make_shared<std::atomic_bool>(false);
    m_savedRsaStatus->setText(bits == maxRsaBits
        ? "Ищем два простых числа по 32 768 бит. Это может занять значительное время."
        : "Генерация пары RSA…");
    auto generate = [directory, name, bits, owner, cancel = m_cancelRsa]() -> QVariantMap {
        QVariantMap result{{"quick", true}, {"owner", owner}, {"keySize", bits}};
        try {
            auto first = std::async(std::launch::async, [bits, cancel] { return generateRsaPrime(bits / 2, *cancel); });
            BigInt second;
            try {
                second = generateRsaPrime(bits / 2, *cancel);
            } catch (...) {
                const bool cancelled = cancel->exchange(true);
                result.insert("message", cancelled ? "Генерация отменена." : "Не удалось сгенерировать простое число.");
                return result;
            }
            auto p = first.get();
            while (p == second && !cancel->load()) second = generateRsaPrime(bits / 2, *cancel);
            RSAKeyManager keys;
            if (!cancel->load() && keys.generateRSAKeyPair(p, second, bits) && keys.getPublicKey().first.bitLength() == bits) {
                result.insert("savedPublicKey", saveRsaPair(keys, directory, name));
                if (result.value("savedPublicKey").toString().isEmpty()) result.insert("message", "Не удалось сохранить пару RSA.");
                return result;
            }
        } catch (const std::exception &) {
            // The worker reports failure through the status label without exposing key material.
        }
        result.insert("message", cancel->load() ? "Генерация отменена." : "Не удалось сгенерировать пару RSA.");
        return result;
    };
    m_keyGenerationWatcher->setFuture(QtConcurrent::run(generate));
    updatePrimeControlsState();
}

void KuznechikWidget::generateRSAKeys()
{
    onGenerateKeyPairClicked();
}

void KuznechikWidget::ensureKeyGenerationWatcher()
{
    if (m_keyGenerationWatcher) {
        return;
    }

    m_keyGenerationWatcher = new QFutureWatcher<QVariantMap>(this);
    connect(m_keyGenerationWatcher, &QFutureWatcher<QVariantMap>::finished,
            this, &KuznechikWidget::onKeyGenerationFinished);
}

void KuznechikWidget::ensureKeySaveWatcher()
{
    if (m_keySaveWatcher) {
        return;
    }

    m_keySaveWatcher = new QFutureWatcher<QVariantMap>(this);
    connect(m_keySaveWatcher, &QFutureWatcher<QVariantMap>::finished,
            this, &KuznechikWidget::onKeySaveFinished);
}

void KuznechikWidget::ensurePrimeGenerationWatcher()
{
    if (m_primeGenerationWatcher) {
        return;
    }

    m_primeGenerationWatcher = new QFutureWatcher<QVariantMap>(this);
    connect(m_primeGenerationWatcher, &QFutureWatcher<QVariantMap>::finished,
            this, &KuznechikWidget::onPrimeGenerationFinished);
}

void KuznechikWidget::ensureEncryptDecryptWatcher()
{
    if (m_encryptDecryptWatcher) {
        return;
    }

    m_encryptDecryptWatcher = new QFutureWatcher<QVariantMap>(this);
    connect(m_encryptDecryptWatcher, &QFutureWatcher<QVariantMap>::finished,
            this, &KuznechikWidget::onEncryptDecryptFinished);
}

QString KuznechikWidget::resolveProjectRoot() const
{
    QDir projectDir(QCoreApplication::applicationDirPath());

    if (projectDir.absolutePath().contains("/Contents/MacOS")) {
        projectDir.cd("../../../../");
        return projectDir.absolutePath();
    }

    // Поднимаемся вверх, пока не найдем CMakeLists.txt
    QDir probe = projectDir;
    while (!probe.isRoot()) {
        if (probe.exists("CMakeLists.txt")) {
            return probe.absolutePath();
        }
        probe.cdUp();
    }

    return projectDir.absolutePath();
}

QString KuznechikWidget::resolveRsaKeysDirectory() const
{
    return QDir(resolveProjectRoot()).absoluteFilePath("rsa_keys");
}

QString KuznechikWidget::resolveDefaultPrimesDirectory() const
{
    if (!m_primesDirectory.isEmpty()) {
        return m_primesDirectory;
    }

    QString subdirectory = "generated_primes";
    if (m_userId > 0) subdirectory += QString("/user-%1").arg(m_userId);
    const QString primesPath = QDir(resolveProjectRoot()).absoluteFilePath(subdirectory);
    if (QDir().mkpath(primesPath)) return primesPath;

    QString docs = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (docs.isEmpty()) {
        docs = QDir::homePath();
    }
    const QString fallback = QDir(docs).absoluteFilePath(subdirectory);
    return QDir().mkpath(fallback) ? fallback : QString{};
}

void KuznechikWidget::prepareDefaultPrimes()
{
    if (m_userId <= 0 || !m_primesDirectory.isEmpty() || m_defaultPrimesWatcher) return;

    const auto directory = resolveDefaultPrimesDirectory();
    if (directory.isEmpty()) {
        m_primesStatusLabel->setText("Выберите папку, доступную для записи.");
        return;
    }

    const int userId = m_userId;
    auto *watcher = new QFutureWatcher<bool>(this);
    m_defaultPrimesWatcher = watcher;
    m_selectPrimesDirButton->setEnabled(false);
    m_primesStatusLabel->setText("Подготовка простых чисел для RSA…");
    connect(watcher, &QFutureWatcher<bool>::finished, this, [this, watcher, userId, directory] {
        const bool ready = watcher->result();
        m_defaultPrimesWatcher = nullptr;
        watcher->deleteLater();
        m_selectPrimesDirButton->setEnabled(true);
        if (m_userId != userId) {
            refreshPrimeSelections();
            if (m_currentAlgorithm == RSAAlgorithm) prepareDefaultPrimes();
            return;
        }
        if (ready) {
            m_primesDirectory = directory;
            refreshPrimeSelections();
        } else {
            m_primesStatusLabel->setText("Не удалось подготовить простые числа. Выберите папку вручную.");
        }
    });
    watcher->setFuture(QtConcurrent::run(writeDefaultPrimes, directory));
}

QVariantMap KuznechikWidget::makePrimeData(const QFileInfo &info) const
{
    QVariantMap data;
    QRegularExpression rx("^(.*)_(\\d+)\\.txt$", QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatch match = rx.match(info.fileName());
    if (!match.hasMatch()) {
        return data;
    }

    data.insert("base", match.captured(1));
    data.insert("bits", match.captured(2).toInt());
    data.insert("path", info.absoluteFilePath());
    return data;
}

void KuznechikWidget::refreshPrimeSelections()
{
    if (!m_primeFirstCombo || !m_primeSecondCombo) {
        return;
    }

    if (m_primesDirectory.isEmpty()) {
        m_primeFirstCombo->clear();
        m_primeFirstCombo->setEnabled(false);
        m_primeSecondCombo->clear();
        m_primeSecondCombo->setEnabled(false);
        if (m_rsaKeyNameEdit) {
            m_rsaKeyNameEdit->setEnabled(false);
        }
        // Группа остается активной, но элементы внутри неактивны
        updatePrimeControlsState();
        return;
    }

    QDir dir(m_primesDirectory);
    if (!dir.exists()) {
        QDir().mkpath(m_primesDirectory);
    }

    QFileInfoList files = dir.entryInfoList(QStringList() << "*.txt", QDir::Files, QDir::Name);

    // Проверяем, не пуста ли папка, и обновляем подсказку
    if (files.isEmpty() && m_primesStatusLabel) {
        m_primesStatusLabel->setText("Папка пуста. Сгенерируйте или импортируйте простые числа.");
    }

    QVector<QVariantMap> entries;
    entries.reserve(files.size());
    for (const QFileInfo &info : files) {
        QVariantMap data = makePrimeData(info);
        if (data.isEmpty()) {
            continue;
        }
        entries.append(data);
    }

    // Сортируем по битности (по возрастанию) - одинаково для обоих списков
    // Сначала по битности, потом по имени
    std::sort(entries.begin(), entries.end(), [](const QVariantMap &a, const QVariantMap &b) {
        int bitsA = a.value("bits").toInt();
        int bitsB = b.value("bits").toInt();
        if (bitsA != bitsB) {
            return bitsA < bitsB; // Сначала по возрастанию битности
        }
        // Если битность одинаковая, сортируем по имени
        return a.value("base").toString() < b.value("base").toString();
    });

    // Функция для заполнения списка - одинаковая для обоих списков
    auto populate = [&](MaterialComboBox *combo) {
        combo->clear();
        for (const QVariantMap &data : entries) {
            QString label = QString("%1 (%2 бит)")
                                .arg(data.value("base").toString())
                                .arg(data.value("bits").toInt());
            combo->addItem(label, data);
        }
        combo->setCurrentIndex(-1);
        const bool enabled = !m_primesDirectory.isEmpty() && combo->count() > 0;
        combo->setEnabled(enabled);
    };

    // Заполняем оба списка одинаково отсортированными данными
    populate(m_primeFirstCombo);
    populate(m_primeSecondCombo);

    // Обновляем подсказку в зависимости от состояния
    if (m_primesStatusLabel) {
        if (entries.isEmpty()) {
            m_primesStatusLabel->setText("В папке не найдено простых чисел. Сгенерируйте или импортируйте их.");
        } else {
            m_primesStatusLabel->setText("Выберите два различных простых числа одинакового размера.");
        }
    }

    updatePrimeControlsState();
}

void KuznechikWidget::updatePrimeGeneratorWidgets(bool primeGenerating)
{
    const bool inRsaMode = (m_currentAlgorithm == RSAAlgorithm);
    const QString bitsText = m_primeBitsEdit ? m_primeBitsEdit->text().trimmed() : QString();
    const bool hasBits = !bitsText.isEmpty();
    const bool bitsValid = isPrimeBitSizeValid();
    const bool hasResult = !m_generatedPrimeDecimal.isEmpty();

    if (m_primeGeneratorGroup) {
        m_primeGeneratorGroup->setEnabled(inRsaMode);
    }

    if (m_primeBitsEdit) {
        const bool enableBits = inRsaMode && !primeGenerating;
        m_primeBitsEdit->setEnabled(enableBits);
    }

    if (m_generatePrimeButton) {
        const bool enableGenerate = inRsaMode && !primeGenerating && hasBits;
        m_generatePrimeButton->setEnabled(enableGenerate);
        m_generatePrimeButton->setText(primeGenerating ? "Генерация..." : "Сгенерировать простое");
    }

    if (m_savePrimeButton) {
        const bool enableSave = inRsaMode && !primeGenerating && hasResult;
        m_savePrimeButton->setEnabled(enableSave);
    }

    if (m_primeGenerationProgress) {
        if (primeGenerating) {
            m_primeGenerationProgress->setRange(0, 0);
            m_primeGenerationProgress->setVisible(true);
            m_primeGenerationProgress->setEnabled(true);
        } else {
            m_primeGenerationProgress->setRange(0, 100);
            m_primeGenerationProgress->setValue(0);
            m_primeGenerationProgress->setEnabled(false);
            m_primeGenerationProgress->setVisible(false); // Скрываем после завершения генерации
        }
    }

    if (!m_primeGenerationStatusLabel) {
        return;
    }

    if (!inRsaMode) {
        m_primeGenerationStatusLabel->clear();
        return;
    }

    if (primeGenerating) {
        m_primeGenerationStatusLabel->setText("Генерация простого числа выполняется...");
        return;
    }

    if (!hasResult && hasBits && !bitsValid) {
        m_primeGenerationStatusLabel->setText("Размер должен быть кратен 32 и находиться в диапазоне 32–32768.");
    } else if (!hasResult && hasBits) {
        m_primeGenerationStatusLabel->setText("Нажмите «Сгенерировать простое», чтобы запустить генерацию.");
    } else if (!hasResult) {
        m_primeGenerationStatusLabel->setText("Введите значение, кратное 32 (например, 1024) и нажмите «Сгенерировать простое».");
    } else {
        m_primeGenerationStatusLabel->setText(
            QString("Простое число на %1 бит сгенерировано. Сохраните его файл.")
                .arg(m_generatedPrimeBits));
    }
}

void KuznechikWidget::setPrimeBitsFieldState(bool valid)
{
    if (!m_primeBitsEdit) {
        return;
    }

    if (valid || m_primeBitsEdit->text().trimmed().isEmpty()) {
        AppTheme::role(m_primeBitsEdit, "input");
    } else {
        AppTheme::role(m_primeBitsEdit, "invalid");
    }
    // Информационное сообщение теперь в m_primeGenerationStatusLabel, обновляется через updatePrimeGeneratorWidgets
}

bool KuznechikWidget::isPrimeBitSizeValid() const
{
    if (!m_primeBitsEdit) {
        return false;
    }

    bool ok = false;
    const int bits = m_primeBitsEdit->text().trimmed().toInt(&ok);
    if (!ok) {
        return false;
    }

    if (bits < 32 || bits > 32768) {
        return false;
    }

    return bits % 32 == 0;
}

void KuznechikWidget::resetPrimeGenerationState()
{
    m_generatedPrimeDecimal.clear();
    m_generatedPrimeHex.clear();
    m_generatedPrimeBits = 0;
    if (m_primeGenerationProgress) {
        m_primeGenerationProgress->setRange(0, 100);
        m_primeGenerationProgress->setValue(0);
        m_primeGenerationProgress->setEnabled(false);
        m_primeGenerationProgress->setVisible(false);
    }

}

QVariantMap KuznechikWidget::currentPrimeData(MaterialComboBox *combo) const
{
    if (!combo || combo->currentIndex() < 0) {
        return QVariantMap();
    }
    return combo->currentData().toMap();
}

bool KuznechikWidget::loadPrimeFromPath(const QString &path, BigInt &prime, QString &errorMessage) const
{
    return readPrimeFromFile(path, prime, errorMessage);
}

void KuznechikWidget::updatePrimeControlsState()
{
    if (!m_primeFirstCombo || !m_primeSecondCombo) {
        return;
    }

    const bool keyGenerating = m_keyGenerationWatcher && m_keyGenerationWatcher->isRunning();
    const bool primeGenerating = m_primeGenerationActive ||
                                 (m_primeGenerationWatcher && m_primeGenerationWatcher->isRunning());
    const bool keySaving = m_keySaveWatcher && m_keySaveWatcher->isRunning();
    const bool busy = keyGenerating || primeGenerating || keySaving;
    const bool hasDirectory = !m_primesDirectory.isEmpty();

    updatePrimeGeneratorWidgets(primeGenerating);
    m_rsaKeyBits->setEnabled(!busy);
    m_createRsaPair->setText(m_cancelRsa ? "Отменить генерацию" : "Создать и сохранить пару");
    m_createRsaPair->setEnabled(m_cancelRsa ? !m_cancelRsa->load() : (m_userId > 0 && !busy));

    // Группа всегда активна, но элементы внутри могут быть неактивны
    if (m_primeSelectionGroup) {
        m_primeSelectionGroup->setEnabled(true);
    }

    // Если папка не выбрана - делаем все неактивным и серым
    if (!hasDirectory) {
        if (m_primeFirstCombo) {
            m_primeFirstCombo->setEnabled(false);
        }
        if (m_primeSecondCombo) {
            m_primeSecondCombo->setEnabled(false);
        }
        if (m_rsaKeyNameEdit) {
            m_rsaKeyNameEdit->setEnabled(false);
        }
        if (m_generateRsaKeysButton) {
            m_generateRsaKeysButton->setEnabled(false);
        }
        if (m_saveRsaKeysButton) {
            m_saveRsaKeysButton->setEnabled(false);
        }
        if (m_primesStatusLabel) {
            m_primesStatusLabel->setText(m_defaultPrimesWatcher
                ? "Подготовка простых чисел для RSA…" : "Сначала выберите папку с простыми числами.");
        }
        return;
    }

    // Если папка выбрана, активируем элементы в зависимости от состояния
    if (!busy) {
        // Активируем списки только если в них есть элементы И папка выбрана
        bool hasItems1 = m_primeFirstCombo && m_primeFirstCombo->count() > 0;
        bool hasItems2 = m_primeSecondCombo && m_primeSecondCombo->count() > 0;
        bool shouldEnable1 = hasDirectory && hasItems1;
        bool shouldEnable2 = hasDirectory && hasItems2;

        if (m_primeFirstCombo) {
            m_primeFirstCombo->setEnabled(shouldEnable1);
        }
        if (m_primeSecondCombo) {
            m_primeSecondCombo->setEnabled(shouldEnable2);
        }
        if (m_rsaKeyNameEdit) {
            m_rsaKeyNameEdit->setEnabled(hasDirectory);
        }
    } else {
        // Во время генерации блокируем все
        if (m_primeFirstCombo) {
            m_primeFirstCombo->setEnabled(false);
        }
        if (m_primeSecondCombo) {
            m_primeSecondCombo->setEnabled(false);
        }
        if (m_rsaKeyNameEdit) {
            m_rsaKeyNameEdit->setEnabled(false);
        }
    }

    const QVariantMap prime1 = currentPrimeData(m_primeFirstCombo);
    const QVariantMap prime2 = currentPrimeData(m_primeSecondCombo);
    const QString keyName = m_rsaKeyNameEdit ? m_rsaKeyNameEdit->text().trimmed() : QString();

    bool primesSelected = !prime1.isEmpty() && !prime2.isEmpty();
    bool samePrime = primesSelected && prime1.value("path").toString() == prime2.value("path").toString();
    bool sameSize = primesSelected && prime1.value("bits").toInt() == prime2.value("bits").toInt();

    if (busy) {
        if (m_primesStatusLabel) {
            if (keyGenerating) {
                m_primesStatusLabel->setText("Идёт генерация RSA ключей...");
            } else {
                m_primesStatusLabel->setText("Идёт генерация простого числа...");
            }
        }
    } else if (!primesSelected) {
        if (m_primesStatusLabel) {
            // Проверяем, есть ли элементы в списках
            bool hasItems = (m_primeFirstCombo && m_primeFirstCombo->count() > 0) ||
                           (m_primeSecondCombo && m_primeSecondCombo->count() > 0);
            if (hasItems) {
                m_primesStatusLabel->setText("Выберите два различных простых числа одинакового размера.");
            } else {
                m_primesStatusLabel->setText("Папка пуста. Сгенерируйте или импортируйте простые числа.");
            }
        }
    } else if (samePrime) {
        if (m_primesStatusLabel) {
            m_primesStatusLabel->setText("Простые числа не должны совпадать.");
        }
    } else if (!sameSize) {
        if (m_primesStatusLabel) {
            m_primesStatusLabel->setText("Размеры выбранных простых чисел различаются.");
        }
    } else if (keyName.isEmpty()) {
        if (m_primesStatusLabel) {
            m_primesStatusLabel->setText("Введите имя для ключей.");
        }
    } else if (m_primesStatusLabel) {
        m_primesStatusLabel->setText("Нажмите «Сгенерировать ключи», чтобы создать пару RSA.");
    }

    bool ready = !busy && primesSelected && !samePrime && sameSize && !keyName.isEmpty();
    if (m_generateRsaKeysButton) {
        m_generateRsaKeysButton->setEnabled(ready);
    }

    if (!busy && m_keyGenerationProgress) {
        // Останавливаем прогресс и скрываем виджет
        m_keyGenerationProgress->setRange(0, 100);
        m_keyGenerationProgress->setValue(0); // Устанавливаем в 0% - без анимации
        m_keyGenerationProgress->setEnabled(false);
        m_keyGenerationProgress->setVisible(false); // Скрываем когда не генерируем
    }

    if (!busy && m_keyGenerationIndicator) {
        m_keyGenerationIndicator->setVisible(false);
    }
}

void KuznechikWidget::onSelectPrimesDirectory()
{
    qDebug() << "onSelectPrimesDirectory: слот вызван";

    if (m_defaultPrimesWatcher) return;
    if (!m_selectPrimesDirButton) {
        qDebug() << "onSelectPrimesDirectory: кнопка не инициализирована";
        return;
    }

    QString startDir = m_primesDirectory.isEmpty() ? resolveDefaultPrimesDirectory() : m_primesDirectory;

    // Проверяем, что начальная директория существует, иначе используем домашнюю
    QDir checkDir(startDir);
    if (!checkDir.exists()) {
        startDir = QDir::homePath();
    }

    qDebug() << "onSelectPrimesDirectory: открываем диалог, начальная директория:" << startDir;

    // Убеждаемся, что окно активно (как в onSavePdfClicked)
    if (QWidget *w = window()) {
        w->raise();
        w->activateWindow();
    }

    QFileDialog dialog(this, "Выберите папку с простыми числами", startDir);
    dialog.setFileMode(QFileDialog::Directory);
    dialog.setOption(QFileDialog::ShowDirsOnly, true);
    dialog.setOption(QFileDialog::DontResolveSymlinks, true);
    dialog.setWindowModality(Qt::ApplicationModal);
    dialog.setDirectory(startDir);

    qDebug() << "onSelectPrimesDirectory: запускаем диалог exec()";

    QString dir;
    if (dialog.exec() == QDialog::Accepted) {
        QStringList selectedDirs = dialog.selectedFiles();
        if (!selectedDirs.isEmpty()) {
            dir = selectedDirs.first();
        }
    }

    qDebug() << "onSelectPrimesDirectory: выбранная директория:" << dir;

    if (dir.isEmpty()) {
        qDebug() << "onSelectPrimesDirectory: пользователь отменил выбор";
        return;
    }

    m_primesDirectory = dir;
    qDebug() << "onSelectPrimesDirectory: установлена директория" << m_primesDirectory;
    refreshPrimeSelections();
    updatePrimeControlsState();
}

void KuznechikWidget::onPrimeSelectionChanged()
{
    QVariantMap prime1 = currentPrimeData(m_primeFirstCombo);
    QVariantMap prime2 = currentPrimeData(m_primeSecondCombo);

    m_selectedPrimePath1 = prime1.value("path").toString();
    m_selectedPrimeBits1 = prime1.value("bits").toInt();
    m_selectedPrimePath2 = prime2.value("path").toString();
    m_selectedPrimeBits2 = prime2.value("bits").toInt();

    updatePrimeControlsState();
}

void KuznechikWidget::onPrimeBitSizeEdited(const QString &text)
{
    Q_UNUSED(text)

    if (!m_primeBitsEdit) {
        return;
    }

    setPrimeBitsFieldState(true);

    const bool primeGenerating = m_primeGenerationActive ||
                                 (m_primeGenerationWatcher && m_primeGenerationWatcher->isRunning());

    const QString trimmed = m_primeBitsEdit->text().trimmed();
    bool ok = false;
    const int bits = trimmed.toInt(&ok);

    if (!primeGenerating) {
        const bool hasPrime = !m_generatedPrimeDecimal.isEmpty();
        if (hasPrime) {
            const bool matchesStored = ok && bits == m_generatedPrimeBits;
            if (!matchesStored || trimmed.isEmpty()) {
                resetPrimeGenerationState();
            }
        }
    }

    updatePrimeControlsState();
}

void KuznechikWidget::onGeneratePrimeNumber()
{
    if (!m_primeBitsEdit) {
        return;
    }

    ensurePrimeGenerationWatcher();
    if (m_primeGenerationWatcher->isRunning()) {
        return;
    }

    if (!isPrimeBitSizeValid()) {
        setPrimeBitsFieldState(false);
        if (m_primeGenerationStatusLabel) {
            m_primeGenerationStatusLabel->setText("Размер должен быть кратен 32 и находиться в диапазоне 32–32768.");
        }
        return;
    }

    bool ok = false;
    const int bits = m_primeBitsEdit->text().trimmed().toInt(&ok);
    if (!ok) {
        setPrimeBitsFieldState(false);
        if (m_primeGenerationStatusLabel) {
            m_primeGenerationStatusLabel->setText("Введите корректное значение размера простого числа.");
        }
        return;
    }

    m_primeGenerationActive = true;
    resetPrimeGenerationState();
    setPrimeBitsFieldState(true);

    if (m_primeGenerationStatusLabel) {
        m_primeGenerationStatusLabel->setText("Генерация простого числа запущена...");
    }

    updatePrimeGeneratorWidgets(true);

    auto task = [bits]() -> QVariantMap {
        QVariantMap result;
        result.insert("success", false);

        try {
            struct BNDeleter {
                void operator()(BIGNUM *bn) const { BN_free(bn); }
            };
            struct StrDeleter {
                void operator()(char *ptr) const { OPENSSL_free(ptr); }
            };

            std::unique_ptr<BIGNUM, BNDeleter> prime(BN_new());
            if (!prime) {
                result.insert("message", "Не удалось выделить память для генерации числа (BN_new).");
                return result;
            }

            if (BN_generate_prime_ex(prime.get(), bits, 0, nullptr, nullptr, nullptr) != 1) {
                result.insert("message", "OpenSSL не смог сгенерировать простое число.");
                return result;
            }

            std::unique_ptr<char, StrDeleter> decStr(BN_bn2dec(prime.get()));
            std::unique_ptr<char, StrDeleter> hexStr(BN_bn2hex(prime.get()));
            if (!decStr || !hexStr) {
                result.insert("message", "Не удалось преобразовать простое число в строку.");
                return result;
            }

            result.insert("success", true);
            result.insert("bits", bits);
            result.insert("decimal", QString::fromUtf8(decStr.get()));
            result.insert("hex", QString::fromUtf8(hexStr.get()));
        } catch (const std::exception &ex) {
            result.insert("message", QString::fromUtf8(ex.what()));
        } catch (...) {
            result.insert("message", "Неизвестная ошибка при генерации простого числа.");
        }

        return result;
    };

    m_primeGenerationWatcher->setFuture(QtConcurrent::run(task));
    updatePrimeControlsState();
}

void KuznechikWidget::onPrimeGenerationFinished()
{
    if (!m_primeGenerationWatcher) {
        return;
    }

    const QVariantMap result = m_primeGenerationWatcher->result();
    m_primeGenerationActive = false;

    const bool success = result.value("success").toBool();
    if (success) {
        m_generatedPrimeBits = result.value("bits").toInt();
        m_generatedPrimeDecimal = result.value("decimal").toString();
        m_generatedPrimeHex = result.value("hex").toString();

        if (m_primeGenerationStatusLabel) {
            m_primeGenerationStatusLabel->setText(
                QString("Простое число на %1 бит сгенерировано. Сохраните его файл.").arg(m_generatedPrimeBits));
        }
    } else {
        QString message = result.value("message").toString();
        if (message.isEmpty()) {
            message = "Не удалось сгенерировать простое число.";
        }
        m_generatedPrimeDecimal.clear();
        m_generatedPrimeHex.clear();
        m_generatedPrimeBits = 0;
            if (m_primeGenerationStatusLabel) {
            m_primeGenerationStatusLabel->setText(message);
        }
        AppMessage::warning(this, "Ошибка генерации", message);
    }

    updatePrimeGeneratorWidgets(false);
    updatePrimeControlsState();
}

void KuznechikWidget::onSavePrimeNumber()
{
    if (m_generatedPrimeDecimal.isEmpty() || m_generatedPrimeBits <= 0) {
        AppMessage::warning(this, "Сохранение", "Сначала сгенерируйте простое число.");
        return;
    }

    const QString timeStamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    const QString suggestedName = QString("prime_%1_%2.txt").arg(timeStamp).arg(m_generatedPrimeBits);

    QString defaultDir = !m_primesDirectory.isEmpty()
        ? m_primesDirectory
        : resolveDefaultPrimesDirectory();

    // Убеждаемся, что окно активно (как в onSavePdfClicked)
    if (QWidget *w = window()) {
        w->raise();
        w->activateWindow();
    }

    QFileDialog saveDialog(this, "Сохранить простое число", defaultDir + "/" + suggestedName, "Текстовые файлы (*.txt)");
    saveDialog.setAcceptMode(QFileDialog::AcceptSave);
    saveDialog.setFileMode(QFileDialog::AnyFile);
    saveDialog.setWindowModality(Qt::ApplicationModal);
    saveDialog.setNameFilter("Текстовые файлы (*.txt)");
    saveDialog.setDefaultSuffix("txt");
    saveDialog.setDirectory(defaultDir);
    saveDialog.selectFile(suggestedName);

    QString filePath;
    if (saveDialog.exec() == QDialog::Accepted) {
        const QStringList files = saveDialog.selectedFiles();
        if (!files.isEmpty()) filePath = files.first();
    }

    if (filePath.isEmpty()) {
        qDebug() << "Сохранение простого числа отменено пользователем";
        return;
    }

    QString finalPath = filePath;
    if (!finalPath.endsWith(".txt", Qt::CaseInsensitive)) {
        finalPath += ".txt";
    }

    QFile file(finalPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        AppMessage::warning(this, "Ошибка сохранения",
                             QString("Не удалось открыть файл для записи:\n%1").arg(finalPath));
        return;
    }

    QTextStream stream(&file);
    stream << m_generatedPrimeDecimal;
    stream.flush();
    file.close();

    if (stream.status() != QTextStream::Ok) {
        AppMessage::warning(this, "Ошибка сохранения",
                             QString("Ошибка при записи в файл:\n%1").arg(finalPath));
        return;
    }

    if (m_primeGenerationStatusLabel) {
        m_primeGenerationStatusLabel->setText(QString("Простое число сохранено: %1").arg(finalPath));
    }

    // Обновляем списки, если файл сохранён в текущую директорию простых чисел
    if (!m_primesDirectory.isEmpty()) {
        QFileInfo info(finalPath);
        if (QDir(m_primesDirectory).absolutePath() == info.absolutePath()) {
            refreshPrimeSelections();
        }
    }

    updatePrimeGeneratorWidgets(false);
}

void KuznechikWidget::onKeyNameChanged(const QString &text)
{
    Q_UNUSED(text)
    updatePrimeControlsState();
}

void KuznechikWidget::onGenerateKeyPairClicked()
{
    if (!m_generateRsaKeysButton || !m_primeFirstCombo || !m_primeSecondCombo) {
        return;
    }

    QVariantMap prime1 = currentPrimeData(m_primeFirstCombo);
    QVariantMap prime2 = currentPrimeData(m_primeSecondCombo);
    QString keyName = m_rsaKeyNameEdit ? m_rsaKeyNameEdit->text().trimmed() : QString();

    if (prime1.isEmpty() || prime2.isEmpty() || keyName.isEmpty()) {
        updatePrimeControlsState();
        return;
    }

    if (prime1.value("path").toString() == prime2.value("path").toString()) {
        AppMessage::warning(this, "Ошибка", "Простые числа не должны совпадать.");
        return;
    }

    if (prime1.value("bits").toInt() != prime2.value("bits").toInt()) {
        AppMessage::warning(this, "Ошибка", "Размеры выбранных простых чисел должны совпадать.");
        return;
    }

    ensureKeyGenerationWatcher();
    if (m_keyGenerationWatcher->isRunning() || (m_keySaveWatcher && m_keySaveWatcher->isRunning())) {
        return;
    }

    m_lastGeneratedKeyName = keyName;
    m_generatedKeySize = 0;
    m_saveRsaKeysButton->setEnabled(false);

    QString path1 = prime1.value("path").toString();
    QString path2 = prime2.value("path").toString();
    int bits = prime1.value("bits").toInt();
    const QString directory = managedKeyDirectory("rsa");
    const int owner = m_userId;
    if (bits <= 0 || bits > maxRsaBits / 2) {
        AppMessage::warning(this, "Размер ключа", "Для RSA используйте простые числа размером до 32 768 бит.");
        return;
    }

    if (m_keyGenerationProgress) {
        m_keyGenerationProgress->setEnabled(true);
        m_keyGenerationProgress->setRange(0, 0); // Индетерминированный прогресс (анимация)
        m_keyGenerationProgress->setVisible(true); // Показываем во время генерации
    }
    if (m_keyGenerationIndicator) {
        m_keyGenerationIndicator->setVisible(true);
    }
    if (m_rsaStatusLabel) {
        m_rsaStatusLabel->clear();
    }

    auto task = [manager = m_rsaKeyManager, path1, path2, bits, owner, directory]() -> QVariantMap {
        QVariantMap result;
        result.insert("success", false);
        result.insert("owner", owner);

        QString error;
        BigInt primeP;
        BigInt primeQ;

        if (!readPrimeFromFile(path1, primeP, error)) {
            result.insert("message", error);
            return result;
        }

        if (!readPrimeFromFile(path2, primeQ, error)) {
            result.insert("message", error);
            return result;
        }

        if (primeP == primeQ) {
            result.insert("message", "Простые числа совпадают.");
            return result;
        }

        int keySize = bits * 2;
        if (primeP.bitLength() != bits || primeQ.bitLength() != bits) {
            result.insert("message", QString("Простые числа несовместимы для RSA-%1.").arg(keySize));
            return result;
        }

        bool generated = manager->generateRSAKeyPair(primeP, primeQ, keySize);
        if (!generated) {
            result.insert("message", "Не удалось сгенерировать ключи.");
            return result;
        }

        result.insert("success", true);
        result.insert("keySize", keySize);
        result.insert("savedPublicKey", saveRsaPair(*manager, directory, keyFileStem(QString("RSA-%1").arg(keySize))));
        return result;
    };

    m_keyGenerationWatcher->setFuture(QtConcurrent::run(task));
    updatePrimeControlsState();
}

void KuznechikWidget::onSaveKeyPairClicked()
{
    if (!m_rsaKeyManager || m_generatedKeySize <= 0) {
        AppMessage::warning(this, "Сохранение", "Сначала сгенерируйте ключи.");
        return;
    }

    QString keyName = m_rsaKeyNameEdit ? m_rsaKeyNameEdit->text().trimmed() : QString();
    if (keyName.isEmpty()) {
        AppMessage::warning(this, "Сохранение", "Введите имя для ключей.");
        return;
    }

    // Убеждаемся, что окно активно (как в onSavePdfClicked)
    if (QWidget *w = window()) {
        w->raise();
        w->activateWindow();
    }

    QString defaultDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    QFileDialog saveDialog(this, "Выберите папку для сохранения ключей", defaultDir);
    saveDialog.setFileMode(QFileDialog::Directory);
    saveDialog.setOption(QFileDialog::ShowDirsOnly, true);
    saveDialog.setWindowModality(Qt::ApplicationModal);
    saveDialog.setDirectory(defaultDir);

    QString saveDir;
    if (saveDialog.exec() == QDialog::Accepted) {
        QStringList selectedDirs = saveDialog.selectedFiles();
        if (!selectedDirs.isEmpty()) {
            saveDir = selectedDirs.first();
        }
    }

    if (saveDir.isEmpty()) {
        return;
    }

    ensureKeySaveWatcher();
    if (m_keySaveWatcher->isRunning()) {
        return;
    }

    // Блокируем кнопку сохранения
    if (m_saveRsaKeysButton) {
        m_saveRsaKeysButton->setEnabled(false);
    }

    // Показываем индикатор прогресса
    if (m_keyGenerationProgress) {
        m_keyGenerationProgress->setEnabled(true);
        m_keyGenerationProgress->setRange(0, 0); // Индетерминированный прогресс (анимация)
        m_keyGenerationProgress->setVisible(true); // Показываем во время сохранения
    }
    if (m_keyGenerationIndicator) {
        m_keyGenerationIndicator->setVisible(true);
    }
    if (m_rsaStatusLabel) {
        m_rsaStatusLabel->setText("Сохранение ключей...");
    }

    // Запускаем сохранение в отдельном потоке напрямую в выбранную папку
    auto saveTask = [manager = m_rsaKeyManager, keyName, keySize = m_generatedKeySize, saveDir]() -> QVariantMap {
        QVariantMap result;
        result.insert("success", false);

        try {
            // Получаем ключи из RSAKeyManager
            auto publicKey = manager->getPublicKey();
            BigInt n = publicKey.first;
            BigInt e = publicKey.second;

            auto privateKey = manager->getPrivateKey();
            BigInt d = privateKey.second;

            // Формируем пути к файлам в выбранной папке
            QString publicPath = QDir(saveDir).absoluteFilePath(QString("%1_public_%2.txt").arg(keyName).arg(keySize));
            QString privatePath = QDir(saveDir).absoluteFilePath(QString("%1_private_%2.txt").arg(keyName).arg(keySize));

            // Удаляем существующие файлы, если есть
            QFile::remove(publicPath);
            QFile::remove(privatePath);

            // Сохраняем публичный ключ
            QFile publicFile(publicPath);
            if (!publicFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
                result.insert("message", QString("Не удалось создать файл публичного ключа: %1").arg(publicPath));
                return result;
            }

            QTextStream publicStream(&publicFile);
            publicStream << "# RSA Public Key\n";
            publicStream << "# Key Size: " << keySize << " bits\n";
            publicStream << "# Generated: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
            publicStream << "# Modulus (n):\n";
            publicStream << QString::fromStdString(BigIntConversion::gmpFastToDecimal(n)) << "\n";
            publicStream << "# Public Exponent (e):\n";
            publicStream << QString::fromStdString(BigIntConversion::gmpFastToDecimal(e)) << "\n";
            publicFile.close();

            // Сохраняем приватный ключ
            QFile privateFile(privatePath);
            if (!privateFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
                result.insert("message", QString("Не удалось создать файл приватного ключа: %1").arg(privatePath));
                return result;
            }

            QTextStream privateStream(&privateFile);
            privateStream << "# RSA Private Key\n";
            privateStream << "# Key Size: " << keySize << " bits\n";
            privateStream << "# Generated: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
            privateStream << "# Modulus (n):\n";
            privateStream << QString::fromStdString(BigIntConversion::gmpFastToDecimal(n)) << "\n";
            privateStream << "# Private Exponent (d):\n";
            privateStream << QString::fromStdString(BigIntConversion::gmpFastToDecimal(d)) << "\n";
            privateFile.close();

            result.insert("success", true);
            result.insert("keyName", keyName);
            result.insert("keySize", keySize);
            result.insert("publicTarget", publicPath);
            result.insert("privateTarget", privatePath);
            result.insert("saveDir", saveDir);
        } catch (const std::exception &ex) {
            result.insert("message", QString("Ошибка сохранения: %1").arg(ex.what()));
        }

        return result;
    };

    m_keySaveWatcher->setFuture(QtConcurrent::run(saveTask));
}

void KuznechikWidget::onKeySaveFinished()
{
    if (!m_keySaveWatcher) {
        return;
    }

    QVariantMap result = m_keySaveWatcher->result();

    // Останавливаем индикатор прогресса, но виджет остается видимым
    if (m_keyGenerationProgress) {
        m_keyGenerationProgress->setRange(0, 100);
        m_keyGenerationProgress->setValue(0); // Устанавливаем в 0% - без анимации
        m_keyGenerationProgress->setEnabled(false);
        m_keyGenerationProgress->setVisible(false); // Скрываем после завершения сохранения
    }
    if (m_keyGenerationIndicator) {
        m_keyGenerationIndicator->setVisible(false);
    }

    bool success = result.value("success").toBool();

    if (success) {
        QString keyName = result.value("keyName").toString();
        int keySize = result.value("keySize").toInt();
        QString publicTarget = result.value("publicTarget").toString();
        QString privateTarget = result.value("privateTarget").toString();
        QString saveDir = result.value("saveDir").toString();

        // Выводим информацию о сохраненных ключах в консоль
        qDebug() << "═══════════════════════════════════════════════════════════";
        qDebug() << "💾 RSA ключи успешно сохранены!";
        qDebug() << "   Имя ключа: " << keyName;
        qDebug() << "   Размер ключа: RSA-" << keySize;
        qDebug() << "   Публичный ключ: " << publicTarget;
        qDebug() << "   Приватный ключ: " << privateTarget;
        qDebug() << "   Папка назначения: " << saveDir;
        qDebug() << "═══════════════════════════════════════════════════════════";

        if (m_rsaStatusLabel) {
            m_rsaStatusLabel->setText(QString("Ключи сохранены в папку: %1").arg(saveDir));
        }

        loadRSAKeysFromDirectory();
        updatePrimeControlsState();
        AppMessage::information(this, "Сохранено", "RSA ключи успешно сохранены в выбранную папку.");
    } else {
        QString message = result.value("message").toString();
        if (message.isEmpty()) {
            message = "Не удалось сохранить ключи.";
        }
        if (m_rsaStatusLabel) {
            m_rsaStatusLabel->setText(message);
        }
        if (m_saveRsaKeysButton) {
            m_saveRsaKeysButton->setEnabled(true);
        }
        AppMessage::warning(this, "Ошибка сохранения", message);
    }

    updatePrimeControlsState();
}

void KuznechikWidget::onKeyGenerationFinished()
{
    if (!m_keyGenerationWatcher) {
        return;
    }

    QVariantMap result = m_keyGenerationWatcher->result();
    if (result.value("quick").toBool()) {
        m_cancelRsa.reset();
        if (result.value("owner").toInt() == m_userId) {
            const QString saved = result.value("savedPublicKey").toString();
            if (!saved.isEmpty()) {
                m_savedRsaStatus->setText(QString("Пара RSA-%1 сохранена в библиотеке.").arg(result.value("keySize").toInt()));
                loadRSAKeysFromDirectory(saved);
            } else {
                m_savedRsaStatus->setText(result.value("message").toString());
            }
        }
        updatePrimeControlsState();
        return;
    }

    if (m_keyGenerationProgress) {
        // Останавливаем прогресс и скрываем виджет после завершения генерации
        m_keyGenerationProgress->setRange(0, 100);
        m_keyGenerationProgress->setValue(0); // Устанавливаем в 0% - без анимации
        m_keyGenerationProgress->setEnabled(false);
        m_keyGenerationProgress->setVisible(false); // Скрываем после завершения генерации
    }
    if (m_keyGenerationIndicator) {
        m_keyGenerationIndicator->setVisible(false);
    }

    if (result.value("owner").toInt() != m_userId) {
        updatePrimeControlsState();
        return;
    }

    bool success = result.value("success").toBool();
    if (success) {
        m_generatedKeySize = result.value("keySize").toInt();
        if (m_generatedKeySize <= 0) {
            m_generatedKeySize = m_selectedPrimeBits1 + m_selectedPrimeBits2;
        }

        // Выводим информацию о сгенерированных ключах в консоль (без самих ключей - они слишком большие)
        QString keyName = m_rsaKeyNameEdit ? m_rsaKeyNameEdit->text().trimmed() : QString();
        qDebug() << "═══════════════════════════════════════════════════════════";
        qDebug() << "[OK] RSA ключи успешно сгенерированы!";
        qDebug() << "   Имя ключа: " << keyName;
        qDebug() << "   Размер ключа: RSA-" << m_generatedKeySize;
        qDebug() << "   Простое число p: " << m_selectedPrimePath1 << " (" << m_selectedPrimeBits1 << " бит)";
        qDebug() << "   Простое число q: " << m_selectedPrimePath2 << " (" << m_selectedPrimeBits2 << " бит)";

        // Пытаемся получить информацию о файлах ключей
        QString sourceDir = resolveRsaKeysDirectory();
        QString publicKeyPath = QDir(sourceDir).absoluteFilePath(QString("%1_public_%2.txt").arg(keyName).arg(m_generatedKeySize));
        QString privateKeyPath = QDir(sourceDir).absoluteFilePath(QString("%1_private_%2.txt").arg(keyName).arg(m_generatedKeySize));

        if (QFile::exists(publicKeyPath)) {
            qDebug() << "   📄 Файл публичного ключа: " << publicKeyPath;
        }
        if (QFile::exists(privateKeyPath)) {
            qDebug() << "   📄 Файл приватного ключа: " << privateKeyPath;
        }

        qDebug() << "═══════════════════════════════════════════════════════════";

        const QString saved = result.value("savedPublicKey").toString();
        if (!saved.isEmpty()) loadRSAKeysFromDirectory(saved);
        m_rsaStatusLabel->setText(saved.isEmpty()
            ? "Пара готова. Сохраните её в выбранную папку."
            : "Пара сохранена в библиотеке. При необходимости экспортируйте копию.");
        if (m_saveRsaKeysButton) {
            m_saveRsaKeysButton->setEnabled(true);
        }
    } else {
        QString message = result.value("message").toString();
        if (message.isEmpty()) {
            message = "Не удалось сгенерировать ключи.";
        }
        qDebug() << "[ERROR] Ошибка генерации RSA ключей: " << message;
        if (m_rsaStatusLabel) {
            m_rsaStatusLabel->setText(message);
        }
        if (m_saveRsaKeysButton) {
            m_saveRsaKeysButton->setEnabled(false);
        }
    }

    updatePrimeControlsState();
}

void KuznechikWidget::loadRSAKeysFromDirectory(const QString &preferredPublicKey)
{
    const QString previousPublic = m_publicKeyCombo->currentData().toString();
    const QString previousPrivate = m_privateKeyCombo->currentData().toString();
    const QSignalBlocker publicSignals(m_publicKeyCombo);
    const QSignalBlocker privateSignals(m_privateKeyCombo);
    m_publicKeyCombo->clear();
    m_privateKeyCombo->clear();
    const QStringList filters{"*_public_*.txt", "*_private_*.txt"};
    const auto addFiles = [&](const QDir &dir, const QString &prefix) {
        for (const auto &file : dir.entryInfoList(filters, QDir::Files | QDir::NoSymLinks, QDir::Name)) {
            auto *combo = file.fileName().contains("_public_") ? m_publicKeyCombo : m_privateKeyCombo;
            combo->addItem(prefix + file.fileName(), file.absoluteFilePath());
        }
    };
    QString recentPublic;
    const QString library = managedKeyDirectory("rsa");
    if (!library.isEmpty()) {
        for (const auto &pair : QDir(library).entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks, QDir::Time)) {
            if (pair.fileName().startsWith(".pending-")) continue;
            const int first = m_publicKeyCombo->count();
            addFiles(QDir(pair.absoluteFilePath()), {});
            if (recentPublic.isEmpty() && first < m_publicKeyCombo->count()) recentPublic = m_publicKeyCombo->itemData(first).toString();
        }
    }
    addFiles(QDir(resolveRsaKeysDirectory()), {});
    const QDir examples(QDir(resolveProjectRoot()).filePath("algorithms/RSA-32768/rsa_keys"));
    addFiles(examples, "Пример · ");

    const QString selected = !preferredPublicKey.isEmpty() ? preferredPublicKey :
        m_publicKeyCombo->findData(previousPublic) >= 0 ? previousPublic : recentPublic;
    m_publicKeyCombo->setCurrentIndex(m_publicKeyCombo->findData(selected));
    if (!selected.isEmpty()) {
        const QFileInfo file(selected);
        QString partner = file.fileName();
        partner.replace("_public_", "_private_");
        m_privateKeyCombo->setCurrentIndex(m_privateKeyCombo->findData(QDir(file.absolutePath()).filePath(partner)));
    } else {
        m_privateKeyCombo->setCurrentIndex(m_privateKeyCombo->findData(previousPrivate));
    }
    updateRsaTypeLabel();
    updateEncryptDecryptButtonsState();
}

void KuznechikWidget::updateRsaTypeLabel()
{
    if (!m_rsaTypeLabel) {
        return;
    }

    // Показываем только в режиме RSA
    if (m_currentAlgorithm != RSAAlgorithm) {
        m_rsaTypeLabel->setVisible(false);
        return;
    }

    // Получаем пути выбранных ключей
    QString publicKeyPath;
    QString privateKeyPath;

    int publicIndex = m_publicKeyCombo ? m_publicKeyCombo->currentIndex() : -1;
    int privateIndex = m_privateKeyCombo ? m_privateKeyCombo->currentIndex() : -1;

    if (publicIndex >= 0 && m_publicKeyCombo) {
        publicKeyPath = m_publicKeyCombo->itemData(publicIndex).toString();
    }
    if (privateIndex >= 0 && m_privateKeyCombo) {
        privateKeyPath = m_privateKeyCombo->itemData(privateIndex).toString();
    }

    // Если оба ключа не выбраны - показываем "RSA - "
    if (publicKeyPath.isEmpty() && privateKeyPath.isEmpty()) {
        m_rsaTypeLabel->setText("RSA - ");
        m_rsaTypeLabel->setVisible(true);
        return;
    }

    // Определяем размер ключей
    int publicBits = 0;
    int privateBits = 0;

    if (!publicKeyPath.isEmpty()) {
        publicBits = extractRsaKeyBitLength(publicKeyPath);
    }
    if (!privateKeyPath.isEmpty()) {
        privateBits = extractRsaKeyBitLength(privateKeyPath);
    }

    // Обновляем текст метки - RSA размер = размер ключа * 2
    if (publicBits > 0 && privateBits > 0) {
        if (publicBits == privateBits) {
            int rsaSize = publicBits * 2;
            m_rsaTypeLabel->setText(QString("RSA-%1").arg(rsaSize));
        } else {
            int rsaSizePublic = publicBits * 2;
            int rsaSizePrivate = privateBits * 2;
            m_rsaTypeLabel->setText(QString("RSA - (размеры не совпадают: %1/%2)").arg(rsaSizePublic).arg(rsaSizePrivate));
        }
        m_rsaTypeLabel->setVisible(true);
    } else if (publicBits > 0) {
        int rsaSize = publicBits * 2;
        m_rsaTypeLabel->setText(QString("RSA-%1").arg(rsaSize));
        m_rsaTypeLabel->setVisible(true);
    } else if (privateBits > 0) {
        int rsaSize = privateBits * 2;
        m_rsaTypeLabel->setText(QString("RSA-%1").arg(rsaSize));
        m_rsaTypeLabel->setVisible(true);
    } else {
        m_rsaTypeLabel->setText("RSA - ");
        m_rsaTypeLabel->setVisible(true);
    }
}

void KuznechikWidget::updateEncryptDecryptButtonsState()
{
    if (!m_encryptButton || !m_decryptButton) {
        return;
    }

    const bool running = m_encryptDecryptWatcher && m_encryptDecryptWatcher->isRunning();
    m_algorithmSwitch->setEnabled(!running);
    if (running) {
        m_encryptButton->setEnabled(false);
        m_decryptButton->setEnabled(false);
        return;
    }

    // В режиме Кузнечик кнопки активны только если поле ключа заполнено
    if (m_currentAlgorithm == KuznechikAlgorithm) {
        bool hasKey = m_keyEdit && !m_keyEdit->text().trimmed().isEmpty();
        m_encryptButton->setEnabled(hasKey);
        m_decryptButton->setEnabled(hasKey);
        return;
    }

    // В режиме RSA кнопки активны только если выбраны оба ключа
    if (m_currentAlgorithm == RSAAlgorithm) {
        int publicIndex = m_publicKeyCombo ? m_publicKeyCombo->currentIndex() : -1;
        int privateIndex = m_privateKeyCombo ? m_privateKeyCombo->currentIndex() : -1;

        bool bothKeysSelected = (publicIndex >= 0 && m_publicKeyCombo && m_publicKeyCombo->count() > 0) &&
                               (privateIndex >= 0 && m_privateKeyCombo && m_privateKeyCombo->count() > 0);

        m_encryptButton->setEnabled(bothKeysSelected);
        m_decryptButton->setEnabled(bothKeysSelected);
    } else {
        // Для других режимов (если будут добавлены) кнопки неактивны
        m_encryptButton->setEnabled(false);
        m_decryptButton->setEnabled(false);
    }
}

void KuznechikWidget::onPublicKeySelected(int index)
{
    // Игнорируем срабатывание при инициализации или если индекс невалидный
    if (index < 0 || index >= m_publicKeyCombo->count()) {
        // Сброс выбора - очищаем приватный ключ
        m_privateKeyCombo->blockSignals(true);
        m_privateKeyCombo->setCurrentIndex(-1);
        m_privateKeyCombo->blockSignals(false);
        updateRsaTypeLabel(); // Обновляем тип RSA при сбросе
        updateEncryptDecryptButtonsState(); // Обновляем состояние кнопок при сбросе
        return;
    }

    // Игнорируем, если комбобокс еще не был показан пользователю
    if (!m_publicKeyCombo->isVisible()) {
        return;
    }

    QString publicKeyPath = m_publicKeyCombo->itemData(index).toString();
    QFileInfo publicKeyInfo(publicKeyPath);
    QString fileName = publicKeyInfo.fileName();

    // Находим парный приватный ключ
    QString privateFileName = fileName;
    privateFileName.replace("_public_", "_private_");
    QString privateKeyPath = QDir(publicKeyInfo.absolutePath()).absoluteFilePath(privateFileName);

    // Проверяем существование файла приватного ключа
    bool privateFileExists = QFile::exists(privateKeyPath);

    // Ищем соответствующий приватный ключ в комбобоксе
    int privateIndex = -1;
    for (int i = 0; i < m_privateKeyCombo->count(); i++) {
        QString privatePath = m_privateKeyCombo->itemData(i).toString();
        if (privatePath == privateKeyPath) {
            privateIndex = i;
            break;
        }
    }

    // Блокируем сигналы для предотвращения рекурсии
    m_privateKeyCombo->blockSignals(true);
    if (privateIndex >= 0) {
        m_privateKeyCombo->setCurrentIndex(privateIndex);
        m_privateKeyCombo->blockSignals(false);

        // Валидируем ключи, если оба выбраны
        if (QFile::exists(publicKeyPath) && QFile::exists(privateKeyPath)) {
            validateRSAKeys(publicKeyPath, privateKeyPath);
        }
        // Обновляем тип RSA сразу, до валидации
        updateRsaTypeLabel();
        // Обновляем состояние кнопок шифрования/расшифрования
        updateEncryptDecryptButtonsState();
    } else {
        // Парный приватный ключ не найден в комбобоксе
        updateRsaTypeLabel(); // Обновляем тип RSA при отсутствии парного ключа
        // Обновляем состояние кнопок шифрования/расшифрования
        updateEncryptDecryptButtonsState();
        m_privateKeyCombo->setCurrentIndex(-1);
        m_privateKeyCombo->blockSignals(false);

        if (!privateFileExists) {
            // Файл не существует
            AppMessage::warning(this, "Парный ключ не найден",
                QString("Для публичного ключа\n%1\n\nне найден парный приватный ключ:\n%2\n\nПроверьте, что файл существует в папке ключей.")
                    .arg(fileName)
                    .arg(privateFileName));
        } else {
            // Файл существует, но не загружен в комбобокс (это не должно происходить, но на всякий случай)
            AppMessage::warning(this, "Парный ключ не загружен",
                QString("Для публичного ключа\n%1\n\nпарный приватный ключ существует, но не был загружен в список.\n\nПопробуйте перезагрузить ключи.")
                    .arg(fileName));
        }
    }
}

void KuznechikWidget::onPrivateKeySelected(int index)
{
    // Игнорируем срабатывание при инициализации или если индекс невалидный
    if (index < 0 || index >= m_privateKeyCombo->count()) {
        // Сброс выбора - очищаем публичный ключ
        m_publicKeyCombo->blockSignals(true);
        m_publicKeyCombo->setCurrentIndex(-1);
        m_publicKeyCombo->blockSignals(false);
        updateRsaTypeLabel(); // Обновляем тип RSA при сбросе
        updateEncryptDecryptButtonsState(); // Обновляем состояние кнопок при сбросе
        return;
    }

    // Игнорируем, если комбобокс еще не был показан пользователю
    if (!m_privateKeyCombo->isVisible()) {
        return;
    }

    QString privateKeyPath = m_privateKeyCombo->itemData(index).toString();
    QFileInfo privateKeyInfo(privateKeyPath);
    QString fileName = privateKeyInfo.fileName();

    // Находим парный публичный ключ
    QString publicFileName = fileName;
    publicFileName.replace("_private_", "_public_");
    QString publicKeyPath = QDir(privateKeyInfo.absolutePath()).absoluteFilePath(publicFileName);

    // Проверяем существование файла публичного ключа
    bool publicFileExists = QFile::exists(publicKeyPath);

    // Ищем соответствующий публичный ключ в комбобоксе
    int publicIndex = -1;
    for (int i = 0; i < m_publicKeyCombo->count(); i++) {
        QString publicPath = m_publicKeyCombo->itemData(i).toString();
        if (publicPath == publicKeyPath) {
            publicIndex = i;
            break;
        }
    }

    // Блокируем сигналы для предотвращения рекурсии
    m_publicKeyCombo->blockSignals(true);
    if (publicIndex >= 0) {
        m_publicKeyCombo->setCurrentIndex(publicIndex);
        m_publicKeyCombo->blockSignals(false);

        // Валидируем ключи, если оба выбраны
        if (QFile::exists(publicKeyPath) && QFile::exists(privateKeyPath)) {
            validateRSAKeys(publicKeyPath, privateKeyPath);
        }
        // Обновляем тип RSA сразу, до валидации
        updateRsaTypeLabel();
        // Обновляем состояние кнопок шифрования/расшифрования
        updateEncryptDecryptButtonsState();
    } else {
        // Парный публичный ключ не найден в комбобоксе
        updateRsaTypeLabel(); // Обновляем тип RSA при отсутствии парного ключа
        // Обновляем состояние кнопок шифрования/расшифрования
        updateEncryptDecryptButtonsState();
        m_publicKeyCombo->setCurrentIndex(-1);
        m_publicKeyCombo->blockSignals(false);

        if (!publicFileExists) {
            // Файл не существует
            AppMessage::warning(this, "Парный ключ не найден",
                QString("Для приватного ключа\n%1\n\nне найден парный публичный ключ:\n%2\n\nПроверьте, что файл существует в папке ключей.")
                    .arg(fileName)
                    .arg(publicFileName));
        } else {
            // Файл существует, но не загружен в комбобокс (это не должно происходить, но на всякий случай)
            AppMessage::warning(this, "Парный ключ не загружен",
                QString("Для приватного ключа\n%1\n\nпарный публичный ключ существует, но не был загружен в список.\n\nПопробуйте перезагрузить ключи.")
                    .arg(fileName));
        }
    }
}

void KuznechikWidget::validateRSAKeys(const QString &publicKeyPath, const QString &privateKeyPath)
{
    const auto modulus = [](const QString &path) -> QByteArray {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly) || file.size() > 128 * 1024) return {};
        while (!file.atEnd()) {
            if (file.readLine().contains("Modulus (n):")) return file.readLine().trimmed();
        }
        return {};
    };
    const auto publicModulus = modulus(publicKeyPath);
    if (!publicModulus.isEmpty() && publicModulus == modulus(privateKeyPath)) return;
    m_publicKeyCombo->setCurrentIndex(-1);
    m_privateKeyCombo->setCurrentIndex(-1);
    AppMessage::warning(this, "Ключи не совпадают", "Выберите открытый и закрытый ключи одной пары RSA.");
}

void KuznechikWidget::onGeneratePrimesClicked()
{
    // Диалог для выбора размера простого числа и папки
    bool ok;
    QStringList sizes = {"64", "128", "256", "512", "1024", "2048", "4096", "8192", "16384"};
    QString sizeStr = QInputDialog::getItem(this, "Генерация простых чисел",
        "Выберите размер простого числа в битах:", sizes, 4, false, &ok);

    if (!ok || sizeStr.isEmpty()) return;

    int bitSize = sizeStr.toInt();

    // Выбор папки для сохранения простых чисел
    QString defaultDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + "/generated_primes";
    QString dir = QFileDialog::getExistingDirectory(this, "Выберите папку для сохранения простых чисел",
        defaultDir, QFileDialog::ShowDirsOnly);

    if (dir.isEmpty()) return;

    // Имя файла для простого числа
    QString name = QInputDialog::getText(this, "Имя файла",
        "Введите имя для простого числа (без расширения):", QLineEdit::Normal,
        "prime_" + sizeStr, &ok);

    if (!ok || name.isEmpty()) return;

    // Создаем прогресс-диалог
    QProgressDialog progress("Генерация простого числа...", nullptr, 0, 0, this);
    progress.setWindowModality(Qt::WindowModal);
    progress.setCancelButton(nullptr);
    progress.setLabelText(QString("Генерация простого числа %1 бит...\nЭто может занять некоторое время...").arg(sizeStr));
    progress.show();
    QApplication::processEvents();

    try {
        // Генерируем простое число через BigInt
        // Используем BigInt_SIMD для генерации
        progress.setLabelText("Инициализация генератора...");
        QApplication::processEvents();

        // TODO: Реализовать генерацию простых чисел через BigInt_SIMD
        // Пока используем временную заглушку
        AppMessage::information(this, "В разработке",
            QString("Генерация простых чисел будет реализована.\n"
                   "Размер: %1 бит\n"
                   "Папка: %2\n"
                   "Имя: %3").arg(sizeStr).arg(dir).arg(name));

        progress.close();

    } catch (const std::exception& e) {
        progress.close();
        AppMessage::critical(this, "Ошибка",
            QString("Ошибка при генерации простого числа:\n%1").arg(e.what()));
    }
}

void KuznechikWidget::onEncryptClicked()
{
    if (m_currentAlgorithm == KuznechikAlgorithm) {
        // Шифрование для Кузнечик
        QString keyText = m_keyEdit->text().trimmed();
        if (keyText.isEmpty()) {
            AppMessage::warning(this, "Ошибка", "Введите ключ или сгенерируйте новый!");
            return;
        }

        QByteArray key = KuznechikEncryption::fromHex(keyText);
        if (key.size() != 32) {
            AppMessage::warning(this, "Ошибка",
                QString("Неверный размер ключа! Требуется 32 байта (64 hex символа).\n")
                + QString("Получено: %1 байт после парсинга.").arg(key.size())
                + "\nПроверьте формат ключа.");
            return;
        }

        QString input = m_inputTextEdit->toPlainText().trimmed();
        if (input.isEmpty()) {
            AppMessage::warning(this, "Ошибка", "Введите данные для шифрования!");
            return;
        }

        // Деактивируем кнопку сохранения PDF до завершения операции
        if (m_savePdfButton) {
            m_savePdfButton->setEnabled(false);
        }

        QString result;
        // Используем выбранный режим
        if (m_currentMode == HexMode) {
            result = m_cryptoFacade->encryptKuznechikHex(input, key);
        } else {
            result = m_cryptoFacade->encryptKuznechikText(input, key);
        }

        if (result.isEmpty()) {
            AppMessage::warning(this, "Ошибка", "Не удалось зашифровать данные. Проверьте входные данные.");
            // Кнопка сохранения PDF остается деактивированной при ошибке
            return;
        }

        m_outputTextEdit->setPlainText(result);
        AppMessage::information(this, "Успех", "Данные успешно зашифрованы!");

        // Сохраняем контекст операции для PDF и активируем кнопку только после успешного завершения
        m_lastOperation = OpEncrypt;
        m_lastInput = input;
        m_lastOutput = result;
        m_lastKey = keyText;
        if (m_savePdfButton) {
            m_savePdfButton->setEnabled(true);
        }
    } else {
        // RSA: шифрование (асинхронно)
        // Проверяем, что выбран публичный ключ
        int publicIndex = m_publicKeyCombo ? m_publicKeyCombo->currentIndex() : -1;

        if (publicIndex < 0 || !m_publicKeyCombo || m_publicKeyCombo->count() == 0) {
            AppMessage::warning(this, "Ошибка", "Выберите публичный ключ!");
            return;
        }

        QString input = m_inputTextEdit->toPlainText().trimmed();
        if (input.isEmpty()) {
            AppMessage::warning(this, "Ошибка", "Введите данные для шифрования!");
            return;
        }

        // Получаем путь к публичному ключу
        QString publicKeyPath = m_publicKeyCombo->itemData(publicIndex).toString();
        if (!QFile::exists(publicKeyPath)) {
            AppMessage::critical(this, "Ошибка",
                QString("Файл публичного ключа не найден:\n%1").arg(publicKeyPath));
            return;
        }

        // Проверяем, не выполняется ли уже операция
        ensureEncryptDecryptWatcher();
        if (m_encryptDecryptWatcher->isRunning()) {
            AppMessage::information(this, "Операция выполняется",
                "Шифрование или расшифровка уже выполняется. Пожалуйста, подождите.");
            return;
        }

        // Блокируем кнопки шифрования/расшифровки
        if (m_encryptButton) {
            m_encryptButton->setEnabled(false);
        }
        if (m_decryptButton) {
            m_decryptButton->setEnabled(false);
        }

        // Деактивируем кнопку сохранения PDF до завершения операции
        if (m_savePdfButton) {
            m_savePdfButton->setEnabled(false);
        }

        // Показываем индикатор прогресса
        if (m_keyGenerationProgress) {
            m_keyGenerationProgress->setEnabled(true);
            m_keyGenerationProgress->setRange(0, 0); // Индетерминированный прогресс (анимация)
            m_keyGenerationProgress->setVisible(true);
        }
        if (m_rsaStatusLabel) {
            m_rsaStatusLabel->setText("Шифрование...");
        }

        // Определяем режим (Text или Hex)
        int modeId = m_rsaModeGroup ? m_rsaModeGroup->checkedId() : TextMode;
        bool isHexMode = (modeId == HexMode);

        // Подготавливаем данные для асинхронной операции
        QString inputQStr = input;
        QString publicKeyPathQStr = publicKeyPath;

        // Создаем задачу для выполнения в отдельном потоке
        auto encryptTask = [cryptoFacade = m_cryptoFacade, inputQStr, publicKeyPathQStr, isHexMode, owner = m_userId]() -> QVariantMap {
            QVariantMap result;
            result.insert("owner", owner);
            result.insert("success", false);
            result.insert("operation", "encrypt");
            result.insert("isHexMode", isHexMode);

            try {
                QString resultStr;
                if (isHexMode) {
                    resultStr = cryptoFacade->encryptRSAHex(inputQStr, publicKeyPathQStr);
                } else {
                    resultStr = cryptoFacade->encryptRSAText(inputQStr, publicKeyPathQStr);
                }

                result.insert("success", true);
                result.insert("output", resultStr);
                result.insert("input", inputQStr);
                result.insert("keyPath", publicKeyPathQStr);
            } catch (const std::exception& e) {
                result.insert("error", QString::fromStdString(e.what()));
            } catch (...) {
                result.insert("error", "Неизвестная ошибка при шифровании.");
            }

            return result;
        };

        // Запускаем шифрование в отдельном потоке
        m_encryptDecryptWatcher->setFuture(QtConcurrent::run(encryptTask));
        updateEncryptDecryptButtonsState();
    }
}

void KuznechikWidget::onDecryptClicked()
{
    if (m_currentAlgorithm == KuznechikAlgorithm) {
        // Расшифровка для Кузнечик
        QString keyText = m_keyEdit->text().trimmed();
        if (keyText.isEmpty()) {
            AppMessage::warning(this, "Ошибка", "Введите ключ или сгенерируйте новый!");
            return;
        }

        QByteArray key = KuznechikEncryption::fromHex(keyText);
        if (key.size() != 32) {
            AppMessage::warning(this, "Ошибка",
                QString("Неверный размер ключа! Требуется 32 байта (64 hex символа).\n")
                + QString("Получено: %1 байт после парсинга.").arg(key.size())
                + "\nПроверьте формат ключа.");
            return;
        }

        QString input = m_inputTextEdit->toPlainText().trimmed();
        if (input.isEmpty()) {
            AppMessage::warning(this, "Ошибка", "Введите зашифрованные данные!");
            return;
        }

        // Деактивируем кнопку сохранения PDF до завершения операции
        if (m_savePdfButton) {
            m_savePdfButton->setEnabled(false);
        }

        // Используем выбранный режим для расшифрования
        QString result;
        if (m_currentMode == HexMode) {
            result = m_cryptoFacade->decryptKuznechikHex(input, key);
        } else {
            result = m_cryptoFacade->decryptKuznechikText(input, key);
        }

        if (result.isEmpty()) {
            AppMessage::warning(this, "Ошибка", "Не удалось расшифровать данные. Проверьте ключ и зашифрованные данные.");
            // Кнопка сохранения PDF остается деактивированной при ошибке
            return;
        }

        m_outputTextEdit->setPlainText(result);
        AppMessage::information(this, "Успех", "Данные успешно расшифрованы!");

        // Сохраняем контекст операции для PDF и активируем кнопку только после успешного завершения
        m_lastOperation = OpDecrypt;
        m_lastInput = input;
        m_lastOutput = result;
        m_lastKey = keyText;
        if (m_savePdfButton) {
            m_savePdfButton->setEnabled(true);
        }
    } else {
        // RSA: расшифровка
        // Проверяем, что выбран приватный ключ
        int privateIndex = m_privateKeyCombo ? m_privateKeyCombo->currentIndex() : -1;

        if (privateIndex < 0 || !m_privateKeyCombo || m_privateKeyCombo->count() == 0) {
            AppMessage::warning(this, "Ошибка", "Выберите приватный ключ!");
            return;
        }

        QString input = m_inputTextEdit->toPlainText().trimmed();
        if (input.isEmpty()) {
            AppMessage::warning(this, "Ошибка", "Введите зашифрованные данные!");
            return;
        }

        // Получаем путь к приватному ключу
        QString privateKeyPath = m_privateKeyCombo->itemData(privateIndex).toString();
        if (!QFile::exists(privateKeyPath)) {
            AppMessage::critical(this, "Ошибка",
                QString("Файл приватного ключа не найден:\n%1").arg(privateKeyPath));
            return;
        }

        // Проверяем, не выполняется ли уже операция
        ensureEncryptDecryptWatcher();
        if (m_encryptDecryptWatcher->isRunning()) {
            AppMessage::information(this, "Операция выполняется",
                "Шифрование или расшифровка уже выполняется. Пожалуйста, подождите.");
            return;
        }

        // Блокируем кнопки шифрования/расшифровки
        if (m_encryptButton) {
            m_encryptButton->setEnabled(false);
        }
        if (m_decryptButton) {
            m_decryptButton->setEnabled(false);
        }

        // Деактивируем кнопку сохранения PDF до завершения операции
        if (m_savePdfButton) {
            m_savePdfButton->setEnabled(false);
        }

        // Показываем индикатор прогресса
        if (m_keyGenerationProgress) {
            m_keyGenerationProgress->setEnabled(true);
            m_keyGenerationProgress->setRange(0, 0); // Индетерминированный прогресс (анимация)
            m_keyGenerationProgress->setVisible(true);
        }
        if (m_rsaStatusLabel) {
            m_rsaStatusLabel->setText("Расшифровка...");
        }

        // Определяем режим (Text или Hex)
        int modeId = m_rsaModeGroup ? m_rsaModeGroup->checkedId() : TextMode;
        bool isHexMode = (modeId == HexMode);

        // Подготавливаем данные для асинхронной операции
        QString inputQStr = input;
        QString privateKeyPathQStr = privateKeyPath;

        // Создаем задачу для выполнения в отдельном потоке
        auto decryptTask = [cryptoFacade = m_cryptoFacade, inputQStr, privateKeyPathQStr, isHexMode, owner = m_userId]() -> QVariantMap {
            QVariantMap result;
            result.insert("owner", owner);
            result.insert("success", false);
            result.insert("operation", "decrypt");
            result.insert("isHexMode", isHexMode);

            try {
                QString resultStr;
                if (isHexMode) {
                    resultStr = cryptoFacade->decryptRSAHex(inputQStr, privateKeyPathQStr);
                } else {
                    resultStr = cryptoFacade->decryptRSAText(inputQStr, privateKeyPathQStr);
                }

                result.insert("success", true);
                result.insert("output", resultStr);
                result.insert("input", inputQStr);
                result.insert("keyPath", privateKeyPathQStr);
            } catch (const std::exception& e) {
                result.insert("error", QString::fromStdString(e.what()));
            } catch (...) {
                result.insert("error", "Неизвестная ошибка при расшифровке.");
            }

            return result;
        };

        // Запускаем расшифровку в отдельном потоке
        m_encryptDecryptWatcher->setFuture(QtConcurrent::run(decryptTask));
        updateEncryptDecryptButtonsState();
    }
}

void KuznechikWidget::onEncryptDecryptFinished()
{
    if (!m_encryptDecryptWatcher) {
        return;
    }

    QVariantMap result = m_encryptDecryptWatcher->result();

    // Скрываем индикатор прогресса
    if (m_keyGenerationProgress) {
        m_keyGenerationProgress->setRange(0, 100);
        m_keyGenerationProgress->setValue(0);
        m_keyGenerationProgress->setEnabled(false);
        m_keyGenerationProgress->setVisible(false);
    }
    if (m_rsaStatusLabel) {
        m_rsaStatusLabel->clear();
    }
    if (result.value("owner").toInt() != m_userId) {
        updateEncryptDecryptButtonsState();
        return;
    }

    // Проверяем результат операции
    bool success = result.value("success", false).toBool();
    QString operation = result.value("operation").toString();

    if (!success) {
        QString error = result.value("error").toString();
        // Восстанавливаем состояние кнопок
        updateEncryptDecryptButtonsState();
        // Кнопка сохранения PDF остается деактивированной при ошибке
        AppMessage::critical(this,
            operation == "encrypt" ? "Ошибка шифрования" : "Ошибка расшифровки",
            QString("Произошла ошибка:\n%1").arg(error));
        return;
    }

    // Получаем результат
    QString output = result.value("output").toString();
    QString input = result.value("input").toString();
    QString keyPath = result.value("keyPath").toString();

    if (output.isEmpty()) {
        // Восстанавливаем состояние кнопок
        updateEncryptDecryptButtonsState();
        // Кнопка сохранения PDF остается деактивированной при пустом результате
        AppMessage::warning(this,
            operation == "encrypt" ? "Ошибка шифрования" : "Ошибка расшифровки",
            QString("Не удалось %1 данные. Проверьте входные данные и ключ.")
                .arg(operation == "encrypt" ? "зашифровать" : "расшифровать"));
        return;
    }

    // Отображаем результат
    m_outputTextEdit->setPlainText(output);
    AppMessage::information(this, "Успех",
        QString("Данные успешно %1!")
            .arg(operation == "encrypt" ? "зашифрованы" : "расшифрованы"));

    // Сохраняем контекст операции для PDF
    m_lastOperation = (operation == "encrypt") ? OpEncrypt : OpDecrypt;
    m_lastInput = input;
    m_lastOutput = output;
    m_lastKey = keyPath;

    // Восстанавливаем состояние кнопок и активируем кнопку сохранения PDF только после успешного завершения
    updateEncryptDecryptButtonsState();
    if (m_savePdfButton) {
        m_savePdfButton->setEnabled(true);
    }
}

void KuznechikWidget::onBackClicked()
{
    // Возвращаемся в главное меню выбора
    emit backToMenu();
}

void KuznechikWidget::onSavePdfClicked()
{
    if (m_lastOperation == OpNone || m_lastOutput.trimmed().isEmpty()) {
        AppMessage::warning(this, "Нет данных", "Сначала получите результат, затем сохраните в PDF.");
        return;
    }

    const QString suggestedName = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") +
        (m_lastOperation == OpEncrypt ? "_encrypt.pdf" : "_decrypt.pdf");

    const QString defaultDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (QWidget *w = window()) { w->raise(); w->activateWindow(); }

    QFileDialog saveDialog(this, "Сохранить результат в PDF", defaultDir + "/" + suggestedName, "PDF (*.pdf)");
    saveDialog.setAcceptMode(QFileDialog::AcceptSave);
    saveDialog.setFileMode(QFileDialog::AnyFile);
    saveDialog.setWindowModality(Qt::ApplicationModal);
    saveDialog.setNameFilter("PDF (*.pdf)");
    saveDialog.setDefaultSuffix("pdf");
    saveDialog.setDirectory(defaultDir);
    saveDialog.selectFile(suggestedName);
    QString filePath;
    if (saveDialog.exec() == QDialog::Accepted) {
        const QStringList files = saveDialog.selectedFiles();
        if (!files.isEmpty()) filePath = files.first();
    }
    if (filePath.isEmpty()) {
        qDebug() << "Сохранение PDF отменено пользователем";
        AppMessage::information(this, "Отмена", "Сохранение отменено.");
        return;
    }

    QString finalPath = filePath;
    if (!finalPath.endsWith(".pdf", Qt::CaseInsensitive)) {
        finalPath += ".pdf";
    }
    qDebug() << "Путь для сохранения PDF:" << finalPath;

    // Запросим email для отображения в документе (запоминаем для следующих сохранений)
    if (m_userEmail.trimmed().isEmpty()) {
        bool ok = false;
        const QString email = QInputDialog::getText(
            this,
            "Ваш email",
            "Укажите почту для отображения в PDF (поле 'Автор' в тексте):",
            QLineEdit::Normal,
            QString(),
            &ok
        ).trimmed();
        if (ok && !email.isEmpty()) {
            m_userEmail = email;
        }
    }

    // Формируем HTML отчёт
    // Используем pt (points) вместо px для правильного масштабирования при печати
    QString html;
    html += "<html><head><meta charset='utf-8'>";
    html += "<style>";
    html += "body{font-family:Helvetica,Arial,sans-serif;color:#111827;font-size:14pt;line-height:1.4;}";
    html += "h1{font-size:24pt;font-weight:bold;margin:0 0 6pt 0;}";
    html += "h2{font-size:16pt;font-weight:bold;margin:28pt 0 10pt 0;}";  // Увеличенные отступы между разделами
    html += "p{font-size:14pt;margin:6pt 0;}";
    html += ".meta{font-size:11pt;color:#444444;margin:2pt 0;}";
    html += ".header{margin-bottom:20pt;}";  // Отступ после заголовка
    html += ".icon-cell{padding-right:32pt;}";  // Отступ иконки от текста
    html += "code{font-family:'Courier New',monospace;font-size:11pt;white-space:pre-wrap;word-break:break-word;background:#F5F5F5;padding:10pt 12pt;border-radius:4pt;display:block;border:1px solid #DDDDDD;margin:8pt 0;}";
    html += "</style></head><body>";

    // Загружаем иконку приложения и конвертируем в base64 для встраивания в PDF
    QString iconBase64;
    QFile iconFile(QCoreApplication::applicationDirPath() + "/../icons/app_icon.png");
    if (!iconFile.exists()) {
        iconFile.setFileName(QCoreApplication::applicationDirPath() + "/icons/app_icon.png");
    }
    if (!iconFile.exists()) {
        iconFile.setFileName("icons/app_icon.png");
    }
    if (iconFile.open(QIODevice::ReadOnly)) {
        QByteArray iconData = iconFile.readAll();
        iconBase64 = QString("data:image/png;base64,") + iconData.toBase64();
        iconFile.close();
    }

    if (m_currentAlgorithm == KuznechikAlgorithm) {
        // Отчёт для Кузнечик с иконкой
        html += "<div class='header'>";
        html += "<table cellpadding='0' cellspacing='0' border='0'><tr>";
        if (!iconBase64.isEmpty()) {
            html += QString("<td valign='top' class='icon-cell'><img src='%1' width='56' height='56'/></td>").arg(iconBase64);
        }
        html += "<td valign='top'>";
        html += QString("<h1>Отчёт Кузнечик (%1)</h1>")
                    .arg(m_lastOperation == OpEncrypt ? "Шифрование" : "Расшифрование");
        html += QString("<p class='meta'>Алгоритм: Кузнечик (ГОСТ Р 34.12-2015)</p>");
        html += QString("<p class='meta'>Время: %1</p>")
                    .arg(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss"));
        html += QString("<p class='meta'>Автор: %1</p>")
                    .arg(m_userEmail.isEmpty() ? QString("не указан") : m_userEmail.toHtmlEscaped());
        html += QString("<p class='meta'>Режим ввода: %1</p>")
                    .arg(m_currentMode == HexMode ? "Hex" : "Text");
        html += "</td></tr></table>";
        html += "</div>";

        html += "<h2>Ключ</h2><code>" + m_lastKey.toHtmlEscaped() + "</code>";

        if (m_lastOperation == OpEncrypt) {
            // Для шифрования: исходный, ключ, зашифрованный, проверочный расшифрованный
            html += "<h2>Исходные данные</h2><code>" + m_lastInput.toHtmlEscaped() + "</code>";
            html += "<h2>Зашифрованные данные</h2><code>" + m_lastOutput.toHtmlEscaped() + "</code>";
            // Проверка обратным преобразованием
            QString verifiedDecrypted;
            QByteArray key = KuznechikEncryption::fromHex(m_lastKey); // Статический метод остается
            if (m_currentMode == HexMode)
                verifiedDecrypted = m_cryptoFacade->decryptKuznechikHex(m_lastOutput, key);
            else
                verifiedDecrypted = m_cryptoFacade->decryptKuznechikText(m_lastOutput, key);
            if (!verifiedDecrypted.isEmpty())
                html += "<h2>Проверка (расшифровано обратно)</h2><code>" + verifiedDecrypted.toHtmlEscaped() + "</code>";
        } else {
            // Для расшифрования: исходный зашифрованный, ключ, расшифрованный
            html += "<h2>Исходные зашифрованные данные</h2><code>" + m_lastInput.toHtmlEscaped() + "</code>";
            html += "<h2>Расшифрованные данные</h2><code>" + m_lastOutput.toHtmlEscaped() + "</code>";
        }
    } else {
        // Отчёт для RSA с иконкой
        html += "<div class='header'>";
        html += "<table cellpadding='0' cellspacing='0' border='0'><tr>";
        if (!iconBase64.isEmpty()) {
            html += QString("<td valign='top' class='icon-cell'><img src='%1' width='56' height='56'/></td>").arg(iconBase64);
        }
        html += "<td valign='top'>";
        html += QString("<h1>Отчёт RSA (%1)</h1>")
                    .arg(m_lastOperation == OpEncrypt ? "Шифрование" : "Расшифрование");
        html += QString("<p class='meta'>Алгоритм: RSA</p>");
        html += QString("<p class='meta'>Время: %1</p>")
                    .arg(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss"));
        html += QString("<p class='meta'>Автор: %1</p>")
                    .arg(m_userEmail.isEmpty() ? QString("не указан") : m_userEmail.toHtmlEscaped());
        html += "</td></tr></table>";
        html += "</div>";

        // Определяем режим (Text или Hex) для RSA
        int modeId = m_rsaModeGroup ? m_rsaModeGroup->checkedId() : TextMode;
        bool isHexMode = (modeId == HexMode);
        html += QString("<small>Режим ввода: %1</small>")
                    .arg(isHexMode ? "Hex" : "Text");

        // Читаем ключ из файла для отображения в PDF
        // Для шифрования RSA показываем приватный ключ (парный к использованному публичному)
        // Для расшифровки RSA показываем публичный ключ (парный к использованному приватному)
        QString keyFilePath = m_lastKey;
        QString keyType;
        QString keyContent;

        if (m_lastOperation == OpEncrypt) {
            // Шифрование: использован публичный ключ, показываем приватный
            QFileInfo keyInfo(keyFilePath);
            QString fileName = keyInfo.fileName();
            QString privateFileName = fileName;
            privateFileName.replace("_public_", "_private_");
            QString privateKeyPath = QDir(keyInfo.absolutePath()).absoluteFilePath(privateFileName);

            if (QFile::exists(privateKeyPath)) {
                keyFilePath = privateKeyPath;
                keyType = "Приватный ключ";
            } else {
                keyType = "Ключ не найден";
                keyContent = "Парный приватный ключ не найден";
            }
        } else {
            // Расшифровка: использован приватный ключ, показываем публичный
            QFileInfo keyInfo(keyFilePath);
            QString fileName = keyInfo.fileName();
            QString publicFileName = fileName;
            publicFileName.replace("_private_", "_public_");
            QString publicKeyPath = QDir(keyInfo.absolutePath()).absoluteFilePath(publicFileName);

            if (QFile::exists(publicKeyPath)) {
                keyFilePath = publicKeyPath;
                keyType = "Публичный ключ";
            } else {
                keyType = "Ключ не найден";
                keyContent = "Парный публичный ключ не найден";
            }
        }

        // Читаем ключ из файла
        if (keyContent.isEmpty()) {
            QFile keyFile(keyFilePath);
            if (keyFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QTextStream stream(&keyFile);
                QString fileContent = stream.readAll();
                keyFile.close();

                // Извлекаем Modulus и Exponent из файла
                QStringList lines = fileContent.split('\n', Qt::SkipEmptyParts);
                QString modulus, exponent;
                bool inModulus = false, inExponent = false;

                for (const QString &line : lines) {
                    QString trimmed = line.trimmed();
                    if (trimmed.contains("Modulus (n):")) {
                        inModulus = true;
                        inExponent = false;
                        continue;
                    } else if (trimmed.contains("Public Exponent (e):") || trimmed.contains("Private Exponent (d):")) {
                        inModulus = false;
                        inExponent = true;
                        continue;
                    } else if (trimmed.startsWith("#") || trimmed.isEmpty()) {
                        continue;
                    }

                    if (inModulus && modulus.isEmpty()) {
                        modulus = trimmed;
                    } else if (inExponent && exponent.isEmpty()) {
                        exponent = trimmed;
                    }
                }

                keyContent = QString();
                if (!modulus.isEmpty()) {
                    keyContent += QString("Modulus (n): %1\n").arg(modulus);
                }
                if (!exponent.isEmpty()) {
                    keyContent += QString("Exponent: %1\n").arg(exponent);
                }
                if (modulus.isEmpty() && exponent.isEmpty()) {
                    keyContent = "Не удалось извлечь ключ из файла";
                }
            } else {
                keyContent = "Не удалось открыть файл ключа";
            }
        }

        html += QString("<h2>%1</h2><code>%2</code>")
                    .arg(keyType)
                    .arg(keyContent.toHtmlEscaped());

        if (m_lastOperation == OpEncrypt) {
            // Для шифрования: исходный, зашифрованный
            html += "<h2>Исходные данные</h2><code>" + m_lastInput.toHtmlEscaped() + "</code>";
            html += "<h2>Зашифрованные данные</h2><code>" + m_lastOutput.toHtmlEscaped() + "</code>";
        } else {
            // Для расшифрования: исходный зашифрованный, расшифрованный
            html += "<h2>Исходные зашифрованные данные</h2><code>" + m_lastInput.toHtmlEscaped() + "</code>";
            html += "<h2>Расшифрованные данные</h2><code>" + m_lastOutput.toHtmlEscaped() + "</code>";
        }
    }

    html += "</body></html>";

    // Печатаем в PDF используя стандартный метод Qt (более надежный)
    QTextDocument doc;
    doc.setHtml(html);

    // Устанавливаем метаданные документа:
    // Author в свойствах файла = "3FA-Signer" (для RSA и Kuznechik)
    // В тексте документа = email пользователя
    doc.setMetaInformation(QTextDocument::DocumentTitle,
        m_currentAlgorithm == KuznechikAlgorithm ? "Отчёт Кузнечик" : "Отчёт RSA");

    QPrinter printer(QPrinter::HighResolution);
    printer.setOutputFormat(QPrinter::PdfFormat);
    printer.setOutputFileName(finalPath);

    // Устанавливаем Creator в метаданных PDF = "3FA-Signer"
    // Это будет видно в свойствах файла PDF как "Автор приложения"
    printer.setCreator("3FA-Signer");
    // Устанавливаем DocName который используется как Author в PDF метаданных
    printer.setDocName("3FA-Signer");

    printer.setPageSize(QPageSize(QPageSize::A4));
    printer.setPageMargins(QMarginsF(20, 20, 20, 20), QPageLayout::Millimeter);

    // Используем стандартный метод print() - он более надежен чем QPainter
    // doc.print() правильно обрабатывает многостраничные документы и структуру PDF
    doc.print(&printer);

    // Ждем завершения записи PDF: отслеживаем размер и наличие %%EOF
    QFileInfo fi(finalPath);
    qint64 stableSize = -1;
    bool eofFound = false;
    const int maxIterations = 30;
    for (int i = 0; i < maxIterations; ++i) {
        QCoreApplication::processEvents();
        fi.refresh();
        qint64 currentSize = fi.size();
        if (currentSize > 0 && currentSize == stableSize) {
            QFile tailFile(finalPath);
            if (tailFile.open(QIODevice::ReadOnly)) {
                const qint64 tailBytes = 4096;
                if (tailFile.size() > tailBytes) {
                    tailFile.seek(tailFile.size() - tailBytes);
                }
                QByteArray tail = tailFile.read(tailBytes);
                tailFile.close();
                if (tail.contains("%%EOF")) {
                    eofFound = true;
                    break;
                }
            }
        }
        stableSize = currentSize;
        QThread::msleep(100);
    }

    if (!eofFound) {
        QFile tailFile(finalPath);
        if (tailFile.open(QIODevice::ReadOnly)) {
            const qint64 tailBytes = 4096;
            if (tailFile.size() > tailBytes) {
                tailFile.seek(tailFile.size() - tailBytes);
            }
            QByteArray tail = tailFile.read(tailBytes);
            tailFile.close();
            eofFound = tail.contains("%%EOF");
        }
    }

    // Проверяем, что файл действительно создан и не пустой
    fi.refresh();
    if (!fi.exists() || fi.size() == 0) {
        qDebug() << "Сохранение PDF не удалось или пустой файл:" << finalPath;
        AppMessage::warning(this, "Ошибка", "Не удалось сохранить PDF. Проверьте доступ к выбранной папке.");
        return;
    }
    if (!eofFound) {
        qWarning() << "Сгенерированный PDF не содержит %%EOF, файл может быть неполным";
        AppMessage::warning(this, "Ошибка",
            "Сгенерированный PDF не удалось корректно сохранить. Попробуйте ещё раз.");
        return;
    }

    // Проверяем, что PDF валиден (начинается с %PDF)
    QFile checkFile(finalPath);
    if (checkFile.open(QIODevice::ReadOnly)) {
        QByteArray header = checkFile.read(4);
        checkFile.close();
        if (header != "%PDF") {
            qWarning() << "Сгенерированный PDF поврежден (заголовок:" << header << ")";
            AppMessage::warning(this, "Ошибка",
                "Сгенерированный PDF поврежден. Попробуйте снова или проверьте настройки принтера.");
            return;
        }
    }

    qDebug() << "PDF успешно сохранён:" << finalPath << ", размер:" << fi.size() << "байт";

    // pyHanko handles PDF preprocessing internally, so we don't need qpdf preprocessing
    // Just use the original PDF directly - pyHanko will handle it correctly
    QString pdfForSigning = finalPath;
    QString sanitizedPath;  // Not used anymore, kept for cleanup compatibility

    // Проверяем, что PDF содержит %%EOF перед отправкой на сервер
    QFile checkEofFile(pdfForSigning);
    if (checkEofFile.open(QIODevice::ReadOnly)) {
        const qint64 tailBytes = 2048;
        qint64 fileSize = checkEofFile.size();
        if (fileSize > tailBytes) {
            checkEofFile.seek(fileSize - tailBytes);
        }
        QByteArray tail = checkEofFile.read(tailBytes);
        checkEofFile.close();
        if (!tail.contains("%%EOF")) {
            qWarning() << "PDF не содержит %%EOF маркер, файл может быть поврежден";
            AppMessage::warning(this, "Ошибка",
                "Сгенерированный PDF не содержит обязательный маркер %%EOF и не может быть подписан.\n"
                "Попробуйте сохранить PDF еще раз.");
            return;
        }
    }

    // =========================================================================
    // ПОДПИСЬ ЭЦП ВКЛЮЧЕНА
    // =========================================================================
    // Отправляем PDF на сервер подписи для добавления электронной подписи
    // =========================================================================

    // Отправляем PDF на сервер подписи
    QFile pdfFile(pdfForSigning);
    if (!pdfFile.open(QIODevice::ReadOnly)) {
        AppMessage::warning(this, "Ошибка", "Не удалось открыть PDF для подписи.");
        return;
    }

    QByteArray pdfData = pdfFile.readAll();
    pdfFile.close();
    qDebug() << "Отправляем PDF на подпись:" << pdfForSigning << "bytes:" << pdfData.size();

    // Дополнительная проверка: убеждаемся, что PDF данные не пустые
    if (pdfData.isEmpty()) {
        AppMessage::warning(this, "Ошибка", "PDF файл пуст, не удалось прочитать данные для подписи.");
        return;
    }

    // Формируем запрос к серверу подписи
    // Используем фиксированное имя "3FA-Signer" для подписи
    QString cn = "3FA-Signer";
    QUrl url(QString("http://%1:%2/pdf-sign-embed").arg(m_serverBindAddr).arg(m_serverPort));
    QUrlQuery query;
    query.addQueryItem("cn", cn);
    query.addQueryItem("san", QString("DNS:%1").arg(cn));
    // Используем английский текст для видимой подписи (Helvetica не поддерживает кириллицу)
    query.addQueryItem("reason", "Document signing");
    query.addQueryItem("location", "3FA Application");

    // Добавляем TSA URL для метки времени, если он указан в переменной окружения
    QString tsaUrl = qEnvironmentVariable("TSA_URL");
    if (!tsaUrl.isEmpty()) {
        query.addQueryItem("tsa-url", tsaUrl);
        qDebug() << "Добавлен TSA URL для метки времени:" << tsaUrl;
    }

    url.setQuery(query);

    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/pdf");
    request.setRawHeader("Content-Length", QByteArray::number(pdfData.size()));

    // Устанавливаем таймауты для запроса (5 минут на выполнение)
    request.setTransferTimeout(300000); // 5 минут для больших PDF
    request.setAttribute(QNetworkRequest::HttpPipeliningAllowedAttribute, false);

    QNetworkReply *reply = m_networkManager->post(request, pdfData);

    // Устанавливаем дополнительные настройки для reply
    reply->setReadBufferSize(pdfData.size() * 2); // Увеличиваем буфер чтения
    reply->setProperty("finalPath", finalPath);
    if (!sanitizedPath.isEmpty() && pdfForSigning == sanitizedPath) {
        reply->setProperty("sanitizedPath", sanitizedPath);
    }
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { onPdfSigned(reply); });

    // Обрабатываем ошибки, которые могут возникнуть до завершения
    connect(reply, QOverload<QNetworkReply::NetworkError>::of(&QNetworkReply::errorOccurred),
            this, [this, reply](QNetworkReply::NetworkError error) {
        qWarning() << "PDF signing network error occurred:" << error << reply->errorString();
    });
    return;  // Выходим из функции, результат будет показан в onPdfSigned
}

void KuznechikWidget::onPdfSigned(QNetworkReply *reply)
{
    QString finalPath = reply->property("finalPath").toString();
    const QString sanitizedPath = reply->property("sanitizedPath").toString();

    if (reply->error() != QNetworkReply::NoError) {
        qWarning() << "PDF signing failed:" << reply->errorString();
        // При ошибке подключения (сервер недоступен) информируем, что PDF сохранён без подписи
        if (reply->error() == QNetworkReply::ConnectionRefusedError ||
            reply->error() == QNetworkReply::RemoteHostClosedError) {
            AppMessage::information(this, "PDF сохранён",
                QString("PDF успешно сохранён:\n%1\n\nСервер подписи недоступен, PDF сохранён без подписи.")
                    .arg(finalPath));
        } else {
            AppMessage::warning(this, "Ошибка подписи",
                QString("Не удалось подписать PDF:\n%1\n\nPDF сохранён без подписи:\n%2")
                    .arg(reply->errorString())
                    .arg(finalPath));
        }

        // Сохраняем неподписанный PDF в базу данных при ошибке
        if (m_database && m_userId >= 0 && QFile::exists(finalPath)) {
            QFile pdfFile(finalPath);
            if (pdfFile.open(QIODevice::ReadOnly)) {
                QByteArray pdfData = pdfFile.readAll();
                pdfFile.close();
                if (!pdfData.isEmpty()) {
                    QFileInfo fileInfo(finalPath);
                    QString filename = fileInfo.fileName();
                    QString algorithm = (m_currentAlgorithm == KuznechikAlgorithm) ? "Kuznechik" : "RSA";
                    QString operation = (m_lastOperation == OpEncrypt) ? "encrypt" : (m_lastOperation == OpDecrypt) ? "decrypt" : "";

                    if (m_database->saveUserPdf(m_userId, pdfData, filename, algorithm, operation)) {
                        qDebug() << "Неподписанный PDF сохранён в базу данных для пользователя ID:" << m_userId;
                    } else {
                        qWarning() << "Не удалось сохранить неподписанный PDF в базу данных:" << m_database->getLastError();
                    }
                }
            }
        }

        reply->deleteLater();
        if (!sanitizedPath.isEmpty()) {
            QFile::remove(sanitizedPath);
        }
        return;
    }

    int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (httpStatus != 200) {
        qWarning() << "PDF signing failed, HTTP status:" << httpStatus;
        QByteArray errorBody = reply->readAll();
        QString errorMsg = QString::fromUtf8(errorBody);
        if (errorMsg.isEmpty()) {
            errorMsg = QString("HTTP %1").arg(httpStatus);
        }
        AppMessage::warning(this, "Ошибка подписи",
            QString("Не удалось подписать PDF:\n%1\n\nPDF сохранён без подписи:\n%2")
                .arg(errorMsg)
                .arg(finalPath));

        // Сохраняем неподписанный PDF в базу данных при ошибке HTTP
        if (m_database && m_userId >= 0 && QFile::exists(finalPath)) {
            QFile pdfFile(finalPath);
            if (pdfFile.open(QIODevice::ReadOnly)) {
                QByteArray pdfData = pdfFile.readAll();
                pdfFile.close();
                if (!pdfData.isEmpty()) {
                    QFileInfo fileInfo(finalPath);
                    QString filename = fileInfo.fileName();
                    QString algorithm = (m_currentAlgorithm == KuznechikAlgorithm) ? "Kuznechik" : "RSA";
                    QString operation = (m_lastOperation == OpEncrypt) ? "encrypt" : (m_lastOperation == OpDecrypt) ? "decrypt" : "";

                    if (m_database->saveUserPdf(m_userId, pdfData, filename, algorithm, operation)) {
                        qDebug() << "Неподписанный PDF сохранён в базу данных для пользователя ID:" << m_userId;
                    } else {
                        qWarning() << "Не удалось сохранить неподписанный PDF в базу данных:" << m_database->getLastError();
                    }
                }
            }
        }

        reply->deleteLater();
        if (!sanitizedPath.isEmpty()) {
            QFile::remove(sanitizedPath);
        }
        return;
    }

    // Сохраняем подписанный PDF
    // Читаем данные полностью, чтобы убедиться, что все данные получены
    QByteArray signedPdf;
    while (reply->bytesAvailable() > 0) {
        signedPdf.append(reply->readAll());
        QCoreApplication::processEvents(); // Обрабатываем события пока читаем
    }

    // Если данных не осталось, читаем все что есть
    if (signedPdf.isEmpty()) {
        signedPdf = reply->readAll();
    }

    reply->deleteLater();

    if (!sanitizedPath.isEmpty()) {
        QFile::remove(sanitizedPath);
    }

    QFile signedFile(finalPath);
    if (!signedFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        AppMessage::warning(this, "Ошибка", "Не удалось сохранить подписанный PDF.");
        return;
    }

    signedFile.write(signedPdf);
    signedFile.close();

    qDebug() << "PDF подписан и сохранён:" << finalPath << ", размер:" << signedPdf.size() << "байт";

    // Сохраняем PDF в базу данных под текущим пользователем
    if (m_database && m_userId >= 0) {
        QFileInfo fileInfo(finalPath);
        QString filename = fileInfo.fileName();
        QString algorithm = (m_currentAlgorithm == KuznechikAlgorithm) ? "Kuznechik" : "RSA";
        QString operation = (m_lastOperation == OpEncrypt) ? "encrypt" : (m_lastOperation == OpDecrypt) ? "decrypt" : "";

        if (m_database->saveUserPdf(m_userId, signedPdf, filename, algorithm, operation)) {
            qDebug() << "PDF успешно сохранён в базу данных для пользователя ID:" << m_userId;
        } else {
            qWarning() << "Не удалось сохранить PDF в базу данных:" << m_database->getLastError();
        }
    } else {
        qWarning() << "Не удалось сохранить PDF в БД: Database или userId не установлены";
    }

    // Автоматическая проверка ЭЦП после создания файла
    // Определяем путь к скрипту verify_pdf_signature.py
    // Аналогично mainwindow.cpp: определяем корень проекта от директории приложения
    QDir appDir(QCoreApplication::applicationDirPath());
    QDir projectDir = appDir;
    // macOS bundle: <project>/build/3FA.app/Contents/MacOS
    if (appDir.absolutePath().contains("/Contents/MacOS")) {
        // Поднимаемся от Contents/MacOS до корня проекта
        while (!projectDir.exists("CMakeLists.txt") && projectDir.cdUp()) {
            if (projectDir.isRoot()) break;
        }
    } else {
        // Обычный случай: бинарь в build/ → поднимаемся на один уровень к корню проекта
        QDir tryBuildParent(projectDir.absoluteFilePath(".."));
        if (tryBuildParent.exists("CMakeLists.txt")) {
            projectDir = tryBuildParent;
        } else {
            // Поднимаемся до корня проекта
            while (!projectDir.exists("CMakeLists.txt") && projectDir.cdUp()) {
                if (projectDir.isRoot()) break;
            }
        }
    }

    QString verifyScriptPath = projectDir.absoluteFilePath("ca/verify_pdf_signature.py");
    QString rootCertPath = projectDir.absoluteFilePath("ca/root.crt");

    if (QFile::exists(verifyScriptPath)) {
        qDebug() << "=== Запуск проверки ЭЦП ===";

        QProcess *verifyProcess = new QProcess(this);
        verifyProcess->setProcessChannelMode(QProcess::MergedChannels);

        // Подключаем вывод скрипта к консоли
        connect(verifyProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                [this, verifyProcess](int exitCode, QProcess::ExitStatus exitStatus) {
            QByteArray output = verifyProcess->readAllStandardOutput();
            QString outputStr = QString::fromUtf8(output);

            // Выводим результаты проверки в консоль
            qDebug() << "\n=== Результаты проверки ЭЦП ===";
            QStringList lines = outputStr.split('\n', Qt::SkipEmptyParts);
            for (const QString &line : lines) {
                qDebug() << line;
            }
            qDebug() << "=== Конец результатов проверки ===\n";

            verifyProcess->deleteLater();
        });

        // Запускаем скрипт проверки с путем к подписанному PDF и корневому сертификату
        QStringList args;
        args << verifyScriptPath << finalPath;
        if (QFile::exists(rootCertPath)) {
            args << rootCertPath;
        }

        verifyProcess->start("python3", args);

        if (!verifyProcess->waitForStarted(3000)) {
            qWarning() << "Не удалось запустить скрипт проверки ЭЦП:" << verifyProcess->errorString();
            verifyProcess->deleteLater();
        } else {
            qDebug() << "Скрипт проверки ЭЦП запущен...";
        }
    } else {
        qWarning() << "Скрипт проверки ЭЦП не найден:" << verifyScriptPath;
    }

    AppMessage::information(this, "Готово",
        QString("PDF сохранён и подписан сертификатом центра сертификации.\n\nФайл: %1\nРазмер: %2 байт")
            .arg(finalPath).arg(signedPdf.size()));
}
