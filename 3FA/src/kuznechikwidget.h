#ifndef KUZNECHIKWIDGET_H
#define KUZNECHIKWIDGET_H

#include <QWidget>
#include "materialcombobox.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QTextEdit>
#include <QLabel>
#include <QLineEdit>
#include <QButtonGroup>
#include <QRadioButton>
#include <QGroupBox>
#include <QFrame>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QFileDialog>
#include <QComboBox>
#include <QProgressDialog>
#include <QProgressBar>
#include <QInputDialog>
#include <QStandardPaths>
#include <QApplication>
#include <QFutureWatcher>
#include <QtConcurrent/QtConcurrent>
#include <QVariantMap>
#include <atomic>
#include <memory>
#include "cryptofacade.h"
#include "BigInt.h"
#include "RSAKeyManager.h"
#include "PrimeFileManager.h"
#include "database.h"

class AlgorithmSelector;

/**
 * @brief Виджет для шифрования/расшифрования данных алгоритмом Кузнечик
 * 
 * Предоставляет графический интерфейс для работы с алгоритмом шифрования
 * Кузнечик (ГОСТ Р 34.12-2015) с выбором режима работы: шифрование байтов
 * или текста, аналогично функциональности main.cpp проекта Kuznechik.
 */
class KuznechikWidget : public QWidget
{
    Q_OBJECT

public:
    explicit KuznechikWidget(QWidget *parent = nullptr);
    ~KuznechikWidget();
    void setUserEmail(const QString &email) { m_userEmail = email; }
    void setUserId(int userId);
    void setDatabase(Database *database) { m_database = database; }

private slots:
    void onEncryptClicked();
    void onDecryptClicked();
    void onGenerateKeyClicked();
    void onGeneratePrimesClicked();  // Генерация простых чисел для RSA
    void onPublicKeySelected(int index);   // Выбор публичного ключа
    void onPrivateKeySelected(int index);  // Выбор приватного ключа
    void onModeChanged(int id);
    void onAlgorithmChanged(int id);
    void onBackClicked();
    void onSavePdfClicked();
    void onSelectPrimesDirectory();
    void onPrimeSelectionChanged();
    void onKeyNameChanged(const QString& text);
    void onGenerateKeyPairClicked();
    void onSaveKeyPairClicked();
    void onKeyGenerationFinished();
    void onKeySaveFinished();
    void onEncryptDecryptFinished();

signals:
    void backToMenu();
    void logoutRequested();  // Сигнал для выхода из системы и возврата к первому фактору

private:
    void setupUI();
    void loadServerConfig();  // Загрузка конфигурации сервера из JSON
    void loadRSAKeysFromDirectory(const QString &preferredPublicKey = {});
    void loadKuznechikKeys();
    void selectKuznechikKey(int index);
    void createSavedRsaPair();
    QString managedKeyDirectory(const QString &algorithm) const;
    void generateRSAKeys();  // Генерация RSA ключей
    void updateRSAUI();       // Обновление UI для RSA режима
    void updateRsaTypeLabel();  // Обновление метки типа RSA на основе выбранных ключей
    void updateEncryptDecryptButtonsState();  // Обновление состояния кнопок "Зашифровать" и "Расшифровать"
    void validateRSAKeys(const QString &publicKeyPath, const QString &privateKeyPath);

    // Алгоритмы шифрования
    enum AlgorithmType {
        KuznechikAlgorithm,  // Алгоритм Кузнечик (ГОСТ Р 34.12-2015)
        RSAAlgorithm        // RSA алгоритм
    };
    
    AlgorithmType m_currentAlgorithm = KuznechikAlgorithm;
    
    // Режимы шифрования (для Кузнечик)
    enum EncryptionMode {
        HexMode,    // Шифрование байтов в hex формате
        TextMode    // Шифрование текста
    };
    
    EncryptionMode m_currentMode;
    
    // UI компоненты
    QFrame *m_card;
    QLabel *m_titleLabel;
    QLabel *m_subtitleLabel;
    
    // Выбор алгоритма (Кузнечик/RSA)
    AlgorithmSelector *m_algorithmSwitch;
    
    // Выбор режима (для Кузнечик)
    QLabel *m_modeLabel;              // Метка "Режим:" для Кузнечика
    QButtonGroup *m_modeGroup;
    QRadioButton *m_hexModeRadio;
    QRadioButton *m_textModeRadio;
    QLabel *m_rsaModeLabel;
    QButtonGroup *m_rsaModeGroup;
    QRadioButton *m_rsaTextModeRadio;
    QRadioButton *m_rsaHexModeRadio;
    
    // Ввод ключа для Кузнечик
    QLabel *m_keyLabel;
    QLineEdit *m_keyEdit;
    QPushButton *m_generateKeyButton;
    QComboBox *m_kuznechikKeys;
    QGroupBox *m_savedRsaGroup;
    QComboBox *m_rsaKeyBits;
    QPushButton *m_createRsaPair;
    QLabel *m_savedRsaStatus;
    std::shared_ptr<std::atomic_bool> m_cancelRsa;
    QGroupBox *m_primeGeneratorGroup;
    QLineEdit *m_primeBitsEdit;
    QPushButton *m_generatePrimeButton;
    QPushButton *m_savePrimeButton;
    QProgressBar *m_primeGenerationProgress;
    QLabel *m_primeGenerationStatusLabel;
    QString m_generatedPrimeDecimal;
    QString m_generatedPrimeHex;
    int m_generatedPrimeBits = 0;
    
    // Выбор простых чисел и генерация RSA ключей
    QGroupBox *m_primeSelectionGroup;
    QPushButton *m_selectPrimesDirButton;
    MaterialComboBox *m_primeFirstCombo;
    MaterialComboBox *m_primeSecondCombo;
    QLabel *m_primesStatusLabel;
    QLineEdit *m_rsaKeyNameEdit;
    QPushButton *m_generateRsaKeysButton;
    QPushButton *m_saveRsaKeysButton;
    QProgressBar *m_keyGenerationProgress;
    QLabel *m_keyGenerationIndicator;
    QLabel *m_rsaTypeLabel;
    QLabel *m_rsaStatusLabel;
    
    QLabel *m_publicKeyLabel;
    MaterialComboBox *m_publicKeyCombo;
    QLabel *m_privateKeyLabel;
    MaterialComboBox *m_privateKeyCombo;
    bool m_primeGenerationActive = false;
    
    // Ввод данных
    QLabel *m_inputLabel;
    QTextEdit *m_inputTextEdit;
    
    // Кнопки действий
    QPushButton *m_encryptButton;
    QPushButton *m_decryptButton;
    QPushButton *m_backButton;
    QPushButton *m_savePdfButton;
    
    // Layout'ы для кнопок действий (вертикальный для Кузнечика, горизонтальный для RSA)
    QVBoxLayout *m_encryptDecryptVerticalLayout;
    QHBoxLayout *m_encryptDecryptHorizontalLayout;
    QWidget *m_encryptDecryptVerticalContainer;  // Контейнер с вертикальным layout
    QWidget *m_encryptDecryptHorizontalContainer;  // Контейнер с горизонтальным layout
    
    // Вывод результата
    QLabel *m_outputLabel;
    QTextEdit *m_outputTextEdit;
    
    // Сервисы шифрования
    CryptoFacade *m_cryptoFacade;
    RSAKeyManager *m_rsaKeyManager;
    PrimeFileManager *m_primeFileManager;

    // Параметры выбора простых чисел
    QString m_primesDirectory;
    QString m_selectedPrimePath1;
    QString m_selectedPrimePath2;
    int m_selectedPrimeBits1 = 0;
    int m_selectedPrimeBits2 = 0;
    int m_generatedKeySize = 0;
    QString m_lastGeneratedKeyName;
    QFutureWatcher<QVariantMap> *m_keyGenerationWatcher;
    QFutureWatcher<QVariantMap> *m_keySaveWatcher;
    QFutureWatcher<QVariantMap> *m_primeGenerationWatcher;
    QFutureWatcher<bool> *m_defaultPrimesWatcher = nullptr;
    QFutureWatcher<QVariantMap> *m_encryptDecryptWatcher;

    // Данные последней операции для экспорта
    enum LastOperation { OpNone, OpEncrypt, OpDecrypt };
    LastOperation m_lastOperation = OpNone;
    QString m_lastInput;
    QString m_lastOutput;
    QString m_lastKey;
    QString m_userEmail;
    int m_userId = -1;
    Database *m_database = nullptr;
    QNetworkAccessManager *m_networkManager;
    
    // Server configuration
    QString m_serverBindAddr;
    int m_serverPort;
    
    // Утилиты
    void refreshPrimeSelections();
    void updatePrimeControlsState();
    QVariantMap currentPrimeData(MaterialComboBox *combo) const;
    bool loadPrimeFromPath(const QString &path, BigInt &prime, QString &errorMessage) const;
    QString resolveDefaultPrimesDirectory() const;
    void prepareDefaultPrimes();
    QVariantMap makePrimeData(const QFileInfo &info) const;
    void ensureKeyGenerationWatcher();
    void ensureKeySaveWatcher();
    void ensurePrimeGenerationWatcher();
    void ensureEncryptDecryptWatcher();
    QString resolveProjectRoot() const;
    QString resolveRsaKeysDirectory() const;
    void updatePrimeGeneratorWidgets(bool primeGenerating);
    void setPrimeBitsFieldState(bool valid);
    bool isPrimeBitSizeValid() const;
    void resetPrimeGenerationState();

private slots:
    void onPdfSigned(QNetworkReply *reply);
    void onPrimeBitSizeEdited(const QString &text);
    void onGeneratePrimeNumber();
    void onPrimeGenerationFinished();
    void onSavePrimeNumber();
};

#endif // KUZNECHIKWIDGET_H
