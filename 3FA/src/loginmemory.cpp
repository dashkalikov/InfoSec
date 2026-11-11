#include "loginmemory.h"

#include <QSettings>
#include <openssl/crypto.h>

#ifdef Q_OS_WIN
#include <windows.h>
#include <dpapi.h>
#elif defined(Q_OS_LINUX)
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QProcess>
#include <QStandardPaths>
#endif

namespace {
constexpr auto emailKey = "signin/email";
constexpr auto passwordKey = "signin/password";

#ifdef Q_OS_WIN
DATA_BLOB asBlob(QByteArray &bytes)
{
    return {static_cast<DWORD>(bytes.size()), reinterpret_cast<BYTE *>(bytes.data())};
}

QByteArray protect(QByteArray &data, const QString &email, bool encrypt)
{
    auto emailBytes = email.toUtf8();
    auto input = asBlob(data);
    auto entropy = asBlob(emailBytes);
    DATA_BLOB output{};
    const bool ok = encrypt
        ? CryptProtectData(&input, L"3FA", &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)
        : CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output);
    if (!ok) return {};
    QByteArray result(reinterpret_cast<const char *>(output.pbData), output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    return result;
}
#elif defined(Q_OS_LINUX)
QString secretTool()
{
    const auto runtime = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
    if (!qEnvironmentVariableIsSet("DBUS_SESSION_BUS_ADDRESS") &&
        (runtime.isEmpty() || !QFileInfo::exists(QDir(runtime).filePath("bus")))) return {};
    return QStandardPaths::findExecutable("secret-tool", {"/usr/bin", "/bin", "/usr/local/bin"});
}

bool runSecretTool(QStringList arguments, QByteArray *secret = nullptr)
{
    const auto tool = secretTool();
    if (tool.isEmpty()) return false;
    const bool storing = arguments.first() == "store";
    arguments << "application" << QCoreApplication::organizationName() + '/' + QCoreApplication::applicationName()
              << "slot" << "last-login";
    QProcess process;
    process.start(tool, arguments);
    if (!process.waitForStarted(500)) return false;
    if (storing) process.write(*secret);
    process.closeWriteChannel();
    if (!process.waitForFinished(1500)) {
        process.kill();
        process.waitForFinished(500);
        return false;
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) return false;
    if (secret && !storing) *secret = process.readAllStandardOutput();
    return true;
}
#endif
}

bool LoginMemory::canSavePassword()
{
#ifdef Q_OS_WIN
    return true;
#elif defined(Q_OS_LINUX)
    return !secretTool().isEmpty();
#else
    return false;
#endif
}

LoginMemory::Fields LoginMemory::restore()
{
    const QSettings settings;
    Fields fields{settings.value(emailKey).toString(), {}};
    if (fields.email.isEmpty() || !settings.contains(passwordKey)) return fields;
    QByteArray secret;
#ifdef Q_OS_WIN
    auto encrypted = settings.value(passwordKey).toByteArray();
    secret = protect(encrypted, fields.email, false);
#elif defined(Q_OS_LINUX)
    if (runSecretTool({"lookup"}, &secret)) {
        const QByteArray prefix = fields.email.toUtf8() + '\n';
        if (secret.startsWith(prefix)) fields.password = QString::fromUtf8(secret.constData() + prefix.size(), secret.size() - prefix.size());
    }
#endif
#ifdef Q_OS_WIN
    fields.password = QString::fromUtf8(secret);
#endif
    if (!secret.isEmpty()) OPENSSL_cleanse(secret.data(), secret.size());
    return fields;
}

void LoginMemory::remember(const QString &email, const std::optional<QString> &password)
{
    if (email.isEmpty()) return;
    QSettings settings;
    if (!password && settings.value(emailKey).toString() == email) return;
#ifdef Q_OS_LINUX
    const bool hadPassword = settings.contains(passwordKey);
#endif
    settings.setValue(emailKey, email);
    settings.remove(passwordKey);
    if (!password || password->isEmpty()) {
#ifdef Q_OS_LINUX
        if (hadPassword) runSecretTool({"clear"});
#endif
        return;
    }

    auto secret = password->toUtf8();
#ifdef Q_OS_WIN
    const auto encrypted = protect(secret, email, true);
    if (!encrypted.isEmpty()) settings.setValue(passwordKey, encrypted);
#elif defined(Q_OS_LINUX)
    secret.prepend(email.toUtf8() + '\n');
    if (runSecretTool({"store", "--label=3FA"}, &secret)) settings.setValue(passwordKey, true);
    else if (hadPassword) runSecretTool({"clear"});
#endif
    OPENSSL_cleanse(secret.data(), secret.size());
}
