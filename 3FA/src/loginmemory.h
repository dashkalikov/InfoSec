#pragma once

#include <QString>
#include <optional>

namespace LoginMemory {
struct Fields {
    QString email;
    QString password;
};

bool canSavePassword();
Fields restore();
void remember(const QString &email, const std::optional<QString> &password);
}
