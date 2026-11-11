#pragma once

class QString;
class QWidget;

namespace AppMessage {
enum class Kind { Information, Warning, Error };

void show(QWidget *parent, const QString &title, const QString &text, Kind kind = Kind::Information);
void persistent(QWidget *parent, const QString &title, const QString &text, Kind kind = Kind::Information);
void information(QWidget *parent, const QString &title, const QString &text);
void warning(QWidget *parent, const QString &title, const QString &text);
void critical(QWidget *parent, const QString &title, const QString &text);
bool confirm(QWidget *parent, const QString &title, const QString &text, const QString &action);
}
