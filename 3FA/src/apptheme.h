#ifndef APPTHEME_H
#define APPTHEME_H

#include <QIcon>
#include <QString>

class QAbstractButton;
class QColor;
class QLayout;
class QTableWidget;
class QVBoxLayout;
class QWidget;

namespace AppTheme {
void restore();
void setDark(bool dark);
bool isDark();
QColor primaryColor();
int zoomPercent();
void setZoomPercent(int percent);
int pixels(int value);
void dimension(QWidget *widget, const char *property, int value);
void fixedWidth(QWidget *widget, int width);
void fixedHeight(QWidget *widget, int height);
void fixedSize(QWidget *widget, int width, int height);
void margins(QLayout *layout, int left, int top, int right, int bottom);
void spacing(QLayout *layout, int value);
void centerBlock(QVBoxLayout *layout, QWidget *block);
QVBoxLayout *centeredCard(QWidget *page, int width);
QTableWidget *createAdminTable();
void setTableCell(QTableWidget *table, int row, int column, QWidget *control,
                  const QString &copyText = {});
void role(QWidget *widget, const char *name);
void buttonIcon(QAbstractButton *button, const char *name);
QIcon statusIcon(const char *name, const char *tone);
QIcon logo();
}

#endif
