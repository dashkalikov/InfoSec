#ifndef MASKWIDGET_H
#define MASKWIDGET_H

#include <QWidget>
#include <QPainter>
#include <QPainterPath>

class MaskWidget : public QWidget
{
    Q_OBJECT
public:
    explicit MaskWidget(QWidget *parent = nullptr);
    
protected:
    void paintEvent(QPaintEvent *event) override;
    
private:
    QColor m_backgroundColor;
    QColor m_holeColor;
    int m_holeRadius;
};

#endif // MASKWIDGET_H
