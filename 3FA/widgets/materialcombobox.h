#pragma once

#include <QComboBox>

class MaterialComboBox : public QComboBox
{
    Q_OBJECT

public:
    explicit MaterialComboBox(QWidget *parent = nullptr);

protected:
    void wheelEvent(QWheelEvent *event) override;
};
