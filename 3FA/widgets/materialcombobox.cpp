#include "materialcombobox.h"

#include <QWheelEvent>

MaterialComboBox::MaterialComboBox(QWidget *parent)
    : QComboBox(parent)
{
    setMaxVisibleItems(8);
    setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    setMinimumContentsLength(16);
}

void MaterialComboBox::wheelEvent(QWheelEvent *event)
{
    event->ignore();
}
