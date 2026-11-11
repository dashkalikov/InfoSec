#include "maskwidget.h"
#include <QPainter>
#include <QPainterPath>

MaskWidget::MaskWidget(QWidget *parent)
    : QWidget(parent)
    , m_backgroundColor(QColor(248, 249, 250, 255)) // Цвет фона карточки
    , m_holeColor(Qt::transparent) // Прозрачная дырка
    , m_holeRadius(130) // Радиус дырки (половина от высоты 260)
{
    setAttribute(Qt::WA_TranslucentBackground);
}

void MaskWidget::paintEvent(QPaintEvent *event)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    
    // Создаем путь для всей области
    QPainterPath fullPath;
    fullPath.addRect(rect());
    
    // Создаем путь для дырки в центре (лицо)
    QPainterPath holePath;
    QRect holeRect = rect().adjusted(
        (width() - m_holeRadius * 2) / 2,  // Центрируем по горизонтали
        (height() - m_holeRadius * 2) / 2, // Центрируем по вертикали
        -(width() - m_holeRadius * 2) / 2,
        -(height() - m_holeRadius * 2) / 2
    );
    holePath.addEllipse(holeRect);
    
    // Вычитаем дырку из полного пути
    QPainterPath maskPath = fullPath.subtracted(holePath);
    
    // Заливаем основную область вокруг дырки
    painter.fillPath(maskPath, m_backgroundColor);
    
    // === РИСУЕМ КЛОУНА ===
    int centerX = width() / 2;
    int centerY = height() / 2;
    int holeCenterX = centerX;
    int holeCenterY = centerY;
    
    // 1. Парик клоуна (разноцветные секции сверху)
    QPainterPath wigPath;
    // Левая часть парика (синяя)
    QRect wigLeftRect(holeCenterX - m_holeRadius - 40, holeCenterY - m_holeRadius - 30, 50, 40);
    wigPath.addEllipse(wigLeftRect);
    painter.fillPath(wigPath, QColor(0, 100, 200, 255)); // Синий
    
    // Правая часть парика (красная)
    QPainterPath wigRightPath;
    QRect wigRightRect(holeCenterX + m_holeRadius - 10, holeCenterY - m_holeRadius - 30, 50, 40);
    wigRightPath.addEllipse(wigRightRect);
    painter.fillPath(wigRightPath, QColor(255, 0, 0, 255)); // Красный
    
    // Центральная часть парика (желтая)
    QPainterPath wigCenterPath;
    QRect wigCenterRect(holeCenterX - 25, holeCenterY - m_holeRadius - 35, 50, 35);
    wigCenterPath.addEllipse(wigCenterRect);
    painter.fillPath(wigCenterPath, QColor(255, 255, 0, 255)); // Желтый
    
    // 2. Красный нос клоуна (круг над центром лица)
    QPainterPath nosePath;
    QRect noseRect(holeCenterX - 15, holeCenterY - 10, 30, 30);
    nosePath.addEllipse(noseRect);
    // Вычитаем область лица из носа, чтобы он не перекрывал лицо
    QPainterPath noseMask = nosePath.subtracted(holePath);
    painter.fillPath(noseMask, QColor(255, 0, 0, 255)); // Красный нос
    
    // 3. Декоративные элементы по бокам (шарики)
    // Левый шарик (зеленый)
    QPainterPath leftBallPath;
    QRect leftBallRect(holeCenterX - m_holeRadius - 25, holeCenterY - 20, 30, 30);
    leftBallPath.addEllipse(leftBallRect);
    QPainterPath leftBallMask = leftBallPath.subtracted(holePath);
    painter.fillPath(leftBallMask, QColor(0, 200, 0, 255)); // Зеленый
    
    // Правый шарик (фиолетовый)
    QPainterPath rightBallPath;
    QRect rightBallRect(holeCenterX + m_holeRadius - 5, holeCenterY - 20, 30, 30);
    rightBallPath.addEllipse(rightBallRect);
    QPainterPath rightBallMask = rightBallPath.subtracted(holePath);
    painter.fillPath(rightBallMask, QColor(200, 0, 200, 255)); // Фиолетовый
    
    // 4. Улыбка клоуна (дуга внизу)
    QPainterPath smilePath;
    QRect smileRect(holeCenterX - 40, holeCenterY + m_holeRadius - 30, 80, 40);
    smilePath.addEllipse(smileRect);
    // Вырезаем верхнюю часть эллипса для улыбки
    QPainterPath smileCut;
    smileCut.addRect(smileRect.x(), smileRect.y(), smileRect.width(), smileRect.height() / 2.0);
    QPainterPath smileArc = smilePath.subtracted(smileCut).subtracted(holePath);
    painter.fillPath(smileArc, QColor(255, 200, 0, 255)); // Оранжевый
    
    // 5. Борода/воротник (внизу, разноцветные полосы)
    QPainterPath collarPath1;
    QRect collarRect1(holeCenterX - m_holeRadius - 20, holeCenterY + m_holeRadius - 10, 30, 25);
    collarPath1.addEllipse(collarRect1);
    QPainterPath collarMask1 = collarPath1.subtracted(holePath);
    painter.fillPath(collarMask1, QColor(255, 100, 0, 255)); // Оранжевый
    
    QPainterPath collarPath2;
    QRect collarRect2(holeCenterX + m_holeRadius - 10, holeCenterY + m_holeRadius - 10, 30, 25);
    collarPath2.addEllipse(collarRect2);
    QPainterPath collarMask2 = collarPath2.subtracted(holePath);
    painter.fillPath(collarMask2, QColor(0, 150, 255, 255)); // Голубой
}
