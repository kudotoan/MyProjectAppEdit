#include "toast.h"
#include <QLabel>
#include <QVBoxLayout>
#include <QTimer>
#include <QGraphicsOpacityEffect>
#include <QPropertyAnimation>

Toast::Toast(const QString &message, QWidget *parent) : QWidget(parent) {
    setWindowFlags(Qt::FramelessWindowHint | Qt::Tool | Qt::WindowStaysOnTopHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_ShowWithoutActivating);

    QLabel *label = new QLabel(message);
    label->setStyleSheet("background-color: rgba(0, 0, 0, 180); color: white; padding: 10px; border-radius: 5px;");
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->addWidget(label);
    layout->setContentsMargins(0, 0, 0, 0);
    setLayout(layout);
    adjustSize();

    QGraphicsOpacityEffect *effect = new QGraphicsOpacityEffect(this);
    setGraphicsEffect(effect);

    QTimer::singleShot(2000, this, [=]() {
        QPropertyAnimation *fade = new QPropertyAnimation(effect, "opacity");
        fade->setDuration(1000);
        fade->setStartValue(1);
        fade->setEndValue(0);
        connect(fade, &QPropertyAnimation::finished, this, [this]() {
            this->deleteLater();
        });
        fade->start(QAbstractAnimation::DeleteWhenStopped);
    });
}

void Toast::showAtCorner(QWidget *mainWindow) {
    QPoint pos = mainWindow->geometry().topRight() - QPoint(width() + 20, -20);
    move(pos);
    show();
}
