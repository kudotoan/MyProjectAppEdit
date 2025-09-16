#ifndef TOAST_H
#define TOAST_H

#include <QWidget>

class Toast : public QWidget {
    Q_OBJECT
public:
    explicit Toast(const QString &message, QWidget *parent = nullptr);
    void showAtCorner(QWidget *mainWindow);

private:
    void startFadeOut();
};

#endif // TOAST_H
