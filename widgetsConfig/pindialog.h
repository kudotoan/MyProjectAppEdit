#pragma once
#include <QDialog>

class QLineEdit;

class PinDialog : public QDialog {
    Q_OBJECT
public:
    explicit PinDialog(QWidget* parent = nullptr);
    QString getPin() const;

private:
    QLineEdit* pinEdit;
};
