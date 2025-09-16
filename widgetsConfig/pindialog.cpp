#include "pindialog.h"
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>

PinDialog::PinDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Nhập mã PIN");

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(new QLabel("Mã PIN:"));

    pinEdit = new QLineEdit(this);
    pinEdit->setEchoMode(QLineEdit::Password);
    layout->addWidget(pinEdit);

    auto* okButton = new QPushButton("OK", this);
    layout->addWidget(okButton);

    connect(okButton, &QPushButton::clicked, this, &QDialog::accept);
}

QString PinDialog::getPin() const {
    return pinEdit->text();
}
