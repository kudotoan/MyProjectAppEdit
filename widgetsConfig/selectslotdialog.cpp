#include "SelectSlotDialog.h"
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

SelectSlotDialog::SelectSlotDialog(const QVector<unsigned long> &slotIDs,
                                   const QVector<QString> &labels,
                                   QWidget *parent)
    : QDialog(parent), m_slotIDs(slotIDs)
{
    setWindowTitle("Chọn Slot");

    QVBoxLayout *layout = new QVBoxLayout(this);

    m_list = new QListWidget(this);
    for (int i = 0; i < slotIDs.size(); i++) {
        m_list->addItem(labels[i]);
    }

    layout->addWidget(m_list);

    QPushButton *btnOk = new QPushButton("OK", this);
    layout->addWidget(btnOk);

    connect(btnOk, &QPushButton::clicked, this, &SelectSlotDialog::onOkClicked);
}

quint64 SelectSlotDialog::selectedSlotID() const
{
    return m_selectedSlotID;
}

void SelectSlotDialog::onOkClicked()
{
    int idx = m_list->currentRow();
    if (idx >= 0 && idx < m_slotIDs.size()) {
        m_selectedSlotID = m_slotIDs[idx];
        accept();
    } else {
        m_selectedSlotID = 0;
        reject();
    }
}
