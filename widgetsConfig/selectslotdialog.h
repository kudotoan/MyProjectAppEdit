#pragma once
#include <QDialog>
#include <QVector>
#include <QString>
class QListWidget;

class SelectSlotDialog : public QDialog
{
    Q_OBJECT
public:
    explicit SelectSlotDialog(const QVector<unsigned long> &slotIDs,
                              const QVector<QString> &labels,
                              QWidget *parent = nullptr);

    // Lấy slot ID đã chọn
    quint64 selectedSlotID() const;

private slots:
    void onOkClicked();

private:
    QListWidget *m_list;
    QVector<unsigned long> m_slotIDs;
    quint64 m_selectedSlotID = 0;
};
