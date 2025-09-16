#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <Qdebug>
#include <QPdfDocument>
#include <QtPdfWidgets/QtPdfWidgets>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>
#include <vector>
#include "Model/signature.h"
#include "Model/hsmconfig.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
std::uintmax_t size;
private slots:

void clickOpenFileOnLable();

void on_btnSelectPos_clicked();

void on_btnBackFisrtPage_clicked();

void on_btnBackPage_clicked();

void on_btnNextPage_clicked();

void on_btnNextLastPage_clicked();

void on_lineEditPageNum_returnPressed();

void on_btnSelectDocument_clicked();

void on_btnCancel_clicked();

void on_btnReSign_clicked();

void on_btnAccept_clicked();



void on_btnLogin_clicked();

void on_btnSelectTokenAgain_clicked();

void on_btnSelectSignatureImage_clicked();

private:
    Ui::MainWindow *ui;
    QPdfDocument pdfDocument;
    QPdfView *pdfView = nullptr;
    QPointF selectedPos;
    QString pdfFilePath;
    QString pdfFilePathGoc;

    std::vector<unsigned long long> FileSize;
    void setCursorToStamp(QWidget *targetWidget);
    void signature();
    void setUnCheckedBtnPageNum();
    void showNavigationPageNum();
    void hideSomeOne();
    void openAndShowDocument(const QString &filePath);
    void showSomeOne();
    HSMConfig* hsm;
    Signature sig;
    bool restorePdfFromBackup();
    QString createTempFile(const QString &originalFilePath);
    QString signatureImagePath;
    double signatureScale = 1.0;
    double tempScale = 1.0;

protected:
    // bool nativeEvent(const QByteArray &eventType, void *message, qintptr *result) override;
    bool eventFilter(QObject *obj, QEvent *event) override;
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;
};
#endif // MAINWINDOW_H
