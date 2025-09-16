#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "pdfeditor.h"
#include <QScreen>
#include <QLabel>
#include <QPdfPageNavigator>
#include "toast.h"
#include "SelectSlotDialog.h"
#include "../Model/signature.h"
#include <windows.h>
#include <QStandardPaths>
#include <QRandomGenerator>
#include <QFileInfo>
#include <QDir>
//check widget_3 and pdfView
bool widget3NotHavepdfView = true;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    // // title application
    this->setWindowTitle("Phần mềm chữ ký số");

    //config widget 3 to show pdfDocument: layout << widget_3 << pdfView << pdfDocument << *file
    pdfView = new QPdfView(this);
    pdfView->setObjectName("PDFView");
    pdfView->setDocument(&pdfDocument);
    pdfView->setPageMode(QPdfView::PageMode::SinglePage);
    pdfView->setZoomMode(QPdfView::ZoomMode::FitToWidth);
    pdfView->hide();
    connect(ui->label_2, &ClickableLabel::clicked, this, &MainWindow::clickOpenFileOnLable);

    setAcceptDrops(false);

    this->hideSomeOne();
    FileSize.clear();

    hsm = new HSMConfig();
    QString libPath = QCoreApplication::applicationDirPath() + "/lib/softhsm2-x64.dll";

    if (!this->hsm->loadHSMLibrary(libPath))
        QMessageBox::warning(this, "Cảnh báo", "Có lỗi trong quá trình tải lên thư viện thiết bị!");

    ui->label_TokenName->hide();
    //add provider
    _putenv_s("PKCS11_MODULE_PATH", libPath.toStdString().c_str());
    QString providerDir = QCoreApplication::applicationDirPath() + "/lib/libp11/src";
    QString currentPath = qEnvironmentVariable("PATH");
    if (!currentPath.contains(providerDir, Qt::CaseInsensitive)) {
        QString newPath = currentPath + ";" + providerDir;
        qputenv("PATH", newPath.toUtf8());
    }
    _putenv_s("OPENSSL_MODULES",providerDir.toStdString().c_str());

    //tạo thư mục rác
    QString tempDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    QString appTempDir = tempDir + "/PDFEditTemp";
    QDir dir(appTempDir);
    if (dir.exists()) {
        dir.removeRecursively();
    }

    QDir().mkpath(appTempDir);

    //load chữ ký và scale
    QSettings settings("setting.ini", QSettings::IniFormat);
    signatureImagePath = settings.value("signatureImagePath", "").toString();
    signatureScale = settings.value("signatureScale", 1.0).toDouble();

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::hideSomeOne() {
    ui->label_3->hide();
    ui->btnBackFisrtPage->hide();
    ui->btnBackPage->hide();
    ui->btnNextPage->hide();
    ui->btnNextLastPage->hide();
    ui->label_saperatorPageNum->hide();
    ui->labelTotalPageNum->hide();
    ui->lineEditPageNum->hide();
    ui->btnSelectPos->hide();
    ui->btnAccept->hide();
    ui->btnCancel->hide();
    ui->btnReSign->hide();
    ui->btnSelectDocument->hide();
    ui->btnSelectTokenAgain->hide();
    ui->btnSelectSignatureImage->hide();
}

void MainWindow::showSomeOne() {
    this->showNavigationPageNum();
    ui->btnSelectPos->show();
    ui->btnAccept->show();
    ui->btnCancel->show();
    ui->btnReSign->show();
    ui->btnSelectDocument->show();
    ui->btnSelectTokenAgain->show();
    ui->btnSelectSignatureImage->show();

}

void MainWindow::clickOpenFileOnLable()
{
    if (ui->label_TokenName->isHidden()) {
        QMessageBox::information(this,"Thông báo", "Vui lòng chọn thiết bị để tiếp tục");
        return;
    }
    QString filePath = QFileDialog::getOpenFileName(this,"Open PDF File",QString(),"PDF files (*.pdf)");
    if (filePath.isEmpty()) return;
    pdfFilePathGoc = filePath;
    QString tempFile = createTempFile(filePath);
    if (tempFile.isEmpty()) return;

    pdfFilePath = tempFile;
    this->openAndShowDocument(pdfFilePath);
}

void MainWindow::showNavigationPageNum() {
    ui->label_3->show();
    ui->btnBackFisrtPage->show();
    ui->btnBackFisrtPage->setEnabled(false);
    ui->btnBackPage->show();
    ui->btnBackPage->setEnabled(false);
    ui->btnNextPage->show();
    ui->btnNextLastPage->show();
    ui->label_saperatorPageNum->show();
    ui->labelTotalPageNum->setText(QString::number(pdfDocument.pageCount()));
    ui->labelTotalPageNum->show();
    ui->lineEditPageNum->setText("1");
    ui->lineEditPageNum->show();
    ui->lineEditPageNum->setValidator(new QIntValidator(1, pdfDocument.pageCount(), this));
    if (pdfDocument.pageCount()==1) {
        ui->btnNextPage->setEnabled(false);
        ui->btnNextLastPage->setEnabled(false);
        return;
    }
    ui->btnNextPage->setEnabled(true);
    ui->btnNextLastPage->setEnabled(true);
}

bool MainWindow::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonPress) {
        if (obj->parent()->objectName().compare("PDFView", Qt::CaseSensitive) == 0) {
            QMouseEvent *mouseEvent = static_cast<QMouseEvent *>(event);

            QPoint widgetPos = mouseEvent->pos();

            selectedPos = PDFEditor::mappingPosWidgetToDocument(widgetPos, pdfDocument, pdfView);
            pdfView->viewport()->removeEventFilter(this);
            pdfView->viewport()->unsetCursor();
            ui->btnSelectPos->setText("Chọn vị trí");
            ui->btnSelectPos->setChecked(false);

            this->signature();
            return false;
        }
    }
    return QMainWindow::eventFilter(obj, event);
}


void MainWindow::setCursorToStamp(QWidget *targetWidget)
{
    QPixmap original(this->signatureImagePath);
    if (original.isNull()) {
        qWarning() << "[Error] Cannot Find Image Your Signature!";
        return;
    }

    int currentPage = pdfView->pageNavigator()->currentPage();
    QSizeF pageSizePt = pdfDocument.pagePointSize(currentPage);

    int viewportWidthPx = pdfView->viewport()->width();

    double pixelPerPoint = viewportWidthPx / pageSizePt.width();

    double imageWidthPt = original.width();
    double imageHeightPt = original.height();

    int imageWidthPx = static_cast<int>(imageWidthPt * pixelPerPoint);
    int imageHeightPx = static_cast<int>(imageHeightPt * pixelPerPoint);

    QPixmap scaled = original.scaled(imageWidthPx*this->signatureScale, imageHeightPx*this->signatureScale, Qt::KeepAspectRatio, Qt::SmoothTransformation);

    QPixmap transparent(scaled.size());
    transparent.fill(Qt::transparent);

    QPainter p(&transparent);
    p.setOpacity(0.5);
    p.drawPixmap(0, 0, scaled);
    p.end();

    QCursor cursor(transparent, transparent.width() / 2, transparent.height() / 2);
    targetWidget->setCursor(cursor);
}



void MainWindow::on_btnSelectPos_clicked(){
    if (this->signatureImagePath.isEmpty()) {
        QMessageBox::information(this, "Thông báo", "Vui lòng chọn chữ ký trước!");
    }
    if (this->pdfView->isHidden()) return;
    if (ui->btnSelectPos->text().at(0)=='H') { // H=Huy bo char At 0
        pdfView->viewport()->removeEventFilter(this);
        pdfView->viewport()->unsetCursor();
        ui->btnSelectPos->setText("Chọn vị trí");
        ui->btnSelectPos->setChecked(false);
    } else {
        setCursorToStamp(pdfView->viewport());
        pdfView->viewport()->installEventFilter(this);
        ui->btnSelectPos->setText("Hủy bỏ");
        ui->btnSelectPos->setChecked(true);
    }
}



void MainWindow::signature() {
    if (signatureImagePath.isEmpty()) {
        QMessageBox::warning(this, "Lỗi", "Chưa chọn ảnh chữ ký!");
        return;
    }

    QMessageBox::StandardButton reply;
    reply = QMessageBox::warning(this,
                                 "Xác nhận",
                                 "Bạn có chắc chắn muốn ký tại đây?",
                                 QMessageBox::Yes | QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    try {
        QPixmap original(signatureImagePath);
        if (original.isNull()) {
            qWarning() << "[Error] Cannot load signature image!";
            return;
        }

        int currentPage = pdfView->pageNavigator()->currentPage();

        // Tính góc dưới trái dựa trên tâm
        double posX = selectedPos.x() - original.width() / 2 * signatureScale;
        double posY = selectedPos.y() - original.height() / 2 * signatureScale;

        PDFEditor::insertImageToDocument(
            pdfFilePath.toStdString(),
            signatureImagePath.toStdString(),
            currentPage,
            posX,
            posY,
            signatureScale,
            signatureScale
            );

        this->FileSize.push_back(PDFEditor::getFileSize(pdfFilePath.toStdString()));
        if (this->FileSize.back() == 0) {
            QMessageBox::warning(this, "Lỗi", "Có lỗi xảy ra khi ký tài liệu!");
            return;
        }
    } catch (const std::exception& e) {
        qDebug() << "[Error]: " << e.what();
    }

    int scrollPosY = this->pdfView->verticalScrollBar()->value();
    pdfDocument.load(pdfFilePath);
    this->pdfView->verticalScrollBar()->setValue(scrollPosY);
}

void MainWindow::on_btnBackFisrtPage_clicked()
{
    pdfView->pageNavigator()->jump(0,QPointF(0, 0));
    ui->lineEditPageNum->setText("1");
    ui->btnBackFisrtPage->setEnabled(false);
    ui->btnBackPage->setEnabled(false);
    ui->btnNextLastPage->setEnabled(true);
    ui->btnNextPage->setEnabled(true);
}


void MainWindow::on_btnBackPage_clicked()
{
    int CurrentPageNum = pdfView->pageNavigator()->currentPage();
    pdfView->pageNavigator()->jump(CurrentPageNum-1,QPointF(0, 0));
    ui->lineEditPageNum->setText(QString::number(CurrentPageNum));
    if (CurrentPageNum-1==0) {
        ui->btnBackFisrtPage->setEnabled(false);
        ui->btnBackPage->setEnabled(false);
    }
    ui->btnNextLastPage->setEnabled(true);
    ui->btnNextPage->setEnabled(true);

}


void MainWindow::on_btnNextPage_clicked()
{
    int CurrentPageNum = pdfView->pageNavigator()->currentPage();
    pdfView->pageNavigator()->jump(CurrentPageNum+1,QPointF(0, 0));
    ui->lineEditPageNum->setText(QString::number(CurrentPageNum+2));
    if (pdfView->pageNavigator()->currentPage()==pdfDocument.pageCount()-1) {
        ui->btnNextLastPage->setEnabled(false);
        ui->btnNextPage->setEnabled(false);
    }
    ui->btnBackFisrtPage->setEnabled(true);
    ui->btnBackPage->setEnabled(true);
}


void MainWindow::on_btnNextLastPage_clicked()
{
    int totalPage = pdfDocument.pageCount()-1;
    pdfView->pageNavigator()->jump(totalPage,QPointF(0, 0));
    ui->lineEditPageNum->setText(QString::number(totalPage+1));
    ui->btnNextLastPage->setEnabled(false);
    ui->btnNextPage->setEnabled(false);
    ui->btnBackFisrtPage->setEnabled(true);
    ui->btnBackPage->setEnabled(true);

}


void MainWindow::on_lineEditPageNum_returnPressed()
{

    int pageNum = ui->lineEditPageNum->text().toInt();

    pdfView->pageNavigator()->jump(pageNum-1,QPointF(0, 0));
    ui->lineEditPageNum->setText(QString::number(pageNum));
    if (pageNum==1) {
        ui->btnBackFisrtPage->setEnabled(false);
        ui->btnBackPage->setEnabled(false);
        ui->btnNextLastPage->setEnabled(true);
        ui->btnNextPage->setEnabled(true);
        return;
    }
    if (pageNum == pdfDocument.pageCount()) {
        ui->btnNextLastPage->setEnabled(false);
        ui->btnNextPage->setEnabled(false);
        ui->btnBackFisrtPage->setEnabled(true);
        ui->btnBackPage->setEnabled(true);
        return;
    }
    ui->btnNextLastPage->setEnabled(true);
    ui->btnNextPage->setEnabled(true);
    ui->btnBackFisrtPage->setEnabled(true);
    ui->btnBackPage->setEnabled(true);

}


void MainWindow::on_btnSelectDocument_clicked()
{
    if (this->FileSize.size()>1) {
        QMessageBox::StandardButton reply;
        reply = QMessageBox::warning(this,
                                     "Xác nhận",
                                     "Bạn chưa lưu chữ ký trong tài liệu, tiếp tục nếu bạn muốn hủy bỏ toàn bộ chữ ký đã ký của mình trên tài liệu?",
                                     QMessageBox::Yes | QMessageBox::No);
        if (reply == QMessageBox::No) return;
    }

    QString filePath = QFileDialog::getOpenFileName(this,"Open PDF File",QString(),"PDF files (*.pdf)");
    if (filePath.isEmpty()) return;
    pdfFilePathGoc = filePath;
    QString tempFile = createTempFile(filePath);
    if (tempFile.isEmpty()) return;
    pdfFilePath = tempFile;
    this->openAndShowDocument(pdfFilePath);
}


void MainWindow::on_btnCancel_clicked()
{
    if (this->FileSize.size()>1) {
        QMessageBox::StandardButton reply;
        reply = QMessageBox::warning(this,
                                     "Xác nhận",
                                     "Bạn chưa lưu chữ ký trong tài liệu, tiếp tục nếu bạn muốn hủy bỏ toàn bộ chữ ký đã ký của mình trên tài liệu?",
                                     QMessageBox::Yes | QMessageBox::No);
        if (reply == QMessageBox::No) return;
        if (!PDFEditor::resizeFile(pdfFilePath.toStdString(),this->FileSize.front())) {
            QMessageBox::warning(this, "Lỗi", "Có lỗi xảy ra, vui lòng thử lại!");
            return;
        }
    }
    pdfView->hide();
    ui->label_2->show();
    this->FileSize.clear();
    setAcceptDrops(true);

}

void MainWindow::dragEnterEvent(QDragEnterEvent* event)
{
    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();
        if (!urls.isEmpty() && urls[0].toLocalFile().endsWith(".pdf", Qt::CaseInsensitive)) {
            event->acceptProposedAction();
        }
    }
}

void MainWindow::dropEvent(QDropEvent* event)
{
    const QMimeData* mimeData = event->mimeData();
    if (mimeData->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();
        if (urls.size()>1) {
            QMessageBox::warning(this, "Lỗi", "Vui lòng xử lý từng file PDF!");
            return;
        }
        QString filePath;
        if (!urls.isEmpty()) {
            filePath = urls.first().toLocalFile();
        }
        pdfFilePathGoc = filePath;
        QString tempFile = createTempFile(filePath);
        if (tempFile.isEmpty()) return;
        pdfFilePath = tempFile;
        this->openAndShowDocument(pdfFilePath);
    }
}


void MainWindow::openAndShowDocument(const QString& filePath) {
    pdfDocument.load(filePath);
    qDebug() << PDFEditor::getFileSize(filePath.toStdString());
    if (pdfDocument.status() == QPdfDocument::Status::Error) {
        QMessageBox::warning(this, "Lỗi", "Đã xảy ra lỗi khi mở file PDF!");
        return;
    } else {
        if (widget3NotHavepdfView) {
            ui->widget_3->layout()->addWidget(pdfView);
            widget3NotHavepdfView = false;
        }
        ui->label_2->hide();
        pdfView->show();
        // pdfView->update();
        pdfView->pageNavigator()->jump(0,QPointF(0, 0));
        this->showSomeOne();
        setAcceptDrops(false);
        this->FileSize.clear();


        qint64 oldFileSize = 0;
        if (Signature::loadLastFromFile(filePath, this->sig, oldFileSize)) PDFEditor::resizeFile(filePath.toStdString(), oldFileSize);
        this->FileSize.push_back(PDFEditor::getFileSize(filePath.toStdString()));
        // qDebug() << this->sig.signature.size() << " " << this->sig.fileSize.size();
        // qDebug() << this->sig.fileSize;
    }
}

void MainWindow::on_btnReSign_clicked()
{
    if (this->FileSize.size()<=1) return;
    int scrollPosY = this->pdfView->verticalScrollBar()->value();
    this->FileSize.pop_back();
    if (!PDFEditor::resizeFile(this->pdfFilePath.toStdString(),this->FileSize.back())) {
        QMessageBox::warning(this, "Lỗi", "Có lỗi xảy ra, vui lòng thử lại!");
        return;
    }
    pdfDocument.load(pdfFilePath);
    this->pdfView->verticalScrollBar()->setValue(scrollPosY);
}


void MainWindow::on_btnAccept_clicked()
{

    // kiểm tra có thay đổi hoặc sự đúng đắn của token
    if (this->FileSize.size()<=1 || this->hsm->countObjectByID("2")!=1) return;

    //lấy certificate trong token
    this->hsm->findAllCer();
    Certificate* tokenCer = nullptr;
    Certificate* CAInterCer = nullptr;
    QVector<Certificate> allCerts = this->hsm->getAllCertificates();
    for (int i =0; i< allCerts.size(); i++) {
        if (allCerts[i].getIdHex()=="01") {
            tokenCer = &allCerts[i];
        } else if (allCerts[i].getIdHex()=="02") {
            CAInterCer = &allCerts[i];
        }
    }


    if (!tokenCer || !CAInterCer) {
        QMessageBox::warning(this, "Lỗi", "Có lỗi xảy ra, vui lòng kiểm tra lại thiết bị của bạn!");
        return;
    }

    // add dữ liệu thêm vào sig
    sig.tokenCer.push_back(tokenCer->toDer());
    sig.interCACer.push_back(CAInterCer->toDer());
    sig.fileSize.push_back(this->FileSize.back());

    //lấy key
    QString selectedId = QString::fromStdString(tokenCer->getIdHex());
    QByteArray idBytes = QByteArray::fromHex(selectedId.toUtf8());
    QString encodedId = QString::fromLatin1(QUrl::toPercentEncoding(QString::fromLatin1(idBytes)));
    CK_TOKEN_INFO tokenInfo = this->hsm->getInfoToken(this->hsm->getSlotID());
    QString serial = QString::fromUtf8(reinterpret_cast<const char*>(tokenInfo.serialNumber), sizeof(tokenInfo.serialNumber)).trimmed();

    QString tokenLabel = this->hsm->getLable(this->hsm->getSlotID());
    QString keyUri = QStringLiteral("pkcs11:token=%1;serial=%2;id=%3;type=private")
                         .arg(tokenLabel, serial, encodedId);

    EVP_PKEY* caKey = this->hsm->loadKey(keyUri);
    if (!caKey) {
        QMessageBox::warning(this, "Lỗi", "Không tải được khóa từ Token.");
        return;
    }
    //lấy chữ ký file và lưu vào sig
    sig.signature.push_back(tokenCer->signFile(this->pdfFilePath,caKey));

    //save sig lại vào file
    sig.saveToFile(this->pdfFilePath);

    //thay thế file temp thành file gốc
    if (!QFile::remove(pdfFilePathGoc)) {
        QMessageBox::warning(this, "Lỗi", "Không thể ghi đè lên file gốc!");
        return;
    }
    if (!QFile::copy(pdfFilePath, pdfFilePathGoc)) {
        QMessageBox::warning(this, "Lỗi", "Không thể sao chép file tạm lên file gốc!");
        return;
    }

    Toast *t = new Toast("Thành công!", this);
    t->showAtCorner(this);
    pdfView->hide();
    ui->label_2->show();
    this->FileSize.clear();
}



void MainWindow::on_btnLogin_clicked()
{
    this->hsm->getAllSlotID();

    if (this->hsm->allSlotID.isEmpty()) {
        return;
    }

    QVector<QString> labels;
    for (auto slotID : this->hsm->allSlotID)
        labels.append(this->hsm->getLable(slotID));

    SelectSlotDialog dlg(this->hsm->allSlotID, labels, this);
    if (dlg.exec() == QDialog::Accepted) {
        this->hsm->setSlotID(dlg.selectedSlotID());
        this->hsm->connectToSlot();
        ui->label_TokenName->setText(this->hsm->getLable(this->hsm->getSlotID()));
        ui->label_TokenName->show();
        this->showSomeOne();
        setAcceptDrops(true);
        ui->btnLogin->hide();
    }
}


void MainWindow::on_btnSelectTokenAgain_clicked()
{

    if (this->FileSize.size()>1) {
        QMessageBox::StandardButton reply;
        reply = QMessageBox::warning(this,
                                     "Xác nhận",
                                     "Bạn chưa lưu chữ ký trong tài liệu, tiếp tục nếu bạn muốn hủy bỏ toàn bộ chữ ký đã ký của mình trên tài liệu?",
                                     QMessageBox::Yes | QMessageBox::No);
        if (reply == QMessageBox::No) return;
        if (!PDFEditor::resizeFile(pdfFilePath.toStdString(),this->FileSize.front())) {
            QMessageBox::warning(this, "Lỗi", "Có lỗi xảy ra, vui lòng thử lại!");
            return;
        }
    }
    pdfView->hide();
    ui->label_2->show();
    this->FileSize.clear();
    this->hsm->closeState();
    this->hideSomeOne();
    ui->btnLogin->show();
    ui->label_TokenName->hide();
    setAcceptDrops(false);
}


void MainWindow::on_btnSelectSignatureImage_clicked()
{
    QSettings settings("setting.ini", QSettings::IniFormat);
    QString currentImagePath = settings.value("signatureImagePath", "").toString();
    double currentScale = settings.value("signatureScale", 1.0).toDouble();

    if (!currentImagePath.isEmpty())
        signatureImagePath = currentImagePath;
    tempScale = currentScale;

    QDialog dlg(this);
    dlg.setWindowTitle("Chọn ảnh chữ ký và chỉnh Scale");

    QVBoxLayout *layout = new QVBoxLayout(&dlg);

    QPushButton *btnSelectFile = new QPushButton("Chọn file chữ ký");
    layout->addWidget(btnSelectFile);

    QLabel *labelFile = new QLabel(signatureImagePath.isEmpty() ? "Chưa chọn file" : QFileInfo(signatureImagePath).fileName());
    layout->addWidget(labelFile);

    QLabel *labelScale = new QLabel(QString("Scale: %1").arg(tempScale, 0, 'f', 2));
    layout->addWidget(labelScale);

    QSlider *slider = new QSlider(Qt::Horizontal);
    slider->setRange(10, 500);
    slider->setValue(static_cast<int>(tempScale * 100));
    layout->addWidget(slider);

    connect(btnSelectFile, &QPushButton::clicked, [&]() {
        QString filePath = QFileDialog::getOpenFileName(this,
                                                        "Chọn ảnh chữ ký", QString(),
                                                        "Image Files (*.png *.jpg *.bmp)");
        if (!filePath.isEmpty()) {
            signatureImagePath = filePath;
            labelFile->setText(QFileInfo(filePath).fileName());
        }
    });

    connect(slider, &QSlider::sliderMoved, [&](int value){
        tempScale = value / 100.0;
        labelScale->setText(QString("Scale: %1").arg(tempScale, 0, 'f', 2));
        if (ui->btnSelectPos->isChecked() && !pdfView->isHidden() && !signatureImagePath.isEmpty()) {
            signatureScale = tempScale;  // update tạm
            setCursorToStamp(pdfView->viewport());
        }
    });

    dlg.exec();
    signatureScale = tempScale;

    settings.setValue("signatureImagePath", signatureImagePath);
    settings.setValue("signatureScale", signatureScale);

}




QString MainWindow::createTempFile(const QString &originalFilePath) {
    QString tempDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation);

    QString appTempDir = tempDir + "/PDFEditTemp";
    QDir().mkpath(appTempDir);
    QString baseName = QFileInfo(originalFilePath).fileName();
    QString timeStr = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    QString tempFileName = QString("PDFtemp_%1_%2").arg(timeStr,baseName);

    QString tempFilePath = appTempDir + "/" + tempFileName;

    if (!QFile::copy(originalFilePath, tempFilePath)) {
        QMessageBox::warning(this, "Lỗi", "Không thể tạo file tạm!");
        return QString();
    }

    return tempFilePath;
}
