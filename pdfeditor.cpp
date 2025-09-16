#include "pdfeditor.h"
#include <QtPdfWidgets/QtPdfWidgets>
#include <QPdfPageNavigator>
#include <filesystem>
#include <windows.h>
#include <fcntl.h>
#include <io.h>
PDFEditor::PDFEditor() {}

void PDFEditor::insertImageToDocument(const std::string& pdfPath,
                           const std::string& imagePath,
                           int pageIndex,
                           double posX,
                           double posY,
                           double scaleX,
                           double scaleY)
{
    //load
    PoDoFo::PdfMemDocument pdfMemDoc;
    pdfMemDoc.Load(pdfPath);  //set document file with PdfDocument object
    std::unique_ptr<PoDoFo::PdfImage> image = pdfMemDoc.CreateImage(); //register one obj img in PDF binary code
    image->Load(imagePath);  //load image

    // painter
    PoDoFo::PdfPainter painter;
    painter.SetCanvas(pdfMemDoc.GetPages().GetPageAt(pageIndex)); //set Canvas to edit PDF document at pageIndex
    painter.DrawImage(*image, posX, posY, scaleX, scaleY);
    painter.FinishDrawing();
    pdfMemDoc.SaveUpdate(pdfPath); // update increment
}

QSizeF PDFEditor::convertPointToPixel(const QSizeF &posPoint, qreal dpiX, qreal dpiY)
{
    return QSizeF(posPoint.width() * dpiX / 72.0, posPoint.height() * dpiY / 72.0);
}

QPointF PDFEditor::convertPixelToPoint(const QSize &posPx, qreal dpiX, qreal dpiY)
{
    return QPointF(posPx.width() * 72.0 / dpiX, posPx.height() * 72.0 / dpiY);
}

bool PDFEditor::resizeFile(const std::string &filePath, unsigned long long size)
{
    std::filesystem::path path = std::filesystem::u8path(filePath);
    try {
        std::filesystem::resize_file(path, size);
    } catch (const std::filesystem::filesystem_error& e) {
        return false;
    }
    return true;
}

unsigned long long PDFEditor::getFileSize(const std::string &filePath)
{
    unsigned long long size;
    std::filesystem::path path = std::filesystem::u8path(filePath);

    try {
        size = std::filesystem::file_size(path);
    } catch (const std::filesystem::filesystem_error& e) {
        return 0;
    }
    return size;
}

bool PDFEditor::insertStringToBinaryFile(const std::string &filePath, const std::string &text)
{
    int wlen = MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, nullptr, 0);
    if (wlen == 0) return false;

    std::wstring wFilePath(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, &wFilePath[0], wlen);

    HANDLE h = CreateFileW(
        wFilePath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
        );

    if (h == INVALID_HANDLE_VALUE)
        return false;

    int fd = _open_osfhandle(reinterpret_cast<intptr_t>(h), _O_APPEND | _O_BINARY);
    if (fd == -1) {
        CloseHandle(h);
        return false;
    }

    FILE* f = _fdopen(fd, "ab");
    if (!f) {
        _close(fd);
        return false;
    }

    size_t written = fwrite(text.c_str(), 1, text.size(), f);
    fclose(f);

    return written == text.size();
}


// bool PDFEditor::insertStringToBinaryFile(const std::string &filePath, const std::string& text)
// {
//     std::filesystem::path path = std::filesystem::u8path(filePath);
//     FILE* f = nullptr;
//     errno_t err = fopen_s(&f, filePath.c_str(), "ab");  // "a" = append, "b" = binary
//     if (err != 0 || f == nullptr) {
//         qDebug() << "fopen_s failed with error: " << err;
//         perror("fopen_s");
//         return false;
//     }
//     size_t written = fwrite(text.c_str(), 1, text.size(), f);
//     fclose(f);
//     return written == text.size();
// }

QPointF PDFEditor::mappingPosWidgetToDocument(QPoint widgetPos, const QPdfDocument &pdfDocument, QPdfView *pdfView)
{
    const int marginPdfViewWithLayout = 6; //default margin 6px
    const float pointsPerInch = 72.0;
    //get Page Size
    int currentPage = pdfView->pageNavigator()->currentPage();
    QSizeF pageSize = pdfDocument.pagePointSize(currentPage);

    //get DPI
    qreal dpiX = pdfView->logicalDpiX();
    qreal dpiY = pdfView->logicalDpiY();

    //covert point to px
    QSizeF pageSizePx = PDFEditor::convertPointToPixel(pageSize,dpiX,dpiY);

    //get WidgetSize
    QSize widgetSize = pdfView->viewport()->size();

    int scrollMax = pdfView->verticalScrollBar()->maximum(); //scroll bar V max
    int currentScroll = pdfView->verticalScrollBar()->value(); //current scroll bar V
    int maxHeightWidget = (scrollMax!=0) ? widgetSize.height()+scrollMax : pageSizePx.height()*widgetSize.width()/pageSizePx.width()+marginPdfViewWithLayout;
    //caculator real pos click in document
    QSize realPosPxInDocument;
    realPosPxInDocument.setWidth(pageSizePx.width()*(widgetPos.x()-marginPdfViewWithLayout)/(widgetSize.width()-marginPdfViewWithLayout*2));
    realPosPxInDocument.setHeight(pageSizePx.height()*(widgetPos.y()+currentScroll-marginPdfViewWithLayout)/(maxHeightWidget-marginPdfViewWithLayout*2));
    QPointF realPosPointInDocument = PDFEditor::convertPixelToPoint(realPosPxInDocument,dpiX,dpiY);
    realPosPointInDocument.setY(pageSize.height() - realPosPointInDocument.y());

    return realPosPointInDocument;
}
