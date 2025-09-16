#ifndef PDFEDITOR_H
#define PDFEDITOR_H
#include <podofo/main/PdfEncodingFactory.h>
#include <podofo/auxiliary/StreamDevice.h>
#include <podofo/podofo.h>
#include <QDebug>
#include <QPdfDocument>
#include <QPdfView>

class PDFEditor
{
public:
    PDFEditor();
    static void insertImageToDocument(
        const std::string& pdfPath,
        const std::string& imagePath,
        int pageIndex,
        double posX,
        double posY,
        double scaleX = 1,
        double scaleY = 1
);
    static QPointF mappingPosWidgetToDocument(
        QPoint widgetPos,
        const QPdfDocument &pdfDocument,
        QPdfView *pdfView
    );
    static QSizeF convertPointToPixel(const QSizeF &pageSizePt, qreal dpiX, qreal dpiY);
    static QPointF convertPixelToPoint(const QSize &posPx, qreal dpiX, qreal dpiY);
    static bool resizeFile(const std::string& filePath, unsigned long long size);
    static unsigned long long getFileSize(const std::string& filePath);
    static bool insertStringToBinaryFile(const std::string& filePath, const std::string& text);
};
#endif // PDFEDITOR_H
