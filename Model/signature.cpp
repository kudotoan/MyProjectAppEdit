#include "Signature.h"
#include <QFile>
#include <QDebug>

// fileSize dùng unsigned long long
QDataStream& operator<<(QDataStream& out, const Signature& obj) {
    // interCACer
    out << static_cast<quint32>(obj.interCACer.size());
    for (const auto &s : obj.interCACer)
        out << s;

    // tokenCer
    out << static_cast<quint32>(obj.tokenCer.size());
    for (const auto &s : obj.tokenCer)
        out << s;

    // signature
    out << static_cast<quint32>(obj.signature.size());
    for (const auto &s : obj.signature)
        out << s;

    // fileSize
    out << static_cast<quint32>(obj.fileSize.size());
    for (auto s : obj.fileSize)
        out << static_cast<quint64>(s);  // serialize as unsigned long long

    return out;
}

QDataStream& operator>>(QDataStream& in, Signature& obj) {
    quint32 size;

    // interCACer
    in >> size;
    obj.interCACer.clear();
    obj.interCACer.reserve(size);
    for (quint32 i = 0; i < size; i++) {
        QByteArray s;
        in >> s;
        obj.interCACer.push_back(s);
    }

    // tokenCer
    in >> size;
    obj.tokenCer.clear();
    obj.tokenCer.reserve(size);
    for (quint32 i = 0; i < size; i++) {
        QByteArray s;
        in >> s;
        obj.tokenCer.push_back(s);
    }

    // signature
    in >> size;
    obj.signature.clear();
    obj.signature.reserve(size);
    for (quint32 i = 0; i < size; i++) {
        QByteArray s;
        in >> s;
        obj.signature.push_back(s);
    }

    // fileSize
    in >> size;
    obj.fileSize.clear();
    obj.fileSize.reserve(size);
    for (quint32 i = 0; i < size; i++) {
        quint64 s;
        in >> s;
        obj.fileSize.push_back(static_cast<unsigned long long>(s));
    }

    return in;
}

bool Signature::saveToFile(const QString &filePath) const {
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append)) {
        qWarning() << "Không mở được file để ghi!";
        return false;
    }

    QByteArray buffer;
    QDataStream tempOut(&buffer, QIODevice::WriteOnly);
    tempOut.setVersion(QDataStream::Qt_6_5);
    tempOut << *this;

    if (file.write(buffer) != buffer.size()) {
        qWarning() << "Không ghi đủ dữ liệu!";
        file.close();
        return false;
    }

    QDataStream out(&file);
    out.setVersion(QDataStream::Qt_6_5);
    out << static_cast<quint32>(buffer.size());

    QByteArray mark("Kudotoan", 8);
    if (file.write(mark) != mark.size()) {
        qWarning() << "Không ghi đủ dấu hiệu!";
        file.close();
        return false;
    }

    file.close();
    return true;
}


bool Signature::loadLastFromFile(const QString &filePath, Signature &outSig, qint64 &outOriginalFileSize) {
    QFile fileIn(filePath);
    if (!fileIn.open(QIODevice::ReadOnly)) {
        qWarning() << "Không mở được file để đọc!";
        return false;
    }

    qint64 fileSize = fileIn.size();
    const int markSize = 8;
    const int sizeField = 4;

    outOriginalFileSize = fileSize;

    if (fileSize < markSize + sizeField) {
        fileIn.close();
        return true;
    }

    fileIn.seek(fileSize - markSize);
    QByteArray mark = fileIn.read(markSize);
    if (mark != "Kudotoan") {
        fileIn.close();
        return true;
    }

    fileIn.seek(fileSize - markSize - sizeField);
    QDataStream in(&fileIn);
    in.setVersion(QDataStream::Qt_6_5);
    quint32 bufferSize = 0;
    in >> bufferSize;

    qint64 dataPos = fileSize - markSize - sizeField - bufferSize;
    if (dataPos < 0) {
        qWarning() << "File hỏng hoặc size không hợp lệ!";
        fileIn.close();
        return false;
    }

    fileIn.seek(dataPos);
    QByteArray bufferIn(bufferSize, 0);
    if (fileIn.read(bufferIn.data(), bufferSize) != bufferSize) {
        qWarning() << "Không đọc đủ dữ liệu!";
        fileIn.close();
        return true;
    }

    QDataStream tempIn(&bufferIn, QIODevice::ReadOnly);
    tempIn.setVersion(QDataStream::Qt_6_5);
    tempIn >> outSig;

    // Kích thước file trước khi append record cuối
    outOriginalFileSize = fileSize - (bufferSize + sizeField + markSize);

    fileIn.close();
    return true;
}

