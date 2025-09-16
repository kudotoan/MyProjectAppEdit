#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <QByteArray>
#include <QDataStream>
#include <QString>
#include <QFile>
#include <vector>

class Signature
{
public:
    std::vector<QByteArray> interCACer;   // chứng chỉ trung gian
    std::vector<QByteArray> tokenCer;     // chứng chỉ của token
    std::vector<QByteArray> signature;    // chữ ký
    std::vector<unsigned long long> fileSize;
    // Serialize
    friend QDataStream& operator<<(QDataStream& out, const Signature& obj);
    friend QDataStream& operator>>(QDataStream& in, Signature& obj);

    // Save/Load
    bool saveToFile(const QString &filePath) const;
    static bool loadLastFromFile(const QString &filePath, Signature &outSig, qint64 &outRecordSize);
};

#endif // SIGNATURE_H
