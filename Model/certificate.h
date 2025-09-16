#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <vector>
#include <string>
#include <openssl/x509.h>
#include <QString>
class Certificate
{
public:
    Certificate();
    Certificate(const std::vector<unsigned char>& derData,
                const std::string& label,
                const std::vector<unsigned char>& id);
    Certificate(X509* x509);

    ~Certificate();

    bool parseInfo();
    QString getAuthorityKeyIdentifier() const;
    QString toPemString() const;
    QString getVersion() const;
    QString getSignatureAlgorithm() const;
    QString getPublicKeyInfo() const;
    QString getKeyUsage() const;
    QString getBasicConstraints() const;
    QString getSubjectKeyIdentifier() const;
    QString getSignatureHex() const;
    std::string getSubject() const;
    std::string getIssuer() const;
    std::string getNotBefore() const;
    std::string getNotAfter() const;
    std::string getSerial() const;
    std::string getLabel() const;
    std::string getIdHex() const;
    bool canSignCSR() const;
    Certificate(const Certificate& other);
    Certificate& operator=(const Certificate& other);
    X509* signCSR(X509_REQ* csr, int daysValid, EVP_PKEY* caKey);
    QByteArray signFile(const QString& filePath, EVP_PKEY* caKey); //return SignatureFile

    EVP_PKEY *getPublicKey() const;
    QString getPublicKeyPem() const;
    QString getInfo() const;
    bool saveCerPemToFile(const QString &filePath) const;
    X509* cert;
    QByteArray toPem() const;
    QByteArray toDer() const;

private:
    std::vector<unsigned char> derData;
    std::string label;
    std::vector<unsigned char> id;
    std::string x509NameToString(X509_NAME* name) const;
    std::string asn1TimeToString(const ASN1_TIME* time) const;
};

#endif // CERTIFICATE_H
