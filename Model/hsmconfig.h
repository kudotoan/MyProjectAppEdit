#ifndef HSMCONFIG_H
#define HSMCONFIG_H
#include <cryptoki.h>
#define NOMINMAX
#include <Windows.h>
#include <QString>
#include <QVector>
#include "Certificate.h"
#include <openssl/ui.h>

class HSMConfig
{
public:
    HSMConfig();
    ~HSMConfig();
    bool loadHSMLibrary(const QString& libPath);
    bool connectToSlot();
    bool login(CK_BYTE *slotPin);
    bool logout();
    bool disconnectToSlot();
    QVector<CK_SLOT_ID> allSlotID;
    QString getLable(CK_SLOT_ID slotID);
    CK_TOKEN_INFO getInfoToken(CK_SLOT_ID slotID);
    bool getAllSlotID();
    void setSlotID(CK_SLOT_ID slotID);
    CK_SLOT_ID getSlotID();
    void findAllCer();
    QVector<Certificate> getAllCertificates();
    UI_METHOD* createCustomUIMethod();
    void closeState();

    Certificate getCertificateById(const std::string& idHex) const;
    EVP_PKEY* loadKey(const QString& pkcs11Uri);
    bool isLoggedIn() const;
    void resetOpenSSLCtx();

    int createCertificate(const QString& label, const QString& commonName, const QString& organization,    // O
                          const QString& country,
                          int validDays,
                          bool canSignCer = false);
    int changePin(QString &currentPin, QString &newPin);
    bool hasAnyObject(CK_SLOT_ID slotID);
    X509_REQ* createCSR(const QString &label, const QString &commonName, const QString &organization, const QString &country, bool canSignCert);
    bool DestroyObject(const QString& Qid);
    int saveCertificateFromFile(const QString &filePath, int ID);
    int saveCertificateFromMem(X509 *cer, const QString& label, int ID);
    int countObjectByID(const QString& ID);
private:
    int createPairKey(const QString& label, bool isForCertSign);
    QVector<Certificate> allCertificates;
    HINSTANCE libHandle;
    CK_FUNCTION_LIST *p11Func;
    CK_SLOT_ID slotID;
    CK_SESSION_HANDLE sessionHandle;
    void freeResource();
    bool checkOperation(CK_RV rv, const char *message);
    bool selectSlotByLabel(const QString& expectedLabel);
    bool isInitialized = false;
    OSSL_LIB_CTX*   m_libctx       = nullptr;
    OSSL_PROVIDER*  m_provDefault  = nullptr;
    OSSL_PROVIDER*  m_provPkcs11   = nullptr;

    bool ensureOpenSSLCtx();
};

#endif // HSMCONFIG_H
