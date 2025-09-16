#include "hsmconfig.h"
#include <QDebug>
#include <QCoreApplication>
#include <QVector>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <openssl/engine.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include "../widgetsConfig/pindialog.h"
#include <QUrl>
#include <QFileInfo>

HSMConfig::HSMConfig() {
    libHandle = 0;
    p11Func = NULL;
    slotID = 0;
    sessionHandle = 0;
}

HSMConfig::~HSMConfig() {
    this->freeResource();
}

void HSMConfig::freeResource()
{
    if (this->p11Func && this->sessionHandle) {
        this->p11Func->C_CloseSession(this->sessionHandle);
        this->sessionHandle = 0;
    }
    if (isInitialized && this->p11Func) {
        CK_RV rv = this->p11Func->C_Finalize(NULL_PTR);
        this->isInitialized=false;
        if (rv != CKR_OK) {
            qWarning("C_Finalize failed: 0x%lX", rv);
        }
        this->p11Func = nullptr;
    }

    if (this->libHandle) {
        FreeLibrary(this->libHandle);
        this->libHandle = nullptr;
    }

    this->sessionHandle = 0;
    this->slotID = 0;
    this->allSlotID.clear();
    this->allCertificates.clear();

}

bool HSMConfig::getAllSlotID()
{
    CK_ULONG slotCount = 0;
    if (!checkOperation(this->p11Func->C_GetSlotList(CK_TRUE, nullptr, &slotCount),"C_GetSlotList") || slotCount == 0) {
        this->allSlotID.clear();
        return false;
    }

    this->allSlotID.resize(slotCount);
    if (!checkOperation(this->p11Func->C_GetSlotList(CK_TRUE, this->allSlotID.data(), &slotCount),"C_GetSlotList"))
        return false;
    return true;
}

void HSMConfig::setSlotID(CK_SLOT_ID slotID)
{
    this->slotID = slotID;
}

CK_SLOT_ID HSMConfig::getSlotID()
{
    return this->slotID;

}

void HSMConfig::findAllCer() {
    if (!p11Func || !sessionHandle) {
        return;
    }

    allCertificates.clear();

    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_ATTRIBUTE searchTemplate[] = {
        {CKA_CLASS, &certClass, sizeof(certClass)}
    };

    CK_RV rv = p11Func->C_FindObjectsInit(sessionHandle, searchTemplate, 1);
    if (rv != CKR_OK) {
        qWarning("C_FindObjectsInit failed.");
        return;
    }

    const CK_ULONG maxObj = 10;
    CK_OBJECT_HANDLE objs[maxObj];
    CK_ULONG found = 0;
    while (true) {

        rv = p11Func->C_FindObjects(sessionHandle, objs, maxObj, &found);
        if (rv != CKR_OK || found == 0)
            break;

        for (CK_ULONG i = 0; i < found; ++i) {
            CK_OBJECT_HANDLE obj = objs[i];

            // 1. Lấy CKA_VALUE
            CK_ATTRIBUTE attrValue = {CKA_VALUE, NULL_PTR, 0};
            if (p11Func->C_GetAttributeValue(sessionHandle, obj, &attrValue, 1) != CKR_OK)
                continue;
            std::vector<unsigned char> der(attrValue.ulValueLen);
            attrValue.pValue = der.data();
            if (p11Func->C_GetAttributeValue(sessionHandle, obj, &attrValue, 1) != CKR_OK)
                continue;

            // 2. Lấy CKA_LABEL
            QString label;
            CK_ATTRIBUTE attrLabel = {CKA_LABEL, NULL_PTR, 0};
            if (p11Func->C_GetAttributeValue(sessionHandle, obj, &attrLabel, 1) == CKR_OK) {
                std::vector<char> buf(attrLabel.ulValueLen + 1, 0);
                attrLabel.pValue = buf.data();
                if (p11Func->C_GetAttributeValue(sessionHandle, obj, &attrLabel, 1) == CKR_OK) {
                    label = QString::fromUtf8(buf.data());
                }
            }

            // 3. Lấy CKA_ID
            std::vector<unsigned char> id;
            CK_ATTRIBUTE attrID = {CKA_ID, NULL_PTR, 0};
            if (p11Func->C_GetAttributeValue(sessionHandle, obj, &attrID, 1) == CKR_OK) {
                id.resize(attrID.ulValueLen);
                attrID.pValue = id.data();
                p11Func->C_GetAttributeValue(sessionHandle, obj, &attrID, 1);
            }

            Certificate cert(der, label.toStdString(), id);
            this->allCertificates.push_back(cert);
        }
    }

    p11Func->C_FindObjectsFinal(sessionHandle);
}

QVector<Certificate> HSMConfig::getAllCertificates() {
    return this->allCertificates;
}

UI_METHOD* HSMConfig::createCustomUIMethod()
{
    static UI_METHOD* method = nullptr;
    if (method) return method;

    method = UI_create_method("Qt PIN UI");

    UI_method_set_reader(method, [](UI* ui, UI_STRING* uis) -> int {
        if (UI_get_string_type(uis) == UIT_PROMPT) {
            PinDialog dlg;
            if (dlg.exec() != QDialog::Accepted) return 0;

            QString pin = dlg.getPin();
            QByteArray pinBytes = pin.toUtf8();

            char* buffer = const_cast<char*>(UI_get0_result_string(uis));
            if (buffer) {
                size_t len = qMin(pinBytes.size(), static_cast<int>(UI_get_result_maxsize(uis)));
                memcpy(buffer, pinBytes.constData(), len);
                if (len < UI_get_result_maxsize(uis))
                    buffer[len] = '\0';

                pinBytes.fill(0);
                return 1;
            }

            pinBytes.fill(0);
        }
        return 0;
    });


    return method;
}

void HSMConfig::closeState()
{
    if (this->p11Func && this->sessionHandle) {
        this->p11Func->C_CloseSession(this->sessionHandle);

    }
    this->sessionHandle = 0;
    this->resetOpenSSLCtx();
    this->slotID = 0;
    this->allSlotID.clear();
    this->allCertificates.clear();
}



Certificate HSMConfig::getCertificateById(const std::string& idHex) const
{
    for (const auto& cert : allCertificates) {
        if (cert.getIdHex() == idHex) {
            return cert;
        }
    }

    return Certificate();
}


EVP_PKEY* HSMConfig::loadKey(const QString& pkcs11Uri)
{

    this->ensureOpenSSLCtx();
    EVP_PKEY* pkey = nullptr;

    UI_METHOD* uiMethod = createCustomUIMethod();
    // OSSL_LIB_CTX* libctx = nullptr;

    OSSL_STORE_CTX* store = OSSL_STORE_open_ex(
        pkcs11Uri.toStdString().c_str(),
        this->m_libctx,
        nullptr,         // no property query
        uiMethod,
        nullptr,         // no ui_data
        nullptr,         // no params
        nullptr,
        nullptr
        );

    if (!store) {
        return nullptr;
    }

    OSSL_STORE_INFO* info = nullptr;
    while (!OSSL_STORE_eof(store)) {
        info = OSSL_STORE_load(store);
        if (!info) {
            break;
        }
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            pkey = OSSL_STORE_INFO_get1_PKEY(info);
            OSSL_STORE_INFO_free(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store);
    return pkey;
}


bool HSMConfig::isLoggedIn() const
{
    CK_SESSION_INFO info;
    CK_RV rv = this->p11Func->C_GetSessionInfo(this->sessionHandle, &info);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_GetSessionInfo failed: 0x%lX\n", rv);
        return false;
    }

    return (info.state == CKS_RO_USER_FUNCTIONS ||
            info.state == CKS_RW_USER_FUNCTIONS);
}

bool HSMConfig::loadHSMLibrary(const QString& libPath)
{
    if (this->libHandle) {
        this->freeResource();
    }

    this->libHandle = LoadLibraryA(libPath.toStdString().c_str());
    if (!this->libHandle) {
        return false;
    }

    auto cGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(this->libHandle, "C_GetFunctionList");
    if (!cGetFunctionList) {
        this->freeResource();
        return false;
    }

    CK_RV rv = cGetFunctionList(&this->p11Func);
    if (rv != CKR_OK || !this->p11Func) {
        qWarning("C_GetFunctionList failed: 0x%lX", rv);
        this->freeResource();
        return false;
    }

    rv = this->p11Func->C_Initialize(NULL_PTR);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        qWarning("C_Initialize failed: 0x%lX", rv);
        return false;
    }
    isInitialized = true;
    return true;
}



bool HSMConfig::checkOperation(CK_RV rv, const char *message)
{
    if (rv!=CKR_OK) {
        return false;
    }
    return true;
}

bool HSMConfig::selectSlotByLabel(const QString& expectedLabel)
{
    CK_ULONG slotCount = this->allSlotID.size();
    for (CK_ULONG i = 0; i < slotCount; ++i) {
        CK_TOKEN_INFO tokenInfo;
        QString label = this->getLable(this->allSlotID[i]);

        if (label == expectedLabel) {
            this->slotID = this->allSlotID[i];
            return true;
        }
    }
    return false;
}

bool HSMConfig::login(CK_BYTE *slotPin)
{
    if (this->sessionHandle == 0) return false;
    bool result = this->checkOperation(
        this->p11Func->C_Login(this->sessionHandle, CKU_USER, slotPin, strlen((const char*)slotPin)),
        "C_Login"
        );

    SecureZeroMemory(slotPin, strlen((const char*)slotPin));
    return result;
}

bool HSMConfig::logout()
{
    if (!this->sessionHandle) return false;
    return this->checkOperation(this->p11Func->C_Logout(this->sessionHandle),"C_Logout");
}

bool HSMConfig::connectToSlot()
{
    if (!this->slotID) {
        return false;
    }
    return this->checkOperation(this->p11Func->C_OpenSession(this->slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &this->sessionHandle),"C_OpenSession");
}

bool HSMConfig::disconnectToSlot()
{
    if (!this->sessionHandle) return false;
    return this->checkOperation(this->p11Func->C_CloseSession(this->sessionHandle),"C_CloseSession");
}

QString HSMConfig::getLable(CK_SLOT_ID slotID)
{
    CK_TOKEN_INFO tokenInfo;
    if (!checkOperation(this->p11Func->C_GetTokenInfo(slotID, &tokenInfo),"C_GetTokenInfo"))
        return "";

    QString label = QString::fromUtf8((char*)tokenInfo.label, sizeof(tokenInfo.label)).trimmed();
    return label;
}

CK_TOKEN_INFO HSMConfig::getInfoToken(CK_SLOT_ID slotID)
{
    CK_TOKEN_INFO tokenInfo;
    memset(&tokenInfo, 0, sizeof(tokenInfo));
    this->p11Func->C_GetTokenInfo(slotID, &tokenInfo);
    return tokenInfo;
}

bool HSMConfig::ensureOpenSSLCtx() {
    if (!m_libctx) {
        m_libctx = OSSL_LIB_CTX_new();
        if (!m_libctx) return false;
    }
    if (!m_provDefault) {
        m_provDefault = OSSL_PROVIDER_load(m_libctx, "default");
        if (!m_provDefault) return false;
    }
    if (!m_provPkcs11) {
        m_provPkcs11 = OSSL_PROVIDER_load(m_libctx, "pkcs11prov");
        if (!m_provPkcs11) return false;
    }
    return true;
}

void HSMConfig::resetOpenSSLCtx() {
    // if (m_provPkcs11) { OSSL_PROVIDER_unload(m_provPkcs11); m_provPkcs11 = nullptr; }
    // if (m_provDefault) { OSSL_PROVIDER_unload(m_provDefault); m_provDefault = nullptr; }
    if (m_provPkcs11) {m_provPkcs11 = nullptr; }
    if (m_provDefault) {m_provDefault = nullptr; }
    if (m_libctx) { OSSL_LIB_CTX_free(m_libctx); m_libctx = nullptr; }
}

int HSMConfig::createCertificate(const QString &label, const QString &commonName, const QString &organization, const QString &country, int validDays, bool canSignCer)
{
    int ID = this->createPairKey(label, canSignCer);
    if (!ID) return 0;
    QString selectedId = QString::number(ID);
    QByteArray idBytes = QByteArray::fromHex(selectedId.toUtf8());
    QString encodedId = QString::fromLatin1(QUrl::toPercentEncoding(QString::fromLatin1(idBytes)));

    // Lấy private key tương ứng trong HSM
    CK_TOKEN_INFO tokenInfo = this->getInfoToken(this->getSlotID());
    QString serial = QString::fromUtf8(reinterpret_cast<const char*>(tokenInfo.serialNumber), sizeof(tokenInfo.serialNumber)).trimmed();
    QString tokenLabel = this->getLable(this->getSlotID());
    QString keyUri = QStringLiteral("pkcs11:token=%1;serial=%2;id=%3;type=public")
                         .arg(tokenLabel, serial, encodedId);

    EVP_PKEY* pubkey = this->loadKey(keyUri);
    if (!pubkey) {
        return 0;
    }
    QString keyUriPrivate = QStringLiteral("pkcs11:token=%1;serial=%2;id=%3;type=private")
                                .arg(tokenLabel, serial, encodedId);

    EVP_PKEY* priKey = this->loadKey(keyUriPrivate);
    if (!priKey) {
        EVP_PKEY_free(pubkey);
        return 0;
    }



    X509* x509 = X509_new();
    if (!x509) return 0;
    X509_set_version(x509, 2); // v3
    ASN1_INTEGER* asn1Serial = ASN1_INTEGER_new();
    BIGNUM* bn = BN_new();
    BN_pseudo_rand(bn, 64, 0, 0);        // sinh 64-bit ngẫu nhiên
    BN_to_ASN1_INTEGER(bn, asn1Serial);
    X509_set_serialNumber(x509, asn1Serial);
    ASN1_INTEGER_free(asn1Serial);
    BN_free(bn);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), validDays * 24 * 60 * 60);
    X509_set_pubkey(x509, pubkey);
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN",  MBSTRING_UTF8, (unsigned char*)commonName.toUtf8().data(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",   MBSTRING_UTF8, (unsigned char*)organization.toUtf8().data(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "C",   MBSTRING_UTF8, (unsigned char*)country.toUtf8().data(), -1, -1, 0);
    X509_set_issuer_name(x509, name);

    X509_EXTENSION* ext = nullptr;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x509, x509, nullptr, nullptr, 0);

    // Basic Constraints
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, canSignCer ? "CA:TRUE" : "CA:FALSE");
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);

    // Key Usage
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, canSignCer ? "digitalSignature,keyEncipherment,keyCertSign" : "digitalSignature,keyEncipherment");
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);

    if (!X509_sign(x509, priKey, EVP_sha256())) {
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(priKey);
        X509_free(x509);
        return 0;
    }

    // X509_print_fp(stdout, x509);
    // save to HSM token

    // Lấy Subject
    int len = i2d_X509_NAME(X509_get_subject_name(x509), nullptr);
    QByteArray subject(len, 0);
    unsigned char* p = (unsigned char*)subject.data();
    i2d_X509_NAME(X509_get_subject_name(x509), &p);

    // Lấy Issuer
    len = i2d_X509_NAME(X509_get_issuer_name(x509), nullptr);
    QByteArray issuer(len, 0);
    p = (unsigned char*)issuer.data();
    i2d_X509_NAME(X509_get_issuer_name(x509), &p);

    // Lấy Serial Number
    ASN1_INTEGER* asn1Serial2 = X509_get_serialNumber(x509);
    len = i2d_ASN1_INTEGER(asn1Serial2, nullptr);
    QByteArray certSerial(len, 0);
    p = (unsigned char*)certSerial.data();
    i2d_ASN1_INTEGER(asn1Serial2, &p);


    unsigned char* der = nullptr;
    int derLen = i2d_X509(x509, &der);
    if (derLen <= 0) {
        X509_free(x509);
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(priKey);
        return 0;
    }
    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BYTE ckID[1];
    ckID[0] = ID & 0xFF;
    QByteArray labelBytes = label.toLatin1();
    if (labelBytes.size() > 32) labelBytes = labelBytes.left(32);

    CK_ATTRIBUTE certTemplate[] = {
        {CKA_CLASS, &certClass, sizeof(certClass)},
        {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)},
        {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE, der, static_cast<CK_ULONG>(derLen)},
        {CKA_ID, ckID, sizeof(ckID)},
        {CKA_LABEL, reinterpret_cast<CK_BYTE_PTR>(labelBytes.data()), static_cast<CK_ULONG>(labelBytes.size())},
        {CKA_SUBJECT, (CK_VOID_PTR)subject.data(), (CK_ULONG)subject.size()},
        {CKA_ISSUER, (CK_VOID_PTR)issuer.data(), (CK_ULONG)issuer.size()},
        {CKA_SERIAL_NUMBER, (CK_VOID_PTR)certSerial.data(), (CK_ULONG)certSerial.size()}
    };

    CK_OBJECT_HANDLE certHandle;
    CK_RV rv = p11Func->C_CreateObject(sessionHandle, certTemplate,
                                       sizeof(certTemplate)/sizeof(CK_ATTRIBUTE),
                                       &certHandle);
    // qDebug() << rv;
    OPENSSL_free(der);
    X509_free(x509);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(priKey);
    return 1;
}

int HSMConfig::createPairKey(const QString& label, bool isForCertSign)
{

    if (!this->p11Func || !this->sessionHandle) {
        return 0;
    }
    // --- count CK_ID ---
    CK_BYTE nextId = 1;

    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE searchTemplate[] = { {CKA_CLASS, &keyClass, sizeof(keyClass)} };

    CK_RV rv = p11Func->C_FindObjectsInit(sessionHandle, searchTemplate, 1);
    if (rv == CKR_OK) {
        const CK_ULONG maxObj = 50;
        CK_OBJECT_HANDLE objs[maxObj];
        CK_ULONG found = 0;
        while (true) {
            rv = p11Func->C_FindObjects(sessionHandle, objs, maxObj, &found);
            if (rv != CKR_OK || found == 0) break;

            for (CK_ULONG i = 0; i < found; ++i) {
                CK_OBJECT_HANDLE obj = objs[i];

                CK_ATTRIBUTE attrID = {CKA_ID, nullptr, 0};
                if (p11Func->C_GetAttributeValue(sessionHandle, obj, &attrID, 1) == CKR_OK && attrID.ulValueLen > 0) {
                    std::vector<CK_BYTE> id(attrID.ulValueLen);
                    attrID.pValue = id.data();
                    if (p11Func->C_GetAttributeValue(sessionHandle, obj, &attrID, 1) == CKR_OK) {
                        if (id[0] >= nextId) nextId = id[0] + 1;
                    }
                }
            }
        }
        p11Func->C_FindObjectsFinal(sessionHandle);
    }
    if (nextId>=10) return -1;

    //gen KeyPair
    CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

    CK_ULONG modulusBits = 4096;
    CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 }; // 65537
    CK_BBOOL ckTrue = CK_TRUE;

    // Label
    std::string pubLabel = label.toStdString();
    std::string privLabel = label.toStdString();

    // Public key template
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ATTRIBUTE pubTemplate[] = {
        {CKA_CLASS, &pubClass, sizeof(pubClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
        {CKA_ENCRYPT, &ckTrue, sizeof(ckTrue)},
        {CKA_VERIFY, &ckTrue, sizeof(ckTrue)},
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
        {CKA_LABEL, (CK_VOID_PTR)pubLabel.c_str(), (CK_ULONG)pubLabel.size()},
        {CKA_ID, &nextId, sizeof(nextId)}
    };

    // Private key template
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE privTemplate[12];
    int privCount = 0;

    privTemplate[privCount++] = {CKA_CLASS, &privClass, sizeof(privClass)};
    privTemplate[privCount++] = {CKA_KEY_TYPE, &keyType, sizeof(keyType)};
    privTemplate[privCount++] = {CKA_TOKEN, &ckTrue, sizeof(ckTrue)};
    privTemplate[privCount++] = {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)};
    privTemplate[privCount++] = {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)};
    privTemplate[privCount++] = {CKA_DECRYPT, &ckTrue, sizeof(ckTrue)};
    privTemplate[privCount++] = {CKA_LABEL, (CK_VOID_PTR)privLabel.c_str(), (CK_ULONG)privLabel.size()};
    privTemplate[privCount++] = {CKA_ID, &nextId, sizeof(nextId)};
    privTemplate[privCount++] = {CKA_SIGN, &ckTrue, sizeof(ckTrue)};

    CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hPriv = CK_INVALID_HANDLE;
    rv = this->p11Func->C_GenerateKeyPair(
        this->sessionHandle,
        &mechanism,
        pubTemplate, sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE),
        privTemplate, privCount,
        &hPub, &hPriv
        );

    // qDebug() << rv;
    if (rv != CKR_OK) {
        return 0;
    }

    return nextId;
}


int HSMConfig::changePin(QString &currentPin, QString &newPin)
{
    if (!this->p11Func || !this->sessionHandle) {
        return -1; //PKCS#11 not initialized or no session.
    }

    // Lấy độ dài PIN
    CK_TOKEN_INFO tokenInfo;
    memset(&tokenInfo, 0, sizeof(tokenInfo));
    CK_RV rvInfo = this->p11Func->C_GetTokenInfo(this->slotID, &tokenInfo);
    if (rvInfo != CKR_OK) {
        return -2; //changePin: GetTokenInfo failed
    }

    QByteArray oldPinBytes = currentPin.toUtf8();
    QByteArray newPinBytes = newPin.toUtf8();

    currentPin.fill(QChar(0));
    newPin.fill(QChar(0));

    const CK_ULONG newLen = static_cast<CK_ULONG>(newPinBytes.size());
    const CK_ULONG minLen = tokenInfo.ulMinPinLen;
    const CK_ULONG maxLen = tokenInfo.ulMaxPinLen ? tokenInfo.ulMaxPinLen : 255;

    if (newLen < minLen || newLen > maxLen) {
        SecureZeroMemory(oldPinBytes.data(), oldPinBytes.size());
        SecureZeroMemory(newPinBytes.data(), newPinBytes.size());
        oldPinBytes.fill(0);
        newPinBytes.fill(0);
        return -3; //changePin: New PIN length invalid
    }

    CK_RV rv = this->p11Func->C_SetPIN(
        this->sessionHandle,
        reinterpret_cast<CK_UTF8CHAR_PTR>(oldPinBytes.data()),
        static_cast<CK_ULONG>(oldPinBytes.size()),
        reinterpret_cast<CK_UTF8CHAR_PTR>(newPinBytes.data()),
        static_cast<CK_ULONG>(newPinBytes.size())
        );

    SecureZeroMemory(oldPinBytes.data(), oldPinBytes.size());
    SecureZeroMemory(newPinBytes.data(), newPinBytes.size());
    oldPinBytes.fill(0);
    newPinBytes.fill(0);

    if (rv == CKR_OK) {
        return 1;
    }

    switch (rv) {
    case CKR_USER_NOT_LOGGED_IN:
        return -4; //changePin: USER_NOT_LOGGED_IN
    case CKR_PIN_INCORRECT:
        return -5; //changePin: PIN_INCORRECT
    case CKR_PIN_LOCKED:
        return -6; //changePin: PIN_LOCKED
    case CKR_PIN_LEN_RANGE:
        return -7; //changePin: PIN_LEN_RANGE
    }

    return 0; //không xác định
}

bool HSMConfig::hasAnyObject(CK_SLOT_ID slotID)
{
    if (!p11Func) return false;

    CK_SESSION_HANDLE session;
    CK_RV rv = p11Func->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) return false;

    rv = p11Func->C_FindObjectsInit(session, nullptr, 0);
    if (rv != CKR_OK) {
        p11Func->C_CloseSession(session);
        return false;
    }

    CK_OBJECT_HANDLE obj;
    CK_ULONG objCount = 0;
    rv = p11Func->C_FindObjects(session, &obj, 1, &objCount);

    p11Func->C_FindObjectsFinal(session);
    p11Func->C_CloseSession(session);

    return (rv == CKR_OK && objCount > 0);
}

int HSMConfig::countObjectByID(const QString& ID)
{
    if (!p11Func || ID.isEmpty())
        return 0;

    CK_SESSION_HANDLE session;
    CK_RV rv = p11Func->C_OpenSession(this->slotID, CKF_SERIAL_SESSION, nullptr, nullptr, &session);
    if (rv != CKR_OK)
        return 0;

    int IDx = ID.toInt();
    CK_BYTE ckID[1];
    ckID[0] = IDx & 0xFF;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_ID, ckID, sizeof(CK_BYTE)}
    };

    rv = p11Func->C_FindObjectsInit(session, tmpl, 1);
    if (rv != CKR_OK) {
        p11Func->C_CloseSession(session);
        return 0;
    }

    CK_OBJECT_HANDLE objs[10];
    CK_ULONG foundThisTime = 0;
    CK_ULONG totalFound = 0;

    do {
        rv = p11Func->C_FindObjects(session, objs, 10, &foundThisTime);
        if (rv != CKR_OK)
            break;
        totalFound += foundThisTime;
    } while (foundThisTime > 0);

    p11Func->C_FindObjectsFinal(session);
    p11Func->C_CloseSession(session);

    return static_cast<int>(totalFound);
}


X509_REQ *HSMConfig::createCSR(const QString &label, const QString &commonName, const QString &organization, const QString &country, bool canSignCert)
{
    int ID = this->createPairKey(label, canSignCert);
    if (!ID) return nullptr;

    QString selectedId = QString::number(ID);
    QByteArray idBytes = QByteArray::fromHex(selectedId.toUtf8());
    QString encodedId = QString::fromLatin1(QUrl::toPercentEncoding(QString::fromLatin1(idBytes)));

    CK_TOKEN_INFO tokenInfo = this->getInfoToken(this->getSlotID());
    QString serial = QString::fromUtf8(reinterpret_cast<const char*>(tokenInfo.serialNumber),
                                       sizeof(tokenInfo.serialNumber)).trimmed();
    QString tokenLabel = this->getLable(this->getSlotID());

    QString pubUri = QStringLiteral("pkcs11:token=%1;serial=%2;id=%3;type=public")
                         .arg(tokenLabel, serial, encodedId);
    QString priUri = QStringLiteral("pkcs11:token=%1;serial=%2;id=%3;type=private")
                         .arg(tokenLabel, serial, encodedId);

    EVP_PKEY* pubkey = this->loadKey(pubUri);
    EVP_PKEY* prikey = this->loadKey(priUri);

    if (!pubkey || !prikey) {
        if (pubkey) EVP_PKEY_free(pubkey);
        if (prikey) EVP_PKEY_free(prikey);
        return nullptr;
    }

    X509_REQ* req = X509_REQ_new();
    if (!req) {
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(prikey);
        return nullptr;
    }

    X509_REQ_set_version(req, 1); // v1

    X509_NAME* name = X509_NAME_new();
    if (!commonName.isEmpty())
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                   (unsigned char*)commonName.toUtf8().data(), -1, -1, 0);
    if (!organization.isEmpty())
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_UTF8,
                                   (unsigned char*)organization.toUtf8().data(), -1, -1, 0);
    if (!country.isEmpty())
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_UTF8,
                                   (unsigned char*)country.toUtf8().data(), -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name);

    X509_REQ_set_pubkey(req, pubkey);

    if (!X509_REQ_sign(req, prikey, EVP_sha256())) {
        X509_REQ_free(req);
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(prikey);
        return nullptr;
    }

    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(prikey);

    return req;
}



bool HSMConfig::DestroyObject(const QString& Qid)
{
    std::vector<CK_BYTE> id;
    qDebug() << Qid;
    int idNum = Qid.toInt();
    id.push_back(static_cast<CK_BYTE>(idNum & 0xFF));
    qDebug() << id;
    qDebug() << "-----";
    CK_ATTRIBUTE tmp[] = {CKA_ID, id.data(), static_cast<CK_ULONG>(id.size())};
    CK_RV ok = this->p11Func->C_FindObjectsInit(this->sessionHandle,tmp,sizeof(tmp)/sizeof(CK_ATTRIBUTE));
    if (ok!=CKR_OK) return false;
    CK_OBJECT_HANDLE oh;
    CK_ULONG find=0;
    while (true) {
        ok=this->p11Func->C_FindObjects(this->sessionHandle,&oh,1, &find);
        if (ok!=CKR_OK) {
            this->p11Func->C_FindObjectsFinal(this->sessionHandle);
            return false;
        }
        qDebug() << find;
        if (find==0) {
            this->p11Func->C_FindObjectsFinal(this->sessionHandle);
            break;
        }
        ok=this->p11Func->C_DestroyObject(this->sessionHandle,oh);
        if (ok!=CKR_OK) {
            this->p11Func->C_FindObjectsFinal(this->sessionHandle);
            return false;
        }
    }
    return true;
}


int HSMConfig::saveCertificateFromFile(const QString &filePath, int ID) {
    QFileInfo fi(filePath);
    QString label = fi.completeBaseName();

    FILE *fp = fopen(filePath.toUtf8().constData(), "r");
    if (!fp) {
        qWarning() << "Không mở được file:" << filePath;
        return 0;
    }

    X509 *x509 = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!x509) {
        rewind(fp);
        x509 = d2i_X509_fp(fp, NULL);
    }
    fclose(fp);

    if (!x509) {
        qWarning() << "Không load được chứng chỉ từ file:" << filePath;
        return 0;
    }

    int len = i2d_X509_NAME(X509_get_subject_name(x509), nullptr);
    QByteArray subject(len, 0);
    unsigned char* p = (unsigned char*)subject.data();
    i2d_X509_NAME(X509_get_subject_name(x509), &p);

    len = i2d_X509_NAME(X509_get_issuer_name(x509), nullptr);
    QByteArray issuer(len, 0);
    p = (unsigned char*)issuer.data();
    i2d_X509_NAME(X509_get_issuer_name(x509), &p);

    ASN1_INTEGER* asn1Serial = X509_get_serialNumber(x509);
    len = i2d_ASN1_INTEGER(asn1Serial, nullptr);
    QByteArray certSerial(len, 0);
    p = (unsigned char*)certSerial.data();
    i2d_ASN1_INTEGER(asn1Serial, &p);

    unsigned char* der = nullptr;
    int derLen = i2d_X509(x509, &der);
    if (derLen <= 0) {
        X509_free(x509);
        return 0;
    }

    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BYTE ckID[1];
    ckID[0] = ID & 0xFF;

    QByteArray labelBytes = label.toLatin1();
    if (labelBytes.size() > 32) labelBytes = labelBytes.left(32);

    CK_ATTRIBUTE certTemplate[] = {
        {CKA_CLASS, &certClass, sizeof(certClass)},
        {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)},
        {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE, der, static_cast<CK_ULONG>(derLen)},
        {CKA_ID, ckID, sizeof(ckID)},
        {CKA_LABEL, reinterpret_cast<CK_BYTE_PTR>(labelBytes.data()),
         static_cast<CK_ULONG>(labelBytes.size())},
        {CKA_SUBJECT, (CK_VOID_PTR)subject.data(), (CK_ULONG)subject.size()},
        {CKA_ISSUER, (CK_VOID_PTR)issuer.data(), (CK_ULONG)issuer.size()},
        {CKA_SERIAL_NUMBER, (CK_VOID_PTR)certSerial.data(),
         (CK_ULONG)certSerial.size()}
    };

    CK_OBJECT_HANDLE certHandle;
    CK_RV rv = p11Func->C_CreateObject(
        sessionHandle,
        certTemplate,
        sizeof(certTemplate)/sizeof(CK_ATTRIBUTE),
        &certHandle
        );

    OPENSSL_free(der);
    X509_free(x509);

    if (rv != CKR_OK) {
        qWarning() << "C_CreateObject failed:" << rv;
        return 0;
    }

    return 1;
}

int HSMConfig::saveCertificateFromMem(X509 *cer, const QString& label, int ID)
{
    if (!cer) {
        qWarning() << "Không thể load chứng chỉ!";
        return 0;
    }

    // Subject
    int len = i2d_X509_NAME(X509_get_subject_name(cer), nullptr);
    QByteArray subject(len, 0);
    unsigned char* p = reinterpret_cast<unsigned char*>(subject.data());
    i2d_X509_NAME(X509_get_subject_name(cer), &p);

    // Issuer
    len = i2d_X509_NAME(X509_get_issuer_name(cer), nullptr);
    QByteArray issuer(len, 0);
    p = reinterpret_cast<unsigned char*>(issuer.data());
    i2d_X509_NAME(X509_get_issuer_name(cer), &p);

    // Serial number
    ASN1_INTEGER* asn1Serial = X509_get_serialNumber(cer);
    len = i2d_ASN1_INTEGER(asn1Serial, nullptr);
    QByteArray certSerial(len, 0);
    p = reinterpret_cast<unsigned char*>(certSerial.data());
    i2d_ASN1_INTEGER(asn1Serial, &p);

    // To DER
    unsigned char* der = nullptr;
    int derLen = i2d_X509(cer, &der);
    if (derLen <= 0) {
        X509_free(cer);
        return 0;
    }

    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BYTE ckID[1];
    ckID[0] = ID & 0xFF;

    QByteArray labelBytes = label.toLatin1();
    if (labelBytes.size() > 32)
        labelBytes = labelBytes.left(32);

    CK_ATTRIBUTE certTemplate[] = {
        {CKA_CLASS, &certClass, sizeof(certClass)},
        {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)},
        {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE, der, static_cast<CK_ULONG>(derLen)},
        {CKA_ID, ckID, sizeof(ckID)},
        {CKA_LABEL, reinterpret_cast<CK_BYTE_PTR>(labelBytes.data()),
         static_cast<CK_ULONG>(labelBytes.size())},
        {CKA_SUBJECT, (CK_VOID_PTR)subject.data(), (CK_ULONG)subject.size()},
        {CKA_ISSUER, (CK_VOID_PTR)issuer.data(), (CK_ULONG)issuer.size()},
        {CKA_SERIAL_NUMBER, (CK_VOID_PTR)certSerial.data(),
         (CK_ULONG)certSerial.size()}
    };

    CK_OBJECT_HANDLE certHandle;
    CK_RV rv = p11Func->C_CreateObject(
        sessionHandle,
        certTemplate,
        sizeof(certTemplate) / sizeof(CK_ATTRIBUTE),
        &certHandle);

    OPENSSL_free(der);
    X509_free(cer);

    if (rv != CKR_OK) {
        qWarning() << "C_CreateObject failed:" << rv;
        return 0;
    }

    return 1;
}

