#include "cryptomanager.h"

#include <QFile>
#include <QDebug>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/rand.h>

// ── Magic bytes that mark an encrypted file ───────────────────────────────────
//    "FENC" + version byte 0x01 + 3 reserved bytes
const char CryptoManager::MAGIC[8] = {'F','E','N','C','\x01','\x00','\x00','\x00'};

// ── Singleton ─────────────────────────────────────────────────────────────────
CryptoManager& CryptoManager::instance()
{
    // Guaranteed to be initialised exactly once (C++11 §6.7)
    static CryptoManager s_instance;
    return s_instance;
}

// ── Key derivation ────────────────────────────────────────────────────────────
void CryptoManager::deriveKeyAndIV(const QByteArray& password,
                                   const QByteArray& salt,
                                   QByteArray&       outKey,
                                   QByteArray&       outIV)
{
    // We need KEY_BYTES + IV_BYTES of material from PBKDF2
    QByteArray derived(KEY_BYTES + IV_BYTES, '\0');

    int ok = PKCS5_PBKDF2_HMAC(
        password.constData(), password.size(),
        reinterpret_cast<const unsigned char*>(salt.constData()), salt.size(),
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        derived.size(),
        reinterpret_cast<unsigned char*>(derived.data())
        );

    if (!ok) {
        qCritical() << "[CryptoManager] PBKDF2 failed!";
        return;
    }

    outKey = derived.left(KEY_BYTES);
    outIV  = derived.right(IV_BYTES);
}

// ── Encryption ────────────────────────────────────────────────────────────────
bool CryptoManager::encryptFile(const QString& filePath, const QString& password)
{
    QFile file(filePath);

    // --- Read plaintext --------------------------------------------------
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "[Encrypt] Cannot open:" << filePath;
        return false;
    }
    QByteArray plaintext = file.readAll();
    file.close();

    // --- Skip already-encrypted files ------------------------------------
    if (plaintext.startsWith(QByteArray(MAGIC, sizeof(MAGIC)))) {
        qInfo() << "[Encrypt] Already encrypted, skipping:" << filePath;
        return true;
    }

    // --- Generate random salt and derive key/IV --------------------------
    QByteArray salt(SALT_BYTES, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), SALT_BYTES) != 1) {
        qCritical() << "[Encrypt] RAND_bytes failed for salt";
        return false;
    }

    QByteArray key, iv;
    deriveKeyAndIV(password.toUtf8(), salt, key, iv);

    // --- AES-256-CBC encrypt ---------------------------------------------
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { qCritical() << "[Encrypt] EVP_CIPHER_CTX_new failed"; return false; }

    if (EVP_EncryptInit_ex(ctx,
                           EVP_aes_256_cbc(),
                           nullptr,
                           reinterpret_cast<const unsigned char*>(key.constData()),
                           reinterpret_cast<const unsigned char*>(iv.constData())) != 1)
    {
        qCritical() << "[Encrypt] EVP_EncryptInit_ex failed";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Ciphertext can be up to plaintext.size() + one extra AES block (padding)
    QByteArray ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH, '\0');
    int outLen1 = 0, outLen2 = 0;

    if (EVP_EncryptUpdate(ctx,
                          reinterpret_cast<unsigned char*>(ciphertext.data()),
                          &outLen1,
                          reinterpret_cast<const unsigned char*>(plaintext.constData()),
                          plaintext.size()) != 1)
    {
        qCritical() << "[Encrypt] EVP_EncryptUpdate failed";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char*>(ciphertext.data()) + outLen1,
                            &outLen2) != 1)
    {
        qCritical() << "[Encrypt] EVP_EncryptFinal_ex failed";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(outLen1 + outLen2);

    // --- Write output file: MAGIC | SALT | IV | CIPHERTEXT ---------------
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "[Encrypt] Cannot write:" << filePath;
        return false;
    }
    file.write(MAGIC, sizeof(MAGIC));
    file.write(salt);
    // IV is derived deterministically from salt+password, but we store it
    // explicitly so future format changes (e.g. random IV) remain compatible
    file.write(iv);
    file.write(ciphertext);
    file.close();

    qInfo() << "[Encrypt] OK:" << filePath;
    return true;
}

// ── Decryption ────────────────────────────────────────────────────────────────
bool CryptoManager::decryptFile(const QString& filePath, const QString& password)
{
    QFile file(filePath);

    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "[Decrypt] Cannot open:" << filePath;
        return false;
    }
    QByteArray data = file.readAll();
    file.close();

    // --- Verify magic header ---------------------------------------------
    const int HEADER_SIZE = sizeof(MAGIC) + SALT_BYTES + IV_BYTES;
    if (data.size() < HEADER_SIZE ||
        !data.startsWith(QByteArray(MAGIC, sizeof(MAGIC))))
    {
        qWarning() << "[Decrypt] Not an encrypted file, skipping:" << filePath;
        return true;   // not our file → treat as success (skip silently)
    }

    QByteArray salt       = data.mid(sizeof(MAGIC), SALT_BYTES);
    QByteArray storedIV   = data.mid(sizeof(MAGIC) + SALT_BYTES, IV_BYTES);
    QByteArray ciphertext = data.mid(HEADER_SIZE);

    // --- Derive key/IV ---------------------------------------------------
    QByteArray key, derivedIV;
    deriveKeyAndIV(password.toUtf8(), salt, key, derivedIV);

    // Use the IV that was stored in the file (identical to derivedIV in this
    // scheme, but stored explicitly for forward-compatibility)
    Q_UNUSED(derivedIV)

    // --- AES-256-CBC decrypt ---------------------------------------------
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { qCritical() << "[Decrypt] EVP_CIPHER_CTX_new failed"; return false; }

    if (EVP_DecryptInit_ex(ctx,
                           EVP_aes_256_cbc(),
                           nullptr,
                           reinterpret_cast<const unsigned char*>(key.constData()),
                           reinterpret_cast<const unsigned char*>(storedIV.constData())) != 1)
    {
        qCritical() << "[Decrypt] EVP_DecryptInit_ex failed";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    QByteArray plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH, '\0');
    int outLen1 = 0, outLen2 = 0;

    if (EVP_DecryptUpdate(ctx,
                          reinterpret_cast<unsigned char*>(plaintext.data()),
                          &outLen1,
                          reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                          ciphertext.size()) != 1)
    {
        qCritical() << "[Decrypt] EVP_DecryptUpdate failed — wrong password?";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char*>(plaintext.data()) + outLen1,
                            &outLen2) != 1)
    {
        // This is the most common error when the password is wrong
        qWarning() << "[Decrypt] EVP_DecryptFinal_ex failed — bad password or corrupted file:" << filePath;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(outLen1 + outLen2);

    // --- Write back plaintext --------------------------------------------
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "[Decrypt] Cannot write:" << filePath;
        return false;
    }
    file.write(plaintext);
    file.close();

    qInfo() << "[Decrypt] OK:" << filePath;
    return true;
}
