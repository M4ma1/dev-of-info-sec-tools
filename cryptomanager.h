#pragma once

#include <QString>
#include <QByteArray>

/**
 * CryptoManager — Singleton
 *
 * Encrypts / decrypts a single file using AES-256-CBC (OpenSSL EVP API).
 * The user-supplied password is never stored; it is derived into a
 * 32-byte AES key + 16-byte IV using PBKDF2-SHA256 with a fixed salt
 * (stored in the encrypted file header so decryption needs only the password).
 *
 * File format after encryption:
 *   [8 bytes magic "FENC\x01\x00\x00\x00"]
 *   [16 bytes salt used for PBKDF2]
 *   [16 bytes IV  used for AES-CBC]
 *   [N  bytes AES-256-CBC ciphertext (padded to 16-byte blocks)]
 */
class CryptoManager
{
public:
    // ── Singleton access ──────────────────────────────────────────────────
    static CryptoManager& instance();

    // Delete copy / move so nobody can duplicate the singleton
    CryptoManager(const CryptoManager&)            = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Encrypt the file at @p filePath in-place using @p password.
     * Returns true on success, false otherwise (error printed to stderr).
     * Files that are already encrypted (magic header present) are skipped.
     */
    bool encryptFile(const QString& filePath, const QString& password);

    /**
     * Decrypt the file at @p filePath in-place using @p password.
     * Returns true on success, false otherwise.
     * Files that are NOT encrypted are skipped with a warning.
     */
    bool decryptFile(const QString& filePath, const QString& password);

private:
    CryptoManager() = default;   // private constructor → only instance() creates it

    // ── Internal helpers ──────────────────────────────────────────────────

    /**
     * Derive a 32-byte AES key and 16-byte IV from @p password and @p salt
     * using PBKDF2-SHA256 with PBKDF2_ITERATIONS iterations.
     */
    void deriveKeyAndIV(const QByteArray& password,
                        const QByteArray& salt,
                        QByteArray&       outKey,
                        QByteArray&       outIV);

    static constexpr int  PBKDF2_ITERATIONS = 100'000;
    static constexpr int  KEY_BYTES         = 32;  // AES-256
    static constexpr int  IV_BYTES          = 16;  // AES block size
    static constexpr int  SALT_BYTES        = 16;
    static const char     MAGIC[8];
};
