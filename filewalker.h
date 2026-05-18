#pragma once

#include <QString>

/**
 * FileWalker
 *
 * Recursively iterates over every file inside @p rootPath
 * and calls CryptoManager::encryptFile() or decryptFile() on each one.
 *
 * It uses QDirIterator with the QDirIterator::Subdirectories flag,
 * which is the Qt idiomatic way to traverse a directory tree.
 */
class FileWalker
{
public:
    enum class Mode { Encrypt, Decrypt };

    explicit FileWalker(const QString& rootPath, Mode mode, const QString& password);

    /**
     * Run the walk.  Returns the number of files successfully processed.
     * Errors are printed to stderr but do not abort the walk.
     */
    int run();

private:
    QString  m_rootPath;
    Mode     m_mode;
    QString  m_password;
};
