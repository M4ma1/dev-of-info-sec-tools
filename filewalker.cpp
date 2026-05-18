#include "filewalker.h"
#include "cryptomanager.h"

#include <QDirIterator>
#include <QDebug>

FileWalker::FileWalker(const QString& rootPath, Mode mode, const QString& password)
    : m_rootPath(rootPath)
    , m_mode(mode)
    , m_password(password)
{}

int FileWalker::run()
{
    // QDirIterator::Subdirectories  → descend into every subfolder
    // QDir::Files                   → yield only regular files (skip dirs themselves)
    // QDir::NoDotAndDotDot          → skip "." and ".."
    QDirIterator it(
        m_rootPath,
        QDir::Files | QDir::NoDotAndDotDot,
        QDirIterator::Subdirectories
        );

    if (!it.hasNext()) {
        qWarning() << "[FileWalker] No files found in:" << m_rootPath;
        return 0;
    }

    CryptoManager& crypto = CryptoManager::instance();
    int successCount = 0;

    while (it.hasNext()) {
        const QString filePath = it.next();   // advances and returns the path

        bool ok = false;
        if (m_mode == Mode::Encrypt) {
            ok = crypto.encryptFile(filePath, m_password);
        } else {
            ok = crypto.decryptFile(filePath, m_password);
        }

        if (ok) ++successCount;
    }

    return successCount;
}
