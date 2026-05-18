#include <QCoreApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QDebug>
#include <iostream>

#include "filewalker.h"

int main(int argc, char* argv[])
{
    // QCoreApplication initialises Qt internals (no GUI needed for a CLI app)
    QCoreApplication app(argc, argv);
    app.setApplicationName("FileEncryptor");
    app.setApplicationVersion("1.0");

    // ── Argument parsing ──────────────────────────────────────────────────
    QCommandLineParser parser;
    parser.setApplicationDescription(
        "Recursively encrypt or decrypt all files in a folder using AES-256-CBC."
        );
    parser.addHelpOption();
    parser.addVersionOption();

    // --encrypt / --decrypt  (mutually exclusive, checked below)
    QCommandLineOption encryptOpt(
        {"e", "encrypt"},
        "Encrypt the target folder."
        );
    QCommandLineOption decryptOpt(
        {"d", "decrypt"},
        "Decrypt the target folder."
        );

    // --path <directory>
    QCommandLineOption pathOpt(
        {"p", "path"},
        "Path to the folder to process.",
        "directory"
        );

    // --password <secret>
    QCommandLineOption passwordOpt(
        {"k", "password"},
        "Password used as the encryption key.",
        "secret"
        );

    parser.addOption(encryptOpt);
    parser.addOption(decryptOpt);
    parser.addOption(pathOpt);
    parser.addOption(passwordOpt);

    parser.process(app);

    // ── Validate arguments ────────────────────────────────────────────────
    bool doEncrypt = parser.isSet(encryptOpt);
    bool doDecrypt = parser.isSet(decryptOpt);

    if (doEncrypt == doDecrypt) {     // both set or neither set
        std::cerr << "Error: specify exactly one of --encrypt or --decrypt.\n\n";
        parser.showHelp(1);
    }

    if (!parser.isSet(pathOpt)) {
        std::cerr << "Error: --path is required.\n\n";
        parser.showHelp(1);
    }

    if (!parser.isSet(passwordOpt)) {
        std::cerr << "Error: --password is required.\n\n";
        parser.showHelp(1);
    }

    const QString path     = parser.value(pathOpt);
    const QString password = parser.value(passwordOpt);

    if (!QDir(path).exists()) {
        std::cerr << "Error: directory does not exist: " << qPrintable(path) << "\n";
        return 1;
    }

    // ── Run ───────────────────────────────────────────────────────────────
    FileWalker::Mode mode = doEncrypt ? FileWalker::Mode::Encrypt
                                      : FileWalker::Mode::Decrypt;

    std::cout << (doEncrypt ? "Encrypting" : "Decrypting")
              << " all files in: " << qPrintable(path) << "\n";

    FileWalker walker(path, mode, password);
    int count = walker.run();

    std::cout << "Done. Files processed successfully: " << count << "\n";
    return 0;
}
