#ifndef CRYPTOUTILS_H
#define CRYPTOUTILS_H

#include <QByteArray>
#include <QString>
#include <QStringList>

enum CompressionType {
    COMPRESSION_NONE = 0,
    COMPRESSION_ZLIB = 1,
    COMPRESSION_BZIP2 = 2
};

class CryptoUtils {

public:
    static bool isConfigFile(const QString &fileName);

    static bool detectCompression(const QByteArray &fileContent);

    static CompressionType detectCompressionType(const QByteArray &fileContent);

    static QByteArray decompressZlibChunk(const QByteArray &compressedData, QString *errorMsg = nullptr);

    static QByteArray decompressBzip2Chunk(const QByteArray &compressedData, QString *errorMsg = nullptr);

    static QByteArray decompressChunk(const QByteArray &compressedData, CompressionType type, QString *errorMsg = nullptr);

    static QByteArray processFileContent(const QByteArray &fileContent, bool isCompressed, const QString &fileName,
                                         CompressionType compressionType = COMPRESSION_NONE, QString *errorMsg = nullptr);

    static QByteArray decryptString(const QByteArray &encryptedData, const QString &password, QString *errorMsg = nullptr);

    static QByteArray processFileContentWithPassword(const QByteArray &fileContent, bool isCompressed,
                                                      const QString &fileName, const QString &password,
                                                      CompressionType compressionType = COMPRESSION_NONE, QString *errorMsg = nullptr);

    static int cryptIvLength();

private:
    static const QStringList CONFIG_FILES;
    static const int CHUNK_SIZE_PREFIX_LENGTH; // 4 bytes for compressed chunk size
    static const int ENCRYPTION_CHUNK_SIZE;    // 512000 + 16 (IV) + 16 (AES padding)
};

#endif // CRYPTOUTILS_H
