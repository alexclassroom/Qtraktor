#include "cryptoutils.h"

#include <QStringList>
#include <QCryptographicHash>
#include <zlib.h>
#include <bzlib.h>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

#ifndef AES_BLOCK_SIZE
    #define AES_BLOCK_SIZE 16
#endif

const QStringList CryptoUtils::CONFIG_FILES = {
    "package.json",
    "multisite.json"
};

const int CryptoUtils::CHUNK_SIZE_PREFIX_LENGTH = 4;
const int CryptoUtils::ENCRYPTION_CHUNK_SIZE = 512032; // 512000 plaintext + 16 IV + 16 AES padding
static constexpr int OUTPUT_BUFFER_SIZE = 32768;

static quint32 readBigEndianUInt32(const QByteArray& data, int offset)
{
    quint32 value = 0;
    for (int i = 0; i < 4; ++i) {
        value = (value << 8) | static_cast<unsigned char>(data[offset + i]);
    }
    return value;
}

bool CryptoUtils::isConfigFile(const QString& fileName)
{
    return CONFIG_FILES.contains(fileName.section('/', -1));
}

static QByteArray inflateWithMode(const QByteArray& compressedData, int windowBits, QString* errorMsg)
{
    if (errorMsg) errorMsg->clear();

    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));

    zs.next_in  = reinterpret_cast<Bytef*>(const_cast<char*>(compressedData.data()));
    zs.avail_in = static_cast<uInt>(compressedData.size());

    const int initRet = inflateInit2(&zs, windowBits);
    if (initRet != Z_OK) {
        if (errorMsg) *errorMsg = QString("zlib inflateInit2 failed: %1").arg(initRet);
        return {};
    }

    QByteArray output;
    char buffer[OUTPUT_BUFFER_SIZE];

    int ret = Z_OK;
    while (ret == Z_OK) {
        zs.next_out  = reinterpret_cast<Bytef*>(buffer);
        zs.avail_out = sizeof(buffer);

        ret = inflate(&zs, Z_NO_FLUSH);

        const int produced = static_cast<int>(sizeof(buffer) - zs.avail_out);
        if (produced > 0) {
            output.append(buffer, produced);
        }

        if (ret == Z_BUF_ERROR && produced == 0) {

            break;
        }
    }

    inflateEnd(&zs);

    if (ret != Z_STREAM_END) {
        if (errorMsg) {
            *errorMsg = QString("zlib inflate failed: %1 (%2)")
                            .arg(ret)
                            .arg(zs.msg ? zs.msg : "no message");
        }
        return {};
    }

    return output;
}

QByteArray CryptoUtils::decompressZlibChunk(const QByteArray& compressedData, QString* errorMsg)
{
    if (errorMsg) errorMsg->clear();

    if (compressedData.isEmpty()) {
        if (errorMsg) *errorMsg = "zlib: empty input";
        return {};
    }

    QByteArray out = inflateWithMode(compressedData, 15, errorMsg);
    if (errorMsg && errorMsg->isEmpty()) {
        return out;
    }

    if (compressedData.size() >= 2 &&
        static_cast<unsigned char>(compressedData[0]) == 0x1f &&
        static_cast<unsigned char>(compressedData[1]) == 0x8b) {
        QString gzipErr;
        QByteArray outGzip = inflateWithMode(compressedData, 31, &gzipErr);
        if (gzipErr.isEmpty()) {
            if (errorMsg) errorMsg->clear();
            return outGzip;
        }
    }

    if (errorMsg && errorMsg->isEmpty()) {
        *errorMsg = QString("zlib/gzip decompression failed");
    }
    return {};
}

QByteArray CryptoUtils::decompressBzip2Chunk(const QByteArray& compressedData, QString* errorMsg)
{
    if (errorMsg) errorMsg->clear();

    if (compressedData.isEmpty()) {
        if (errorMsg) *errorMsg = "bzip2: empty input";
        return {};
    }

    bz_stream stream;
    std::memset(&stream, 0, sizeof(stream));

    stream.next_in  = const_cast<char*>(compressedData.data());
    stream.avail_in = static_cast<unsigned int>(compressedData.size());

    const int initRet = BZ2_bzDecompressInit(&stream, 0, 0);
    if (initRet != BZ_OK) {
        if (errorMsg) *errorMsg = QString("bzip2 init failed: %1").arg(initRet);
        return {};
    }

    QByteArray output;
    char buffer[OUTPUT_BUFFER_SIZE];

    int ret = BZ_OK;
    while (ret == BZ_OK) {
        stream.next_out  = buffer;
        stream.avail_out = sizeof(buffer);

        ret = BZ2_bzDecompress(&stream);

        const int produced = static_cast<int>(sizeof(buffer) - stream.avail_out);
        if (produced > 0) {
            output.append(buffer, produced);
        }
    }

    BZ2_bzDecompressEnd(&stream);

    if (ret != BZ_STREAM_END) {
        if (errorMsg) *errorMsg = QString("bzip2 decompression failed: %1").arg(ret);
        return {};
    }

    return output;
}

QByteArray CryptoUtils::decompressChunk(const QByteArray& compressedData, CompressionType type, QString* errorMsg)
{
    switch (type) {
        case COMPRESSION_ZLIB:
            return decompressZlibChunk(compressedData, errorMsg);
        case COMPRESSION_BZIP2:
            return decompressBzip2Chunk(compressedData, errorMsg);
        default:
            if (errorMsg) *errorMsg = "Unknown compression type";
            return {};
    }
}

QByteArray CryptoUtils::processFileContent(
    const QByteArray& fileContent,
    bool isCompressed,
    const QString& fileName,
    CompressionType compressionType,
    QString* errorMsg
) {
    if (errorMsg) errorMsg->clear();

    if (isConfigFile(fileName) || !isCompressed) {
        return fileContent;
    }

    if (compressionType == COMPRESSION_NONE) {
        return fileContent;
    }

    QByteArray result;
    int pos = 0;

    while (pos < fileContent.size()) {
        if (pos + CHUNK_SIZE_PREFIX_LENGTH > fileContent.size()) {
            if (errorMsg) *errorMsg = "Incomplete chunk header";
            return {};
        }

        const quint32 chunkSize = readBigEndianUInt32(fileContent, pos);
        pos += CHUNK_SIZE_PREFIX_LENGTH;

        if (chunkSize == 0 || pos + static_cast<int>(chunkSize) > fileContent.size()) {
            if (errorMsg) *errorMsg = "Invalid chunk size";
            return {};
        }

        const QByteArray compressedChunk = fileContent.mid(pos, chunkSize);
        pos += chunkSize;

        QString decompErr;
        QByteArray decompressed = decompressChunk(compressedChunk, compressionType, &decompErr);

        if (!decompErr.isEmpty()) {
            if (errorMsg) *errorMsg = decompErr;
            return {};
        }

        result.append(decompressed);
    }

    return result;
}

int CryptoUtils::cryptIvLength()
{
    return 16; // AES block size
}

QByteArray CryptoUtils::decryptString(const QByteArray& encryptedData, const QString& password, QString* errorMsg)
{
    if (errorMsg) {
        errorMsg->clear();
    }

    if (encryptedData.isEmpty()) {
        if (errorMsg) *errorMsg = "Empty encrypted data";
        return {};
    }

    if (password.isEmpty()) {
        if (errorMsg) *errorMsg = "Empty password";
        return {};
    }

    const int ivLength = cryptIvLength(); // 16 bytes

    if (encryptedData.size() < ivLength) {
        if (errorMsg) *errorMsg = "Encrypted data too short (missing IV)";
        return {};
    }

    QByteArray iv = encryptedData.left(ivLength);
    QByteArray ciphertext = encryptedData.mid(ivLength);

    QByteArray passwordBytes = password.toUtf8();
    QByteArray keyHash = QCryptographicHash::hash(passwordBytes, QCryptographicHash::Sha1);
    QByteArray key16 = keyHash.left(ivLength);
    QByteArray key32 = key16;
    key32.append(QByteArray(16, '\0'));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (errorMsg) *errorMsg = "Failed to create cipher context";
        return {};
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char*>(key32.data()),
                           reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        if (errorMsg) *errorMsg = "Failed to initialize decryption";
        return {};
    }

    // Decrypt
    QByteArray plaintext;
    plaintext.resize(ciphertext.size() + AES_BLOCK_SIZE);
    int outlen = 0;
    int finalLen = 0;

    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &outlen,
                          reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        if (errorMsg) *errorMsg = "Decryption update failed";
        return {};
    }

    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + outlen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        if (errorMsg) *errorMsg = "Decryption finalization failed (wrong password?)";
        return {};
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(outlen + finalLen);
    return plaintext;
}

QByteArray CryptoUtils::processFileContentWithPassword(
    const QByteArray& fileContent,
    bool isCompressed,
    const QString& fileName,
    const QString& password,
    CompressionType compressionType,
    QString* errorMsg
) {
    if (errorMsg) errorMsg->clear();

    if (isConfigFile(fileName)) {
        return fileContent;
    }

    if (!isCompressed) {
        if (!password.isEmpty()) {
            // Encrypted without compression: fixed-size chunks (no 4-byte size headers).
            // The PHP compressor encrypts 512000-byte plaintext chunks independently,
            // each producing 512032 bytes (16 IV + 512000 + 16 PKCS7 padding).
            QByteArray result;
            int pos = 0;

            while (pos < fileContent.size()) {
                const int chunkSize = qMin(ENCRYPTION_CHUNK_SIZE, fileContent.size() - pos);
                const QByteArray chunk = fileContent.mid(pos, chunkSize);
                pos += chunkSize;

                QString decryptErr;
                QByteArray decrypted = decryptString(chunk, password, &decryptErr);
                if (!decryptErr.isEmpty()) {
                    if (errorMsg) *errorMsg = decryptErr;
                    return {};
                }
                result.append(decrypted);
            }

            return result;
        }
        return fileContent;
    }

    if (compressionType == COMPRESSION_NONE) {
        return fileContent;
    }

    QByteArray result;
    int pos = 0;

    while (pos < fileContent.size()) {
        if (pos + CHUNK_SIZE_PREFIX_LENGTH > fileContent.size()) {
            if (errorMsg) *errorMsg = "Incomplete chunk header";
            return {};
        }

        const quint32 chunkSize = readBigEndianUInt32(fileContent, pos);
        pos += CHUNK_SIZE_PREFIX_LENGTH;

        if (chunkSize == 0 || pos + static_cast<int>(chunkSize) > fileContent.size()) {
            if (errorMsg) *errorMsg = "Invalid chunk size";
            return {};
        }

        QByteArray encryptedChunk = fileContent.mid(pos, chunkSize);
        pos += chunkSize;

        QByteArray decryptedChunk = encryptedChunk;
        if (!password.isEmpty()) {
            QString decryptErr;
            decryptedChunk = decryptString(encryptedChunk, password, &decryptErr);

            if (!decryptErr.isEmpty()) {
                if (errorMsg) {
                    *errorMsg = QString("Chunk decryption failed: %1").arg(decryptErr);
                }
                return {};
            }
        }

        QString decompErr;
        QByteArray decompressed = decompressChunk(decryptedChunk, compressionType, &decompErr);

        if (!decompErr.isEmpty()) {
            if (errorMsg) *errorMsg = decompErr;
            return {};
        }

        result.append(decompressed);
    }

    return result;
}
