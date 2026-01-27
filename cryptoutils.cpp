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

bool CryptoUtils::detectCompression(const QByteArray& fileContent)
{
    Q_UNUSED(fileContent);
    return false;
}

CompressionType CryptoUtils::detectCompressionType(const QByteArray& fileContent)
{
    Q_UNUSED(fileContent);
    return COMPRESSION_NONE;
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
    if (!out.isNull() && !out.isEmpty()) {
        return out;
    }

    if (compressedData.size() >= 2 && 
        static_cast<unsigned char>(compressedData[0]) == 0x1f && 
        static_cast<unsigned char>(compressedData[1]) == 0x8b) {
        QString gzipErr;
        QByteArray outGzip = inflateWithMode(compressedData, 31, &gzipErr);
        if (!outGzip.isNull() && !outGzip.isEmpty()) {
            if (errorMsg) errorMsg->clear();
            return outGzip;
        }
    }

    if (errorMsg) {
        *errorMsg = QString("zlib/gzip decompression failed (tried zlib=15, gzip=31, raw=-15)");
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

    CompressionType effectiveType = compressionType;
    if (effectiveType == COMPRESSION_NONE) {
        effectiveType = detectCompressionType(fileContent);
    }

    if (effectiveType == COMPRESSION_NONE) {
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

        CompressionType chunkType = effectiveType;

        QString decompErr;
        QByteArray decompressed = decompressChunk(compressedChunk, chunkType, &decompErr);

        if (decompressed.isEmpty() && compressedChunk.size() > 10) {
            if (chunkType == COMPRESSION_ZLIB) {
                QString gzipErr;
                QByteArray gzipDecompressed = decompressZlibChunk(compressedChunk, &gzipErr);

                if (!gzipDecompressed.isEmpty()) {
                    decompressed = gzipDecompressed;
                    decompErr.clear();
                } else if (compressedChunk.size() > 50) {
                    if (errorMsg) {
                        *errorMsg = QString("Decompression failed: %1").arg(decompErr.isEmpty() ? gzipErr : decompErr);
                    }
                    return {};
                }
            } else if (compressedChunk.size() > 50) {
                if (errorMsg) {
                    *errorMsg = decompErr.isEmpty() ? "Decompression produced empty output" : decompErr;
                }
                return {};
            }
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
            QString decryptErr;
            QByteArray decrypted = decryptString(fileContent, password, &decryptErr);
            if (decrypted.isEmpty() && !fileContent.isEmpty()) {
                if (errorMsg) *errorMsg = decryptErr.isEmpty() ? "Decryption failed" : decryptErr;
                return {};
            }
            return decrypted;
        }
        return fileContent;
    }

    CompressionType effectiveType = compressionType;
    if (effectiveType == COMPRESSION_NONE) {
        effectiveType = detectCompressionType(fileContent);
    }

    if (effectiveType == COMPRESSION_NONE) {
        if (!password.isEmpty()) {
            QString decryptErr;
            QByteArray decrypted = decryptString(fileContent, password, &decryptErr);
            if (decrypted.isEmpty() && !fileContent.isEmpty()) {
                if (errorMsg) *errorMsg = decryptErr.isEmpty() ? "Decryption failed" : decryptErr;
                return {};
            }
            return decrypted;
        }
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
            
            const int ivLength = 16;
            if (encryptedChunk.size() < ivLength) {
                if (errorMsg) {
                    *errorMsg = QString("Chunk too small to contain IV: %1 < %2")
                        .arg(encryptedChunk.size()).arg(ivLength);
                }
                return {};
            }
            
            QString decryptErr;
            decryptedChunk = decryptString(encryptedChunk, password, &decryptErr);
        
            if (decryptedChunk.isEmpty()) {
                if (encryptedChunk.size() > ivLength) {

                    if (errorMsg) {
                        *errorMsg = decryptErr.isEmpty() 
                            ? "Chunk decryption failed (wrong password?)" 
                            : QString("Chunk decryption failed: %1").arg(decryptErr);
                    }
                    return {};
                }
            }
        }

        CompressionType chunkType = effectiveType;

        QString decompErr;
        QByteArray decompressed;
        
        if (chunkType != COMPRESSION_NONE) {
            if (decryptedChunk.isEmpty()) {
                if (errorMsg) *errorMsg = "Cannot decompress empty chunk";
                return {};
            }
            
            if (chunkType == COMPRESSION_ZLIB && decryptedChunk.size() < 2) {
                if (errorMsg) {
                    *errorMsg = QString("Chunk too small for zlib/gzip decompression: %1 bytes")
                        .arg(decryptedChunk.size());
                }
                return {};
            }
            
            if (chunkType == COMPRESSION_BZIP2 && decryptedChunk.size() < 10) {
                if (errorMsg) {
                    *errorMsg = QString("Chunk too small for bzip2 decompression: %1 bytes")
                        .arg(decryptedChunk.size());
                }
                return {};
            }
            
            decompressed = decompressChunk(decryptedChunk, chunkType, &decompErr);
            
            if (decompressed.isEmpty() && chunkType == COMPRESSION_ZLIB) {
                QString gzipErr;
                QByteArray gzipDecompressed = decompressZlibChunk(decryptedChunk, &gzipErr);
                if (!gzipDecompressed.isEmpty()) {
                    decompressed = gzipDecompressed;
                    decompErr.clear();
                } else {
                    if (decryptedChunk.size() < 10) {
                        decompressed = decryptedChunk;
                        decompErr.clear();
                    } else {
                        if (errorMsg) {
                            *errorMsg = QString("Decompression failed: %1 (chunk size: %2 bytes, compression type: %3)")
                                .arg(decompErr.isEmpty() ? gzipErr : decompErr)
                                .arg(decryptedChunk.size())
                                .arg("zlib/gzip");
                        }
                        return {};
                    }
                }
            } else if (decompressed.isEmpty()) {
                if (chunkType == COMPRESSION_BZIP2 && decryptedChunk.size() < 14) {
                    decompressed = decryptedChunk;
                    decompErr.clear();
                } else {
                    if (errorMsg) {
                        *errorMsg = QString("Decompression failed: %1 (chunk size: %2 bytes, compression type: bzip2)")
                            .arg(decompErr)
                            .arg(decryptedChunk.size());
                    }
                    return {};
                }
            }
        } else {
            decompressed = decryptedChunk;
        }

        result.append(decompressed);
    }

    return result;
}
