#include "cryptoutils.h"

#include <QStringList>
#include <QCryptographicHash>
#include <zlib.h>
#include <bzlib.h>
#include <cstring>

// OpenSSL for AES decryption
#ifdef HAVE_OPENSSL
    #include <openssl/evp.h>
    #include <openssl/aes.h>
    #include <openssl/sha.h>
    #define USE_OPENSSL 1
    #ifndef AES_BLOCK_SIZE
        #define AES_BLOCK_SIZE 16
    #endif
#else
    #define USE_OPENSSL 0
#endif

const QStringList CryptoUtils::CONFIG_FILES = {
    "package.json",
    "multisite.json"
};

const int CryptoUtils::CHUNK_SIZE_PREFIX_LENGTH = 4;
static constexpr int OUTPUT_BUFFER_SIZE = 32768;

/* =========================
 * Helpers
 * ========================= */

static quint32 readBigEndianUInt32(const QByteArray& data, int offset)
{
    quint32 value = 0;
    for (int i = 0; i < 4; ++i) {
        value = (value << 8) | static_cast<unsigned char>(data[offset + i]);
    }
    return value;
}

// Proper zlib header validation (RFC1950-ish):
// CMF/FLG must satisfy (CMF*256 + FLG) % 31 == 0 and compression method=8 (deflate).
static bool looksLikeZlib(const QByteArray& data)
{
    if (data.size() < 2) return false;

    const quint8 cmf = static_cast<quint8>(data[0]);
    const quint8 flg = static_cast<quint8>(data[1]);

    if ((cmf & 0x0F) != 8) return false; // deflate method
    const int header = (cmf << 8) | flg;
    if (header % 31 != 0) return false;

    return true;
}

static bool looksLikeBzip2(const QByteArray& data)
{
    return data.size() >= 3 &&
           data[0] == 'B' &&
           data[1] == 'Z' &&
           data[2] == 'h'; // typical bzip2 stream header "BZh"
}

static CompressionType detectByMagic(const QByteArray& data)
{
    if (looksLikeBzip2(data)) return COMPRESSION_BZIP2;
    if (looksLikeZlib(data))  return COMPRESSION_ZLIB;

    // very weak fallback: some zlib streams are still 0x78 ?? but header check failed
    // we avoid guessing here.
    return COMPRESSION_NONE;
}

/* =========================
 * Public API
 * ========================= */

bool CryptoUtils::isConfigFile(const QString& fileName)
{
    return CONFIG_FILES.contains(fileName.section('/', -1));
}

bool CryptoUtils::detectCompression(const QByteArray& fileContent)
{
    return detectCompressionType(fileContent) != COMPRESSION_NONE;
}

CompressionType CryptoUtils::detectCompressionType(const QByteArray& fileContent)
{
    if (fileContent.size() < CHUNK_SIZE_PREFIX_LENGTH) {
        return COMPRESSION_NONE;
    }

    const quint32 chunkSize = readBigEndianUInt32(fileContent, 0);

    if (chunkSize == 0 ||
        chunkSize > static_cast<quint32>(fileContent.size() - CHUNK_SIZE_PREFIX_LENGTH)) {
        return COMPRESSION_NONE;
    }

    const QByteArray firstChunk = fileContent.mid(CHUNK_SIZE_PREFIX_LENGTH, chunkSize);
    return detectByMagic(firstChunk);
}

/* =========================
 * Decompression (zlib)
 * ========================= */

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

        // Handle case: no progress possible
        if (ret == Z_BUF_ERROR && produced == 0) {
            // If no output and no progress, stop.
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

    // JavaScript uses pako.inflate which by default uses windowBits=15 (zlib format)
    // but can also handle gzip automatically. Try zlib first (most common).
    if (looksLikeZlib(compressedData)) {
        QByteArray out = inflateWithMode(compressedData, 15, errorMsg);
        if (!out.isNull() && !out.isEmpty()) {
            return out; // success
        }
    }

    // Try gzip format (windowBits = 31) - pako can handle this too
    // Check for gzip magic bytes (0x1f 0x8b)
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

    // Try gzip format anyway (pako tries multiple formats)
    QString gzipErr;
    QByteArray outGzip = inflateWithMode(compressedData, 31, &gzipErr);
    if (!outGzip.isNull() && !outGzip.isEmpty()) {
        if (errorMsg) errorMsg->clear();
        return outGzip;
    }

    // Try raw DEFLATE as last resort (windowBits = -15)
    QString rawErr;
    QByteArray outRaw = inflateWithMode(compressedData, -15, &rawErr);
    if (!outRaw.isNull() && !outRaw.isEmpty()) {
        if (errorMsg) errorMsg->clear();
        return outRaw;
    }

    if (errorMsg) {
        *errorMsg = QString("zlib/gzip decompression failed (tried zlib=15, gzip=31, raw=-15)");
        if (!gzipErr.isEmpty()) *errorMsg += " - gzip error: " + gzipErr;
        if (!rawErr.isEmpty()) *errorMsg += " - raw error: " + rawErr;
    }
    return {};
}

/* =========================
 * Decompression (bzip2)
 * ========================= */

QByteArray CryptoUtils::decompressBzip2Chunk(const QByteArray& compressedData, QString* errorMsg)
{
    if (errorMsg) errorMsg->clear();

    if (compressedData.isEmpty()) {
        if (errorMsg) *errorMsg = "bzip2: empty input";
        return {};
    }

    if (!looksLikeBzip2(compressedData)) {
        if (errorMsg) *errorMsg = "bzip2: invalid header";
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

/* =========================
 * Dispatch
 * ========================= */

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

/* =========================
 * File Processing
 * ========================= */

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

    CompressionType defaultType = compressionType;
    if (defaultType == COMPRESSION_NONE) {
        defaultType = detectCompressionType(fileContent);
    }
    if (defaultType == COMPRESSION_NONE) {
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

        CompressionType chunkType = detectByMagic(compressedChunk);
        if (chunkType == COMPRESSION_NONE) {
            chunkType = defaultType;
        }

        QString decompErr;
        QByteArray decompressed = decompressChunk(compressedChunk, chunkType, &decompErr);

        // Check if decompression failed - try alternative formats for zlib
        // Empty decompressed result is OK if input was also small/empty
        if (decompressed.isEmpty() && compressedChunk.size() > 10) {
            // For zlib, try gzip format as fallback (windowBits = 31)
            if (chunkType == COMPRESSION_ZLIB) {
                QString gzipErr;
                QByteArray gzipDecompressed = decompressZlibChunk(compressedChunk, &gzipErr);
                if (!gzipDecompressed.isEmpty()) {
                    decompressed = gzipDecompressed;
                    decompErr.clear();
                } else if (compressedChunk.size() > 50) {
                    // Only fail if we had substantial compressed data
                    if (errorMsg) {
                        *errorMsg = QString("Decompression failed: %1").arg(decompErr.isEmpty() ? gzipErr : decompErr);
                    }
                    return {};
                }
                // If compressedChunk was small, empty result might be valid
            } else if (compressedChunk.size() > 50) {
                // For other compression types, only fail if we had substantial data
                if (errorMsg) {
                    *errorMsg = decompErr.isEmpty() ? "Decompression produced empty output" : decompErr;
                }
                return {};
            }
            // If compressedChunk was small, empty result might be valid - continue
        }

        result.append(decompressed);
    }

    return result;
}

/* =========================
 * Decryption
 * ========================= */

int CryptoUtils::cryptIvLength()
{
    return 16; // AES block size
}

QByteArray CryptoUtils::decryptString(const QByteArray& encryptedData, const QString& password, QString* errorMsg)
{
    if (errorMsg) errorMsg->clear();

    if (encryptedData.isEmpty()) {
        if (errorMsg) *errorMsg = "Empty encrypted data";
        return {};
    }

    if (password.isEmpty()) {
        if (errorMsg) *errorMsg = "Empty password";
        return {};
    }

#if USE_OPENSSL
    const int ivLength = cryptIvLength(); // 16 bytes
    
    // Check if we have enough data for IV
    if (encryptedData.size() < ivLength) {
        if (errorMsg) *errorMsg = "Encrypted data too short (missing IV)";
        return {};
    }

    // Extract IV (first 16 bytes) and ciphertext (rest)
    QByteArray iv = encryptedData.left(ivLength);
    QByteArray ciphertext = encryptedData.mid(ivLength);

    // Generate key: SHA1(password) truncated to 16 bytes, then pad with 16 zero bytes
    // This matches the JavaScript implementation: Buffer.concat([key, Buffer.alloc(16)])
    QByteArray passwordBytes = password.toUtf8();
    QByteArray keyHash = QCryptographicHash::hash(passwordBytes, QCryptographicHash::Sha1);
    QByteArray key16 = keyHash.left(ivLength); // First 16 bytes of SHA1
    QByteArray key32 = key16;
    key32.append(QByteArray(16, '\0')); // Pad with 16 zero bytes to make 32 bytes for AES-256

    // Initialize OpenSSL EVP context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (errorMsg) *errorMsg = "Failed to create cipher context";
        return {};
    }

    // Initialize decryption with AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                           reinterpret_cast<const unsigned char*>(key32.data()),
                           reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        if (errorMsg) *errorMsg = "Failed to initialize decryption";
        return {};
    }

    // Decrypt
    QByteArray plaintext;
    plaintext.resize(ciphertext.size() + AES_BLOCK_SIZE); // Extra space for padding
    int outlen = 0;
    int finalLen = 0;

    if (EVP_DecryptUpdate(ctx, 
                         reinterpret_cast<unsigned char*>(plaintext.data()), &outlen,
                         reinterpret_cast<const unsigned char*>(ciphertext.data()), 
                         ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        if (errorMsg) *errorMsg = "Decryption update failed";
        return {};
    }

    if (EVP_DecryptFinal_ex(ctx, 
                           reinterpret_cast<unsigned char*>(plaintext.data()) + outlen, 
                           &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        if (errorMsg) *errorMsg = "Decryption finalization failed (wrong password?)";
        return {};
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(outlen + finalLen);
    return plaintext;
#else
    // OpenSSL not available
    if (errorMsg) {
        *errorMsg = "Decryption requires OpenSSL. Install OpenSSL and define HAVE_OPENSSL in Qtraktor.pro";
    }
    return {};
#endif
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

    // Do not decrypt or decompress config files
    if (isConfigFile(fileName)) {
        return fileContent;
    }

    if (!isCompressed) {
        // For uncompressed files, decrypt the entire content
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

    // For compressed files, process chunk by chunk (decrypt then decompress each chunk)
    CompressionType defaultType = compressionType;
    if (defaultType == COMPRESSION_NONE) {
        defaultType = detectCompressionType(fileContent);
    }
    if (defaultType == COMPRESSION_NONE) {
        // Not compressed, just decrypt
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

        // Decrypt chunk if password provided
        // Order matches JavaScript: decrypt first, then decompress
        QByteArray decryptedChunk = encryptedChunk;
        if (!password.isEmpty()) {
            // Check chunk size before decryption (matches JavaScript validation)
            const int ivLength = 16; // IV_LENGTH from JavaScript
            if (encryptedChunk.size() < ivLength) {
                if (errorMsg) {
                    *errorMsg = QString("Chunk too small to contain IV: %1 < %2")
                        .arg(encryptedChunk.size()).arg(ivLength);
                }
                return {};
            }
            
            QString decryptErr;
            decryptedChunk = decryptString(encryptedChunk, password, &decryptErr);
            
            // Check if decryption produced empty result (but only fail if input was substantial)
            if (decryptedChunk.isEmpty()) {
                if (encryptedChunk.size() > ivLength) {
                    // Had encrypted data but got nothing - decryption failed
                    if (errorMsg) {
                        *errorMsg = decryptErr.isEmpty() 
                            ? "Chunk decryption failed (wrong password?)" 
                            : QString("Chunk decryption failed: %1").arg(decryptErr);
                    }
                    return {};
                }
                // Small chunk might legitimately decrypt to empty
            }
        }

        // Detect compression type for this chunk
        CompressionType chunkType = detectByMagic(decryptedChunk);
        if (chunkType == COMPRESSION_NONE) {
            chunkType = defaultType;
        }

        // Decompress chunk (after decryption, matching JavaScript order)
        QString decompErr;
        QByteArray decompressed;
        
        if (chunkType != COMPRESSION_NONE) {
            // Validate chunk size before decompression (matches JavaScript)
            if (decryptedChunk.isEmpty()) {
                if (errorMsg) *errorMsg = "Cannot decompress empty chunk";
                return {};
            }
            
            // Size validation matches JavaScript checks
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
            
            // Try alternative formats for zlib if first attempt failed
            if (decompressed.isEmpty() && chunkType == COMPRESSION_ZLIB) {
                QString gzipErr;
                QByteArray gzipDecompressed = decompressZlibChunk(decryptedChunk, &gzipErr);
                if (!gzipDecompressed.isEmpty()) {
                    decompressed = gzipDecompressed;
                    decompErr.clear();
                } else {
                    // For very small chunks, they might be stored uncompressed even if compression is enabled
                    // Minimum valid zlib header is typically 6-10 bytes, so chunks smaller than that are likely uncompressed
                    if (decryptedChunk.size() < 10) {
                        // Treat as uncompressed data
                        decompressed = decryptedChunk;
                        decompErr.clear();
                    } else {
                        // Decompression failed for substantial data
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
                // For bzip2, minimum is 10 bytes, so check if it's too small
                if (chunkType == COMPRESSION_BZIP2 && decryptedChunk.size() < 14) {
                    // Treat as uncompressed data
                    decompressed = decryptedChunk;
                    decompErr.clear();
                } else {
                    // Other compression types failed
                    if (errorMsg) {
                        *errorMsg = QString("Decompression failed: %1 (chunk size: %2 bytes, compression type: bzip2)")
                            .arg(decompErr)
                            .arg(decryptedChunk.size());
                    }
                    return {};
                }
            }
        } else {
            // Not compressed
            decompressed = decryptedChunk;
        }

        result.append(decompressed);
    }

    return result;
}
