#ifndef BACKUPFILE_H
#define BACKUPFILE_H

#include <QApplication>
#include <QDir>
#include <QFile>
#include <QJsonObject>
#include <QString>
#include "cryptoutils.h"

class BackupFile : public QFile
{
  Q_OBJECT

public:
  explicit BackupFile(const QString& filename, const QString& password = QString())
    : QFile(filename),
      bytesRead(0),
      eof(kHeaderSize, '\0'),
      filePassword(password),
      isEncrypted(false),
      compressionType(COMPRESSION_NONE)
  {}

  bool isEncryptedFile() const { return isEncrypted; }
  CompressionType getCompressionType() const { return compressionType; }

  void ensureConfigLoaded()
  {
    if (compressionType == COMPRESSION_NONE && !isEncrypted) {
      loadConfig();
    }
  }

  void setConfig(bool encrypted, CompressionType compType)
  {
    isEncrypted = encrypted;
    compressionType = compType;
  }

  bool isValid()
  {
    loadConfig();

    if (!seek(size() - kHeaderSize)) {
      return false;
    }

    if (read(kHeaderSize) != eof) {
      return false;
    }

    if (!seek(0)) {
      return false;
    }

    return true;
  }

  bool extract(QDir extractTo)
  {
    if (compressionType == COMPRESSION_NONE && !isEncrypted) {
      loadConfig();
    }

    while (!atEnd()) {
      HeaderInfo info;
      if (!readHeader(info)) {
        return false;
      }

      if (info.isEof) {
        return true;
      }

      const QString fullPath = buildOutputPath(extractTo, info.fileName, info.filePath);
      QFile out(fullPath);
      if (!out.open(QIODevice::WriteOnly)) {
        return false;
      }

      QByteArray fileContent;
      if (!readExact(info.fileSize, fileContent)) {
        out.close();
        return false;
      }

      const bool isCompressed = !CryptoUtils::isConfigFile(info.fileName) && compressionType != COMPRESSION_NONE;

      QString processError;
      QByteArray processedContent;

      if (isEncrypted && !filePassword.isEmpty()) {
        processedContent = CryptoUtils::processFileContentWithPassword(
          fileContent, isCompressed, info.fileName, filePassword, compressionType, &processError
        );
      } else {
        processedContent = CryptoUtils::processFileContent(
          fileContent, isCompressed, info.fileName, compressionType, &processError
        );
      }

      if (!processError.isEmpty()) {
        const QString errorMsg = QString("Error processing file '%1': %2").arg(info.fileName, processError);
        qWarning() << errorMsg;
        emit error(errorMsg);
        out.close();
        return false;
      }

      if (processedContent.isEmpty() && fileContent.size() > 100) {
        if (isCompressed || (isEncrypted && !filePassword.isEmpty())) {

          const QString errorMsg = QString("Empty processed content for file '%1' (compressed: %2, encrypted: %3)")
            .arg(info.fileName).arg(isCompressed).arg(isEncrypted);

          qWarning() << errorMsg;
          emit error(errorMsg);
          out.close();
          return false;
        }
      }

      if (out.write(processedContent) != processedContent.size()) {
        out.close();
        return false;
      }

      out.close();
    }

    return false;
  }

signals:
  void progress(float percent);
  void error(const QString& errorMessage);

protected:
  qint64 readData(char* data, qint64 maxlen) override
  {
    const qint64 n = QFile::readData(data, maxlen);
    bytesRead += n;

    if (size() > 0) {
      emit progress((static_cast<float>(bytesRead) / static_cast<float>(size())) * 100.0f);
    } else {
      emit progress(0.0f);
    }

    QApplication::processEvents();
    return n;
  }

private:
  static constexpr qint64 kHeaderSize = 4377;

  struct HeaderInfo
  {
    QString fileName;
    QString filePath;
    qint64 fileSize = 0;
    bool isEof = false;
  };

  void loadConfig();

  bool readHeader(HeaderInfo& outInfo)
  {
    const QByteArray header = read(kHeaderSize);
    if (header.size() != kHeaderSize) {
      return false;
    }

    if (header == eof) {
      outInfo.isEof = true;
      return true;
    }

    outInfo.isEof = false;
    outInfo.fileName = parseNullTerminatedString(header, 0, 255);

    bool ok = false;
    const QString sizeStr = parseNullTerminatedString(header, 255, 14);
    const qint64 fileSize = sizeStr.trimmed().toLongLong(&ok);
    if (!ok || fileSize < 0) {
      return false;
    }
    outInfo.fileSize = fileSize;

    outInfo.filePath = parseNullTerminatedString(header, 281, 4096);
    return true;
  }

  static QString parseNullTerminatedString(const QByteArray& src, int offset, int length)
  {
    QByteArray bytes = src.mid(offset, length);
    const int nullPos = bytes.indexOf('\0');
    if (nullPos >= 0) {
      bytes = bytes.left(nullPos);
    }
    return QString::fromUtf8(bytes.trimmed());
  }

  bool readExact(qint64 sizeToRead, QByteArray& out)
  {
    out = read(sizeToRead);
    return out.size() == sizeToRead;
  }

  static QString buildOutputPath(const QDir& extractTo, const QString& fileName, const QString& filePath)
  {
    if (filePath.isEmpty() || filePath == ".") {
      return extractTo.path() + "/" + fileName;
    }

    const QString dirPath = extractTo.path() + "/" + filePath;
    QDir dir(dirPath);
    if (!dir.exists()) {
      if (!QDir().mkpath(dirPath)) {
        return QString();
      }
    }
    return dirPath + "/" + fileName;
  }

private:
  qint64 bytesRead;
  QByteArray eof;
  QString filePassword;
  bool isEncrypted;
  CompressionType compressionType;
};

#endif // BACKUPFILE_H
