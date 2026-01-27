#ifndef BACKUPFILE_H
#define BACKUPFILE_H

#include <QApplication>
#include <QDir>
#include <QFile>
#include <QJsonObject>
#include "cryptoutils.h"

class BackupFile : public QFile
{
  Q_OBJECT
  public:
    BackupFile(const QString& filename, const QString& password = QString())
      : QFile(filename),
        bytesRead(0),
        eof(4377, '\0'),
        filePassword(password),
        isEncrypted(false),
        compressionType(COMPRESSION_NONE)
    {}

    bool isEncryptedFile() const { return isEncrypted; }

    CompressionType getCompressionType() const { return compressionType; }

    void ensureConfigLoaded() { if (compressionType == COMPRESSION_NONE && !isEncrypted) loadConfig(); }

    void setConfig(bool encrypted, CompressionType compType) { isEncrypted = encrypted; compressionType = compType; }

    bool isValid()
    {
      loadConfig();
      if (!seek(size() - 4377)) {
        return false;
      }

      if (read(4377) != eof) {
        return false;
      }

      if (!seek(0)) {
        return false;
      }

      return true;
    }

    bool extract(QDir extractTo)
    {
      // Ensure config is loaded before extraction
      if (compressionType == COMPRESSION_NONE && !isEncrypted) {
        loadConfig();
      }

      while (!atEnd()) {
        QByteArray header = read(4377);
        if (header.size() != 4377) {
          return false;
        }

        if (header == eof) {
          return true;
        }

        // Extract filename (first 255 bytes, null-terminated)
        QByteArray fileNameBytes = header.mid(0, 255);
        int nullPos = fileNameBytes.indexOf('\0');
        if (nullPos >= 0) {
          fileNameBytes = fileNameBytes.left(nullPos);
        }
        QString fileName = QString::fromUtf8(fileNameBytes.trimmed());

        QByteArray sizeBytes = header.mid(255, 14);
        int nullPos2 = sizeBytes.indexOf('\0');
        if (nullPos2 >= 0) {
          sizeBytes = sizeBytes.left(nullPos2);
        }

        bool ok;
        qint64 fileSize = sizeBytes.trimmed().toLongLong(&ok);
        if (!ok || fileSize < 0) {
          return false;
        }

        QByteArray pathBytes = header.mid(281, 4096);
        int nullPos3 = pathBytes.indexOf('\0');
        if (nullPos3 >= 0) {
          pathBytes = pathBytes.left(nullPos3);
        }
        QString filePath = QString::fromUtf8(pathBytes.trimmed());

        // Build full file path
        QString fullPath;
        if (filePath.isEmpty() || filePath == ".") {
          fullPath = extractTo.path() + "/" + fileName;
        } else {
          QString dirPath = extractTo.path() + "/" + filePath;
          QDir dir(dirPath);
          if (!dir.exists()) {
            if (!QDir().mkpath(dirPath)) {
              return false;
            }
          }
          fullPath = dirPath + "/" + fileName;
        }

        QFile file(fullPath);
        if (!file.open(QIODevice::WriteOnly)) {
          return false;
        }

        QByteArray fileContent;
        qint64 remainingSize = fileSize;

        bool isCompressed = !CryptoUtils::isConfigFile(fileName) && compressionType != COMPRESSION_NONE;

        if (isCompressed) {
          fileContent = read(remainingSize);
          if (fileContent.size() != remainingSize) {
            file.close();
            return false;
          }
        } else {
          fileContent = read(remainingSize);
          if (fileContent.size() != remainingSize) {
            file.close();
            return false;
          }
        }

        QString processError;
        QByteArray processedContent;
        if (isEncrypted && !filePassword.isEmpty()) {
          processedContent = CryptoUtils::processFileContentWithPassword(
            fileContent, isCompressed, fileName, filePassword, compressionType, &processError);
        } else {
          processedContent = CryptoUtils::processFileContent(
            fileContent, isCompressed, fileName, compressionType, &processError);
        }

        // Check for processing errors
        if (!processError.isEmpty()) {
          QString errorMsg = QString("Error processing file '%1': %2").arg(fileName, processError);
          qWarning() << errorMsg;
          emit error(errorMsg);
          file.close();
          return false;
        }

        // For compressed files, empty result usually means error
        if (processedContent.isEmpty() && fileContent.size() > 100) {
          if (isCompressed || (isEncrypted && !filePassword.isEmpty())) {
            QString errorMsg = QString("Empty processed content for file '%1' (compressed: %2, encrypted: %3)")
              .arg(fileName).arg(isCompressed).arg(isEncrypted);
            qWarning() << errorMsg;
            emit error(errorMsg);
            file.close();
            return false;
          }
        }

        if (file.write(processedContent) != processedContent.size()) {
          file.close();
          return false;
        }

        file.close();
      }

      return false;
    }

  signals:
    void progress(float percent);
    void error(const QString& errorMessage);

  protected:
    qint64 readData(char* data, qint64 maxlen)
    {
      qint64 _bytesRead = QFile::readData(data, maxlen);
      bytesRead += _bytesRead;
      emit progress((static_cast<float>(bytesRead) / size()) * 100);
      QApplication::processEvents();
      return _bytesRead;
    }

  private:
    void loadConfig();
    qint64 bytesRead;
    QByteArray eof;
    QString filePassword;
    bool isEncrypted;
    CompressionType compressionType;
};

#endif // BACKUPFILE_H
