#include "backupfile.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>

void BackupFile::loadConfig()
{
  isEncrypted = false;
  compressionType = COMPRESSION_NONE;

  // Check if file is already open, if not, open it
  bool wasOpen = isOpen();
  if (!wasOpen) {
    if (!open(QIODevice::ReadOnly)) {
      return;
    }
  }

  // Read first file header to find package.json or multisite.json
  qint64 savedPos = pos();
  if (!seek(0)) {
    if (!wasOpen) {
      close();
    }
    return;
  }

  while (!atEnd()) {
    QByteArray header = read(4377);
    if (header.size() != 4377) {
      break;
    }

    if (header == eof) {
      break;
    }

    // Extract filename
    QByteArray fileNameBytes = header.mid(0, 255);
    int nullPos = fileNameBytes.indexOf('\0');
    if (nullPos >= 0) {
      fileNameBytes = fileNameBytes.left(nullPos);
    }
    QString fileName = QString::fromUtf8(fileNameBytes.trimmed());

    // Extract file size
    QByteArray sizeBytes = header.mid(255, 14);
    int nullPos2 = sizeBytes.indexOf('\0');
    if (nullPos2 >= 0) {
      sizeBytes = sizeBytes.left(nullPos2);
    }
    bool ok;
    qint64 fileSize = sizeBytes.trimmed().toLongLong(&ok);
    if (!ok || fileSize < 0) {
      break;
    }

    // Check if this is package.json or multisite.json
    // Handle both with and without path prefix
    QString baseFileName = fileName.section('/', -1); // Get just the filename part
    QString normalizedFileName = fileName.trimmed();
    
    // Check exact match or base filename match
    if (baseFileName == "package.json" || baseFileName == "multisite.json" ||
        normalizedFileName == "package.json" || normalizedFileName == "multisite.json" ||
        normalizedFileName.endsWith("/package.json") || normalizedFileName.endsWith("/multisite.json")) {
      // Read the JSON content (these files are never compressed or encrypted)
      QByteArray jsonContent = read(fileSize);
      if (jsonContent.size() == fileSize) {
        QJsonParseError error;
        QJsonDocument doc = QJsonDocument::fromJson(jsonContent, &error);
        if (error.error == QJsonParseError::NoError && doc.isObject()) {
          QJsonObject obj = doc.object();

          // Check encryption - handle both bool and string "true"/"false"
          if (obj.contains("Encrypted")) {
            if (obj["Encrypted"].isBool()) {
              isEncrypted = obj["Encrypted"].toBool();
            } else if (obj["Encrypted"].isString()) {
              QString encStr = obj["Encrypted"].toString().toLower();
              isEncrypted = (encStr == "true" || encStr == "1");
            }
          }

          // Check compression
          if (obj.contains("Compression") && obj["Compression"].isObject()) {
            QJsonObject compression = obj["Compression"].toObject();
            if (compression.contains("Enabled")) {
              bool enabled = false;
              if (compression["Enabled"].isBool()) {
                enabled = compression["Enabled"].toBool();
              } else if (compression["Enabled"].isString()) {
                QString enabledStr = compression["Enabled"].toString().toLower();
                enabled = (enabledStr == "true" || enabledStr == "1");
              }
              
              if (enabled && compression.contains("Type")) {
                QString type = compression["Type"].toString().toLower();
                // JavaScript uses "gzip" but it's actually zlib format
                if (type == "zlib" || type == "gzip") {
                  compressionType = COMPRESSION_ZLIB;
                } else if (type == "bzip2") {
                  compressionType = COMPRESSION_BZIP2;
                }
              }
            }
          }
        }
      }
      break; // Found config file, no need to continue
    } else {
      // Skip this file
      if (!seek(pos() + fileSize)) {
        break;
      }
    }
  }

  // Restore position
  seek(savedPos);
  
  // Only close if we opened it
  if (!wasOpen) {
    close();
  }
}
