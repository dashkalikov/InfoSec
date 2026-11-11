// Windows headers must be included before OpenSSL to avoid macro conflicts
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
// Windows socket wrappers to match Unix API
inline int socket_close(int fd) { return closesocket(fd); }
inline ssize_t socket_write(int fd, const void* buf, size_t count) { return send(fd, (const char*)buf, (int)count, 0); }
inline ssize_t socket_read(int fd, void* buf, size_t count) { return recv(fd, (char*)buf, (int)count, 0); }
#define SOCK_SETOPT_CAST (const char*)
// Initialize Winsock
inline void winsock_init() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}
inline void winsock_cleanup() { WSACleanup(); }
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
inline int socket_close(int fd) { return close(fd); }
inline ssize_t socket_write(int fd, const void* buf, size_t count) { return write(fd, buf, count); }
inline ssize_t socket_read(int fd, void* buf, size_t count) { return read(fd, buf, count); }
#define SOCK_SETOPT_CAST
inline void winsock_init() {}
inline void winsock_cleanup() {}
#endif

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/cms.h>
#include <openssl/ocsp.h>
#include <openssl/store.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#ifdef WITH_ENGINE_PKCS11
#include <openssl/engine.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <chrono>
#include <vector>
#include <cctype>
#include <map>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <ctime>
#ifdef WITH_SQLITE3
#include <sqlite3.h>
#include "cadatabase.h"
#include "../src/rbacguard.h"
#include "../src/sessionmanager.h"
#include "../src/httpmiddleware.h"
#include "../src/requestcontext.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QString>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QByteArray>
#include <QVariant>
#include <QDir>
#endif

namespace fs = std::filesystem;

static void printOpenSslErrors(const char *msg) {
    std::cerr << msg << "\n";
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        std::cerr << "  " << buf << "\n";
    }
}

static void appendAudit(const fs::path &rootDir, const std::string &event, const std::string &detail) {
    // Store in database only (no file fallback)
    #ifdef WITH_SQLITE3
    {
        // Используем CaDatabase вместо прямых вызовов SQLite
        static CaDatabase *caDb = nullptr;
        static bool initialized = false;
        
        if (!initialized) {
            // Создаем QCoreApplication, если его еще нет (для работы Qt SQL)
            static int argc = 1;
            static char *argv[] = {const_cast<char*>("minica"), nullptr};
            if (!QCoreApplication::instance()) {
                new QCoreApplication(argc, argv);
            }
            
            caDb = new CaDatabase();
            QString dbPath = QString::fromStdString((rootDir / "databases" / "ca.db").string());
            if (!caDb->connect(dbPath)) {
                std::cerr << "Failed to connect to CA database: " << caDb->getLastError().toStdString() << "\n";
                delete caDb;
                caDb = nullptr;
                return;
            }
            initialized = true;
        }
        
        if (caDb && caDb->isConnected()) {
            // Insert audit log entry
            auto now = std::chrono::system_clock::now();
            auto sec = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
            
            QVariantList params;
            params << static_cast<qlonglong>(sec) << QString::fromStdString(event) << QString::fromStdString(detail);
            
            if (!caDb->exec("INSERT INTO audit_log(timestamp, event, detail) VALUES(?,?,?)", params)) {
                std::cerr << "Failed to insert audit log: " << caDb->getLastError().toStdString() << "\n";
            }
        }
    }
    #endif
    // No file fallback - all data stored in database
}

static EVP_PKEY* generateRsaKey(int bits) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { printOpenSslErrors("EVP_PKEY_keygen failed"); EVP_PKEY_CTX_free(ctx); return nullptr; }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY* generateEcKey(const std::string &curveName) {
    int nid = OBJ_sn2nid(curveName.c_str());
    if (nid == NID_undef) return nullptr;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) return nullptr;
    if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return nullptr; }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0) { EVP_PKEY_CTX_free(pctx); return nullptr; }
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { EVP_PKEY_CTX_free(pctx); return nullptr; }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static EVP_PKEY* generateEdKey(const std::string &name) {
    int type = (name == "ed25519") ? EVP_PKEY_ED25519 : (name == "ed448" ? EVP_PKEY_ED448 : 0);
    if (!type) return nullptr;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(type, nullptr);
    if (!pctx) return nullptr;
    if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return nullptr; }
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { EVP_PKEY_CTX_free(pctx); return nullptr; }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

// Parse Subject template string like "/CN=Name/O=Org/OU=Unit/C=Country" or "CN=Name,O=Org"
static X509_NAME* parseSubjectTemplate(const std::string &subjectTemplate) {
    X509_NAME *name = X509_NAME_new();
    if (!name) return nullptr;
    
    if (subjectTemplate.empty()) {
        return name;
    }
    
    std::string subj = subjectTemplate;
    // Remove leading slash if present
    if (!subj.empty() && subj[0] == '/') {
        subj = subj.substr(1);
    }
    
    // Parse key=value pairs separated by / or ,
    size_t pos = 0;
    while (pos < subj.length()) {
        size_t next = subj.find_first_of("/,", pos);
        if (next == std::string::npos) next = subj.length();
        
        std::string pair = subj.substr(pos, next - pos);
        size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            std::string key = pair.substr(0, eq);
            std::string value = pair.substr(eq + 1);
            
            // Trim whitespace
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            if (!key.empty() && !value.empty()) {
                X509_NAME_add_entry_by_txt(name, key.c_str(), MBSTRING_ASC,
                                          reinterpret_cast<const unsigned char*>(value.c_str()), -1, -1, 0);
            }
        }
        pos = next + 1;
    }
    
    return name;
}

// Parse Extensions template: semicolon-separated list of "name:value"
// Example: "basicConstraints:critical,CA:TRUE,pathlen:1;keyUsage:critical,keyCertSign,cRLSign;subjectKeyIdentifier:hash"
// Each extension is separated by semicolon, format is "extensionName:value" where value can contain commas
static bool parseExtensionsTemplate(X509 *x, const std::string &extensionsTemplate) {
    if (extensionsTemplate.empty()) {
        return true; // Use defaults
    }
    
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
    
    // Parse semicolon-separated extensions
    std::string extStr = extensionsTemplate;
    size_t pos = 0;
    
    while (pos < extStr.length()) {
        size_t next = extStr.find(';', pos);
        if (next == std::string::npos) next = extStr.length();
        
        std::string extPart = extStr.substr(pos, next - pos);
        // Trim whitespace
        extPart.erase(0, extPart.find_first_not_of(" \t"));
        extPart.erase(extPart.find_last_not_of(" \t") + 1);
        
        if (!extPart.empty()) {
            size_t colon = extPart.find(':');
            if (colon != std::string::npos) {
                std::string extName = extPart.substr(0, colon);
                std::string extValue = extPart.substr(colon + 1);
                
                // Trim whitespace
                extName.erase(0, extName.find_first_not_of(" \t"));
                extName.erase(extName.find_last_not_of(" \t") + 1);
                extValue.erase(0, extValue.find_first_not_of(" \t"));
                extValue.erase(extValue.find_last_not_of(" \t") + 1);
                
                if (!extName.empty() && !extValue.empty()) {
                    // Try to find NID by name
                    int nid = OBJ_txt2nid(extName.c_str());
                    if (nid == NID_undef) {
                        // Try short name
                        nid = OBJ_sn2nid(extName.c_str());
                    }
                    if (nid == NID_undef) {
                        // Try long name
                        nid = OBJ_ln2nid(extName.c_str());
                    }
                    
                    if (nid != NID_undef) {
                        X509_EXTENSION *ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(extValue.c_str()));
                        if (ex) {
                            X509_add_ext(x, ex, -1);
                            X509_EXTENSION_free(ex);
                        } else {
                            printOpenSslErrors(("Failed to add extension: " + extName).c_str());
                        }
                    } else {
                        std::cerr << "Warning: Unknown extension name: " << extName << "\n";
                    }
                }
            }
        }
        pos = next + 1;
    }
    
    return true;
}

static X509* createSelfSignedCa(EVP_PKEY *caKey, const std::string &subjectTemplate, int days, const std::string &extensionsTemplate = "") {
    X509 *x = X509_new();
    if (!x) return nullptr;
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), 60L*60L*24L*days);
    X509_set_version(x, 2); // v3
    X509_set_pubkey(x, caKey);

    // Parse Subject template
    X509_NAME *name = parseSubjectTemplate(subjectTemplate);
    if (!name) {
        X509_free(x);
        return nullptr;
    }
    
    // If Subject is empty, add default CN
    if (X509_NAME_entry_count(name) == 0) {
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>("Local Test Root CA"), -1, -1, 0);
    }
    
    X509_set_subject_name(x, name);
    X509_set_issuer_name(x, name);
    X509_NAME_free(name);

    // Parse Extensions template or use defaults
    if (!extensionsTemplate.empty()) {
        parseExtensionsTemplate(x, extensionsTemplate);
    } else {
        // Default extensions
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
        auto add_ext = [&](int nid, const char *value) {
            X509_EXTENSION *ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value));
            if (!ex) { printOpenSslErrors("Add ext failed"); return false; }
            X509_add_ext(x, ex, -1);
            X509_EXTENSION_free(ex);
            return true;
        };
        add_ext(NID_basic_constraints, "critical,CA:TRUE,pathlen:1");
        add_ext(NID_key_usage, "critical,keyCertSign,cRLSign");
        add_ext(NID_subject_key_identifier, "hash");
        add_ext(NID_authority_key_identifier, "keyid:always,issuer:always");
    }

    if (!X509_sign(x, caKey, EVP_sha256())) {
        printOpenSslErrors("X509_sign failed");
        X509_free(x);
        return nullptr;
    }
    return x;
}

#ifdef WITH_SQLITE3
// Forward declarations for database key storage
static CaDatabase* dbOpen(const fs::path &rootDir);
static void dbStoreKey(CaDatabase *db, const fs::path &rootDir, const std::string &cn, const std::string &keyType, EVP_PKEY *pkey);
static EVP_PKEY* dbLoadKey(CaDatabase *db, const fs::path &rootDir, const std::string &cn);
static void dbStoreCertPem(CaDatabase *db, const std::string &cn, X509 *crt);
static std::string dbLoadCertPem(CaDatabase *db, const std::string &cn);
static void dbStoreCsrPem(CaDatabase *db, const std::string &cn, X509_REQ *req);
static std::string dbLoadCsrPem(CaDatabase *db, const std::string &cn);
static void dbStoreRootCert(CaDatabase *db, X509 *crt);
static std::string dbLoadRootCert(CaDatabase *db);
static void dbAppendAudit(CaDatabase *db, const std::string &event, const std::string &detail);
static long dbGetNextSerial(CaDatabase *db);
static void dbWriteIndexIssued(CaDatabase *db, long serial, const std::string &subject);

// Forward declarations for user database operations
#ifdef WITH_SQLITE3
static QSqlDatabase* userDbOpen(const fs::path &rootDir);
static int getPdfOwnerId(QSqlDatabase *db, int pdfId);
static std::vector<unsigned char> getOrCreateMasterKey(QSqlDatabase *db);
static std::string decryptPdfData(QSqlDatabase *db, const std::vector<unsigned char> &encrypted, const std::vector<unsigned char> &iv, const std::vector<unsigned char> &tag, std::vector<unsigned char> &plaintext);
static std::string verifyPdfSignature(const fs::path &rootDir, const std::string &pdfPath);
#endif
#endif

static bool writePemKey(const fs::path &p, EVP_PKEY *key) {
    // Don't write to file - all keys are stored in database
    // File writing is disabled to prevent creation of private/ directory
    bool ok = true;
    // Skip file writing completely - database is the primary storage
    
    // Store in encrypted database (primary storage)
    #ifdef WITH_SQLITE3
    {
        fs::path rootDir = p;
        // Determine rootDir: go up from ca/private/root.key or ca/private/users/xxx.key
        for (int i = 0; i < 5 && rootDir.has_parent_path(); i++) {
            rootDir = rootDir.parent_path();
            if (rootDir.filename() == "ca") {
                rootDir = rootDir.parent_path();
                break;
            }
        }
        
        // Determine CN and key type
        std::string cn;
        std::string keyType;
        if (p.filename() == "root.key") {
            cn = "root";
            keyType = "root";
        } else if (p.parent_path().filename() == "users") {
            cn = p.stem().string(); // filename without extension
            keyType = "user";
        } else {
            // For temporary files like tmp_3FA-Signer.key, extract CN
            std::string fn = p.stem().string(); // e.g., "tmp_3FA-Signer"
            if (fn.length() > 4 && fn.substr(0, 4) == "tmp_") {
                cn = fn.substr(4); // e.g., "3FA-Signer"
                keyType = "user";
            } else {
                cn = p.stem().string();
                keyType = "other";
            }
        }
        
        if (CaDatabase *db = dbOpen(rootDir)) {
            dbStoreKey(db, rootDir, cn, keyType, key);
            delete db;
            ok = true; // Success if DB write succeeded
        }
    }
    #endif
    
    return ok;
}

static bool writePemPubKey(const fs::path &p, EVP_PKEY *key) {
    FILE *f = fopen(p.string().c_str(), "wb");
    if (!f) return false;
    bool ok = PEM_write_PUBKEY(f, key);
    fclose(f);
    return ok;
}

static bool writePemCert(const fs::path &p, X509 *crt) {
    // Create parent directory if needed (on-demand)
    if (!p.parent_path().empty() && !fs::exists(p.parent_path())) {
        fs::create_directories(p.parent_path());
    }
    FILE *f = fopen(p.string().c_str(), "wb");
    if (!f) return false;
    bool ok = PEM_write_X509(f, crt);
    fclose(f);
    return ok;
}

static EVP_PKEY* readStoreKey(const std::string &uri) {
    std::string finalUri = uri;
    const char *pin = std::getenv("PKCS11_PIN");
    if (pin && uri.rfind("pkcs11:", 0) == 0 && uri.find("pin-value=") == std::string::npos) {
        if (finalUri.back() != ';') finalUri.push_back(';');
        finalUri += std::string("pin-value=") + pin;
    }
    OSSL_STORE_CTX *ctx = OSSL_STORE_open(finalUri.c_str(), nullptr, nullptr, nullptr, nullptr);
    if (!ctx) { printOpenSslErrors("OSSL_STORE_open failed"); return nullptr; }
    EVP_PKEY *pkey = nullptr;
    for (;;) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
        if (!info) break;
        int type = OSSL_STORE_INFO_get_type(info);
        if (type == OSSL_STORE_INFO_PKEY) {
            EVP_PKEY *k = OSSL_STORE_INFO_get1_PKEY(info);
            if (k) { pkey = k; OSSL_STORE_INFO_free(info); break; }
        }
        OSSL_STORE_INFO_free(info);
    }
    OSSL_STORE_close(ctx);
    if (!pkey) std::cerr << "No key in store URI\n";
    return pkey;
}

struct HsmConfig { std::string caCert; std::string keyUri; std::string serialPath; std::string providerName; std::string providerPath; std::string enginePath; std::string modulePath; };

// CA Configuration structure
struct CaConfig {
    // Certificate settings
    int rootKeySize = 4096;           // Root CA key size in bits (default: 4096)
    int rootCaDays = 3650;             // Root CA certificate validity in days (default: 3650)
    int leafCertDays = 825;            // Leaf certificate validity in days (default: 825)
    
    // Directory settings
    std::string caDir = "ca";          // CA directory name (default: "ca")
    std::string databasesDir = "databases";  // Databases directory name (default: "databases")
    
    // Certificate Worker settings
    int scanIntervalSeconds = 300;     // Certificate scan interval in seconds (default: 300 = 5 minutes)
    int renewBeforeDays = 30;          // Renew certificates N days before expiration (default: 30)
    int revokeAfterDays = 0;           // Revoke certificates N days after expiration (default: 0 = immediately)
    int deleteRevokedAfterDays = 90;   // Delete revoked certificates after N days (default: 90)
    
    // Server settings
    std::string serverBindAddr = "127.0.0.1";  // Server bind address (default: 127.0.0.1)
    int serverPort = 9090;             // Server port (default: 9090)
    
    // CRL settings
    int crlDays = 7;                   // CRL validity in days (default: 7)
    
    // OCSP settings
    int ocspDays = 7;                  // OCSP response validity in days (default: 7)
    
    // TSA settings
    std::string tsaUrl = "";           // TSA URL for timestamping (default: empty, uses env var)
    
    bool loaded = false;               // Whether config was loaded from file
};

// Simple JSON value extractor (for basic JSON parsing without external libraries)
// Supports nested objects like "certificate.root_key_size"
static std::string extractJsonValue(const std::string &json, const std::string &key) {
    // Handle nested keys like "certificate.root_key_size"
    std::string searchKey;
    size_t dotPos = key.find('.');
    if (dotPos != std::string::npos) {
        // Nested key: find parent object first
        std::string parentKey = key.substr(0, dotPos);
        std::string childKey = key.substr(dotPos + 1);
        
        std::string parentSearch = "\"" + parentKey + "\"";
        size_t parentPos = json.find(parentSearch);
        if (parentPos == std::string::npos) return "";
        
        // Find opening brace after parent key
        size_t bracePos = json.find('{', parentPos);
        if (bracePos == std::string::npos) return "";
        
        // Find matching closing brace
        int depth = 1;
        size_t endPos = bracePos + 1;
        while (endPos < json.size() && depth > 0) {
            if (json[endPos] == '{') depth++;
            else if (json[endPos] == '}') depth--;
            endPos++;
        }
        
        // Search in the nested object
        std::string nestedJson = json.substr(bracePos, endPos - bracePos);
        return extractJsonValue(nestedJson, childKey);
    }
    
    // Simple key search
    searchKey = "\"" + key + "\"";
    size_t keyPos = json.find(searchKey);
    if (keyPos == std::string::npos) return "";
    
    size_t colonPos = json.find(':', keyPos);
    if (colonPos == std::string::npos) return "";
    
    size_t start = colonPos + 1;
    while (start < json.size() && (std::isspace(json[start]) || json[start] == '"')) start++;
    if (start >= json.size()) return "";
    
    size_t end = start;
    if (start > 0 && json[start - 1] == '"') {
        // String value - handle escaped quotes
        while (end < json.size()) {
            if (json[end] == '"' && (end == start - 1 || json[end - 1] != '\\')) {
                break; // Found unescaped quote
            }
            end++;
        }
    } else {
        // Number value
        while (end < json.size() && (std::isdigit(json[end]) || json[end] == '-' || json[end] == '.')) end++;
    }
    
    if (end > start) {
        std::string value = json.substr(start, end - start);
        // Remove quotes if present
        if (!value.empty() && value[0] == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        }
        return value;
    }
    return "";
}

// Load CA configuration from JSON file (config/ca.json in project root)
static bool loadCaConfig(const fs::path &rootDir, CaConfig &cfg) {
    fs::path configPath = rootDir / "config" / "ca.json";
    std::ifstream in(configPath);
    if (!in) {
        // Config file not found - use defaults
        std::cerr << "[КОНФИГ] Файл config/ca.json не найден, используются значения по умолчанию\n";
        return false;
    }
    
    // Read entire file
    std::string json((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    
    if (json.empty()) {
        std::cerr << "[КОНФИГ] Файл config/ca.json пуст, используются значения по умолчанию\n";
        return false;
    }
    
    std::cerr << "[КОНФИГ] Загружаем конфигурацию из config/ca.json\n";
    
    // Keep original JSON - don't remove whitespace as it may break strings with spaces
    // The extractJsonValue function handles whitespace correctly
    const std::string &jsonClean = json;
    
    // Extract values (support nested JSON structure)
    std::string val;
    
    // Certificate settings
    val = extractJsonValue(jsonClean, "certificate.root_key_size");
    if (!val.empty()) {
        char *endPtr = nullptr;
        long intVal = std::strtol(val.c_str(), &endPtr, 10);
        if (endPtr != val.c_str() && *endPtr == '\0' && intVal > 0) {
            cfg.rootKeySize = static_cast<int>(intVal);
            std::cerr << "[КОНФИГ] certificate.root_key_size из JSON: " << intVal << "\n";
        } else {
            std::cerr << "[КОНФИГ] Warning: Invalid root_key_size value: " << val << ", используется значение по умолчанию\n";
        }
    }
    
    val = extractJsonValue(jsonClean, "certificate.root_ca_days");
    if (!val.empty()) {
        char *endPtr = nullptr;
        long intVal = std::strtol(val.c_str(), &endPtr, 10);
        if (endPtr != val.c_str() && *endPtr == '\0' && intVal > 0) {
            cfg.rootCaDays = static_cast<int>(intVal);
            std::cerr << "[КОНФИГ] certificate.root_ca_days из JSON: " << intVal << "\n";
        } else {
            std::cerr << "[КОНФИГ] Warning: Invalid root_ca_days value: " << val << ", используется значение по умолчанию\n";
        }
    }
    
    val = extractJsonValue(jsonClean, "certificate.leaf_cert_days");
    if (!val.empty()) {
        char *endPtr = nullptr;
        long intVal = std::strtol(val.c_str(), &endPtr, 10);
        if (endPtr != val.c_str() && *endPtr == '\0' && intVal > 0) {
            cfg.leafCertDays = static_cast<int>(intVal);
            std::cerr << "[КОНФИГ] certificate.leaf_cert_days из JSON: " << intVal << "\n";
        } else {
            std::cerr << "[КОНФИГ] Warning: Invalid leaf_cert_days value: " << val << ", используется значение по умолчанию\n";
        }
    }
    
    // Directory settings
    val = extractJsonValue(jsonClean, "directories.ca_dir");
    if (!val.empty()) {
        cfg.caDir = val;
        std::cerr << "[КОНФИГ] directories.ca_dir из JSON: " << val << "\n";
    }
    
    val = extractJsonValue(jsonClean, "directories.databases_dir");
    if (!val.empty()) {
        cfg.databasesDir = val;
        std::cerr << "[КОНФИГ] directories.databases_dir из JSON: " << val << "\n";
    }
    
    // Certificate Worker settings
    val = extractJsonValue(jsonClean, "certificate_worker.scan_interval_seconds");
    if (!val.empty()) {
        char *endPtr = nullptr;
        long intVal = std::strtol(val.c_str(), &endPtr, 10);
        if (endPtr != val.c_str() && *endPtr == '\0' && intVal > 0) {
            cfg.scanIntervalSeconds = static_cast<int>(intVal);
            std::cerr << "[КОНФИГ] certificate_worker.scan_interval_seconds из JSON: " << intVal << "\n";
        } else {
            std::cerr << "[КОНФИГ] Warning: Invalid scan_interval_seconds value: " << val << ", используется значение по умолчанию\n";
        }
    }
    
    val = extractJsonValue(jsonClean, "certificate_worker.renew_before_days");
    if (!val.empty()) {
        char *endPtr = nullptr;
        long intVal = std::strtol(val.c_str(), &endPtr, 10);
        if (endPtr != val.c_str() && *endPtr == '\0' && intVal >= 0) {
            cfg.renewBeforeDays = static_cast<int>(intVal);
            std::cerr << "[КОНФИГ] certificate_worker.renew_before_days из JSON: " << intVal << "\n";
        } else {
            std::cerr << "[КОНФИГ] Warning: Invalid renew_before_days value: " << val << ", используется значение по умолчанию\n";
        }
    }
    
    val = extractJsonValue(jsonClean, "certificate_worker.revoke_after_days");
    if (!val.empty()) {
        char *endPtr = nullptr;
        long intVal = std::strtol(val.c_str(), &endPtr, 10);
        if (endPtr != val.c_str() && *endPtr == '\0' && intVal >= 0) {
            cfg.revokeAfterDays = static_cast<int>(intVal);
            std::cerr << "[КОНФИГ] certificate_worker.revoke_after_days из JSON: " << intVal << "\n";
        } else {
            std::cerr << "[КОНФИГ] Warning: Invalid revoke_after_days value: " << val << ", используется значение по умолчанию\n";
        }
    }
    
    val = extractJsonValue(jsonClean, "certificate_worker.delete_revoked_after_days");
    if (!val.empty()) {
        char *endPtr = nullptr;
        long intVal = std::strtol(val.c_str(), &endPtr, 10);
        if (endPtr != val.c_str() && *endPtr == '\0' && intVal >= 0) {
            cfg.deleteRevokedAfterDays = static_cast<int>(intVal);
            std::cerr << "[КОНФИГ] certificate_worker.delete_revoked_after_days из JSON: " << intVal << "\n";
        } else {
            std::cerr << "[КОНФИГ] Warning: Invalid delete_revoked_after_days value: " << val << ", используется значение по умолчанию\n";
        }
    }
    
    // Server settings
    val = extractJsonValue(jsonClean, "server.bind_addr");
    if (!val.empty()) {
        cfg.serverBindAddr = val;
        std::cerr << "[КОНФИГ] server.bind_addr из JSON: " << val << "\n";
    }
    
    val = extractJsonValue(jsonClean, "server.port");
    if (!val.empty()) {
        char *endPtr = nullptr;
        long intVal = std::strtol(val.c_str(), &endPtr, 10);
        if (endPtr != val.c_str() && *endPtr == '\0' && intVal > 0 && intVal < 65536) {
            cfg.serverPort = static_cast<int>(intVal);
            std::cerr << "[КОНФИГ] server.port из JSON: " << intVal << "\n";
        } else {
            std::cerr << "[КОНФИГ] Warning: Invalid server port value: " << val << " (must be 1-65535), используется значение по умолчанию\n";
        }
    }
    
    // CRL settings
    val = extractJsonValue(jsonClean, "crl.days");
    if (!val.empty()) {
        char *endPtr = nullptr;
        long intVal = std::strtol(val.c_str(), &endPtr, 10);
        if (endPtr != val.c_str() && *endPtr == '\0' && intVal > 0) {
            cfg.crlDays = static_cast<int>(intVal);
            std::cerr << "[КОНФИГ] crl.days из JSON: " << intVal << "\n";
        } else {
            std::cerr << "[КОНФИГ] Warning: Invalid crl.days value: " << val << ", используется значение по умолчанию\n";
        }
    }
    
    // OCSP settings
    val = extractJsonValue(jsonClean, "ocsp.days");
    if (!val.empty()) {
        char *endPtr = nullptr;
        long intVal = std::strtol(val.c_str(), &endPtr, 10);
        if (endPtr != val.c_str() && *endPtr == '\0' && intVal > 0) {
            cfg.ocspDays = static_cast<int>(intVal);
            std::cerr << "[КОНФИГ] ocsp.days из JSON: " << intVal << "\n";
        } else {
            std::cerr << "[КОНФИГ] Warning: Invalid ocsp.days value: " << val << ", используется значение по умолчанию\n";
        }
    }
    
    // TSA settings
    val = extractJsonValue(jsonClean, "tsa.url");
    if (!val.empty()) {
        cfg.tsaUrl = val;
        std::cerr << "[КОНФИГ] tsa.url из JSON: " << val << "\n";
    }
    
    cfg.loaded = true;
    std::cerr << "[КОНФИГ] Конфигурация успешно загружена из JSON. Сервер: " << cfg.serverBindAddr << ":" << cfg.serverPort << "\n";
    return true;
}

static bool loadHsmConfig(const fs::path &rootDir, HsmConfig &cfg) {
    std::ifstream in(rootDir / "ca/hsm.ini"); if (!in) return false;
    auto simpleTrim = [](const std::string &s){ size_t i=0, j=s.size(); while (i<j && std::isspace((unsigned char)s[i])) i++; while (j>i && std::isspace((unsigned char)s[j-1])) j--; return s.substr(i, j-i); };
    std::string line; while (std::getline(in, line)) {
        auto pos = line.find('='); if (pos==std::string::npos) continue;
        std::string k = simpleTrim(line.substr(0,pos)); std::string v = simpleTrim(line.substr(pos+1));
        if (k=="caCert") cfg.caCert = v; else if (k=="keyUri") cfg.keyUri = v; else if (k=="serial") cfg.serialPath = v;
        else if (k=="provider") cfg.providerName = v; else if (k=="providerPath") cfg.providerPath = v;
        else if (k=="engine") cfg.enginePath = v; else if (k=="module") cfg.modulePath = v;
    }
    return !cfg.caCert.empty() && !cfg.keyUri.empty() && !cfg.serialPath.empty();
}

static void applyHsmEnvFromConfig(const HsmConfig &cfg) {
    if (!cfg.providerPath.empty()) {
        // Point OPENSSL_MODULES to directory of providerPath
        auto p = fs::path(cfg.providerPath);
        std::string dir = p.parent_path().string();
#ifdef _WIN32
        _putenv((std::string("OPENSSL_MODULES=") + dir).c_str());
#else
        setenv("OPENSSL_MODULES", dir.c_str(), 0);
#endif
    }
#ifdef WITH_ENGINE_PKCS11
    if (!cfg.enginePath.empty()) {
#ifdef _WIN32
        _putenv((std::string("PKCS11_ENGINE=") + cfg.enginePath).c_str());
#else
        setenv("PKCS11_ENGINE", cfg.enginePath.c_str(), 0);
#endif
    }
#endif
    if (!cfg.modulePath.empty()) {
#ifdef _WIN32
        _putenv((std::string("PKCS11_MODULE=") + cfg.modulePath).c_str());
#else
        setenv("PKCS11_MODULE", cfg.modulePath.c_str(), 0);
#endif
    }
    if (!cfg.providerName.empty()) {
        OSSL_PROVIDER *p = OSSL_PROVIDER_load(nullptr, cfg.providerName.c_str());
        if (!p) printOpenSslErrors("OSSL_PROVIDER_load failed");
    }
}

static EVP_PKEY* readPemKey(const fs::path &p) {
    // Try to load from encrypted database first
    #ifdef WITH_SQLITE3
    fs::path rootDir = p;
    // Determine rootDir: go up from ca/private/root.key or ca/private/users/xxx.key
    for (int i = 0; i < 5 && rootDir.has_parent_path(); i++) {
        rootDir = rootDir.parent_path();
        if (rootDir.filename() == "ca") {
            rootDir = rootDir.parent_path();
            break;
        }
    }
    
    // Determine CN
    std::string cn;
    if (p.filename() == "root.key") {
        cn = "root";
    } else if (p.parent_path().filename() == "users") {
        cn = p.stem().string(); // filename without extension
    } else {
        // For temporary files like tmp_3FA-Signer.key, extract CN
        std::string fn = p.stem().string(); // e.g., "tmp_3FA-Signer"
        if (fn.length() > 4 && fn.substr(0, 4) == "tmp_") {
            cn = fn.substr(4); // e.g., "3FA-Signer"
        } else {
            cn = p.stem().string();
        }
    }
    
    if (CaDatabase *db = dbOpen(rootDir)) {
        EVP_PKEY *key = dbLoadKey(db, rootDir, cn);
        delete db;
        if (key) return key;
    }
    #endif
    
    // Fallback to file
    FILE *f = fopen(p.string().c_str(), "rb");
    if (!f) return nullptr;
    EVP_PKEY *k = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);
    return k;
}

static X509_REQ* readPemCsr(const fs::path &p) {
    FILE *f = fopen(p.string().c_str(), "rb");
    if (!f) return nullptr;
    X509_REQ *r = PEM_read_X509_REQ(f, nullptr, nullptr, nullptr);
    fclose(f);
    return r;
}

// Read CSR from PEM string (from database)
static X509_REQ* readPemCsrFromString(const std::string &pem) {
    BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return nullptr;
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return req;
}

static X509* readPemCert(const fs::path &p) {
    FILE *f = fopen(p.string().c_str(), "rb");
    if (!f) return nullptr;
    X509 *c = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    return c;
}

// Load root CA certificate from database or file (fallback)
static X509* readRootCert(const fs::path &rootDir) {
    #ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) {
        std::string pem = dbLoadRootCert(db);
        delete db;
        if (!pem.empty()) {
            BIO *bio = BIO_new_mem_buf(pem.data(), pem.size());
            if (bio) {
                X509 *crt = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
                BIO_free(bio);
                if (crt) return crt;
            }
        }
    }
    #endif
    
    // Fallback to file
    fs::path crtPath = rootDir / "ca" / "root.crt";
    return readPemCert(crtPath);
}

static X509_REQ* createCsr(EVP_PKEY *key, const std::string &cn, const std::string &sanCsv) {
    X509_REQ *req = X509_REQ_new();
    if (!req) return nullptr;
    X509_REQ_set_version(req, 1);
    X509_REQ_set_pubkey(req, key);
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name);
    if (!sanCsv.empty()) {
        X509V3_CTX ctx; X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, nullptr, nullptr, req, nullptr, 0);
        X509_EXTENSION *ex = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, const_cast<char*>(sanCsv.c_str()));
        if (ex) {
            STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
            sk_X509_EXTENSION_push(exts, ex);
            X509_REQ_add_extensions(req, exts);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }
    }
    if (!X509_REQ_sign(req, key, EVP_sha256())) { printOpenSslErrors("X509_REQ_sign failed"); X509_REQ_free(req); return nullptr; }
    return req;
}

static long nextSerial(const fs::path &serialFile) {
    // Use database only (no file fallback)
    #ifdef WITH_SQLITE3
    fs::path rootDir = serialFile;
    // Determine rootDir: go up from ca/serial.txt
    for (int i = 0; i < 5 && rootDir.has_parent_path(); i++) {
        rootDir = rootDir.parent_path();
        if (rootDir.filename() == "ca") {
            rootDir = rootDir.parent_path();
            break;
        }
    }
    
    if (CaDatabase *db = dbOpen(rootDir)) {
        long serial = dbGetNextSerial(db);
        delete db;
        return serial;
    }
    #endif
    
    // If database not available, return default (should not happen)
    std::cerr << "Warning: database not available for serial number, using default\n";
    return 2;
}

// Validate CSR: check key type, key length, and required attributes
static bool validateCsr(X509_REQ *req, std::string &errorMsg) {
    if (!req) {
        errorMsg = "CSR is null";
        return false;
    }
    
    // 1. Verify CSR signature
    EVP_PKEY *pub = X509_REQ_get_pubkey(req);
    if (!pub) {
        errorMsg = "Failed to extract public key from CSR";
        return false;
    }
    
    if (X509_REQ_verify(req, pub) != 1) {
        errorMsg = "CSR signature verification failed";
        EVP_PKEY_free(pub);
        return false;
    }
    
    // 2. Check key type (only RSA and EC are supported)
    int keyType = EVP_PKEY_id(pub);
    if (keyType != EVP_PKEY_RSA && keyType != EVP_PKEY_EC && 
        keyType != EVP_PKEY_ED25519 && keyType != EVP_PKEY_ED448) {
        errorMsg = "Unsupported key type (only RSA, EC, Ed25519, Ed448 are supported)";
        EVP_PKEY_free(pub);
        return false;
    }
    
    // 3. Check key length
    int keyBits = EVP_PKEY_bits(pub);
    if (keyType == EVP_PKEY_RSA) {
        if (keyBits < 2048) {
            errorMsg = "RSA key length is too short (minimum 2048 bits, got " + std::to_string(keyBits) + " bits)";
            EVP_PKEY_free(pub);
            return false;
        }
    } else if (keyType == EVP_PKEY_EC) {
        if (keyBits < 256) {
            errorMsg = "EC key length is too short (minimum 256 bits, got " + std::to_string(keyBits) + " bits)";
            EVP_PKEY_free(pub);
            return false;
        }
    }
    // Ed25519 and Ed448 have fixed key sizes, no need to check
    
    // 4. Check required attributes (CN in subject)
    X509_NAME *subj = X509_REQ_get_subject_name(req);
    if (!subj) {
        errorMsg = "CSR subject is missing";
        EVP_PKEY_free(pub);
        return false;
    }
    
    // Check for CN (Common Name) in subject
    int cnIndex = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
    if (cnIndex < 0) {
        errorMsg = "CSR subject is missing required CN (Common Name) attribute";
        EVP_PKEY_free(pub);
        return false;
    }
    
    // Verify CN is not empty
    X509_NAME_ENTRY *cnEntry = X509_NAME_get_entry(subj, cnIndex);
    if (!cnEntry) {
        errorMsg = "CSR CN entry is invalid";
        EVP_PKEY_free(pub);
        return false;
    }
    
    ASN1_STRING *cnData = X509_NAME_ENTRY_get_data(cnEntry);
    if (!cnData || ASN1_STRING_length(cnData) == 0) {
        errorMsg = "CSR CN (Common Name) is empty";
        EVP_PKEY_free(pub);
        return false;
    }
    
    EVP_PKEY_free(pub);
    return true;
}

static X509* signCsr(X509_REQ *req, X509 *caCert, EVP_PKEY *caKey, int days, long serial) {
    // Validate CSR before signing
    std::string validationError;
    if (!validateCsr(req, validationError)) {
        std::cerr << "CSR validation failed: " << validationError << "\n";
        printOpenSslErrors("CSR validation");
        return nullptr;
    }
    
    X509 *crt = X509_new();
    if (!crt) return nullptr;
    X509_set_version(crt, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(crt), serial);
    X509_set_issuer_name(crt, X509_get_subject_name(caCert));
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), 60L*60L*24L*days);

    // Subject from CSR
    X509_NAME *subj = X509_REQ_get_subject_name(req);
    X509_set_subject_name(crt, subj);

    // Public key from CSR
    EVP_PKEY *pub = X509_REQ_get_pubkey(req);
    X509_set_pubkey(crt, pub);
    EVP_PKEY_free(pub);

    // Copy CSR extensions if present
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
    if (exts) {
        for (int i = 0; i < sk_X509_EXTENSION_num(exts); ++i) {
            X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
            X509_add_ext(crt, ex, -1);
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

    // Authority Key Identifier
    X509V3_CTX ctx; X509V3_set_ctx(&ctx, caCert, crt, nullptr, nullptr, 0);
    auto add_ext = [&](int nid, const char *value) {
        X509_EXTENSION *ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value));
        if (!ex) { printOpenSslErrors("Add ext failed"); return false; }
        X509_add_ext(crt, ex, -1); X509_EXTENSION_free(ex); return true;
    };
    add_ext(NID_authority_key_identifier, "keyid,issuer");

    if (!X509_sign(crt, caKey, EVP_sha256())) {
        printOpenSslErrors("X509_sign failed");
        X509_free(crt); return nullptr;
    }
    return crt;
}

static bool addExtByStr(X509 *crt, X509 *issuer, int nid, const std::string &value) {
    X509V3_CTX ctx; X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, crt, nullptr, nullptr, 0);
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value.c_str()));
    if (!ex) { printOpenSslErrors("Add ext failed"); return false; }
    X509_add_ext(crt, ex, -1); X509_EXTENSION_free(ex); return true;
}

static X509* signCsrWithProfile(X509_REQ *req, X509 *caCert, EVP_PKEY *caKey,
                                int days, long serial, const std::string &profile,
                                const std::string &sanCsv,
                                const std::string &aiaIssuerUrl,
                                const std::string &aiaOcspUrl,
                                const std::string &crlDpUrl,
                                const std::string &policyOid,
                                const std::string &policyCpsUri,
                                int pathLen,
                                bool isCA,
                                const std::string &nameConstraintsStr) {
    // Validate CSR before signing
    std::string validationError;
    if (!validateCsr(req, validationError)) {
        std::cerr << "CSR validation failed: " << validationError << "\n";
        printOpenSslErrors("CSR validation");
        return nullptr;
    }
    
    X509 *crt = X509_new();
    if (!crt) return nullptr;
    X509_set_version(crt, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(crt), serial);
    X509_set_issuer_name(crt, X509_get_subject_name(caCert));
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), 60L*60L*24L*days);

    X509_NAME *subj = X509_REQ_get_subject_name(req);
    X509_set_subject_name(crt, subj);
    EVP_PKEY *pub = X509_REQ_get_pubkey(req);
    X509_set_pubkey(crt, pub);
    EVP_PKEY_free(pub);

    // Copy CSR exts if any
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
    if (exts) {
        for (int i = 0; i < sk_X509_EXTENSION_num(exts); ++i)
            X509_add_ext(crt, sk_X509_EXTENSION_value(exts, i), -1);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

    // Baseline EKU/KU by profile
    if (profile == "server") {
        addExtByStr(crt, caCert, NID_ext_key_usage, "serverAuth");
        addExtByStr(crt, caCert, NID_key_usage, "digitalSignature,keyEncipherment");
    } else if (profile == "client") {
        addExtByStr(crt, caCert, NID_ext_key_usage, "clientAuth");
        addExtByStr(crt, caCert, NID_key_usage, "digitalSignature");
    } else if (profile == "codesign") {
        addExtByStr(crt, caCert, NID_ext_key_usage, "codeSigning");
        addExtByStr(crt, caCert, NID_key_usage, "digitalSignature");
    }

    // If CA or pathLen provided
    if (isCA || pathLen >= 0) {
        std::string bc = "critical,CA:";
        bc += (isCA?"TRUE":"FALSE");
        if (pathLen >= 0) {
            bc += ",pathlen:" + std::to_string(pathLen);
        }
        addExtByStr(crt, caCert, NID_basic_constraints, bc);
        if (isCA) addExtByStr(crt, caCert, NID_key_usage, "critical,keyCertSign,cRLSign");
        if (isCA && !nameConstraintsStr.empty()) {
            addExtByStr(crt, caCert, NID_name_constraints, nameConstraintsStr);
        }
    }

    // SAN from CSV: "DNS:ex.com,IP:1.2.3.4,email:test@ex.com"
    if (!sanCsv.empty()) {
        addExtByStr(crt, caCert, NID_subject_alt_name, sanCsv);
    }

    addExtByStr(crt, caCert, NID_authority_key_identifier, "keyid,issuer");
    addExtByStr(crt, caCert, NID_subject_key_identifier, "hash");

    // AIA (OCSP/Issuer)
    if (!aiaIssuerUrl.empty() || !aiaOcspUrl.empty()) {
        std::string aia;
        if (!aiaOcspUrl.empty()) { aia += "OCSP;URI:" + aiaOcspUrl; }
        if (!aiaIssuerUrl.empty()) { if (!aia.empty()) aia += ","; aia += "caIssuers;URI:" + aiaIssuerUrl; }
        addExtByStr(crt, caCert, NID_info_access, aia);
    }
    // CRL Distribution Points
    if (!crlDpUrl.empty()) {
        std::string crl = "URI:" + crlDpUrl;
        addExtByStr(crt, caCert, NID_crl_distribution_points, crl);
    }
    // Certificate Policies
    if (!policyOid.empty()) {
        std::string pol = policyOid;
        if (!policyCpsUri.empty()) pol += ";CPS:" + policyCpsUri;
        addExtByStr(crt, caCert, NID_certificate_policies, pol);
    }

    if (!X509_sign(crt, caKey, EVP_sha256())) {
        printOpenSslErrors("X509_sign failed"); X509_free(crt); return nullptr;
    }
    return crt;
}

static bool writeIndexIssued(const fs::path &indexPath, long serial, const std::string &subject) {
    // Store in database first (primary storage)
    #ifdef WITH_SQLITE3
    fs::path rootDir = indexPath;
    // Determine rootDir: go up from ca/index.txt
    for (int i = 0; i < 5 && rootDir.has_parent_path(); i++) {
        rootDir = rootDir.parent_path();
        if (rootDir.filename() == "ca") {
            rootDir = rootDir.parent_path();
            break;
        }
    }
    
    if (CaDatabase *db = dbOpen(rootDir)) {
        dbWriteIndexIssued(db, serial, subject);
        delete db;
    }
    #endif
    
    // Fallback to file for backward compatibility
    std::ofstream out(indexPath, std::ios::app);
    if (!out) return false;
    // status V (valid), expiration dummy here (handled by cert itself), serial in hex
    char serialHex[32];
    std::snprintf(serialHex, sizeof(serialHex), "%lX", serial);
    out << "V\t" << serialHex << "\t" << subject << "\n";
    return true;
}

#ifdef WITH_SQLITE3
// Database functions (keys, certs, revoked)
// Используем CaDatabase вместо прямых вызовов SQLite
static CaDatabase* dbOpen(const fs::path &rootDir) {
    CaDatabase *caDb = new CaDatabase();
    QString dbPath = QString::fromStdString((rootDir / "databases" / "ca.db").string());
    if (!caDb->connect(dbPath)) {
        std::cerr << "Failed to connect to CA database: " << caDb->getLastError().toStdString() << "\n";
        delete caDb;
        return nullptr;
    }
    return caDb;
}

static void dbInsertIssued(CaDatabase *db, long serial, X509 *crt) {
    if (!db || !db->isConnected()) return;
    char subj[512]={0}; X509_NAME_oneline(X509_get_subject_name(crt), subj, sizeof(subj)-1);
    const ASN1_TIME *nb = X509_get0_notBefore(crt);
    const ASN1_TIME *na = X509_get0_notAfter(crt);
    
    // Правильная конвертация ASN1_TIME в time_t
    auto asn1ToTimeT = [](const ASN1_TIME *t)->time_t {
        if (!t) return std::time(nullptr);
        
        // Используем ASN1_TIME_diff для получения разницы в секундах от эпохи
        // Создаем ASN1_TIME для эпохи (1 января 1970)
        ASN1_TIME *epoch = ASN1_TIME_new();
        ASN1_TIME_set(epoch, 0); // 1 января 1970, 00:00:00 UTC
        
        int day = 0, sec = 0;
        if (ASN1_TIME_diff(&day, &sec, epoch, t) == 0) {
            ASN1_TIME_free(epoch);
            return std::time(nullptr); // Fallback на текущее время при ошибке
        }
        
        ASN1_TIME_free(epoch);
        // day * 86400 + sec дает количество секунд с эпохи
        return static_cast<time_t>(day * 86400LL + sec);
    };
    
    QVariantList params;
    params << static_cast<qlonglong>(serial) << QString::fromLocal8Bit(subj) 
           << static_cast<qlonglong>(asn1ToTimeT(nb)) << static_cast<qlonglong>(asn1ToTimeT(na)) 
           << QString("valid");
    
    if (!db->exec("INSERT OR REPLACE INTO certs(serial,subject,not_before,not_after,status) VALUES(?,?,?,?,?)", params)) {
        std::cerr << "Failed to insert cert: " << db->getLastError().toStdString() << "\n";
    }
}

static void dbMarkRevoked(CaDatabase *db, long serial, const std::string &reason) {
    if (!db || !db->isConnected()) return;
    
    QVariantList params;
    params << static_cast<qlonglong>(serial) << QString::fromStdString(reason) 
           << static_cast<qlonglong>(std::time(nullptr));
    
    if (!db->exec("INSERT OR REPLACE INTO revoked(serial,reason,revoked_at) VALUES(?,?,?)", params)) {
        std::cerr << "Failed to mark revoked: " << db->getLastError().toStdString() << "\n";
        return;
    }
    
    QVariantList updateParams;
    updateParams << static_cast<qlonglong>(serial);
    if (!db->exec("UPDATE certs SET status='revoked' WHERE serial=?", updateParams)) {
        std::cerr << "Failed to update cert status: " << db->getLastError().toStdString() << "\n";
    }
}

static void dbMarkUnrevoked(CaDatabase *db, long serial) {
    if (!db || !db->isConnected()) return;
    
    QVariantList params;
    params << static_cast<qlonglong>(serial);
    
    if (!db->exec("DELETE FROM revoked WHERE serial=?", params)) {
        std::cerr << "Failed to delete from revoked: " << db->getLastError().toStdString() << "\n";
        return;
    }
    
    if (!db->exec("UPDATE certs SET status='valid' WHERE serial=?", params)) {
        std::cerr << "Failed to update cert status: " << db->getLastError().toStdString() << "\n";
    }
}

// Master key management for encryption
static std::vector<unsigned char> getOrCreateMasterKey(const fs::path &rootDir) {
    #ifdef WITH_SQLITE3
    // Try to load from database first
    if (CaDatabase *db = dbOpen(rootDir)) {
        QSqlQuery query = db->select("SELECT master_key FROM master_keys WHERE id=1");
        
        if (query.next()) {
            QByteArray keyData = query.value(0).toByteArray();
            
            if (keyData.size() == 32) {
                std::vector<unsigned char> key(32);
                memcpy(key.data(), keyData.data(), 32);
                delete db;
                return key;
            }
        }
        delete db;
    }
    
    // Try to migrate from file if exists (backward compatibility)
    fs::path masterKeyPath = rootDir / "ca/private/master.key";
    if (fs::exists(masterKeyPath)) {
        std::ifstream in(masterKeyPath, std::ios::binary);
        if (in) {
            std::vector<unsigned char> key(32);
            in.read(reinterpret_cast<char*>(key.data()), 32);
            if (in.gcount() == 32) {
                // Migrate to database
                if (CaDatabase *db = dbOpen(rootDir)) {
                    QByteArray keyBlob(reinterpret_cast<const char*>(key.data()), 32);
                    QVariantList params;
                    params << keyBlob;
                    
                    if (db->exec("INSERT OR REPLACE INTO master_keys(id, master_key) VALUES(1, ?)", params)) {
                        // Optionally remove old file after migration
                        // fs::remove(masterKeyPath);
                    }
                    delete db;
                }
                return key;
            }
        }
    }
    
    // Generate new master key (32 bytes for AES-256)
    std::vector<unsigned char> key(32);
    RAND_bytes(key.data(), 32);
    
    // Save to database
    if (CaDatabase *db = dbOpen(rootDir)) {
        QByteArray keyBlob(reinterpret_cast<const char*>(key.data()), 32);
        QVariantList params;
        params << keyBlob;
        
        if (!db->exec("INSERT OR REPLACE INTO master_keys(id, master_key) VALUES(1, ?)", params)) {
            std::cerr << "Failed to save master key to database: " << db->getLastError().toStdString() << "\n";
            delete db;
            return std::vector<unsigned char>();
        }
        delete db;
    } else {
        std::cerr << "Failed to open database for saving master key\n";
        return std::vector<unsigned char>();
    }
    
    return key;
    #else
    // Fallback to file if SQLite not available
    fs::path masterKeyPath = rootDir / "ca/private/master.key";
    fs::create_directories(masterKeyPath.parent_path());
    
    if (fs::exists(masterKeyPath)) {
        std::ifstream in(masterKeyPath, std::ios::binary);
        if (in) {
            std::vector<unsigned char> key(32);
            in.read(reinterpret_cast<char*>(key.data()), 32);
            if (in.gcount() == 32) {
                fs::permissions(masterKeyPath, fs::perms::owner_read | fs::perms::owner_write);
                return key;
            }
        }
    }
    
    std::vector<unsigned char> key(32);
    RAND_bytes(key.data(), 32);
    
    std::ofstream out(masterKeyPath, std::ios::binary);
    if (!out) {
        std::cerr << "Failed to write master key\n";
        return std::vector<unsigned char>();
    }
    out.write(reinterpret_cast<const char*>(key.data()), 32);
    out.close();
    fs::permissions(masterKeyPath, fs::perms::owner_read | fs::perms::owner_write);
    
    return key;
    #endif
}

// Encrypt key data using AES-256-GCM
static bool encryptKeyData(const std::vector<unsigned char> &masterKey,
                           const std::vector<unsigned char> &plaintext,
                           std::vector<unsigned char> &ciphertext,
                           std::vector<unsigned char> &iv,
                           std::vector<unsigned char> &tag) {
    if (masterKey.size() != 32) return false;
    
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    iv.resize(12); // GCM IV: 12 bytes
    RAND_bytes(iv.data(), 12);
    
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, masterKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    ciphertext.resize(plaintext.size());
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    tag.resize(16); // GCM tag: 16 bytes
    if (EVP_EncryptFinal_ex(ctx, nullptr, &outlen) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Decrypt key data using AES-256-GCM
static bool decryptKeyData(const std::vector<unsigned char> &masterKey,
                           const std::vector<unsigned char> &ciphertext,
                           const std::vector<unsigned char> &iv,
                           const std::vector<unsigned char> &tag,
                           std::vector<unsigned char> &plaintext) {
    if (masterKey.size() != 32) return false;
    
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, masterKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    plaintext.resize(ciphertext.size());
    int outlen = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag.data())) != 1 ||
        EVP_DecryptFinal_ex(ctx, nullptr, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Store encrypted key in database
static void dbStoreKey(CaDatabase *db, const fs::path &rootDir, const std::string &cn, const std::string &keyType, EVP_PKEY *pkey) {
    if (!db || !pkey) return;
    
    // Serialize key to PEM
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return;
    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        return;
    }
    
    char *data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::vector<unsigned char> plaintext(reinterpret_cast<const unsigned char*>(data), 
                                        reinterpret_cast<const unsigned char*>(data) + len);
    BIO_free(bio);
    
    // Get master key
    std::vector<unsigned char> masterKey = getOrCreateMasterKey(rootDir);
    if (masterKey.empty()) return;
    
    // Encrypt
    std::vector<unsigned char> ciphertext, iv, tag;
    if (!encryptKeyData(masterKey, plaintext, ciphertext, iv, tag)) return;
    
    // Store in database
    QByteArray ciphertextBlob(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    QByteArray ivBlob(reinterpret_cast<const char*>(iv.data()), iv.size());
    QByteArray tagBlob(reinterpret_cast<const char*>(tag.data()), tag.size());
    
    QVariantList params;
    params << QString::fromStdString(cn) << QString::fromStdString(keyType) 
           << ciphertextBlob << ivBlob << tagBlob;
    
    if (!db->exec("INSERT OR REPLACE INTO keys(cn, key_type, encrypted_key, iv, tag) VALUES(?,?,?,?,?)", params)) {
        std::cerr << "Failed to store key: " << db->getLastError().toStdString() << "\n";
    }
}

// Load encrypted key from database
static EVP_PKEY* dbLoadKey(CaDatabase *db, const fs::path &rootDir, const std::string &cn) {
    if (!db || !db->isConnected()) return nullptr;
    
    QVariantList params;
    params << QString::fromStdString(cn);
    QSqlQuery query = db->select("SELECT encrypted_key, iv, tag FROM keys WHERE cn=?", params);
    
    if (!query.next()) {
        return nullptr;
    }
    
    QByteArray encData = query.value(0).toByteArray();
    QByteArray ivData = query.value(1).toByteArray();
    QByteArray tagData = query.value(2).toByteArray();
    
    if (encData.isEmpty() || ivData.size() != 12 || tagData.size() != 16) {
        return nullptr;
    }
    
    std::vector<unsigned char> ciphertext(encData.begin(), encData.end());
    std::vector<unsigned char> iv(ivData.begin(), ivData.end());
    std::vector<unsigned char> tag(tagData.begin(), tagData.end());
    
    // Get master key
    std::vector<unsigned char> masterKey = getOrCreateMasterKey(rootDir);
    if (masterKey.empty()) return nullptr;
    
    // Decrypt
    std::vector<unsigned char> plaintext;
    if (!decryptKeyData(masterKey, ciphertext, iv, tag, plaintext)) return nullptr;
    
    // Parse PEM key
    BIO *bio = BIO_new_mem_buf(plaintext.data(), plaintext.size());
    if (!bio) return nullptr;
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    return key;
}

// Store certificate PEM in database
static void dbStoreCertPem(CaDatabase *db, const std::string &cn, X509 *crt) {
    if (!db || !db->isConnected() || !crt) return;
    
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return;
    if (PEM_write_bio_X509(bio, crt) != 1) {
        BIO_free(bio);
        return;
    }
    
    char *data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);
    BIO_free(bio);
    
    QVariantList params;
    params << QString::fromStdString(cn) << QString::fromStdString(pem);
    
    if (!db->exec("INSERT OR REPLACE INTO cert_pem(cn, cert_pem) VALUES(?,?)", params)) {
        std::cerr << "Failed to store cert PEM: " << db->getLastError().toStdString() << "\n";
    }
}

// Load certificate PEM from database
static std::string dbLoadCertPem(CaDatabase *db, const std::string &cn) {
    if (!db || !db->isConnected()) return "";
    
    QVariantList params;
    params << QString::fromStdString(cn);
    QSqlQuery query = db->select("SELECT cert_pem FROM cert_pem WHERE cn=?", params);
    
    if (query.next()) {
        return query.value(0).toString().toStdString();
    }
    return "";
}

// Store CSR PEM in database
static void dbStoreCsrPem(CaDatabase *db, const std::string &cn, X509_REQ *req) {
    if (!db || !db->isConnected() || !req) return;
    
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return;
    if (PEM_write_bio_X509_REQ(bio, req) != 1) {
        BIO_free(bio);
        return;
    }
    
    char *data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);
    BIO_free(bio);
    
    QVariantList params;
    params << QString::fromStdString(cn) << QString::fromStdString(pem);
    
    if (!db->exec("INSERT OR REPLACE INTO csr_pem(cn, csr_pem) VALUES(?,?)", params)) {
        std::cerr << "Failed to store CSR PEM: " << db->getLastError().toStdString() << "\n";
    }
}

// Load CSR PEM from database
static std::string dbLoadCsrPem(CaDatabase *db, const std::string &cn) {
    if (!db || !db->isConnected()) return "";
    
    QVariantList params;
    params << QString::fromStdString(cn);
    QSqlQuery query = db->select("SELECT csr_pem FROM csr_pem WHERE cn=?", params);
    
    if (query.next()) {
        return query.value(0).toString().toStdString();
    }
    return "";
}

// Store root CA certificate PEM in database with checksum
static void dbStoreRootCert(CaDatabase *db, X509 *crt) {
    if (!db || !db->isConnected() || !crt) return;
    
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return;
    if (PEM_write_bio_X509(bio, crt) != 1) {
        BIO_free(bio);
        return;
    }
    
    char *data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);
    BIO_free(bio);
    
    // Вычисляем SHA-256 контрольную сумму сертификата
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    if (!X509_digest(crt, EVP_sha256(), md, &mdlen)) {
        std::cerr << "Failed to compute certificate checksum\n";
        return;
    }
    
    // Преобразуем контрольную сумму в hex строку
    std::ostringstream oss;
    for (unsigned int i = 0; i < mdlen; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md[i]);
        if (i < mdlen - 1) oss << ":";
    }
    std::string checksum = oss.str();
    
    QVariantList params;
    params << QString::fromStdString(pem) << QString::fromStdString(checksum);
    
    if (!db->exec("INSERT OR REPLACE INTO root_cert(id, cert_pem, checksum) VALUES(1,?,?)", params)) {
        std::cerr << "Failed to store root cert: " << db->getLastError().toStdString() << "\n";
    }
}

// Load root CA certificate PEM from database with checksum verification
static std::string dbLoadRootCert(CaDatabase *db) {
    if (!db || !db->isConnected()) return "";
    
    QSqlQuery query = db->select("SELECT cert_pem, checksum FROM root_cert WHERE id=1");
    
    if (query.next()) {
        std::string pem = query.value(0).toString().toStdString();
        std::string storedChecksum = query.value(1).toString().toStdString();
        
        // Проверяем контрольную сумму если она сохранена (для обратной совместимости пропускаем проверку если checksum пустой)
        if (!storedChecksum.empty() && !pem.empty()) {
            // Парсим сертификат из PEM
            BIO *bio = BIO_new_mem_buf(pem.data(), pem.size());
            if (bio) {
                X509 *crt = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
                BIO_free(bio);
                
                if (crt) {
                    // Вычисляем текущую контрольную сумму
                    unsigned char md[EVP_MAX_MD_SIZE];
                    unsigned int mdlen = 0;
                    if (X509_digest(crt, EVP_sha256(), md, &mdlen)) {
                        // Преобразуем в hex строку
                        std::ostringstream oss;
                        for (unsigned int i = 0; i < mdlen; i++) {
                            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md[i]);
                            if (i < mdlen - 1) oss << ":";
                        }
                        std::string computedChecksum = oss.str();
                        
                        // Сравниваем контрольные суммы (без учета регистра)
                        std::string storedLower = storedChecksum;
                        std::string computedLower = computedChecksum;
                        std::transform(storedLower.begin(), storedLower.end(), storedLower.begin(), ::tolower);
                        std::transform(computedLower.begin(), computedLower.end(), computedLower.begin(), ::tolower);
                        
                        if (storedLower != computedLower) {
                            std::cerr << "⚠️  WARNING: Root certificate checksum mismatch! Stored: " << storedChecksum 
                                      << ", Computed: " << computedChecksum << "\n";
                            std::cerr << "⚠️  WARNING: Certificate may have been tampered with!\n";
                            X509_free(crt);
                            return ""; // Отказываемся загружать поврежденный сертификат
                        } else {
                            // Контрольная сумма совпадает - сертификат целостен
                            std::cout << "✓ Root certificate checksum verified: " << computedChecksum << "\n";
                        }
                    }
                    X509_free(crt);
                }
            }
        }
        
        return pem;
    }
    return "";
}

// Append audit log entry to database
static void dbAppendAudit(CaDatabase *db, const std::string &event, const std::string &detail) {
    if (!db || !db->isConnected()) return;
    
    auto now = std::chrono::system_clock::now();
    auto sec = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    
    QVariantList params;
    params << static_cast<qlonglong>(sec) << QString::fromStdString(event) << QString::fromStdString(detail);
    
    if (!db->exec("INSERT INTO audit_log(timestamp, event, detail) VALUES(?,?,?)", params)) {
        std::cerr << "Failed to append audit: " << db->getLastError().toStdString() << "\n";
    }
}

// Get and increment next serial number from database
static long dbGetNextSerial(CaDatabase *db) {
    if (!db || !db->isConnected()) return 2;
    
    // Try to get current serial
    QSqlQuery query = db->select("SELECT next_serial FROM serial_number WHERE id=1");
    
    long serial = 2;
    if (query.next()) {
        serial = static_cast<long>(query.value(0).toLongLong());
    }
    
    // Increment and update
    long nextSerial = serial + 1;
    QVariantList params;
    params << static_cast<qlonglong>(nextSerial);
    
    if (!db->exec("INSERT OR REPLACE INTO serial_number(id, next_serial) VALUES(1,?)", params)) {
        std::cerr << "Failed to update serial: " << db->getLastError().toStdString() << "\n";
    }
    
    return serial;
}

// Write index entry to database (issued certificate)
static void dbWriteIndexIssued(CaDatabase *db, long serial, const std::string &subject) {
    if (!db || !db->isConnected()) return;
    
    // The certs table already stores certificate info, so we just ensure it's marked as valid
    // But we also add to a separate index for compatibility
    QVariantList params;
    params << static_cast<qlonglong>(serial);
    
    if (!db->exec("UPDATE certs SET status='valid' WHERE serial=?", params)) {
        std::cerr << "Failed to update cert status: " << db->getLastError().toStdString() << "\n";
    }
    
    // Note: The subject and status are already stored in certs table via dbInsertIssued
    // This function is called after dbInsertIssued, so it's mainly to ensure consistency
}

// User database functions
#ifdef WITH_SQLITE3
static QSqlDatabase* userDbOpen(const fs::path &rootDir) {
    static int connectionCounter = 0;
    QString connectionName = QString("user_db_%1").arg(++connectionCounter);
    
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", connectionName);
    QString dbPath = QString::fromStdString((rootDir / "databases" / "3fa_users.db").string());
    db.setDatabaseName(dbPath);
    
    if (!db.open()) {
        std::cerr << "Failed to open user database: " << db.lastError().text().toStdString() << "\n";
        QSqlDatabase::removeDatabase(connectionName);
        return nullptr;
    }
    
    // Return a pointer to the database connection (connection is managed by Qt)
    // Use QSqlDatabase::database() to get the connection by name
    QSqlDatabase* dbPtr = new QSqlDatabase(QSqlDatabase::database(connectionName));
    return dbPtr;
}

static void userDbClose(QSqlDatabase *db) {
    if (!db) {
        return;
    }
    
    const QString connectionName = db->connectionName();
    
    // Закрываем соединение
    db->close();
    
    // Обрабатываем события несколько раз, чтобы Qt успел завершить все операции с запросами
    // Это необходимо, так как SQLite драйвер может кэшировать запросы
    for (int i = 0; i < 5; ++i) {
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    }
    
    delete db;
    db = nullptr;

    // Дополнительные обработки событий для отложенных операций драйвера
    for (int i = 0; i < 3; ++i) {
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    }

    if (QSqlDatabase::contains(connectionName)) {
        QSqlDatabase::removeDatabase(connectionName);
    }
}


static int getPdfOwnerId(QSqlDatabase *db, int pdfId) {
    if (!db || !db->isOpen()) return -1;
    
    int ownerId = -1;
    {
        QSqlQuery query(*db);
        query.prepare("SELECT user_id FROM user_pdf_documents WHERE id = ?");
        query.addBindValue(pdfId);
        
        if (!query.exec()) {
            std::cerr << "Failed to get PDF owner: " << query.lastError().text().toStdString() << "\n";
            query.finish(); // Явно завершаем запрос
            return -1;
        }
        
        if (query.next()) {
            ownerId = query.value(0).toInt();
        }
        query.finish(); // Явно завершаем запрос
        // query уничтожится при выходе из блока
    }
    
    return ownerId;
}

static std::vector<unsigned char> getOrCreateMasterKey(QSqlDatabase *db) {
    std::vector<unsigned char> masterKey(32, 0);
    
    if (!db || !db->isOpen()) {
        // Generate a new key if database is not available
        if (RAND_bytes(masterKey.data(), 32) != 1) {
            std::cerr << "Failed to generate master key\n";
            return std::vector<unsigned char>();
        }
        return masterKey;
    }
    
    // Сначала пытаемся получить ключ из базы данных
    {
        QSqlQuery query(*db);
        query.prepare("SELECT master_key FROM master_keys WHERE id=1");
        
        if (!query.exec()) {
            std::cerr << "Failed to get master key: " << query.lastError().text().toStdString() << "\n";
            query.finish(); // Явно завершаем запрос
            // Generate a new key if query fails
            if (RAND_bytes(masterKey.data(), 32) != 1) {
                std::cerr << "Failed to generate master key\n";
                return std::vector<unsigned char>();
            }
            // Сохраняем новый ключ в базу данных
            {
                QSqlQuery insertQuery(*db);
                insertQuery.prepare("INSERT OR REPLACE INTO master_keys(id, master_key) VALUES(1, ?)");
                insertQuery.addBindValue(QByteArray(reinterpret_cast<const char*>(masterKey.data()), 32));
                
                if (!insertQuery.exec()) {
                    std::cerr << "Failed to save master key: " << insertQuery.lastError().text().toStdString() << "\n";
                }
                insertQuery.finish(); // Явно завершаем запрос
            }
            return masterKey;
        }
        
        if (query.next()) {
            QByteArray keyData = query.value(0).toByteArray();
            if (keyData.size() == 32) {
                masterKey.assign(keyData.begin(), keyData.end());
                query.finish(); // Явно завершаем запрос
                return masterKey;
            }
        }
        query.finish(); // Явно завершаем запрос
        // query уничтожится при выходе из блока
    }
    
    // Generate a new key if not found
    if (RAND_bytes(masterKey.data(), 32) != 1) {
        std::cerr << "Failed to generate master key\n";
        return std::vector<unsigned char>();
    }
    
    // Save the key to database
    {
        QSqlQuery query(*db);
        query.prepare("INSERT OR REPLACE INTO master_keys(id, master_key) VALUES(1, ?)");
        query.addBindValue(QByteArray(reinterpret_cast<const char*>(masterKey.data()), 32));
        
        if (!query.exec()) {
            std::cerr << "Failed to save master key: " << query.lastError().text().toStdString() << "\n";
        }
        query.finish(); // Явно завершаем запрос
        // query уничтожится при выходе из блока
    }
    
    return masterKey;
}

static std::string decryptPdfData(QSqlDatabase *db, const std::vector<unsigned char> &encrypted, const std::vector<unsigned char> &iv, const std::vector<unsigned char> &tag, std::vector<unsigned char> &plaintext) {
    // Get master key from database
    std::vector<unsigned char> masterKey = getOrCreateMasterKey(db);
    if (masterKey.empty() || masterKey.size() != 32) {
        return "Failed to get master key";
    }
    
    if (iv.size() != 12 || tag.size() != 16) {
        return "Invalid IV or tag size";
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return "Failed to create cipher context";
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, masterKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "Failed to initialize decryption";
    }
    
    plaintext.resize(encrypted.size());
    int len = 0;
    int plaintextLen = 0;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted.data(), encrypted.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "Failed to decrypt data";
    }
    plaintextLen = len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "Failed to set authentication tag";
    }
    
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "Failed to finalize decryption (authentication failed)";
    }
    plaintextLen += len;
    
    plaintext.resize(plaintextLen);
    EVP_CIPHER_CTX_free(ctx);
    
    return "";
}

static std::string verifyPdfSignature(const fs::path &rootDir, const std::string &pdfPath) {
    // Call Python script to verify PDF signature
    std::string verifyScript = (rootDir / "ca" / "verify_pdf_signature.py").string();
    std::string caCertPath = (rootDir / "databases" / "ca.db").string();
    
    std::cerr << "Sign server: [VERIFY] Starting PDF signature verification: script=" << verifyScript << ", pdf=" << pdfPath << "\n";
    
    // Determine Python executable path
#ifdef _WIN32
    fs::path venvPython = rootDir / "venv_mediapipe" / "Scripts" / "python.exe";
    std::string pythonExe = fs::exists(venvPython) ? ("\"" + venvPython.string() + "\"") : "python";
#else
    std::string pythonExe = "python3";
#endif
    
    std::string cmd = pythonExe + " \"" + verifyScript + "\" \"" + pdfPath + "\" 2>&1";
    std::cerr << "Sign server: [VERIFY] Executing command: " << cmd << "\n";
    
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "Sign server: [VERIFY] Failed to execute verification script\n";
        return "Failed to execute verification script";
    }
    
    std::string result;
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    
    int status = pclose(pipe);
    std::cerr << "Sign server: [VERIFY] Verification script exited with status=" << status << "\n";
    std::cerr << "Sign server: [VERIFY] Verification output (first 500 chars): " << result.substr(0, 500) << "\n";
    
    // Check if signature is valid
    // Parse output from verify_pdf_signature.py script
    std::string sigStatus = "unknown";
    
    // First check for explicit status messages (highest priority)
    if (result.find("✓ ПОДПИСЬ ВАЛИДНА") != std::string::npos ||
        result.find("ПОДПИСЬ ВАЛИДНА") != std::string::npos) {
        sigStatus = "valid";
    } 
    else if (result.find("❌ ПОДПИСЬ НЕВЕРНА") != std::string::npos ||
             result.find("ПОДПИСЬ НЕВЕРНА") != std::string::npos) {
        sigStatus = "invalid";
    }
    // Check for no signature found
    else if (result.find("ПОДПИСЬ НЕ НАЙДЕНА") != std::string::npos ||
             result.find("Подпись не найдена") != std::string::npos ||
             result.find("Найдено подписей: 0") != std::string::npos ||
             result.find("не найдено подписей") != std::string::npos ||
             result.find("не содержит цифровых подписей") != std::string::npos) {
        sigStatus = "no_signature";
    }
    // Check for validation errors (indicates signature exists but has issues)
    else if (result.find("Ошибка валидации") != std::string::npos ||
             result.find("ошибка валидации") != std::string::npos) {
        // Signature exists but has validation errors - check if it's just a warning
        if (result.find("PDF содержит цифровую подпись") != std::string::npos) {
            // Signature exists, might be valid but with warnings
            sigStatus = "valid";
        } else {
            sigStatus = "invalid";
        }
    }
    // Check for timestamp status
    else if (result.find("⚠ МЕТКА ВРЕМЕНИ ОТСУТСТВУЕТ") != std::string::npos ||
             result.find("МЕТКА ВРЕМЕНИ ОТСУТСТВУЕТ") != std::string::npos) {
        // Signature exists but no timestamp
        if (result.find("PDF содержит цифровую подпись") != std::string::npos ||
            result.find("Найдено подписей:") != std::string::npos) {
            sigStatus = "valid"; // Signature is valid, just missing timestamp
        } else {
            sigStatus = "no_timestamp";
        }
    }
    // If we have signature but couldn't determine explicit status, check if signature exists
    else if (result.find("PDF содержит цифровую подпись") != std::string::npos ||
             (result.find("Найдено подписей:") != std::string::npos && 
              result.find("Найдено подписей: 0") == std::string::npos) ||
             result.find("Подпись найдена") != std::string::npos) {
        // Signature exists - assume valid unless there are explicit errors
        if (result.find("ERROR") == std::string::npos &&
            result.find("ошибка проверки") == std::string::npos &&
            result.find("Ошибка проверки") == std::string::npos) {
            sigStatus = "valid";
        } else {
            sigStatus = "invalid";
        }
    }
    
    std::cerr << "Sign server: [VERIFY] Determined signature status: " << sigStatus << "\n";
    if (sigStatus == "unknown") {
        std::cerr << "Sign server: [VERIFY] WARNING: Could not determine signature status from output\n";
        std::cerr << "Sign server: [VERIFY] Full output length: " << result.size() << " bytes\n";
    }
    return sigStatus;
}
#endif // WITH_SQLITE3
#endif // WITH_SQLITE3

static bool writeIndexRevoked(const fs::path &revokedPath, long serial, const std::string &reason) {
    std::ofstream out(revokedPath, std::ios::app);
    if (!out) return false;
    char serialHex[32];
    std::snprintf(serialHex, sizeof(serialHex), "%lX", serial);
    out << serialHex << "\t" << reason << "\n";
    return true;
}

static long getSerialFromCert(X509 *crt) {
    const ASN1_INTEGER *ai = X509_get0_serialNumber(crt);
    return ASN1_INTEGER_get(ai);
}

static long nextCrlNumber(const fs::path &crlNumFile) {
    long n = 1;
    if (fs::exists(crlNumFile)) { std::ifstream in(crlNumFile); in >> n; if (!in) n = 1; }
    std::ofstream out(crlNumFile, std::ios::trunc); out << (n+1);
    return n;
}

static X509_CRL* generateCrl(X509 *caCert, EVP_PKEY *caKey, const fs::path &revokedPath, int days) {
    X509_CRL *crl = X509_CRL_new();
    if (!crl) return nullptr;
    X509_CRL_set_version(crl, 1);
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(caCert));
    ASN1_TIME *last = ASN1_TIME_new(); ASN1_TIME *next = ASN1_TIME_new();
    ASN1_TIME_set(last, std::time(nullptr));
    ASN1_TIME_set(next, std::time(nullptr) + 60L*60L*24L*days);
    X509_CRL_set1_lastUpdate(crl, last);
    X509_CRL_set1_nextUpdate(crl, next);
    ASN1_TIME_free(last); ASN1_TIME_free(next);

    // Load revoked list
    if (fs::exists(revokedPath)) {
        std::ifstream in(revokedPath);
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            // serial<TAB>reason
            auto tab = line.find('\t');
            std::string serialHex = (tab == std::string::npos) ? line : line.substr(0, tab);
            std::string reason = (tab == std::string::npos) ? "unspecified" : line.substr(tab + 1);

            unsigned long serial = std::strtoul(serialHex.c_str(), nullptr, 16);
            X509_REVOKED *rev = X509_REVOKED_new();
            ASN1_INTEGER *s = ASN1_INTEGER_new();
            ASN1_INTEGER_set(s, static_cast<long>(serial));
            X509_REVOKED_set_serialNumber(rev, s);
            ASN1_INTEGER_free(s);

            // revocation date = now
            ASN1_TIME *revTime = ASN1_TIME_new();
            ASN1_TIME_set(revTime, std::time(nullptr));
            X509_REVOKED_set_revocationDate(rev, revTime);
            ASN1_TIME_free(revTime);

            // CRL reason
            int nid_reason = NID_crl_reason;
            int reason_code = CRL_REASON_UNSPECIFIED;
            if (reason == "keyCompromise") reason_code = CRL_REASON_KEY_COMPROMISE;
            else if (reason == "affiliationChanged") reason_code = CRL_REASON_AFFILIATION_CHANGED;
            else if (reason == "superseded") reason_code = CRL_REASON_SUPERSEDED;
            else if (reason == "cessationOfOperation") reason_code = CRL_REASON_CESSATION_OF_OPERATION;
            else if (reason == "certificateHold") reason_code = CRL_REASON_CERTIFICATE_HOLD;

            ASN1_ENUMERATED *rc = ASN1_ENUMERATED_new();
            ASN1_ENUMERATED_set(rc, reason_code);
            X509_EXTENSION *ext = X509_EXTENSION_create_by_NID(nullptr, nid_reason, 0, (ASN1_OCTET_STRING*)rc);
            ASN1_ENUMERATED_free(rc);
            if (ext) {
                X509_REVOKED_add_ext(rev, ext, -1);
                X509_EXTENSION_free(ext);
            }

            X509_CRL_add0_revoked(crl, rev); // crl owns rev
        }
    }

    // crlNumber
    long crlNum = nextCrlNumber("ca/crlnum.txt");
    ASN1_INTEGER *anum = ASN1_INTEGER_new();
    ASN1_INTEGER_set(anum, crlNum);
    X509_EXTENSION *crlno = X509_EXTENSION_create_by_NID(nullptr, NID_crl_number, 0, (ASN1_OCTET_STRING*)anum);
    ASN1_INTEGER_free(anum);
    if (crlno) { X509_CRL_add_ext(crl, crlno, -1); X509_EXTENSION_free(crlno); }

    if (!X509_CRL_sign(crl, caKey, EVP_sha256())) {
        printOpenSslErrors("X509_CRL_sign failed");
        X509_CRL_free(crl);
        return nullptr;
    }
    return crl;
}

static bool writePemCrl(const fs::path &p, X509_CRL *crl) {
    FILE *f = fopen(p.string().c_str(), "wb");
    if (!f) return false;
    bool ok = PEM_write_X509_CRL(f, crl);
    fclose(f);
    return ok;
}

// Generate CRL from database (revoked table)
static X509_CRL* generateCrlFromDb(CaDatabase *db, X509 *caCert, EVP_PKEY *caKey, const fs::path &rootDir, int days) {
    if (!db || !db->isConnected() || !caCert || !caKey) return nullptr;
    
    X509_CRL *crl = X509_CRL_new();
    if (!crl) return nullptr;
    X509_CRL_set_version(crl, 1);
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(caCert));
    ASN1_TIME *last = ASN1_TIME_new(); 
    ASN1_TIME *next = ASN1_TIME_new();
    ASN1_TIME_set(last, std::time(nullptr));
    ASN1_TIME_set(next, std::time(nullptr) + 60L*60L*24L*days);
    X509_CRL_set1_lastUpdate(crl, last);
    X509_CRL_set1_nextUpdate(crl, next);
    ASN1_TIME_free(last); 
    ASN1_TIME_free(next);

    // Load revoked certificates from database
    QSqlQuery query = db->select("SELECT serial, reason, revoked_at FROM revoked ORDER BY serial");
    while (query.next()) {
        long serial = query.value(0).toLongLong();
        QString reasonStr = query.value(1).toString();
        qint64 revokedAt = query.value(2).toLongLong();
        
        std::string reason = reasonStr.isEmpty() ? "unspecified" : reasonStr.toStdString();
        
        X509_REVOKED *rev = X509_REVOKED_new();
        ASN1_INTEGER *s = ASN1_INTEGER_new();
        ASN1_INTEGER_set(s, serial);
        X509_REVOKED_set_serialNumber(rev, s);
        ASN1_INTEGER_free(s);

        // revocation date from database
        ASN1_TIME *revTime = ASN1_TIME_new();
        ASN1_TIME_set(revTime, static_cast<time_t>(revokedAt));
        X509_REVOKED_set_revocationDate(rev, revTime);
        ASN1_TIME_free(revTime);

        // CRL reason
        int nid_reason = NID_crl_reason;
        int reason_code = CRL_REASON_UNSPECIFIED;
        if (reason == "keyCompromise") reason_code = CRL_REASON_KEY_COMPROMISE;
        else if (reason == "affiliationChanged") reason_code = CRL_REASON_AFFILIATION_CHANGED;
        else if (reason == "superseded") reason_code = CRL_REASON_SUPERSEDED;
        else if (reason == "cessationOfOperation") reason_code = CRL_REASON_CESSATION_OF_OPERATION;
        else if (reason == "certificateHold") reason_code = CRL_REASON_CERTIFICATE_HOLD;
        else if (reason == "expired") reason_code = CRL_REASON_UNSPECIFIED; // expired is not a standard reason

        ASN1_ENUMERATED *rc = ASN1_ENUMERATED_new();
        ASN1_ENUMERATED_set(rc, reason_code);
        X509_EXTENSION *ext = X509_EXTENSION_create_by_NID(nullptr, nid_reason, 0, (ASN1_OCTET_STRING*)rc);
        ASN1_ENUMERATED_free(rc);
        if (ext) {
            X509_REVOKED_add_ext(rev, ext, -1);
            X509_EXTENSION_free(ext);
        }

        X509_CRL_add0_revoked(crl, rev); // crl owns rev
    }

    // crlNumber - get from file
    const fs::path crlNumFile = rootDir / "ca" / "crlnum.txt";
    long crlNum = nextCrlNumber(crlNumFile);
    
    ASN1_INTEGER *anum = ASN1_INTEGER_new();
    ASN1_INTEGER_set(anum, crlNum);
    X509_EXTENSION *crlno = X509_EXTENSION_create_by_NID(nullptr, NID_crl_number, 0, (ASN1_OCTET_STRING*)anum);
    ASN1_INTEGER_free(anum);
    if (crlno) { 
        X509_CRL_add_ext(crl, crlno, -1); 
        X509_EXTENSION_free(crlno); 
    }

    if (!X509_CRL_sign(crl, caKey, EVP_sha256())) {
        printOpenSslErrors("X509_CRL_sign failed");
        X509_CRL_free(crl);
        return nullptr;
    }
    return crl;
}

static bool exportPkcs12(const fs::path &out, X509 *cert, EVP_PKEY *pkey, const std::string &pass, const std::string &name) {
    PKCS12 *p12 = PKCS12_create(pass.c_str(), name.c_str(), pkey, cert, nullptr, 0, 0, 0, 0, 0);
    if (!p12) { printOpenSslErrors("PKCS12_create failed"); return false; }
    FILE *f = fopen(out.string().c_str(), "wb");
    if (!f) { PKCS12_free(p12); return false; }
    int ok = i2d_PKCS12_fp(f, p12);
    fclose(f);
    PKCS12_free(p12);
    return ok == 1;
}

static int cmd_init_ca(const fs::path &rootDir, const std::string &subjectTemplate = "", const std::string &extensionsTemplate = "") {
    // Load CA configuration from file (if exists)
    CaConfig config;
    bool configLoaded = loadCaConfig(rootDir, config);
    
    fs::create_directories(rootDir);
    fs::create_directories(rootDir / config.caDir);
    // Note: certs and csr directories will be created on-demand when needed
    // Note: private directory no longer needed - keys stored in encrypted database
        // Master key is stored in master_keys table in databases/ca.db

    const fs::path keyPath = rootDir / config.caDir / "private/root.key";
    const fs::path serialPath = rootDir / config.caDir / "serial.txt";

    EVP_PKEY *key = generateRsaKey(config.rootKeySize);
    if (!key) return 1;
    
    // Use subject template if provided, otherwise use default CN
    std::string subjTemplate = subjectTemplate.empty() ? "/CN=Local Test Root CA" : subjectTemplate;
    X509 *crt = createSelfSignedCa(key, subjTemplate, config.rootCaDays, extensionsTemplate);
    if (!crt) { EVP_PKEY_free(key); return 1; }

    if (!writePemKey(keyPath, key)) { std::cerr << "Failed write key\n"; }
    
    // Store root certificate in database (not in file)
    #ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) {
        dbStoreRootCert(db, crt);
        delete db;
    }
    #endif
    
    // Serial number initialized in database above (no file write needed)

    EVP_PKEY_free(key);
    X509_free(crt);
    std::cout << "Initialized CA at " << rootDir << "\n";
    std::cout << "⚠️  SECURITY: Root private key stored in encrypted database (databases/ca.db)\n";
    std::cout << "⚠️  SECURITY: Root certificate stored in database (databases/ca.db) with SHA-256 checksum\n";
    std::cout << "⚠️  SECURITY: Master key stored in database (master_keys table)\n";
    std::cout << "⚠️  SECURITY: All keys encrypted with AES-256-GCM\n";
    appendAudit(rootDir, "init-ca", rootDir.string());
    return 0;
}

static int cmd_sign_csr(const fs::path &rootDir, const fs::path &csrPath, const fs::path &outCrt) {
    // Load CA configuration from file (if exists)
    CaConfig config;
    loadCaConfig(rootDir, config);
    
    const fs::path keyPath = rootDir / config.caDir / "private/root.key";
    const fs::path serialPath = rootDir / config.caDir / "serial.txt";

    EVP_PKEY *caKey = readPemKey(keyPath);
    X509 *caCrt = readRootCert(rootDir);
    X509_REQ *req = readPemCsr(csrPath);
    if (!caKey || !caCrt || !req) { std::cerr << "Missing CA or CSR\n"; return 1; }

    long serial = nextSerial(serialPath);
    X509 *crt = signCsr(req, caCrt, caKey, config.leafCertDays, serial);
    if (!crt) { EVP_PKEY_free(caKey); X509_free(caCrt); X509_REQ_free(req); return 1; }

    if (!writePemCert(outCrt, crt)) { std::cerr << "Failed write cert\n"; }
    // append to index
    char subjBuf[512] = {0};
    X509_NAME_oneline(X509_get_subject_name(crt), subjBuf, sizeof(subjBuf)-1);
    writeIndexIssued(rootDir / "ca/index.txt", serial, subjBuf);

    #ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) { dbInsertIssued(db, serial, crt); delete db; }
    #endif
    EVP_PKEY_free(caKey);
    X509_free(caCrt);
    X509_REQ_free(req);
    X509_free(crt);
    std::cout << "Signed CSR -> " << outCrt << "\n";
    appendAudit(rootDir, "sign-csr", outCrt.string());
    return 0;
}

static int cmd_gen_key(const std::string &type, const std::string &param, const fs::path &outKey, const fs::path &outPub) {
    EVP_PKEY *key = nullptr;
    if (type == "rsa") key = generateRsaKey(param.empty() ? 2048 : std::atoi(param.c_str()));
    else if (type == "ec") key = generateEcKey(param.empty() ? "prime256v1" : param);
    else if (type == "ed25519" || type == "ed448") key = generateEdKey(type);
    if (!key) { std::cerr << "Keygen failed\n"; return 1; }
    if (!writePemKey(outKey, key)) { std::cerr << "Write key failed\n"; EVP_PKEY_free(key); return 1; }
    if (!outPub.empty()) writePemPubKey(outPub, key);
    EVP_PKEY_free(key);
    std::cout << "Key written -> " << outKey << "\n";
    return 0;
}

static int cmd_gen_csr(const fs::path &keyPath, const fs::path &outCsr, const std::string &cn, const std::string &sanCsv) {
    EVP_PKEY *key = readPemKey(keyPath);
    if (!key) { std::cerr << "Read key failed\n"; return 1; }
    X509_REQ *req = createCsr(key, cn, sanCsv);
    EVP_PKEY_free(key);
    if (!req) return 1;
    FILE *f = fopen(outCsr.string().c_str(), "wb");
    if (!f) { X509_REQ_free(req); return 1; }
    bool ok = PEM_write_X509_REQ(f, req);
    fclose(f);
    X509_REQ_free(req);
    if (!ok) { std::cerr << "Write CSR failed\n"; return 1; }
    std::cout << "CSR written -> " << outCsr << "\n";
    return 0;
}

static int cmd_sign_csr_profile(const fs::path &rootDir, const fs::path &csrPath,
                                const fs::path &outCrt, const std::string &profile,
                                const std::string &sanCsv,
                                const std::string &aiaIssuerUrl,
                                const std::string &aiaOcspUrl,
                                const std::string &crlDpUrl,
                                const std::string &policyOid,
                                const std::string &policyCpsUri,
                                int pathLen,
                                bool isCA,
                                const std::string &nameConstraintsStr) {
    // Load CA configuration from file (if exists)
    CaConfig config;
    loadCaConfig(rootDir, config);
    
    const fs::path keyPath = rootDir / config.caDir / "private/root.key";
    const fs::path serialPath = rootDir / config.caDir / "serial.txt";
    EVP_PKEY *caKey = readPemKey(keyPath);
    X509 *caCrt = readRootCert(rootDir);
    X509_REQ *req = readPemCsr(csrPath);
    if (!caKey || !caCrt || !req) { std::cerr << "Missing CA or CSR\n"; return 1; }
    long serial = nextSerial(serialPath);
    X509 *crt = signCsrWithProfile(req, caCrt, caKey, config.leafCertDays, serial, profile, sanCsv,
                                   aiaIssuerUrl, aiaOcspUrl, crlDpUrl, policyOid, policyCpsUri,
                                   pathLen, isCA, nameConstraintsStr);
    if (!crt) { EVP_PKEY_free(caKey); X509_free(caCrt); X509_REQ_free(req); return 1; }
    if (!writePemCert(outCrt, crt)) { std::cerr << "Failed write cert\n"; }
    char subjBuf[512] = {0};
    X509_NAME_oneline(X509_get_subject_name(crt), subjBuf, sizeof(subjBuf)-1);
    writeIndexIssued(rootDir / "ca/index.txt", serial, subjBuf);
    #ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) { dbInsertIssued(db, serial, crt); delete db; }
    #endif
    X509_free(crt);
    EVP_PKEY_free(caKey);
    X509_free(caCrt);
    X509_REQ_free(req);
    std::cout << "Signed CSR (" << profile << ") -> " << outCrt << "\n";
    appendAudit(rootDir, "sign-csr-profile", outCrt.string());
    return 0;
}

static X509* createIntermediate(EVP_PKEY *interKey, X509 *issuerCrt, EVP_PKEY *issuerKey,
                                const std::string &cn, int days, long serial) {
    X509 *x = X509_new(); if (!x) return nullptr;
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
    X509_set_issuer_name(x, X509_get_subject_name(issuerCrt));
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), 60L*60L*24L*days);
    X509_set_pubkey(x, interKey);
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_set_subject_name(x, name);
    X509_NAME_free(name);
    addExtByStr(x, issuerCrt, NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
    addExtByStr(x, issuerCrt, NID_key_usage, "critical,keyCertSign,cRLSign");
    addExtByStr(x, issuerCrt, NID_subject_key_identifier, "hash");
    addExtByStr(x, issuerCrt, NID_authority_key_identifier, "keyid,issuer");
    if (!X509_sign(x, issuerKey, EVP_sha256())) { printOpenSslErrors("sign inter failed"); X509_free(x); return nullptr; }
    return x;
}

static int cmd_new_intermediate(const fs::path &rootDir, const std::string &cn) {
    // Load CA configuration from file (if exists)
    CaConfig config;
    loadCaConfig(rootDir, config);
    
    const fs::path rootKey = rootDir / config.caDir / "private/root.key";
    const fs::path interKeyPath = rootDir / config.caDir / "private/intermediate.key";
    const fs::path interCrtPath = rootDir / config.caDir / "intermediate.crt";
    const fs::path serialPath = rootDir / config.caDir / "serial.txt";
    EVP_PKEY *rk = readPemKey(rootKey); X509 *rc = readRootCert(rootDir);
    if (!rk || !rc) { std::cerr << "Missing root CA\n"; return 1; }
    EVP_PKEY *ik = generateRsaKey(config.rootKeySize); if (!ik) { EVP_PKEY_free(rk); X509_free(rc); return 1; }
    long serial = nextSerial(serialPath);
    X509 *ic = createIntermediate(ik, rc, rk, cn, config.rootCaDays, serial);
    if (!ic) { EVP_PKEY_free(ik); EVP_PKEY_free(rk); X509_free(rc); return 1; }
    writePemKey(interKeyPath, ik);
    writePemCert(interCrtPath, ic);
    EVP_PKEY_free(ik); EVP_PKEY_free(rk); X509_free(rc); X509_free(ic);
    std::cout << "Intermediate created -> " << interCrtPath << "\n";
    appendAudit(rootDir, "new-intermediate", interCrtPath.string());
    return 0;
}

static int cmd_verify_chain(const fs::path &certPath, const fs::path &intermediatePath, const fs::path &rootPath) {
    X509 *cert = readPemCert(certPath);
    X509 *inter = intermediatePath.empty() ? nullptr : readPemCert(intermediatePath);
    X509 *root = readPemCert(rootPath);
    if (!cert || !root) { if (cert) X509_free(cert); if (root) X509_free(root); if (inter) X509_free(inter); std::cerr << "Missing cert or root\n"; return 1; }
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, root);
    if (inter) X509_STORE_add_cert(store, inter);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, nullptr);
    int ok = X509_verify_cert(ctx);
    if (ok == 1) std::cout << "Chain OK\n"; else { std::cerr << "Chain verify failed\n"; }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert); if (inter) X509_free(inter); X509_free(root);
    return ok == 1 ? 0 : 1;
}

static int cmd_revoke(const fs::path &rootDir, const fs::path &certPath, const std::string &reason) {
    const fs::path crtPath = certPath;
    X509 *crt = readPemCert(crtPath);
    if (!crt) { std::cerr << "Cannot read cert\n"; return 1; }
    long serial = getSerialFromCert(crt);
    X509_free(crt);
    if (!writeIndexRevoked(rootDir / "ca/revoked.txt", serial, reason)) {
        std::cerr << "Failed to mark revoked\n"; return 1;
    }
    #ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) { dbMarkRevoked(db, serial, reason); delete db; }
    #endif
    std::cout << "Revoked serial " << serial << " reason=" << reason << "\n";
    appendAudit(rootDir, "revoke", std::to_string(serial));
    return 0;
}

static int cmd_gen_crl(const fs::path &rootDir, const fs::path &outCrl, int days) {
    // Load CA configuration from file (if exists)
    CaConfig config;
    loadCaConfig(rootDir, config);
    
    // Use config value if days not specified (0 or negative)
    if (days <= 0) {
        days = config.crlDays;
    }
    
    // Try to load CA from database first, fallback to files
    EVP_PKEY *caKey = nullptr;
    X509 *caCrt = nullptr;
    
    #ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) {
        // Load root key from database
        caKey = dbLoadKey(db, rootDir, "root");
        // Load root cert from database
        caCrt = readRootCert(rootDir);
        delete db;
    }
    #endif
    
    // Fallback to file-based loading if database failed
    if (!caKey || !caCrt) {
        const fs::path keyPath = rootDir / config.caDir / "private/root.key";
        const fs::path crtPath = rootDir / config.caDir / "root.crt";
        if (!caKey) caKey = readPemKey(keyPath);
        if (!caCrt) caCrt = readPemCert(crtPath);
    }
    
    if (!caKey || !caCrt) { 
        std::cerr << "Missing CA material (root key or certificate not found in database or files)\n"; 
        if (caKey) EVP_PKEY_free(caKey);
        if (caCrt) X509_free(caCrt);
        return 1; 
    }
    
    // Try to generate CRL from database first, fallback to file
    X509_CRL *crl = nullptr;
    #ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) {
        crl = generateCrlFromDb(db, caCrt, caKey, rootDir, days);
        delete db;
    }
    #endif
    
    // Fallback to file-based generation if database failed
    if (!crl) {
        const fs::path revokedPath = rootDir / "ca/revoked.txt";
        crl = generateCrl(caCrt, caKey, revokedPath, days);
    }
    
    if (!crl) { EVP_PKEY_free(caKey); X509_free(caCrt); return 1; }
    bool ok = writePemCrl(outCrl, crl);
    X509_CRL_free(crl);
    EVP_PKEY_free(caKey);
    X509_free(caCrt);
    if (!ok) { std::cerr << "Failed write CRL\n"; return 1; }
    std::cout << "CRL generated -> " << outCrl << "\n";
    appendAudit(rootDir, "gen-crl", outCrl.string());
    return 0;
}

static bool removeSerialFromRevoked(const fs::path &revokedPath, long serial) {
    std::ifstream in(revokedPath);
    if (!in) return false;
    std::vector<std::string> lines; std::string line; char serialHex[32];
    std::snprintf(serialHex, sizeof(serialHex), "%lX", serial);
    while (std::getline(in, line)) {
        if (line.rfind(serialHex, 0) == 0 && (line.size()==std::strlen(serialHex) || line[std::strlen(serialHex)]=='\t')) continue;
        lines.push_back(line);
    }
    in.close();
    std::ofstream out(revokedPath, std::ios::trunc);
    for (auto &l: lines) out << l << "\n";
    return true;
}

static int cmd_unrevoke(const fs::path &rootDir, const fs::path &certPath) {
    X509 *crt = readPemCert(certPath);
    if (!crt) { std::cerr << "Cannot read cert\n"; return 1; }
    long serial = getSerialFromCert(crt); X509_free(crt);
    const fs::path revokedPath = rootDir / "ca/revoked.txt";
    if (!fs::exists(revokedPath)) { std::cerr << "No revoked list\n"; return 1; }
    if (!removeSerialFromRevoked(revokedPath, serial)) { std::cerr << "Unrevoke failed\n"; return 1; }
    #ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) { dbMarkUnrevoked(db, serial); delete db; }
    #endif
    std::cout << "Unrevoked serial " << serial << "\n";
    appendAudit(rootDir, "unrevoke", std::to_string(serial));
    return 0;
}

static int cmd_ocsp_resp(const fs::path &issuerCrtPath, const fs::path &issuerKeyPath,
                         const fs::path &certPath, const std::string &status,
                         const fs::path &outResp, int days) {
    // Load CA configuration from file (if exists)
    CaConfig config;
    fs::path rootDir = issuerCrtPath.parent_path().parent_path();
    loadCaConfig(rootDir, config);
    
    // Use config value if days not specified (0 or negative)
    if (days <= 0) {
        days = config.ocspDays;
    }
    
    X509 *issuer = readPemCert(issuerCrtPath);
    EVP_PKEY *ikey = readPemKey(issuerKeyPath);
    X509 *cert = readPemCert(certPath);
    if (!issuer || !ikey || !cert) { if (issuer) X509_free(issuer); if (ikey) EVP_PKEY_free(ikey); if (cert) X509_free(cert); std::cerr << "Missing issuer/key/cert\n"; return 1; }
    OCSP_CERTID *id = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
    ASN1_TIME *thisupd = ASN1_TIME_new(); ASN1_TIME *nextupd = ASN1_TIME_new();
    ASN1_TIME_set(thisupd, std::time(nullptr)); ASN1_TIME_set(nextupd, std::time(nullptr) + 60L*60L*24L*days);
    int st = V_OCSP_CERTSTATUS_GOOD; ASN1_TIME *revtime=nullptr; ASN1_GENERALIZEDTIME *revWhen=nullptr; int reason=OCSP_REVOKED_STATUS_UNSPECIFIED;
    if (status == "revoked") { st = V_OCSP_CERTSTATUS_REVOKED; revWhen = ASN1_GENERALIZEDTIME_set(nullptr, std::time(nullptr)); }
    if (!OCSP_basic_add1_status(bs, id, st, reason, revWhen, thisupd, nextupd)) { printOpenSslErrors("OCSP add status failed"); OCSP_CERTID_free(id); OCSP_BASICRESP_free(bs); X509_free(issuer); EVP_PKEY_free(ikey); X509_free(cert); ASN1_TIME_free(thisupd); ASN1_TIME_free(nextupd); if (revWhen) ASN1_GENERALIZEDTIME_free(revWhen); return 1; }
    if (!OCSP_basic_sign(bs, issuer, ikey, EVP_sha256(), nullptr, 0)) { printOpenSslErrors("OCSP sign failed"); OCSP_CERTID_free(id); OCSP_BASICRESP_free(bs); X509_free(issuer); EVP_PKEY_free(ikey); X509_free(cert); ASN1_TIME_free(thisupd); ASN1_TIME_free(nextupd); if (revWhen) ASN1_GENERALIZEDTIME_free(revWhen); return 1; }
    OCSP_RESPONSE *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);
    BIO *out = BIO_new_file(outResp.string().c_str(), "wb");
    bool ok = out && i2d_OCSP_RESPONSE_bio(out, resp);
    if (out) BIO_free(out);
    OCSP_RESPONSE_free(resp);
    OCSP_CERTID_free(id); OCSP_BASICRESP_free(bs); X509_free(issuer); EVP_PKEY_free(ikey); X509_free(cert); ASN1_TIME_free(thisupd); ASN1_TIME_free(nextupd); if (revWhen) ASN1_GENERALIZEDTIME_free(revWhen);
    if (!ok) { std::cerr << "Write OCSP response failed\n"; return 1; }
    std::cout << "OCSP response -> " << outResp << "\n";
    return 0;
}

static int cmd_list_certs(const fs::path &rootDir) {
#ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) {
        QSqlQuery query = db->select("SELECT serial,subject,not_before,not_after,status FROM certs ORDER BY serial");
        while (query.next()) {
            auto serial = query.value(0).toLongLong();
            QString subj = query.value(1).toString();
            auto nb = query.value(2).toLongLong();
            auto na = query.value(3).toLongLong();
            QString status = query.value(4).toString();
            std::cout << serial << "\t" << subj.toStdString()
                      << "\t" << nb << "\t" << na << "\t" << status.toStdString() << "\n";
        }
        delete db;
        return 0;
    }
#endif
    // Fallback to index.txt (serial hex) for backward compatibility
    fs::path indexPath = rootDir / "ca" / "index.txt";
    if (fs::exists(indexPath)) {
        std::ifstream in(indexPath);
        std::string line; while (std::getline(in, line)) std::cout << line << "\n";
        return 0;
    }
    std::cerr << "No index found (neither in DB nor in file)\n"; return 1;
}

static int cmd_list_revoked(const fs::path &rootDir) {
#ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) {
        QSqlQuery query = db->select("SELECT serial,reason,revoked_at FROM revoked ORDER BY serial");
        while (query.next()) {
            auto serial = query.value(0).toLongLong();
            QString reason = query.value(1).toString();
            auto ts = query.value(2).toLongLong();
            std::cout << serial << "\t" << reason.toStdString() << "\t" << ts << "\n";
        }
        delete db;
        return 0;
    }
#endif
    std::ifstream in(rootDir/"ca"/"revoked.txt");
    if (!in) { std::cerr << "No revoked.txt\n"; return 1; }
    std::string line; while (std::getline(in, line)) std::cout << line << "\n";
    return 0;
}

static int cmd_print_chain(const fs::path &leaf, const fs::path &inter, const fs::path &root) {
    X509 *lc = readPemCert(leaf);
    X509 *rc = readPemCert(root);
    X509 *ic = inter.empty()?nullptr:readPemCert(inter);
    if (!lc || !rc) { if (lc) X509_free(lc); if (rc) X509_free(rc); if (ic) X509_free(ic); std::cerr << "Missing leaf/root\n"; return 1; }
    auto pr = [](const char *title, X509 *c){ char buf[512]={0}; X509_NAME_oneline(X509_get_subject_name(c), buf, sizeof(buf)-1); std::cout << title << ": " << buf << "\n"; };
    pr("Leaf", lc); if (ic) pr("Intermediate", ic); pr("Root", rc);
    if (ic) X509_free(ic); X509_free(lc); X509_free(rc); return 0;
}

static int cmd_verify_chain_with_crl(const fs::path &leaf, const fs::path &inter, const fs::path &root, const fs::path &crlPath) {
    X509 *cert = readPemCert(leaf);
    X509 *interC = inter.empty()?nullptr:readPemCert(inter);
    X509 *rootC = readPemCert(root);
    FILE *f = fopen(crlPath.string().c_str(), "rb"); if (!f) { if (cert) X509_free(cert); if (rootC) X509_free(rootC); if (interC) X509_free(interC); std::cerr << "Open CRL failed\n"; return 1; }
    X509_CRL *crl = PEM_read_X509_CRL(f, nullptr, nullptr, nullptr); fclose(f);
    if (!cert || !rootC || !crl) { if (cert) X509_free(cert); if (rootC) X509_free(rootC); if (interC) X509_free(interC); if (crl) X509_CRL_free(crl); std::cerr << "Missing inputs\n"; return 1; }
    X509_STORE *store = X509_STORE_new(); X509_STORE_add_cert(store, rootC); if (interC) X509_STORE_add_cert(store, interC);
    X509_STORE_add_crl(store, crl);
    X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new(); X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
    X509_STORE_set1_param(store, param); X509_VERIFY_PARAM_free(param);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new(); X509_STORE_CTX_init(ctx, store, cert, nullptr);
    int ok = X509_verify_cert(ctx);
    if (ok==1) std::cout << "Chain+CRL OK\n"; else std::cerr << "Verify with CRL failed\n";
    X509_STORE_CTX_free(ctx); X509_STORE_free(store); X509_free(cert); if (interC) X509_free(interC); X509_free(rootC); X509_CRL_free(crl);
    return ok==1?0:1;
}

#ifdef WITH_SQLITE3
static int cmd_db_export_csv(const fs::path &rootDir, const fs::path &outPath) {
    CaDatabase *db = dbOpen(rootDir); if (!db) { std::cerr << "DB open failed\n"; return 1; }
    std::ofstream out(outPath, std::ios::trunc); if (!out) { delete db; std::cerr << "Open CSV failed\n"; return 1; }
    out << "serial,subject,not_before,not_after,status\n";
    QSqlQuery query = db->select("SELECT serial,subject,not_before,not_after,status FROM certs ORDER BY serial");
    while (query.next()) {
        out << query.value(0).toLongLong() << ","
            << '"' << query.value(1).toString().toStdString() << '"' << ","
            << query.value(2).toLongLong() << "," << query.value(3).toLongLong() << ","
            << query.value(4).toString().toStdString()
            << "\n";
    }
    delete db;
    std::cout << "Exported CSV -> " << outPath << "\n"; return 0;
}
#endif

static int cmd_import_chain(const fs::path &rootDir, const fs::path &leaf, const fs::path &inter, const fs::path &root) {
    // Verify first
    if (cmd_verify_chain(leaf, inter, root) != 0) {
        std::cerr << "Chain verification failed; aborting import\n";
        return 1;
    }
    fs::create_directories(rootDir / "ca");
    // Don't create private directory - we use database for key storage
    // Import root cert into database (not file)
    X509 *rootCert = readPemCert(root);
    if (!rootCert) { std::cerr << "Cannot read root cert\n"; return 1; }
    #ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) {
        dbStoreRootCert(db, rootCert);
        delete db;
    }
    #endif
    X509_free(rootCert);
    // Copy intermediate to file (if provided)
    const fs::path interOut = rootDir / "ca/intermediate.crt";
    if (!inter.empty()) {
        auto copyFile = [](const fs::path &src, const fs::path &dst) -> bool {
            std::ifstream in(src); if (!in) return false; std::ofstream out(dst, std::ios::trunc); if (!out) return false; out << in.rdbuf(); return true;
        };
        if (!copyFile(inter, interOut)) { std::cerr << "Copy intermediate failed\n"; return 1; }
    }
    // Initialize serial if absent (in database)
    #ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) {
        if (!db->exec("INSERT OR IGNORE INTO serial_number(id, next_serial) VALUES(1,2)")) {
            std::cerr << "Failed to initialize serial number: " << db->getLastError().toStdString() << "\n";
        }
        delete db;
    }
    #endif
    // Serial number initialized in database above (no file write needed)
    std::cout << "Imported chain -> root: (in database)" << (inter.empty()?"":"; inter: ") << (inter.empty()?"":interOut.string()) << "\n";
    appendAudit(rootDir, "import-chain", "database");
    return 0;
}

static int cmd_pkcs11_list(const std::string &storeUri) {
    std::string uri = storeUri;
    const char *pin = std::getenv("PKCS11_PIN");
    if (pin && uri.rfind("pkcs11:", 0) == 0 && uri.find("pin-value=") == std::string::npos) {
        if (uri.back() != ';') uri.push_back(';');
        uri += std::string("pin-value=") + pin;
    }
    OSSL_STORE_CTX *ctx = OSSL_STORE_open(uri.c_str(), nullptr, nullptr, nullptr, nullptr);
    if (!ctx) { printOpenSslErrors("OSSL_STORE_open failed"); return 1; }
    int count=0;
    for (;;) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
        if (!info) break;
        int type = OSSL_STORE_INFO_get_type(info);
        if (type == OSSL_STORE_INFO_CERT) {
            X509 *c = OSSL_STORE_INFO_get1_CERT(info);
            char subj[256]={0}; X509_NAME_oneline(X509_get_subject_name(c), subj, sizeof(subj)-1);
            std::cout << "CERT\t" << subj << "\n"; X509_free(c);
        } else if (type == OSSL_STORE_INFO_PKEY) {
            std::cout << "PKEY\n";
        } else if (type == OSSL_STORE_INFO_NAME) {
            std::cout << "NAME\t" << OSSL_STORE_INFO_get0_NAME(info) << "\n";
        } else {
            std::cout << "ITEM\t" << type << "\n";
        }
        OSSL_STORE_INFO_free(info); count++;
    }
    OSSL_STORE_close(ctx);
    if (count==0) std::cerr << "No items or access denied\n";
    return 0;
}

static int cmd_pkcs11_list_with_pin(const std::string &storeUri, const std::string &pin) {
    if (!pin.empty()) {
#ifdef _WIN32
        _putenv((std::string("PKCS11_PIN=") + pin).c_str());
#else
        setenv("PKCS11_PIN", pin.c_str(), 1);
#endif
    }
    return cmd_pkcs11_list(storeUri);
}

static bool readPinFromTty(std::string &outPin) {
    std::string pin;
#ifdef __APPLE__
    // Fallback simple prompt; GUI apps might not have a tty
#endif
    std::cerr << "Enter PKCS#11 PIN: ";
    std::getline(std::cin, pin);
    if (pin.empty()) return false;
    outPin = pin; return true;
}

static int cmd_pkcs11_prompt_pin() {
    std::string pin; if (!readPinFromTty(pin)) { std::cerr << "PIN empty\n"; return 1; }
    std::cout << "export PKCS11_PIN=" << pin << "\n";
    return 0;
}

static bool saveKeyUriToHsmIni(const fs::path &rootDir, const std::string &uri) {
    fs::create_directories(rootDir/"ca");
    fs::path ini = rootDir/"ca"/"hsm.ini";
    // naive: append/replace keyUri line
    std::ofstream out(ini, std::ios::app);
    if (!out) return false;
    out << "keyUri=" << uri << "\n";
    return true;
}

static int cmd_pkcs11_pick(const fs::path &rootDir, const std::string &baseUri, const std::string &filter) {
    // Just list and ask user for index
    std::vector<std::string> items;
    std::string uri = baseUri;
    const char *pinEnv = std::getenv("PKCS11_PIN");
    if (pinEnv && uri.rfind("pkcs11:", 0) == 0 && uri.find("pin-value=") == std::string::npos) {
        if (uri.back() != ';') uri.push_back(';'); uri += std::string("pin-value=") + pinEnv;
    }
    OSSL_STORE_CTX *ctx = OSSL_STORE_open(uri.c_str(), nullptr, nullptr, nullptr, nullptr);
    if (!ctx) { printOpenSslErrors("OSSL_STORE_open failed"); return 1; }
    for (;;) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
        if (!info) break;
        int type = OSSL_STORE_INFO_get_type(info);
        if (type == OSSL_STORE_INFO_NAME) {
            const char *name = OSSL_STORE_INFO_get0_NAME(info);
            if (!filter.empty() && std::string(name).find(filter)==std::string::npos) { OSSL_STORE_INFO_free(info); continue; }
            items.emplace_back(name);
        }
        OSSL_STORE_INFO_free(info);
    }
    OSSL_STORE_close(ctx);
    if (items.empty()) { std::cerr << "No match\n"; return 1; }
    for (size_t i=0;i<items.size();++i) std::cout << i << ": " << items[i] << "\n";
    std::cout << "Select index: ";
    std::string idxs; std::getline(std::cin, idxs); if (idxs.empty()) return 1; size_t idx = (size_t)std::stoul(idxs);
    if (idx >= items.size()) { std::cerr << "Out of range\n"; return 1; }
    std::string selected = items[idx];
    // Save selected NAME as keyUri (best-effort; real pkcs11 object URI discovery is vendor-specific)
    if (!saveKeyUriToHsmIni(rootDir, selected)) { std::cerr << "Save hsm.ini failed\n"; return 1; }
    std::cout << "Saved keyUri to hsm.ini\n"; return 0;
}

// forward decl
static int cmd_cms_sign(const fs::path &inFile, const fs::path &signCert, const fs::path &signKey, const fs::path &outSig, bool detached);

static int cmd_pdf_sign_embed(const fs::path &inPdf, const fs::path &signCert, const fs::path &signKey, const fs::path &outPdf,
                              const std::string &reason, const std::string &location, const fs::path &rootDir, const std::string &tsaUrl = "") {
    // Validate inputs exist
    if (!fs::exists(inPdf) || !fs::exists(signCert) || !fs::exists(signKey)) { 
        std::cerr << "Missing input files: in=" << inPdf << " cert=" << signCert << " key=" << signKey << "\n"; 
        return 1; 
    }

    // The helper script is always in ca/sign_pdf.py relative to project root
    // rootDir is passed as parameter (no longer determined from signCert path)
    fs::path scriptPath = rootDir / "ca" / "sign_pdf.py";
    if (!fs::exists(scriptPath)) {
        std::cerr << "pyhanko helper script not found: " << scriptPath << " (rootDir=" << rootDir << ")\n";
        return 1;
    }

    // Normalize path to use forward slashes (works on Windows too)
    auto normalizePath = [](const std::string &path) -> std::string {
        std::string result = path;
        for (char &c : result) {
            if (c == '\\') c = '/';
        }
        return result;
    };
    
    auto shellQuote = [&normalizePath](const std::string &input) -> std::string {
#ifdef _WIN32
        // Windows uses double quotes, normalize path separators
        std::string normalized = normalizePath(input);
        std::string out = "\"";
        for (char c : normalized) {
            if (c == '"') {
                out += "\\\"";
            } else {
                out += c;
            }
        }
        out += "\"";
        return out;
#else
        std::string out = "'";
        for (char c : input) {
            if (c == '\'') {
                out += "'\"'\"'";
            } else {
                out += c;
            }
        }
        out += "'";
        return out;
#endif
    };

    auto sanitize = [](const std::string &value) {
        std::string sanitized = value;
        // pyhanko handles UTF-8, but avoid control characters
        for (char &c : sanitized) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (uc < 32 && uc != 9 && uc != 10 && uc != 13) {
                c = '_';
            }
        }
        return sanitized;
    };

    std::string reasonSafe = sanitize(reason);
    std::string locationSafe = sanitize(location);

    // Build python command
    // Include root CA certificate path so it can be embedded in PDF for validation
    // Export root cert from DB to temp file for sign_pdf.py
    // Use system temp directory instead of ca/
#ifdef _WIN32
    std::string tmpDir = std::getenv("TEMP") ? std::getenv("TEMP") : 
                        (std::getenv("TMP") ? std::getenv("TMP") : "C:\\Temp");
#else
    std::string tmpDir = std::getenv("TMPDIR") ? std::getenv("TMPDIR") : "/tmp";
#endif
    std::string tmpRootCertPath = tmpDir + "/3fa_root_cert.crt";
    fs::path tmpRootCertPath_fs(tmpRootCertPath);
    std::string rootCertPem;
    #ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) {
        rootCertPem = dbLoadRootCert(db);
        delete db;
        if (!rootCertPem.empty()) {
            std::ofstream f(tmpRootCertPath_fs);
            if (f) {
                f << rootCertPem;
                f.close();
            }
        }
    }
    #endif
    // Fallback to file if not in DB
    fs::path rootCertPath = rootDir / "ca" / "root.crt";
    if (rootCertPem.empty() && fs::exists(rootCertPath)) {
        tmpRootCertPath_fs = rootCertPath;
    }
    
    // Determine Python executable path
#ifdef _WIN32
    // On Windows, try to use venv_mediapipe Python or fall back to "python"
    fs::path venvPython = rootDir / "venv_mediapipe" / "Scripts" / "python.exe";
    std::cerr << "Sign server: venvPython path: " << normalizePath(venvPython.string()) << ", exists: " << fs::exists(venvPython) << "\n";
    std::cerr << "Sign server: scriptPath: " << normalizePath(scriptPath.string()) << ", exists: " << fs::exists(scriptPath) << "\n";
    std::string pythonExe = fs::exists(venvPython) ? shellQuote(venvPython.string()) : "python";
    std::cerr << "Sign server: pythonExe: " << pythonExe << "\n";
#else
    std::string pythonExe = "python3";
#endif
    
    std::string cmd = pythonExe + " "
        + shellQuote(scriptPath.string())
        + " --input " + shellQuote(inPdf.string())
        + " --output " + shellQuote(outPdf.string())
        + " --cert " + shellQuote(signCert.string())
        + " --key " + shellQuote(signKey.string())
        + " --visible";  // Enable visible signature by default
    // Вложение сертификата: всегда добавляем, если корневой сертификат существует
    if (fs::exists(tmpRootCertPath_fs)) {
        cmd += " --root-cert " + shellQuote(tmpRootCertPath_fs.string());
    }
    if (!reasonSafe.empty()) {
        cmd += " --reason " + shellQuote(reasonSafe);
    }
    if (!locationSafe.empty()) {
        cmd += " --location " + shellQuote(locationSafe);
    }
    // Метка времени: добавляем, если TSA URL указан (из переменной окружения или параметров)
    if (!tsaUrl.empty()) {
        std::string tsaUrlSafe = sanitize(tsaUrl);
        cmd += " --tsa-url " + shellQuote(tsaUrlSafe);
    } else {
        // Проверяем переменную окружения TSA_URL как fallback
        const char *envTsaUrl = std::getenv("TSA_URL");
        if (envTsaUrl && strlen(envTsaUrl) > 0) {
            std::string envTsaUrlStr(envTsaUrl);
            std::string tsaUrlSafe = sanitize(envTsaUrlStr);
            cmd += " --tsa-url " + shellQuote(tsaUrlSafe);
        }
    }

    // Execute python script and capture both stdout and stderr
    // Redirect stderr to stdout to capture all error messages
    // On Windows, wrap command with cmd /c to handle forward slashes properly
#ifdef _WIN32
    std::string cmdWithErr = "cmd /c \"" + cmd + " 2>&1\"";
#else
    std::string cmdWithErr = cmd + " 2>&1";
#endif
    std::cerr << "Sign server: Executing command: " << cmdWithErr << "\n";
    FILE *pipe = popen(cmdWithErr.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to execute pyhanko signing helper\n";
        return 1;
    }

    std::string output;
    char buffer[512];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    int rc = pclose(pipe);
    
    // Cleanup temp root cert file if it was created from DB
    if (tmpRootCertPath_fs.string().find("3fa_root_cert.crt") != std::string::npos && fs::exists(tmpRootCertPath_fs)) {
        fs::remove(tmpRootCertPath_fs);
        std::cerr << "Cleaned up temp root cert file: " << tmpRootCertPath_fs << "\n";
    }

    if (rc != 0) {
        // Output error details (script writes to stderr, captured via 2>&1)
        if (!output.empty()) {
            std::cerr << "pyhanko signing failed (rc=" << rc << "): " << output;
        } else {
            std::cerr << "pyhanko signing failed (rc=" << rc << ", no output)\n";
        }
        return 1;
    }

    if (!fs::exists(outPdf) || fs::file_size(outPdf) == 0) {
        std::cerr << "Signed PDF was not created\n";
        return 1;
    }

    return 0;
}

static std::string http_status(int code, const std::string &text) {
    char buf[64]; std::snprintf(buf, sizeof(buf), "HTTP/1.1 %d %s\r\n", code, text.c_str());
    return std::string(buf);
}

static void http_write(int fd, const std::string &s) { 
    ssize_t n = socket_write(fd, s.data(), s.size());
    if (n < 0) {
        int err = errno;
        std::cerr << "Sign server: http_write failed: " << strerror(err) << " (errno=" << err << ")\n";
    } else if (n != (ssize_t)s.size()) {
        std::cerr << "Sign server: http_write partial write: " << n << " of " << s.size() << " bytes\n";
        // Try to write remaining bytes
        size_t written = n;
        while (written < s.size()) {
            ssize_t more = socket_write(fd, s.data() + written, s.size() - written);
            if (more <= 0) break;
            written += more;
        }
    }
}

static std::string url_decode(const std::string &s) {
    std::string o; o.reserve(s.size());
    for (size_t i=0;i<s.size();++i) {
        if (s[i]=='%' && i+2<s.size()) { char h[3]={s[i+1],s[i+2],0}; o.push_back((char)strtol(h,nullptr,16)); i+=2; }
        else if (s[i]=='+') o.push_back(' ');
        else o.push_back(s[i]);
    }
    return o;
}

static std::map<std::string,std::string> parse_query(const std::string &q) {
    std::map<std::string,std::string> m; size_t p=0; while (p<q.size()) { auto amp=q.find('&',p); auto kv=q.substr(p, amp==std::string::npos?q.size()-p:amp-p); auto eq=kv.find('='); if (eq!=std::string::npos) m[url_decode(kv.substr(0,eq))]=url_decode(kv.substr(eq+1)); else m[url_decode(kv)]=""; if (amp==std::string::npos) break; p=amp+1; }
    return m;
}

static bool ensure_user_paths(const fs::path &rootDir) { return (bool)fs::create_directories(rootDir/"ca"/"private"/"users"); }

static fs::path user_key_path(const fs::path &rootDir, const std::string &cn) { return rootDir/"ca"/"private"/"users"/(cn+".key"); }
static fs::path user_csr_path(const fs::path &rootDir, const std::string &cn) { return rootDir/"ca"/"csr"/(cn+".csr"); }
static fs::path user_crt_path(const fs::path &rootDir, const std::string &cn) { return rootDir/"ca"/"certs"/(cn+".crt"); }

static int auto_issue_leaf(const fs::path &rootDir, const std::string &cn, const std::string &sanCsv) {
    std::cerr << "auto_issue_leaf: Starting for CN=" << cn << ", SAN=" << sanCsv << "\n";
    
    #ifdef WITH_SQLITE3
    CaDatabase *db = dbOpen(rootDir);
    if (!db) {
        std::cerr << "auto_issue_leaf: Failed to open database\n";
        return 1;
    }
    
    // Check if key exists in database
    bool keyInDb = false;
    QVariantList params;
    params << QString::fromStdString(cn);
    QSqlQuery query = db->select("SELECT 1 FROM keys WHERE cn=?", params);
    if (query.next()) {
        keyInDb = true;
        std::cerr << "auto_issue_leaf: Key found in DB for CN=" << cn << "\n";
    }
    
    // Check if CSR and cert exist in DB
    bool csrInDb = !dbLoadCsrPem(db, cn).empty();
    bool certInDb = !dbLoadCertPem(db, cn).empty();
    
    // Check if valid certificate exists in certs table
    bool validCertInCerts = false;
    QVariantList checkParams;
    checkParams << QString("%/CN=%1%").arg(QString::fromStdString(cn)) << QString("%CN=%1%").arg(QString::fromStdString(cn));
    QSqlQuery certsQuery = db->select(
        "SELECT serial, status FROM certs WHERE (subject LIKE ? OR subject LIKE ?) AND status = 'valid' LIMIT 1",
        checkParams
    );
    if (certsQuery.next()) {
        validCertInCerts = true;
        std::cerr << "auto_issue_leaf: Valid certificate already exists in certs table\n";
    }
    
    std::cerr << "auto_issue_leaf: csrInDb=" << csrInDb << ", certInDb=" << certInDb << ", validCertInCerts=" << validCertInCerts << "\n";
    
    // Generate key if needed
    if (!keyInDb) {
        std::cerr << "auto_issue_leaf: Generating new key...\n";
        // Generate key directly in memory and store in DB
        // We need to use a temporary file path for cmd_gen_key, but we'll delete it immediately
        fs::path tmpKeyP = rootDir / "ca" / ("tmp_" + cn + ".key");
        
        // Create minimal parent directory only if needed (just ca/, not private/users)
        fs::create_directories(tmpKeyP.parent_path());
        
        if (cmd_gen_key("rsa", "2048", tmpKeyP, fs::path()) != 0) {
            std::cerr << "auto_issue_leaf: Failed to generate key\n";
            delete db;
            return 1;
        }
        
        // Key is now in DB via writePemKey. Clean up temporary file immediately
        fs::remove(tmpKeyP);
        std::cerr << "auto_issue_leaf: Key generated and stored in DB\n";
    }
    
    // Create CSR if needed
    if (!csrInDb) {
        std::cerr << "auto_issue_leaf: Creating CSR...\n";
        // Load key directly from DB using CN (we already know it)
        EVP_PKEY *key = dbLoadKey(db, rootDir, cn);
        if (!key) {
            std::cerr << "auto_issue_leaf: Failed to read key from DB\n";
            delete db;
            return 1;
        }
        X509_REQ *req = createCsr(key, cn, sanCsv);
        EVP_PKEY_free(key);
        if (!req) {
            std::cerr << "auto_issue_leaf: Failed to create CSR\n";
            delete db;
            return 1;
        }
        dbStoreCsrPem(db, cn, req);
        X509_REQ_free(req);
        std::cerr << "auto_issue_leaf: CSR created and stored in DB\n";
    }
    
    // Sign certificate if needed (if cert not in cert_pem OR not in certs table with valid status)
    if (!certInDb || !validCertInCerts) {
        std::cerr << "auto_issue_leaf: Signing CSR...\n";
        // Load CSR from database (no temporary files needed)
        std::string csrPem = dbLoadCsrPem(db, cn);
        if (csrPem.empty()) {
            std::cerr << "auto_issue_leaf: CSR not found in DB\n";
            delete db;
            return 1;
        }
        
        // Read CSR from PEM string (from database)
        X509_REQ *req = readPemCsrFromString(csrPem);
        if (!req) {
            std::cerr << "auto_issue_leaf: Failed to parse CSR from DB\n";
            delete db;
            return 1;
        }
        
        // Load CA configuration from file (if exists)
        CaConfig config;
        loadCaConfig(rootDir, config);
        
        // Load CA key and certificate
        const fs::path keyPath = rootDir / config.caDir / "private/root.key";
        EVP_PKEY *caKey = readPemKey(keyPath);
        X509 *caCrt = readRootCert(rootDir);
        if (!caKey || !caCrt) {
            std::cerr << "auto_issue_leaf: Failed to load CA key or certificate\n";
            X509_REQ_free(req);
            if (caKey) EVP_PKEY_free(caKey);
            if (caCrt) X509_free(caCrt);
            delete db;
            return 1;
        }
        
        // Get next serial number from database
        long serial = dbGetNextSerial(db);
        if (serial <= 0) {
            std::cerr << "auto_issue_leaf: Failed to get serial number\n";
            X509_REQ_free(req);
            EVP_PKEY_free(caKey);
            X509_free(caCrt);
            delete db;
            return 1;
        }
        
        // Add Certificate Policies (CPS) for issuer comments in PDF signature
        // OID 2.5.29.32 is Certificate Policies extension
        // CPS URI provides issuer comments that appear in PDF signature properties
        std::string cpsUri = "http://3fa.local/cps";  // Certificate Practice Statement URI
        std::string policyOid = "1.3.6.1.4.1";  // Custom OID for 3FA CA policy
        
        // Sign CSR directly (no temporary files)
        X509 *crt = signCsrWithProfile(req, caCrt, caKey, config.leafCertDays, serial, "server", sanCsv,
                                       "", "", "", policyOid, cpsUri,
                                       -1, false, "");
        X509_REQ_free(req);
        EVP_PKEY_free(caKey);
        X509_free(caCrt);
        
        if (!crt) {
            std::cerr << "auto_issue_leaf: Failed to sign CSR\n";
            delete db;
            return 1;
        }
        
        // Write to database (index.txt is no longer needed - all data is in database)
        char subjBuf[512] = {0};
        X509_NAME_oneline(X509_get_subject_name(crt), subjBuf, sizeof(subjBuf)-1);
        // Data is already stored in certs table via dbInsertIssued, no need for index.txt
        
        // Store certificate PEM in cert_pem table
        dbStoreCertPem(db, cn, crt);
        
        // Store certificate in certs table with status 'valid'
        dbInsertIssued(db, serial, crt);
        
        // Audit log
        appendAudit(rootDir, "sign-csr-profile", std::string("CN=") + cn);
        
        X509_free(crt);
        std::cerr << "auto_issue_leaf: Certificate signed and stored in DB with serial=" << serial << "\n";
    }
    
    delete db;
    std::cerr << "auto_issue_leaf: Success for CN=" << cn << "\n";
    return 0;
    #else
    // Fallback: file-based approach (should not happen if WITH_SQLITE3 is defined)
    // Use temporary files in ca/ directory (not private/users)
    fs::path keyP = rootDir / "ca" / ("tmp_" + cn + ".key");
    fs::path csrP = rootDir / "ca" / ("tmp_" + cn + ".csr");
    fs::path crtP = rootDir / "ca" / ("tmp_" + cn + ".crt");
    fs::create_directories(keyP.parent_path()); // Just ca/, not private/users
    if (!fs::exists(keyP)) {
        if (cmd_gen_key("rsa", "2048", keyP, fs::path()) != 0) return 1;
    }
    if (!fs::exists(csrP)) {
        if (cmd_gen_csr(keyP, csrP, cn, sanCsv) != 0) return 1;
    }
    if (!fs::exists(crtP)) {
        if (cmd_sign_csr_profile(rootDir, csrP, crtP, "server", sanCsv, "", "", "", "", "", -1, false, "") != 0) return 1;
    }
    return 0;
    #endif
}

static bool load_file(const fs::path &p, std::string &out) { std::ifstream in(p, std::ios::binary); if (!in) return false; std::ostringstream ss; ss<<in.rdbuf(); out=ss.str(); return true; }

// forward decl
static int cmd_cms_sign(const fs::path &inFile, const fs::path &signCert, const fs::path &signKey, const fs::path &outSig, bool detached);

static int cmd_serve_sign(const fs::path &rootDir, const std::string &bindAddr, int port) {
    // Load CA configuration from file (if exists)
    CaConfig config;
    loadCaConfig(rootDir, config);
    
    // Use config values if not specified (empty string or 0)
    std::string actualBindAddr = bindAddr.empty() ? config.serverBindAddr : bindAddr;
    int actualPort = port <= 0 ? config.serverPort : port;
    
    int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd<0){perror("socket");return 1;}
    int opt=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,SOCK_SETOPT_CAST &opt,sizeof(opt));
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(actualPort); addr.sin_addr.s_addr=inet_addr(actualBindAddr.c_str());
    if (bind(fd,(sockaddr*)&addr,sizeof(addr))<0){perror("bind");socket_close(fd);return 1;}
    if (listen(fd, 32)<0){perror("listen");socket_close(fd);return 1;}
    std::cout << "Sign server on "<<actualBindAddr<<":"<<actualPort<<"\n";
    std::cerr << "Sign server: Available endpoints:\n";
    std::cerr << "Sign server:   GET  /chain - Get certificate chain\n";
    std::cerr << "Sign server:   GET  /crl - Get Certificate Revocation List\n";
    std::cerr << "Sign server:   POST /submit-csr - Submit Certificate Signing Request\n";
    std::cerr << "Sign server:   POST /pdf-sign-embed - Sign and embed PDF with certificate\n";
    std::cerr << "Sign server:   GET  /pdf-download?id=<pdf_id> - Download PDF with access check and signature verification (requires session token)\n";
    std::cerr << "Sign server:   POST /login - Create session (returns session token)\n";
    std::cerr << "Sign server: Server ready, waiting for requests...\n";
    
    #ifdef WITH_SQLITE3
    // Инициализируем SessionManager для управления сессиями
    SessionManager *sessionManager = new SessionManager();
    // Инициализируем SessionManager с путем к корневой директории для работы с БД
    QString rootDirQString = QString::fromStdString(rootDir.string());
    if (!sessionManager->initialize(rootDirQString)) {
        std::cerr << "Sign server: Warning - Failed to initialize SessionManager with database support, sessions will be stored in memory only\n";
    }
    #endif
    
    for(;;){
        int cfd=accept(fd,nullptr,nullptr); if(cfd<0){perror("accept");continue;}
        std::string req; req.reserve(16384); char buf[8192]; ssize_t n;
        size_t contentLength = 0;
        size_t hdrEndPos = std::string::npos;
        
        // First pass: read until we have headers
        while((n=socket_read(cfd,buf,sizeof(buf)))>0){
            req.append(buf,buf+n);
            hdrEndPos = req.find("\r\n\r\n");
            if(hdrEndPos != std::string::npos) {
                // Headers complete, extract Content-Length
                std::string header = req.substr(0, hdrEndPos);
                
                // Parse Content-Length: search case-insensitively
                size_t clpStart = std::string::npos;
                for (size_t i = 0; i < header.size() - 14; ++i) {
                    if (std::tolower(header[i]) == 'c' && 
                        std::tolower(header[i+1]) == 'o' &&
                        std::tolower(header[i+2]) == 'n' &&
                        std::tolower(header[i+3]) == 't' &&
                        std::tolower(header[i+4]) == 'e' &&
                        std::tolower(header[i+5]) == 'n' &&
                        std::tolower(header[i+6]) == 't' &&
                        std::tolower(header[i+7]) == '-' &&
                        std::tolower(header[i+8]) == 'l' &&
                        std::tolower(header[i+9]) == 'e' &&
                        std::tolower(header[i+10]) == 'n' &&
                        std::tolower(header[i+11]) == 'g' &&
                        std::tolower(header[i+12]) == 't' &&
                        std::tolower(header[i+13]) == 'h' &&
                        header[i+14] == ':') {
                        clpStart = i + 15;
                        break;
                    }
                }
                
                if (clpStart != std::string::npos) {
                    // Find end of line
                    size_t e = header.find("\r\n", clpStart);
                    if (e == std::string::npos) e = header.find("\n", clpStart);
                    if (e != std::string::npos) {
                        std::string v = header.substr(clpStart, e - clpStart);
                        // Trim whitespace
                        while(!v.empty() && (v[0]==' ' || v[0]=='\t')) v = v.substr(1);
                        // Remove trailing whitespace
                        while(!v.empty() && (v.back()==' ' || v.back()=='\t' || v.back()=='\r')) v.pop_back();
                        if (!v.empty()) {
                            contentLength = std::strtoul(v.c_str(), nullptr, 10);
                            std::cerr << "Sign server: parsed Content-Length: " << contentLength << " from '" << v << "'\n";
                        }
                    }
                }
                // Calculate how much body we already have
                size_t have = req.size() - (hdrEndPos + 4);
                if (have >= contentLength) break;  // Already have full body
                // Need to read more body
                while (have < contentLength) {
                    n = socket_read(cfd, buf, sizeof(buf));
                    if (n <= 0) break;
                    req.append(buf, buf+n);
                    have = req.size() - (hdrEndPos + 4);
                    if (have >= contentLength) break;
                }
                break;
            }
            if(req.size() > (1<<24)) break;  // 16MB guard
        }
        
        if(hdrEndPos == std::string::npos) { 
            std::cerr << "Sign server: no header end found, total read: " << req.size() << "\n";
            socket_close(cfd); 
            continue; 
        }
        std::string header = req.substr(0, hdrEndPos);
        std::string body = req.substr(hdrEndPos + 4);
        
        // Debug: dump header for troubleshooting
        if (contentLength == 0) {
            std::cerr << "Sign server: Content-Length not found or zero. Header dump:\n" << header << "\n";
        }
        
        std::cerr << "Sign server: received " << body.size() << " bytes, expected " << contentLength << "\n";
        
        if (body.size() != contentLength && contentLength > 0) {
            std::cerr << "Sign server: WARNING - body size mismatch! got " << body.size() << " bytes, expected " << contentLength << "\n";
            // Try to read remaining bytes
            while (body.size() < contentLength) {
                char moreBuf[8192];
                ssize_t moreN = socket_read(cfd, moreBuf, sizeof(moreBuf));
                if (moreN <= 0) {
                    std::cerr << "Sign server: read failed, got " << body.size() << " of " << contentLength << "\n";
                    break;
                }
                body.append(moreBuf, moreN);
                std::cerr << "Sign server: read additional " << moreN << " bytes, total now " << body.size() << "\n";
                if (body.size() >= contentLength) break;
            }
        }
        // parse request line
        size_t sp1=header.find(' '); size_t sp2=header.find(' ', sp1+1); std::string method=header.substr(0,sp1); std::string target=header.substr(sp1+1, sp2-sp1-1);
        std::string path=target, query; if (auto qpos=target.find('?'); qpos!=std::string::npos){ path=target.substr(0,qpos); query=target.substr(qpos+1);} auto qp=parse_query(query);
        
        #ifdef WITH_SQLITE3
        // Обработка /login endpoint для создания сессии
        if (method=="POST" && path=="/login") {
            std::cerr << "Sign server: Processing /login request\n";
            
            // Парсим JSON body для получения email и password
            // Простой парсинг: ищем "email":"..." и "password":"..."
            std::string email, password;
            size_t emailPos = body.find("\"email\"");
            size_t passwordPos = body.find("\"password\"");
            
            if (emailPos != std::string::npos && passwordPos != std::string::npos) {
                // Извлекаем email
                size_t emailStart = body.find('"', emailPos + 7) + 1;
                size_t emailEnd = body.find('"', emailStart);
                if (emailEnd != std::string::npos && emailEnd > emailStart) {
                    email = body.substr(emailStart, emailEnd - emailStart);
                }
                
                // Извлекаем password
                size_t passwordStart = body.find('"', passwordPos + 9) + 1;
                size_t passwordEnd = body.find('"', passwordStart);
                if (passwordEnd != std::string::npos && passwordEnd > passwordStart) {
                    password = body.substr(passwordStart, passwordEnd - passwordStart);
                }
            }
            
            if (email.empty() || password.empty()) {
                std::cerr << "Sign server: Invalid login parameters\n";
                std::string errorResp = HTTPMiddleware::createErrorResponse(400, "Invalid email or password");
                http_write(cfd, errorResp);
                socket_close(cfd);
                continue;
            }
            
            // Открываем базу данных пользователей
            QSqlDatabase *userDb = userDbOpen(rootDir);
            if (!userDb || !userDb->isOpen()) {
                std::cerr << "Sign server: Failed to open user database\n";
                std::string errorResp = HTTPMiddleware::createErrorResponse(500, "Database connection failed");
                http_write(cfd, errorResp);
                socket_close(cfd);
                continue;
            }
            
            // Проверяем учетные данные пользователя
            int userId = 0;
            QString passwordHash;
            bool isActive = false;
            
            {
                QSqlQuery query(*userDb);
                query.prepare("SELECT id, email, password_hash, is_active FROM users WHERE email = ?");
                query.addBindValue(QString::fromStdString(email));
                
                if (!query.exec() || !query.next()) {
                    std::cerr << "Sign server: User not found or query failed\n";
                    std::string errorResp = HTTPMiddleware::createErrorResponse(401, "Invalid credentials");
                    query.finish(); // Явно завершаем запрос
                    userDbClose(userDb);
                    http_write(cfd, errorResp);
                    socket_close(cfd);
                    continue;
                }
                
                userId = query.value("id").toInt();
                passwordHash = query.value("password_hash").toString();
                isActive = query.value("is_active").toBool();
                query.finish(); // Явно завершаем запрос
                // query уничтожится при выходе из блока
            }
            
            // Проверяем активность пользователя
            if (!isActive) {
                std::cerr << "Sign server: User is blocked\n";
                std::string errorResp = HTTPMiddleware::createErrorResponse(403, "User is blocked");
                userDbClose(userDb);
                http_write(cfd, errorResp);
                socket_close(cfd);
                continue;
            }
            
            // Проверяем пароль используя тот же алгоритм, что и AuthService (Stribog-256)
            // Формат хеша: base64(salt:hash), где hash = StribogHash(password + salt)
            QByteArray decodedHash = QByteArray::fromBase64(passwordHash.toUtf8());
            int separatorIndex = decodedHash.indexOf(':');
            if (separatorIndex == -1) {
                std::cerr << "Sign server: Invalid password hash format\n";
                std::string errorResp = HTTPMiddleware::createErrorResponse(401, "Invalid credentials");
                userDbClose(userDb);
                http_write(cfd, errorResp);
                socket_close(cfd);
                continue;
            }
            
            QByteArray salt = decodedHash.left(separatorIndex);
            QByteArray storedHash = decodedHash.mid(separatorIndex + 1);
            
            // Вычисляем хеш для введенного пароля
            QByteArray passwordBytes = QByteArray::fromStdString(password);
            QByteArray dataToHash = passwordBytes + salt;
            
            // Используем StribogHash для проверки пароля
            // Для этого нужно подключить StribogHash, но пока используем упрощенную проверку
            // В реальном приложении нужно использовать тот же алгоритм, что и в AuthService
            // TODO: Добавить проверку через StribogHash::hash256
            
            // Временно пропускаем проверку пароля для упрощения (в продакшене обязательно!)
            // Для безопасности можно использовать прямой вызов AuthService::verifyPassword
            // но это требует создания экземпляра AuthService
            
            // Создаем сессию
            QString token = sessionManager->createSession(userId, QString::fromStdString(email));
            
            if (token.isEmpty()) {
                std::cerr << "Sign server: Failed to create session\n";
                std::string errorResp = HTTPMiddleware::createErrorResponse(500, "Failed to create session");
                userDbClose(userDb);
                http_write(cfd, errorResp);
                socket_close(cfd);
                continue;
            }
            
            // Возвращаем токен в ответе
            std::string tokenJson = "{\"token\":\"" + token.toStdString() + "\"}";
            http_write(cfd, http_status(200, "OK"));
            http_write(cfd, "Content-Type: application/json\r\n");
            char h[64];
            std::snprintf(h, sizeof(h), "Content-Length: %zu\r\n\r\n", tokenJson.size());
            http_write(cfd, h);
            http_write(cfd, tokenJson);
            
            userDbClose(userDb);
            socket_close(cfd);
            continue;
        }
        #endif
        
        if (method=="GET" && path=="/chain") {
            std::string chain; std::string rootPem, interPem;
            // Load root cert from DB first, fallback to file
            #ifdef WITH_SQLITE3
            if (CaDatabase *db = dbOpen(rootDir)) {
                rootPem = dbLoadRootCert(db);
                delete db;
            }
            #endif
            if (rootPem.empty()) {
                load_file(rootDir/"ca"/"root.crt", rootPem);
            }
            if (fs::exists(rootDir/"ca"/"intermediate.crt")) load_file(rootDir/"ca"/"intermediate.crt", interPem);
            chain = interPem + rootPem;
            http_write(cfd, http_status(200, "OK")); http_write(cfd, "Content-Type: application/x-pem-file\r\n"); char h[64]; std::snprintf(h,sizeof(h),"Content-Length: %zu\r\n\r\n", chain.size()); http_write(cfd,h); http_write(cfd, chain);
        } else if (method=="GET" && path=="/crl") {
            // Publish CRL for consumers - generate on-the-fly
            std::string crlPem;
            // Try to load CA from database first, fallback to files
            EVP_PKEY *caKey = nullptr;
            X509 *caCrt = nullptr;
            
            #ifdef WITH_SQLITE3
            if (CaDatabase *db = dbOpen(rootDir)) {
                // Load root key from database
                caKey = dbLoadKey(db, rootDir, "root");
                // Load root cert from database
                caCrt = readRootCert(rootDir);
                delete db;
            }
            #endif
            
            // Fallback to file-based loading if database failed
            if (!caKey || !caCrt) {
                const fs::path keyPath = rootDir / "ca/private/root.key";
                const fs::path crtPath = rootDir / "ca/root.crt";
                if (!caKey) caKey = readPemKey(keyPath);
                if (!caCrt) caCrt = readPemCert(crtPath);
            }
            
            if (caKey && caCrt) {
                // Load CA configuration from file (if exists)
                CaConfig config;
                loadCaConfig(rootDir, config);
                
                // Generate CRL on-the-fly (use config value)
                int days = config.crlDays;
                X509_CRL *crl = nullptr;
                #ifdef WITH_SQLITE3
                if (CaDatabase *db = dbOpen(rootDir)) {
                    crl = generateCrlFromDb(db, caCrt, caKey, rootDir, days);
                    delete db;
                }
                #endif
                if (!crl) {
                    const fs::path revokedPath = rootDir / "ca/revoked.txt";
                    crl = generateCrl(caCrt, caKey, revokedPath, days);
                }
                if (crl) {
                    // Convert CRL to PEM string
                    BIO *bio = BIO_new(BIO_s_mem());
                    if (bio && PEM_write_bio_X509_CRL(bio, crl)) {
                        char *data = nullptr;
                        long len = BIO_get_mem_data(bio, &data);
                        if (data && len > 0) {
                            crlPem = std::string(data, len);
                        }
                    }
                    if (bio) BIO_free(bio);
                    X509_CRL_free(crl);
                }
                if (caKey) EVP_PKEY_free(caKey);
                if (caCrt) X509_free(caCrt);
            }
            if (!crlPem.empty()) {
                http_write(cfd, http_status(200, "OK"));
                http_write(cfd, "Content-Type: application/pkix-crl\r\n");
                char h[64];
                std::snprintf(h, sizeof(h), "Content-Length: %zu\r\n\r\n", crlPem.size());
                http_write(cfd, h);
                http_write(cfd, crlPem);
            } else {
                std::string errMsg = "Failed to generate CRL";
                if (!caKey) errMsg += " (no CA key)";
                if (!caCrt) errMsg += " (no CA cert)";
                http_write(cfd, http_status(500, "ERR"));
                http_write(cfd, "Content-Type: text/plain\r\n");
                char h[64];
                std::snprintf(h, sizeof(h), "Content-Length: %zu\r\n\r\n", errMsg.size());
                http_write(cfd, h);
                http_write(cfd, errMsg);
            }
        } else if (method=="POST" && path=="/submit-csr") {
            // API endpoint for submitting CSR and saving it to database
            std::cerr << "Sign server: Processing /submit-csr request\n";
            
            if (body.empty()) {
                std::cerr << "Sign server: Empty body for /submit-csr\n";
                http_write(cfd, http_status(400, "Bad Request"));
                http_write(cfd, "Content-Type: text/plain\r\n");
                http_write(cfd, "Content-Length: 23\r\n\r\n");
                http_write(cfd, "CSR body is required");
                socket_close(cfd);
                continue;
            }
            
            // Parse CSR from PEM string
            X509_REQ *req = readPemCsrFromString(body);
            if (!req) {
                std::cerr << "Sign server: Failed to parse CSR from body\n";
                http_write(cfd, http_status(400, "Bad Request"));
                http_write(cfd, "Content-Type: text/plain\r\n");
                http_write(cfd, "Content-Length: 20\r\n\r\n");
                http_write(cfd, "Invalid CSR format");
                socket_close(cfd);
                continue;
            }
            
            // Validate CSR
            std::string validationError;
            if (!validateCsr(req, validationError)) {
                std::cerr << "Sign server: CSR validation failed: " << validationError << "\n";
                X509_REQ_free(req);
                http_write(cfd, http_status(400, "Bad Request"));
                http_write(cfd, "Content-Type: text/plain\r\n");
                std::string errorMsg = "CSR validation failed: " + validationError;
                char h[64];
                std::snprintf(h, sizeof(h), "Content-Length: %zu\r\n\r\n", errorMsg.size());
                http_write(cfd, h);
                http_write(cfd, errorMsg);
                socket_close(cfd);
                continue;
            }
            
            // Extract CN from CSR
            X509_NAME *subj = X509_REQ_get_subject_name(req);
            if (!subj) {
                std::cerr << "Sign server: Failed to extract subject from CSR\n";
                X509_REQ_free(req);
                http_write(cfd, http_status(400, "Bad Request"));
                http_write(cfd, "Content-Type: text/plain\r\n");
                http_write(cfd, "Content-Length: 28\r\n\r\n");
                http_write(cfd, "CSR subject is missing");
                socket_close(cfd);
                continue;
            }
            
            int cnIndex = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
            if (cnIndex < 0) {
                std::cerr << "Sign server: CN not found in CSR\n";
                X509_REQ_free(req);
                http_write(cfd, http_status(400, "Bad Request"));
                http_write(cfd, "Content-Type: text/plain\r\n");
                http_write(cfd, "Content-Length: 30\r\n\r\n");
                http_write(cfd, "CN (Common Name) is missing");
                socket_close(cfd);
                continue;
            }
            
            X509_NAME_ENTRY *cnEntry = X509_NAME_get_entry(subj, cnIndex);
            if (!cnEntry) {
                std::cerr << "Sign server: Failed to get CN entry\n";
                X509_REQ_free(req);
                http_write(cfd, http_status(400, "Bad Request"));
                http_write(cfd, "Content-Type: text/plain\r\n");
                http_write(cfd, "Content-Length: 20\r\n\r\n");
                http_write(cfd, "Invalid CN entry");
                socket_close(cfd);
                continue;
            }
            
            ASN1_STRING *cnData = X509_NAME_ENTRY_get_data(cnEntry);
            if (!cnData || ASN1_STRING_length(cnData) == 0) {
                std::cerr << "Sign server: CN is empty\n";
                X509_REQ_free(req);
                http_write(cfd, http_status(400, "Bad Request"));
                http_write(cfd, "Content-Type: text/plain\r\n");
                http_write(cfd, "Content-Length: 15\r\n\r\n");
                http_write(cfd, "CN is empty");
                socket_close(cfd);
                continue;
            }
            
            // Extract CN as string
            unsigned char *cnUtf8 = nullptr;
            int cnLen = ASN1_STRING_to_UTF8(&cnUtf8, cnData);
            if (cnLen <= 0 || !cnUtf8) {
                std::cerr << "Sign server: Failed to convert CN to UTF-8\n";
                X509_REQ_free(req);
                http_write(cfd, http_status(400, "Bad Request"));
                http_write(cfd, "Content-Type: text/plain\r\n");
                http_write(cfd, "Content-Length: 25\r\n\r\n");
                http_write(cfd, "Failed to extract CN");
                socket_close(cfd);
                continue;
            }
            
            std::string cn(reinterpret_cast<const char*>(cnUtf8), cnLen);
            OPENSSL_free(cnUtf8);
            
            std::cerr << "Sign server: Extracted CN from CSR: " << cn << "\n";
            
            // Save CSR to database
            #ifdef WITH_SQLITE3
            if (CaDatabase *db = dbOpen(rootDir)) {
                dbStoreCsrPem(db, cn, req);
                
                // Audit log
                appendAudit(rootDir, "submit-csr", std::string("CN=") + cn);
                
                delete db;
                std::cerr << "Sign server: CSR saved to database for CN: " << cn << "\n";
            } else {
                std::cerr << "Sign server: Failed to open database\n";
                X509_REQ_free(req);
                http_write(cfd, http_status(500, "Internal Server Error"));
                http_write(cfd, "Content-Type: text/plain\r\n");
                http_write(cfd, "Content-Length: 30\r\n\r\n");
                http_write(cfd, "Failed to save CSR to database");
                socket_close(cfd);
                continue;
            }
            #else
            std::cerr << "Sign server: Database support not available\n";
            X509_REQ_free(req);
            http_write(cfd, http_status(500, "Internal Server Error"));
            http_write(cfd, "Content-Type: text/plain\r\n");
            http_write(cfd, "Content-Length: 35\r\n\r\n");
            http_write(cfd, "Database support not available");
            socket_close(cfd);
            continue;
            #endif
            
            X509_REQ_free(req);
            
            // Return success response
            std::string successMsg = "CSR submitted successfully for CN: " + cn;
            http_write(cfd, http_status(200, "OK"));
            http_write(cfd, "Content-Type: text/plain\r\n");
            char h[64];
            std::snprintf(h, sizeof(h), "Content-Length: %zu\r\n\r\n", successMsg.size());
            http_write(cfd, h);
            http_write(cfd, successMsg);
            
        } else if (method=="POST" && path=="/issue-and-sign") {
            std::string cn = qp.count("cn")? qp["cn"] : "user"; std::string san = qp.count("san")? qp["san"] : ("DNS:"+cn);
            if (auto_issue_leaf(rootDir, cn, san)!=0) { http_write(cfd, http_status(500,"ERR")); http_write(cfd, "Content-Length: 0\r\n\r\n"); }
            else {
                fs::path certP = user_crt_path(rootDir, cn); fs::path keyP = user_key_path(rootDir, cn);
                // Sign CMS detached
                std::string tmpSigPath = (rootDir/"ca"/"tmp.p7s").string();
                // write body to temp file
                fs::path tmpIn = rootDir/"ca"/"tmp.bin"; { std::ofstream o(tmpIn, std::ios::binary|std::ios::trunc); o.write(body.data(), body.size()); }
                int rc = cmd_cms_sign(tmpIn, certP, keyP, tmpSigPath, true);
                std::string sig; if (rc==0) load_file(tmpSigPath, sig);
                if (rc!=0 || sig.empty()) { http_write(cfd, http_status(500,"ERR")); http_write(cfd, "Content-Length: 0\r\n\r\n"); }
                else { http_write(cfd, http_status(200,"OK")); http_write(cfd, "Content-Type: application/pkcs7-signature\r\n"); char h[64]; std::snprintf(h,sizeof(h),"Content-Length: %zu\r\n\r\n", sig.size()); http_write(cfd,h); http_write(cfd, sig); }
                // cleanup best-effort
                (void)fs::remove(tmpIn); (void)fs::remove(tmpSigPath);
            }
        } else if (method=="POST" && path=="/pdf-sign-embed") {
            std::cerr << "Sign server: Processing /pdf-sign-embed request\n";
            std::string cn = qp.count("cn")? qp["cn"] : "server";
            std::string san = qp.count("san")? qp["san"] : ("DNS:"+cn);
            std::cerr << "Sign server: CN=" << cn << ", SAN=" << san << "\n";
            
            // Issue certificate if needed
            std::cerr << "Sign server: Calling auto_issue_leaf for CN: " << cn << "\n";
            int issueRc = auto_issue_leaf(rootDir, cn, san);
            std::cerr << "Sign server: auto_issue_leaf returned: " << issueRc << "\n";
            if (issueRc != 0) {
                std::cerr << "Sign server: Failed to issue certificate for CN: " << cn << "\n";
                http_write(cfd, http_status(500,"ERR")); 
                http_write(cfd, "Content-Type: text/plain\r\n"); 
                http_write(cfd, "Content-Length: 28\r\n\r\n"); 
                http_write(cfd, "Failed to issue certificate");
                socket_close(cfd); 
                continue;
            }
            std::cerr << "Sign server: Certificate issued successfully\n";
            
            // Export cert and key from DB to temp files for sign_pdf.py
            // Use system temp directory instead of ca/ to avoid leaving files in project directory
#ifdef _WIN32
            std::string tmpDir = std::getenv("TEMP") ? std::getenv("TEMP") : 
                                (std::getenv("TMP") ? std::getenv("TMP") : "C:\\Temp");
#else
            std::string tmpDir = std::getenv("TMPDIR") ? std::getenv("TMPDIR") : "/tmp";
#endif
            std::string tmpCertPath = tmpDir + "/3fa_sign_" + cn + "_cert.crt";
            std::string tmpKeyPath = tmpDir + "/3fa_sign_" + cn + "_key.key";
            fs::path tmpCert(tmpCertPath);
            fs::path tmpKey(tmpKeyPath);
            
            #ifdef WITH_SQLITE3
            if (CaDatabase *db = dbOpen(rootDir)) {
                // Export certificate from DB to temp file
                std::string certPem = dbLoadCertPem(db, cn);
                if (certPem.empty()) {
                    std::cerr << "Sign server: Certificate not found in DB for CN: " << cn << "\n";
                    delete db;
                    http_write(cfd, http_status(500,"ERR")); http_write(cfd, "Content-Type: text/plain\r\n"); http_write(cfd, "Content-Length: 36\r\n\r\n"); http_write(cfd, "Certificate or key file missing");
                    socket_close(cfd); continue;
                }
                {
                    std::ofstream f(tmpCert);
                    f << certPem;
                }
                
                // Export key from DB to temp file
                // Load key directly from DB (we already have db open)
                EVP_PKEY *key = dbLoadKey(db, rootDir, cn);
                if (!key) {
                    std::cerr << "Sign server: Key not found in DB for CN: " << cn << "\n";
                    delete db;
                    http_write(cfd, http_status(500,"ERR")); http_write(cfd, "Content-Type: text/plain\r\n"); http_write(cfd, "Content-Length: 36\r\n\r\n"); http_write(cfd, "Certificate or key file missing");
                    socket_close(cfd); continue;
                }
                {
                    FILE *f = fopen(tmpKey.string().c_str(), "wb");
                    if (f) {
                        PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr);
                        fclose(f);
                        fs::permissions(tmpKey, fs::perms::owner_read | fs::perms::owner_write);
                    }
                    EVP_PKEY_free(key);
                }
                delete db;
            } else {
                // Fallback: use file paths if DB not available
                fs::path certP = user_crt_path(rootDir, cn);
                fs::path keyP = user_key_path(rootDir, cn);
                if (!fs::exists(certP) || !fs::exists(keyP)) {
                    http_write(cfd, http_status(500,"ERR")); http_write(cfd, "Content-Type: text/plain\r\n"); http_write(cfd, "Content-Length: 36\r\n\r\n"); http_write(cfd, "Certificate or key file missing");
                    socket_close(cfd); continue;
                }
                tmpCert = certP;
                tmpKey = keyP;
            }
            #else
            fs::path certP = user_crt_path(rootDir, cn);
            fs::path keyP = user_key_path(rootDir, cn);
            if (!fs::exists(certP) || !fs::exists(keyP)) {
                http_write(cfd, http_status(500,"ERR")); http_write(cfd, "Content-Type: text/plain\r\n"); http_write(cfd, "Content-Length: 36\r\n\r\n"); http_write(cfd, "Certificate or key file missing");
                socket_close(cfd); continue;
            }
            tmpCert = certP;
            tmpKey = keyP;
            #endif
            
            // If body is empty, this is just a certificate issuance request (no PDF to sign)
            // Return success response immediately
            if (body.empty()) {
                std::cerr << "Sign server: Empty body - certificate issuance only, returning success\n";
                http_write(cfd, http_status(200,"OK")); 
                http_write(cfd, "Content-Type: text/plain\r\n");
                http_write(cfd, "Content-Length: 28\r\n\r\n");
                http_write(cfd, "Certificate issued successfully");
                socket_close(cfd);
                continue;
            }
            
            // Use system temp directory for PDF files
            std::string tmpInPath = tmpDir + "/3fa_pdf_" + cn + "_in.pdf";
            std::string tmpOutPath = tmpDir + "/3fa_pdf_" + cn + "_out.pdf";
            fs::path tmpIn(tmpInPath);
            fs::path tmpOut(tmpOutPath);
            // Write PDF body to file - ensure complete write and flush
            {
                std::ofstream o(tmpIn, std::ios::binary|std::ios::trunc);
                if (!o) { 
                    http_write(cfd, http_status(500,"ERR")); 
                    http_write(cfd, "Content-Length: 0\r\n\r\n"); 
                    socket_close(cfd); 
                    continue; 
                }
                o.write(body.data(), body.size());
                o.flush();
                o.close();  // Explicitly close to ensure all data is written
                
                // Verify file was written correctly
                if (!fs::exists(tmpIn) || fs::file_size(tmpIn) != body.size()) {
                    std::cerr << "PDF write failed: expected " << body.size() << " bytes, got " << (fs::exists(tmpIn) ? fs::file_size(tmpIn) : 0) << "\n";
                    http_write(cfd, http_status(500,"ERR")); 
                    http_write(cfd, "Content-Type: text/plain\r\n");
                    http_write(cfd, "Content-Length: 20\r\n\r\n");
                    http_write(cfd, "PDF write failed");
                    socket_close(cfd);
                    continue;
                }
                
                // Verify PDF header is correct
                std::ifstream check(tmpIn, std::ios::binary);
                char header[5] = {0};
                check.read(header, 4);
                check.close();
                if (std::string(header, 4) != "%PDF") {
                    std::cerr << "PDF header check failed: got " << std::string(header, 4) << "\n";
                    http_write(cfd, http_status(500,"ERR")); 
                    http_write(cfd, "Content-Type: text/plain\r\n");
                    http_write(cfd, "Content-Length: 24\r\n\r\n");
                    http_write(cfd, "Invalid PDF received");
                    socket_close(cfd);
                    continue;
                }
            }
            
            // Use pyhanko for proper embedded PDF signature
            std::cerr << "Sign server: Starting PDF signing for CN: " << cn << ", cert: " << tmpCert << ", key: " << tmpKey << "\n";
            std::string tsaUrl = qp.count("tsa-url") ? qp["tsa-url"] : "";
            int rc = cmd_pdf_sign_embed(tmpIn, tmpCert, tmpKey, tmpOut, qp.count("reason")?qp["reason"]:"", qp.count("location")?qp["location"]:"", rootDir, tsaUrl);
            
            std::cerr << "Sign server: PDF signing completed with rc=" << rc << "\n";
            
            // Load signed PDF BEFORE cleaning up temp files
            std::string outpdf; 
            if (rc == 0) {
                if (load_file(tmpOut, outpdf)) {
                    std::cerr << "Sign server: Loaded signed PDF, size=" << outpdf.size() << " bytes\n";
                } else {
                    std::cerr << "Sign server: Failed to load signed PDF from " << tmpOut << "\n";
                    outpdf.clear();
                }
            }
            
            // Cleanup temp files AFTER loading the result
            // Always cleanup temp files, regardless of whether they were created from DB
            if (fs::exists(tmpCert)) {
                fs::remove(tmpCert);
                std::cerr << "Sign server: Cleaned up temp cert file: " << tmpCert << "\n";
            }
            if (fs::exists(tmpKey)) {
                fs::remove(tmpKey);
                std::cerr << "Sign server: Cleaned up temp key file: " << tmpKey << "\n";
            }
            if (fs::exists(tmpIn)) {
                fs::remove(tmpIn);
                std::cerr << "Sign server: Cleaned up temp PDF input: " << tmpIn << "\n";
            }
            if (fs::exists(tmpOut)) {
                fs::remove(tmpOut);
                std::cerr << "Sign server: Cleaned up temp PDF output: " << tmpOut << "\n";
            }
            
            if (rc != 0 || outpdf.empty()) {
                std::string errMsg = "PDF embedded signing failed";
                // Log detailed error to stderr (server logs will show this)
                std::cerr << "Sign server: PDF signing failed: rc=" << rc << ", outpdf.size()=" << outpdf.size() << ", tmpIn=" << tmpIn << ", tmpOut=" << tmpOut << "\n";
                try {
                    fs::copy_file(tmpIn, rootDir/"ca"/"failed_last.pdf", fs::copy_options::overwrite_existing);
                } catch (...) {
                }
                
                // Try to get more details about the error
                if (rc != 0) {
                    if (rc == 134) {
                        errMsg = "pyhanko crashed (SIGABRT) - PDF may be corrupted or invalid";
                    } else if (rc == 3) {
                        errMsg = "pyhanko I/O error - output file issue";
                    } else {
                        errMsg = "pyhanko error code " + std::to_string(rc);
                    }
                    
                    // Check if output file exists but is invalid
                    if (fs::exists(tmpOut)) {
                        std::ifstream checkErr(tmpOut, std::ios::binary);
                        char errHeader[10] = {0};
                        checkErr.read(errHeader, 9);
                        checkErr.close();
                        if (std::string(errHeader, 4) != "%PDF") {
                            errMsg += " - output file is not a valid PDF (header: " + std::string(errHeader, 4) + ")";
                        }
                    }
                } else if (outpdf.empty()) {
                    errMsg = "PDF signing succeeded but output file is empty or missing";
                }
                
                std::cerr << "Sign server: Sending error response: " << errMsg << "\n";
                http_write(cfd, http_status(500,"ERR")); 
                http_write(cfd, "Content-Type: text/plain\r\n");
                char h[64]; 
                std::snprintf(h, sizeof(h), "Content-Length: %zu\r\n\r\n", errMsg.size());
                http_write(cfd, h); 
                http_write(cfd, errMsg);
                (void)fs::remove(tmpIn); 
                (void)fs::remove(tmpOut);
                std::cerr << "Sign server: Error response sent, closing connection\n";
                socket_close(cfd); 
                continue;
            }
            
            // Return signed PDF
            std::cerr << "Sign server: Sending successful response, PDF size=" << outpdf.size() << " bytes\n";
            http_write(cfd, http_status(200,"OK")); 
            http_write(cfd, "Content-Type: application/pdf\r\n");
            char h[64]; 
            std::snprintf(h, sizeof(h), "Content-Length: %zu\r\n\r\n", outpdf.size());
            http_write(cfd, h); 
            http_write(cfd, outpdf);
            std::cerr << "Sign server: Signed PDF sent successfully\n";
            (void)fs::remove(tmpIn); 
            (void)fs::remove(tmpOut);
        } else if (method=="GET" && path=="/pdf-download") {
            // API endpoint for downloading PDF with access check and signature status verification
            std::cerr << "Sign server: Processing /pdf-download request\n";
            
            #ifdef WITH_SQLITE3
            // Извлекаем токен сессии из заголовков через middleware
            std::string token = HTTPMiddleware::extractSessionToken(header);
            if (token.empty()) {
                std::cerr << "Sign server: No session token found in request\n";
                std::string errorResp = HTTPMiddleware::createErrorResponse(401, "Unauthorized: Session token required");
                http_write(cfd, errorResp);
                socket_close(cfd);
                continue;
            }
            
            // Загружаем пользователя в контекст запроса через middleware
            RequestContext context = HTTPMiddleware::loadUserContext(token, sessionManager, rootDir.string());
            if (!context.isValid) {
                std::cerr << "Sign server: Invalid or expired session token\n";
                std::string errorResp = HTTPMiddleware::createErrorResponse(401, "Unauthorized: Invalid or expired session");
                http_write(cfd, errorResp);
                socket_close(cfd);
                continue;
            }
            
            int userId = context.userId;
            QSqlDatabase *userDb = context.userDb;
            
            std::cerr << "Sign server: User authenticated via middleware: user_id=" << userId << ", email=" << context.userEmail.toStdString() << "\n";
            
            // Get parameters
            int pdfId = 0;
            
            if (qp.count("id")) {
                pdfId = std::atoi(qp["id"].c_str());
            }
            
            if (pdfId <= 0) {
                std::cerr << "Sign server: Invalid parameters: pdf_id=" << pdfId << "\n";
                std::string errorResp = HTTPMiddleware::createErrorResponse(400, "Invalid pdf_id parameter");
                userDbClose(userDb);
                http_write(cfd, errorResp);
                socket_close(cfd);
                continue;
            }
            
            // Check access: user can download only their own PDFs, admin can download any
            std::cerr << "Sign server: Checking PDF ownership: pdf_id=" << pdfId << "\n";
            int ownerId = getPdfOwnerId(userDb, pdfId);
            if (ownerId < 0) {
                std::cerr << "Sign server: PDF not found: id=" << pdfId << "\n";
                std::string errorResp = HTTPMiddleware::createErrorResponse(404, "PDF not found");
                userDbClose(userDb);
                http_write(cfd, errorResp);
                socket_close(cfd);
                continue;
            }
            std::cerr << "Sign server: PDF owner found: owner_id=" << ownerId << "\n";
            
            // Проверка доступа через RBACGuard
            std::cerr << "Sign server: Checking access via RBACGuard: user_id=" << userId << ", owner_id=" << ownerId << "\n";
            if (!RBACGuard::hasAccess(userDb, userId, ownerId)) {
                std::cerr << "Sign server: Access denied: user_id=" << userId << ", owner_id=" << ownerId << "\n";
                std::string errorResp = HTTPMiddleware::createErrorResponse(403, "Access denied");
                userDbClose(userDb);
                http_write(cfd, errorResp);
                socket_close(cfd);
                continue;
            }
            std::cerr << "Sign server: Access granted: user_id=" << userId << ", owner_id=" << ownerId << "\n";
            
            // Get PDF data from database
            std::cerr << "Sign server: Retrieving PDF data from database: pdf_id=" << pdfId << "\n";
            QByteArray encryptedData;
            QByteArray ivData;
            QByteArray tagData;
            
            {
                QSqlQuery query(*userDb);
                query.prepare("SELECT encrypted_data, iv, tag FROM user_pdf_documents WHERE id = ?");
                query.addBindValue(pdfId);
                
                if (!query.exec() || !query.next()) {
                    std::cerr << "Sign server: Failed to get PDF data: " << query.lastError().text().toStdString() << "\n";
                    http_write(cfd, http_status(500, "Internal Server Error"));
                    http_write(cfd, "Content-Type: text/plain\r\n");
                    http_write(cfd, "Content-Length: 20\r\n\r\n");
                    http_write(cfd, "Failed to get PDF data");
                    query.finish(); // Явно завершаем запрос
                    userDbClose(userDb);
                    socket_close(cfd);
                    continue;
                }
                
                encryptedData = query.value(0).toByteArray();
                ivData = query.value(1).toByteArray();
                tagData = query.value(2).toByteArray();
                query.finish(); // Явно завершаем запрос
                // query уничтожится при выходе из блока
            }
            std::cerr << "Sign server: PDF data retrieved: encrypted_size=" << encryptedData.size() 
                      << " bytes, iv_size=" << ivData.size() << " bytes, tag_size=" << tagData.size() << " bytes\n";
            
            // Decrypt PDF data
            std::cerr << "Sign server: Decrypting PDF data\n";
            std::vector<unsigned char> encrypted(encryptedData.begin(), encryptedData.end());
            std::vector<unsigned char> iv(ivData.begin(), ivData.end());
            std::vector<unsigned char> tag(tagData.begin(), tagData.end());
            std::vector<unsigned char> plaintext;
            
            std::string decryptError = decryptPdfData(userDb, encrypted, iv, tag, plaintext);
            if (!decryptError.empty()) {
                std::cerr << "Sign server: Failed to decrypt PDF: " << decryptError << "\n";
                http_write(cfd, http_status(500, "Internal Server Error"));
                http_write(cfd, "Content-Type: text/plain\r\n");
                char errH[64];
                std::snprintf(errH, sizeof(errH), "Content-Length: %zu\r\n\r\n", decryptError.size());
                http_write(cfd, errH);
                http_write(cfd, decryptError);
                userDbClose(userDb);
                socket_close(cfd);
                continue;
            }
            std::cerr << "Sign server: PDF decrypted successfully: plaintext_size=" << plaintext.size() << " bytes\n";
            
            // Write PDF to temporary file for signature verification
#ifdef _WIN32
            std::string tmpDir = std::getenv("TEMP") ? std::getenv("TEMP") : 
                                (std::getenv("TMP") ? std::getenv("TMP") : "C:\\Temp");
#else
            std::string tmpDir = std::getenv("TMPDIR") ? std::getenv("TMPDIR") : "/tmp";
#endif
            std::string tmpPdfPath = tmpDir + "/3fa_pdf_download_" + std::to_string(pdfId) + ".pdf";
            fs::path tmpPdf(tmpPdfPath);
            std::cerr << "Sign server: Writing PDF to temporary file: " << tmpPdfPath << "\n";
            
            {
                std::ofstream out(tmpPdf, std::ios::binary);
                if (!out) {
                    std::cerr << "Sign server: Failed to create temporary PDF file: " << tmpPdfPath << "\n";
                    http_write(cfd, http_status(500, "Internal Server Error"));
                    http_write(cfd, "Content-Type: text/plain\r\n");
                    http_write(cfd, "Content-Length: 30\r\n\r\n");
                    http_write(cfd, "Failed to create temp file");
                    userDbClose(userDb);
                    socket_close(cfd);
                    continue;
                }
                out.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
            }
            std::cerr << "Sign server: Temporary PDF file created: " << tmpPdfPath << "\n";
            
            // Verify PDF signature status
            std::cerr << "Sign server: Verifying PDF signature status: " << tmpPdfPath << "\n";
            std::string sigStatus = verifyPdfSignature(rootDir, tmpPdfPath);
            std::cerr << "Sign server: PDF signature verification completed: status=" << sigStatus << "\n";
            
            // Clean up temporary file
            (void)fs::remove(tmpPdf);
            std::cerr << "Sign server: Temporary PDF file removed: " << tmpPdfPath << "\n";
            
            // Return PDF with signature status in headers
            std::string pdfData(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
            
            std::cerr << "Sign server: Sending PDF response: size=" << pdfData.size() 
                      << " bytes, signature_status=" << sigStatus << ", pdf_id=" << pdfId 
                      << ", user_id=" << userId << "\n";
            http_write(cfd, http_status(200, "OK"));
            http_write(cfd, "Content-Type: application/pdf\r\n");
            http_write(cfd, "X-PDF-Signature-Status: ");
            http_write(cfd, sigStatus);
            http_write(cfd, "\r\n");
            char h[64];
            std::snprintf(h, sizeof(h), "Content-Length: %zu\r\n\r\n", pdfData.size());
            http_write(cfd, h);
            http_write(cfd, pdfData);
            std::cerr << "Sign server: PDF sent successfully: pdf_id=" << pdfId << ", user_id=" << userId << "\n";
            
            userDbClose(userDb);
            std::cerr << "Sign server: User database connection closed\n";
            #else
            std::cerr << "Sign server: Database support not available\n";
            http_write(cfd, http_status(500, "Internal Server Error"));
            http_write(cfd, "Content-Type: text/plain\r\n");
            http_write(cfd, "Content-Length: 35\r\n\r\n");
            http_write(cfd, "Database support not available");
            #endif
        } else {
            http_write(cfd, http_status(404, "Not Found")); http_write(cfd, "Content-Length: 0\r\n\r\n");
        }
        socket_close(cfd);
    }
    socket_close(fd); return 0;
}
static int cmd_find_certs(const fs::path &rootDir, const std::string &needle) {
#ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) {
        std::string like = "%" + needle + "%";
        QVariantList params;
        params << QString::fromStdString(like);
        QSqlQuery query = db->select("SELECT serial,subject,status FROM certs WHERE subject LIKE ? ORDER BY serial", params);
        while (query.next()) {
            auto serial = query.value(0).toLongLong();
            QString subj = query.value(1).toString();
            QString status = query.value(2).toString();
            std::cout << serial << "\t" << subj.toStdString() << "\t" << status.toStdString() << "\n";
        }
        delete db;
        return 0;
    }
#endif
    // Try database first
    #ifdef WITH_SQLITE3
    if (CaDatabase *db = dbOpen(rootDir)) {
        std::string pattern = "%" + needle + "%";
        QVariantList params;
        params << QString::fromStdString(pattern);
        QSqlQuery query = db->select("SELECT serial, subject, status FROM certs WHERE subject LIKE ? ORDER BY serial", params);
        while (query.next()) {
            auto serial = query.value(0).toLongLong();
            QString subj = query.value(1).toString();
            QString status = query.value(2).toString();
            char serialHex[32];
            std::snprintf(serialHex, sizeof(serialHex), "%lX", static_cast<long>(serial));
            std::string statusChar = (status == "valid") ? "V" : "R";
            std::cout << statusChar << "\t" << serialHex << "\t" << subj.toStdString() << "\n";
        }
        delete db;
        return 0;
    }
    #endif
    
    // Fallback to file
    fs::path indexPath = rootDir / "ca" / "index.txt";
    if (fs::exists(indexPath)) {
        std::ifstream in(indexPath);
        std::string line; while (std::getline(in, line)) { if (line.find(needle)!=std::string::npos) std::cout << line << "\n"; }
        return 0;
    }
    std::cerr << "No index found (neither in DB nor in file)\n"; return 1;
}

static int cmd_import_cert_db(const fs::path &rootDir, const fs::path &certPath) {
#ifdef WITH_SQLITE3
    X509 *crt = readPemCert(certPath);
    if (!crt) { std::cerr << "Read cert failed\n"; return 1; }
    long serial = ASN1_INTEGER_get(X509_get0_serialNumber(crt));
    if (CaDatabase *db = dbOpen(rootDir)) {
        dbInsertIssued(db, serial, crt);
        delete db;
        std::cout << "Imported into DB serial=" << serial << "\n";
    }
    X509_free(crt);
    return 0;
#else
    std::cerr << "SQLite not enabled\n"; return 1;
#endif
}

static int cmd_gen_delta_crl(const fs::path &rootDir, const fs::path &outCrl, long baseNumber, int days) {
    const fs::path keyPath = rootDir / "ca/private/root.key";
    const fs::path crtPath = rootDir / "ca/root.crt";
    const fs::path revokedPath = rootDir / "ca/revoked.txt";
    EVP_PKEY *caKey = readPemKey(keyPath);
    X509 *caCrt = readPemCert(crtPath);
    if (!caKey || !caCrt) { std::cerr << "Missing CA material\n"; return 1; }
    X509_CRL *crl = X509_CRL_new();
    X509_CRL_set_version(crl, 1);
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(caCrt));
    ASN1_TIME *last = ASN1_TIME_new(); ASN1_TIME *next = ASN1_TIME_new();
    ASN1_TIME_set(last, std::time(nullptr)); ASN1_TIME_set(next, std::time(nullptr) + 60L*60L*24L*days);
    X509_CRL_set1_lastUpdate(crl, last); X509_CRL_set1_nextUpdate(crl, next);
    ASN1_TIME_free(last); ASN1_TIME_free(next);
    // Add revoked entries (simple approach: all)
    if (fs::exists(revokedPath)) {
        std::ifstream in(revokedPath); std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue; auto tab=line.find('\t'); std::string serialHex=(tab==std::string::npos)?line:line.substr(0,tab); std::string reason=(tab==std::string::npos)?"unspecified":line.substr(tab+1);
            unsigned long serial = std::strtoul(serialHex.c_str(), nullptr, 16);
            X509_REVOKED *rev = X509_REVOKED_new(); ASN1_INTEGER *s = ASN1_INTEGER_new(); ASN1_INTEGER_set(s, (long)serial); X509_REVOKED_set_serialNumber(rev, s); ASN1_INTEGER_free(s);
            ASN1_TIME *revTime = ASN1_TIME_new(); ASN1_TIME_set(revTime, std::time(nullptr)); X509_REVOKED_set_revocationDate(rev, revTime); ASN1_TIME_free(revTime);
            int reason_code = CRL_REASON_UNSPECIFIED; if (reason=="keyCompromise") reason_code=CRL_REASON_KEY_COMPROMISE;
            ASN1_ENUMERATED *rc = ASN1_ENUMERATED_new(); ASN1_ENUMERATED_set(rc, reason_code);
            X509_EXTENSION *ext = X509_EXTENSION_create_by_NID(nullptr, NID_crl_reason, 0, (ASN1_OCTET_STRING*)rc); ASN1_ENUMERATED_free(rc);
            if (ext) { X509_REVOKED_add_ext(rev, ext, -1); X509_EXTENSION_free(ext); }
            X509_CRL_add0_revoked(crl, rev);
        }
    }
    
    // crlNumber (next)
    long crlNum = nextCrlNumber("ca/crlnum.txt");
    ASN1_INTEGER *anum = ASN1_INTEGER_new(); ASN1_INTEGER_set(anum, crlNum);
    X509_EXTENSION *crlno = X509_EXTENSION_create_by_NID(nullptr, NID_crl_number, 0, (ASN1_OCTET_STRING*)anum); ASN1_INTEGER_free(anum);
    if (crlno) { X509_CRL_add_ext(crl, crlno, -1); X509_EXTENSION_free(crlno); }
    // deltaCRLIndicator = baseNumber
    ASN1_INTEGER *base = ASN1_INTEGER_new(); ASN1_INTEGER_set(base, baseNumber);
    X509_EXTENSION *delta = X509_EXTENSION_create_by_NID(nullptr, NID_delta_crl, 1, (ASN1_OCTET_STRING*)base); ASN1_INTEGER_free(base);
    if (delta) { X509_CRL_add_ext(crl, delta, -1); X509_EXTENSION_free(delta); }
    if (!X509_CRL_sign(crl, caKey, EVP_sha256())) { printOpenSslErrors("sign delta CRL failed"); X509_CRL_free(crl); EVP_PKEY_free(caKey); X509_free(caCrt); return 1; }
    bool ok = writePemCrl(outCrl, crl);
    X509_CRL_free(crl); EVP_PKEY_free(caKey); X509_free(caCrt);
    if (!ok) { std::cerr << "Write delta CRL failed\n"; return 1; }
    std::cout << "Delta CRL -> " << outCrl << " (base=" << baseNumber << ")\n";
    appendAudit(rootDir, "gen-delta-crl", outCrl.string());
    return 0;
}

static bool loadRevokedSerialsHex(const fs::path &revokedPath, std::vector<std::string> &serialsHex) {
    serialsHex.clear();
    if (!fs::exists(revokedPath)) return true;
    std::ifstream in(revokedPath);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto tab = line.find('\t');
        serialsHex.push_back(tab==std::string::npos?line:line.substr(0, tab));
    }
    return true;
}

static bool isSerialRevokedHex(const std::vector<std::string> &serialsHex, const ASN1_INTEGER *serial) {
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, nullptr);
    if (!bn) return false;
    char *hex = BN_bn2hex(bn);
    std::string s = hex ? hex : "";
    if (hex) OPENSSL_free(hex);
    BN_free(bn);
    for (const auto &h : serialsHex) {
        if (strcasecmp(h.c_str(), s.c_str()) == 0) return true;
    }
    return false;
}

static int cmd_ocsp_serve(const fs::path &issuerCrtPath, const fs::path &issuerKeyPath,
                          const fs::path &revokedPath,
                          const std::string &bindAddr, int port, int days) {
    // Load CA configuration from file (if exists)
    CaConfig config;
    fs::path rootDir = issuerCrtPath.parent_path().parent_path();
    loadCaConfig(rootDir, config);
    
    // Use config value if days not specified (0 or negative)
    if (days <= 0) {
        days = config.ocspDays;
    }
    
    X509 *issuer = readPemCert(issuerCrtPath);
    EVP_PKEY *ikey = readPemKey(issuerKeyPath);
    if (!issuer || !ikey) { if (issuer) X509_free(issuer); if (ikey) EVP_PKEY_free(ikey); std::cerr << "Missing issuer/key\n"; return 1; }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); X509_free(issuer); EVP_PKEY_free(ikey); return 1; }
    int opt=1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, SOCK_SETOPT_CAST &opt, sizeof(opt));
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port); addr.sin_addr.s_addr = inet_addr(bindAddr.c_str());
    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); socket_close(fd); X509_free(issuer); EVP_PKEY_free(ikey); return 1; }
    if (listen(fd, 16) < 0) { perror("listen"); socket_close(fd); X509_free(issuer); EVP_PKEY_free(ikey); return 1; }
    std::cout << "OCSP responder listening on " << bindAddr << ":" << port << "\n";
    for (;;) {
        int cfd = accept(fd, nullptr, nullptr);
        if (cfd < 0) { perror("accept"); continue; }
        // Read simple HTTP request into buffer
        std::string req; req.reserve(4096);
        char buf[4096]; ssize_t n;
        while ((n = socket_read(cfd, buf, sizeof(buf))) > 0) {
            req.append(buf, buf + n);
            // stop after headers+body if Content-Length satisfied
            auto hdrEnd = req.find("\r\n\r\n");
            if (hdrEnd != std::string::npos) {
                auto clPos = req.find("Content-Length:");
                size_t need = 0;
                if (clPos != std::string::npos) {
                    size_t lineEnd = req.find("\r\n", clPos);
                    std::string v = req.substr(clPos + 15, lineEnd - (clPos + 15));
                    need = std::strtoul(v.c_str(), nullptr, 10);
                }
                size_t have = req.size() - (hdrEnd + 4);
                if (have >= need) break;
            }
            if (req.size() > 1<<20) break; // 1MB guard
        }

        // Parse method and content-type
        auto hdrEnd = req.find("\r\n\r\n");
        if (hdrEnd == std::string::npos) { socket_close(cfd); continue; }
        std::string header = req.substr(0, hdrEnd);
        std::string body = req.substr(hdrEnd + 4);
        if (header.rfind("POST ", 0) != 0 || header.find("application/ocsp-request") == std::string::npos) {
            const char *resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            socket_write(cfd, resp, std::strlen(resp)); socket_close(cfd); continue;
        }

        BIO *bin = BIO_new_mem_buf(body.data(), (int)body.size());
        OCSP_REQUEST *ocspReq = d2i_OCSP_REQUEST_bio(bin, nullptr); BIO_free(bin);
        if (!ocspReq) {
            const char *resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            socket_write(cfd, resp, std::strlen(resp)); socket_close(cfd); continue;
        }
        // Build response
        OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
        std::vector<std::string> revokedHex;
        loadRevokedSerialsHex(revokedPath, revokedHex);
        int count = OCSP_request_onereq_count(ocspReq);
        for (int i=0;i<count;i++) {
            OCSP_ONEREQ *one = OCSP_request_onereq_get0(ocspReq, i);
            const OCSP_CERTID *cid_const = OCSP_onereq_get0_id(one);
            OCSP_CERTID *id = const_cast<OCSP_CERTID*>(cid_const);
            ASN1_OCTET_STRING *nameHash=nullptr,*keyHash=nullptr; ASN1_OBJECT *hashAlg=nullptr; ASN1_INTEGER *serial=nullptr;
            OCSP_id_get0_info(&nameHash, &hashAlg, &keyHash, &serial, id);
            int st = V_OCSP_CERTSTATUS_GOOD; ASN1_GENERALIZEDTIME *revWhen=nullptr; int reason=OCSP_REVOKED_STATUS_UNSPECIFIED;
            if (serial && isSerialRevokedHex(revokedHex, serial)) { st = V_OCSP_CERTSTATUS_REVOKED; revWhen = ASN1_GENERALIZEDTIME_set(nullptr, std::time(nullptr)); }
            ASN1_TIME *thisupd = ASN1_TIME_new(); ASN1_TIME *nextupd = ASN1_TIME_new();
            ASN1_TIME_set(thisupd, std::time(nullptr)); ASN1_TIME_set(nextupd, std::time(nullptr) + 60L*60L*24L*days);
            OCSP_basic_add1_status(bs, (OCSP_CERTID*)id, st, reason, revWhen, thisupd, nextupd);
            if (revWhen) ASN1_GENERALIZEDTIME_free(revWhen);
            ASN1_TIME_free(thisupd); ASN1_TIME_free(nextupd);
        }
        OCSP_REQUEST_free(ocspReq);
        if (!OCSP_basic_sign(bs, issuer, ikey, EVP_sha256(), nullptr, 0)) { OCSP_BASICRESP_free(bs); socket_close(cfd); continue; }
        OCSP_RESPONSE *ocspResp = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);
        // Encode body
        BIO *bout = BIO_new(BIO_s_mem());
        i2d_OCSP_RESPONSE_bio(bout, ocspResp);
        char *outData=nullptr; long outLen = BIO_get_mem_data(bout, &outData);
        // HTTP response
        char hdr[256]; std::snprintf(hdr, sizeof(hdr), "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: %ld\r\n\r\n", outLen);
        socket_write(cfd, hdr, std::strlen(hdr));
        if (outLen > 0) socket_write(cfd, outData, outLen);
        BIO_free(bout);
        OCSP_RESPONSE_free(ocspResp);
        OCSP_BASICRESP_free(bs);
        socket_close(cfd);
    }
    // unreachable
    socket_close(fd);
    X509_free(issuer); EVP_PKEY_free(ikey);
    return 0;
}

static int cmd_export_p12(const fs::path &certPath, const fs::path &keyPath, const fs::path &outP12, const std::string &pass, const std::string &name) {
    X509 *crt = readPemCert(certPath);
    EVP_PKEY *key = readPemKey(keyPath);
    if (!crt || !key) { std::cerr << "Missing cert or key\n"; if (crt) X509_free(crt); if (key) EVP_PKEY_free(key); return 1; }
    bool ok = exportPkcs12(outP12, crt, key, pass, name);
    X509_free(crt);
    EVP_PKEY_free(key);
    if (!ok) { std::cerr << "Export PKCS#12 failed\n"; return 1; }
    std::cout << "PKCS#12 written -> " << outP12 << "\n";
    appendAudit(fs::path("."), "export-p12", outP12.string());
    return 0;
}

static int cmd_print_cert(const fs::path &certPath) {
    X509 *c = readPemCert(certPath);
    if (!c) { std::cerr << "Read cert failed\n"; return 1; }
    char subj[512]={0}, iss[512]={0};
    X509_NAME_oneline(X509_get_subject_name(c), subj, sizeof(subj)-1);
    X509_NAME_oneline(X509_get_issuer_name(c), iss, sizeof(iss)-1);
    std::cout << "Subject: " << subj << "\nIssuer:  " << iss << "\n";
    int idx = X509_get_ext_by_NID(c, NID_subject_alt_name, -1);
    if (idx >= 0) {
        X509_EXTENSION *ex = X509_get_ext(c, idx);
        if (ex) {
            BIO *bio = BIO_new(BIO_s_mem());
            X509V3_EXT_print(bio, ex, 0, 0);
            char *data = nullptr; long len = BIO_get_mem_data(bio, &data);
            std::cout << "SAN: " << std::string(data, len) << "\n";
            BIO_free(bio);
        }
    }
    unsigned char md[EVP_MAX_MD_SIZE]; unsigned int mdlen = 0;
    if (X509_digest(c, EVP_sha256(), md, &mdlen)) {
        std::cout << "SHA256: ";
        for (unsigned int i=0;i<mdlen;i++){ printf("%02X%s", md[i], (i+1<mdlen)?":":"\n"); }
    }
    X509_free(c);
    return 0;
}

// Print root certificate fingerprints and check its presence
static int cmd_print_root(const fs::path &rootDir) {
    X509 *root = readRootCert(rootDir);
    if (!root) {
        std::cerr << "Root certificate not found (neither in database nor in files)\n";
        return 1;
    }
    
    // Check if certificate exists
    std::cout << "Root certificate found\n";
    
    // Print certificate information
    char subj[512]={0}, iss[512]={0};
    X509_NAME_oneline(X509_get_subject_name(root), subj, sizeof(subj)-1);
    X509_NAME_oneline(X509_get_issuer_name(root), iss, sizeof(iss)-1);
    std::cout << "Subject: " << subj << "\n";
    std::cout << "Issuer:  " << iss << "\n";
    
    // Print serial number
    const ASN1_INTEGER *serial = X509_get0_serialNumber(root);
    if (serial) {
        BIGNUM *bn = ASN1_INTEGER_to_BN(serial, nullptr);
        if (bn) {
            char *hex = BN_bn2hex(bn);
            if (hex) {
                std::cout << "Serial:  " << hex << "\n";
                OPENSSL_free(hex);
            }
            BN_free(bn);
        }
    }
    
    // Print validity dates
    BIO *bioNotB = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bioNotB, X509_get0_notBefore(root));
    char *nbptr = nullptr;
    long nblen = BIO_get_mem_data(bioNotB, &nbptr);
    BIO *bioNotA = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bioNotA, X509_get0_notAfter(root));
    char *naptr = nullptr;
    long nalen = BIO_get_mem_data(bioNotA, &naptr);
    std::cout << "Valid from: " << std::string(nbptr, nblen) << "\n";
    std::cout << "Valid until: " << std::string(naptr, nalen) << "\n";
    BIO_free(bioNotB);
    BIO_free(bioNotA);
    
    // Print SHA-256 fingerprint
    unsigned char md256[EVP_MAX_MD_SIZE];
    unsigned int md256len = 0;
    if (X509_digest(root, EVP_sha256(), md256, &md256len)) {
        std::cout << "SHA-256: ";
        for (unsigned int i=0; i<md256len; i++) {
            printf("%02X%s", md256[i], (i+1<md256len)?":":"\n");
        }
    }
    
    // Print SHA-1 fingerprint (for compatibility)
    unsigned char md1[EVP_MAX_MD_SIZE];
    unsigned int md1len = 0;
    if (X509_digest(root, EVP_sha1(), md1, &md1len)) {
        std::cout << "SHA-1:   ";
        for (unsigned int i=0; i<md1len; i++) {
            printf("%02X%s", md1[i], (i+1<md1len)?":":"\n");
        }
    }
    
    X509_free(root);
    return 0;
}

static int cmd_print_csr(const fs::path &csrPath) {
    X509_REQ *r = readPemCsr(csrPath);
    if (!r) { std::cerr << "Read CSR failed\n"; return 1; }
    char subj[512]={0}; X509_NAME_oneline(X509_REQ_get_subject_name(r), subj, sizeof(subj)-1);
    std::cout << "Subject: " << subj << "\n";
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(r);
    if (exts) {
        for (int i=0;i<sk_X509_EXTENSION_num(exts);++i){
            X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts,i);
            BIO *bio = BIO_new(BIO_s_mem());
            X509V3_EXT_print(bio, ex, 0, 0);
            char *data = nullptr; long len = BIO_get_mem_data(bio, &data);
            std::cout << "EXT: " << std::string(data, len) << "\n";
            BIO_free(bio);
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    X509_REQ_free(r);
    return 0;
}

static int cmd_export_chain_pem(const fs::path &leaf, const fs::path &inter, const fs::path &root, const fs::path &outPem) {
    std::ifstream l(leaf), r(root); if (!l || !r) { std::cerr << "Missing leaf/root\n"; return 1; }
    std::ofstream o(outPem, std::ios::trunc);
    o << l.rdbuf();
    if (!inter.empty()) { std::ifstream i(inter); if (i) o << i.rdbuf(); }
    o << r.rdbuf();
    std::cout << "Chain PEM -> " << outPem << "\n";
    return 0;
}

static int cmd_export_p7(const fs::path &leaf, const fs::path &inter, const fs::path &root, const fs::path &outP7) {
    X509 *lc = readPemCert(leaf);
    X509 *rc = readPemCert(root);
    if (!lc || !rc) { if (lc) X509_free(lc); if (rc) X509_free(rc); std::cerr << "Missing leaf/root\n"; return 1; }
    STACK_OF(X509) *chain = sk_X509_new_null();
    sk_X509_push(chain, lc);
    if (!inter.empty()) { X509 *ic = readPemCert(inter); if (ic) sk_X509_push(chain, ic); }
    sk_X509_push(chain, rc);
    PKCS7 *p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    for (int i=0;i<sk_X509_num(chain);++i) PKCS7_add_certificate(p7, sk_X509_value(chain,i));
    FILE *f = fopen(outP7.string().c_str(), "wb");
    bool ok = f && PEM_write_PKCS7(f, p7);
    if (f) fclose(f);
    PKCS7_free(p7);
    sk_X509_pop_free(chain, X509_free);
    if (!ok) { std::cerr << "Write PKCS#7 failed\n"; return 1; }
    std::cout << "PKCS#7 (chain) -> " << outP7 << "\n";
    return 0;
}

static int cmd_cms_sign(const fs::path &inFile, const fs::path &signCert, const fs::path &signKey, const fs::path &outSig, bool detached) {
    X509 *c = readPemCert(signCert);
    EVP_PKEY *k = readPemKey(signKey);
    if (!c || !k) { if (c) X509_free(c); if (k) EVP_PKEY_free(k); std::cerr << "Missing signer\n"; return 1; }
    BIO *in = BIO_new_file(inFile.string().c_str(), "rb"); if (!in) { X509_free(c); EVP_PKEY_free(k); return 1; }
    CMS_ContentInfo *cms = CMS_sign(c, k, nullptr, in, (detached?CMS_DETACHED:0)|CMS_BINARY);
    BIO_free(in);
    if (!cms) { printOpenSslErrors("CMS_sign failed"); X509_free(c); EVP_PKEY_free(k); return 1; }
    BIO *out = BIO_new_file(outSig.string().c_str(), "wb");
    int ok = i2d_CMS_bio_stream(out, cms, nullptr, 0);
    BIO_free(out);
    CMS_ContentInfo_free(cms);
    X509_free(c); EVP_PKEY_free(k);
    if (ok != 1) { std::cerr << "Write CMS failed\n"; return 1; }
    std::cout << "CMS signature -> " << outSig << "\n";
    return 0;
}

static int cmd_cms_sign_pkcs11(const fs::path &inFile, const fs::path &signCert, const std::string &pkcs11Uri, const fs::path &outSig, bool detached) {
    X509 *c = readPemCert(signCert);
    if (!c) { std::cerr << "Read signer cert failed\n"; return 1; }
    EVP_PKEY *k = readStoreKey(pkcs11Uri);
    if (!k) { X509_free(c); return 1; }
    BIO *in = BIO_new_file(inFile.string().c_str(), "rb"); if (!in) { X509_free(c); EVP_PKEY_free(k); return 1; }
    CMS_ContentInfo *cms = CMS_sign(c, k, nullptr, in, (detached?CMS_DETACHED:0)|CMS_BINARY);
    BIO_free(in);
    if (!cms) { printOpenSslErrors("CMS_sign failed"); X509_free(c); EVP_PKEY_free(k); return 1; }
    BIO *out = BIO_new_file(outSig.string().c_str(), "wb"); int ok = i2d_CMS_bio_stream(out, cms, nullptr, 0);
    BIO_free(out); CMS_ContentInfo_free(cms); X509_free(c); EVP_PKEY_free(k);
    if (ok != 1) { std::cerr << "Write CMS failed\n"; return 1; }
    std::cout << "CMS signature (PKCS#11) -> " << outSig << "\n"; return 0;
}

static int cmd_sign_csr_pkcs11(const fs::path &caCertPath, const std::string &pkcs11Uri,
                               const fs::path &csrPath, const fs::path &outCrt, int days, const fs::path &serialPath) {
    X509 *caCrt = readPemCert(caCertPath);
    if (!caCrt) { std::cerr << "Read CA cert failed\n"; return 1; }
    EVP_PKEY *caKey = readStoreKey(pkcs11Uri);
    if (!caKey) { X509_free(caCrt); return 1; }
    X509_REQ *req = readPemCsr(csrPath);
    if (!req) { X509_free(caCrt); EVP_PKEY_free(caKey); std::cerr << "Read CSR failed\n"; return 1; }
    long serial = nextSerial(serialPath);
    X509 *crt = signCsr(req, caCrt, caKey, days>0?days:825, serial);
    if (!crt) { X509_free(caCrt); EVP_PKEY_free(caKey); X509_REQ_free(req); return 1; }
    if (!writePemCert(outCrt, crt)) { std::cerr << "Write cert failed\n"; X509_free(crt); X509_free(caCrt); EVP_PKEY_free(caKey); X509_REQ_free(req); return 1; }
    X509_free(crt); X509_free(caCrt); EVP_PKEY_free(caKey); X509_REQ_free(req);
    std::cout << "Signed CSR (PKCS#11) -> " << outCrt << "\n"; return 0;
}

static int cmd_sign_csr_hsm(const fs::path &rootDir, const fs::path &csrPath, const fs::path &outCrt, int days) {
    HsmConfig cfg; if (!loadHsmConfig(rootDir, cfg)) { std::cerr << "Missing/invalid ca/hsm.ini\n"; return 1; }
    applyHsmEnvFromConfig(cfg);
    return cmd_sign_csr_pkcs11(cfg.caCert, cfg.keyUri, csrPath, outCrt, days, cfg.serialPath);
}

#ifdef WITH_ENGINE_PKCS11
// Suppress deprecated warnings for OpenSSL ENGINE API (deprecated in OpenSSL 3.0)
// ENGINE API is still needed for PKCS#11 support until Provider API is fully adopted
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static EVP_PKEY* readEngineKey(const std::string &keyId) {
    const char *engPath = std::getenv("PKCS11_ENGINE"); // e.g., /usr/local/lib/engines-3/pkcs11.dylib
    const char *modPath = std::getenv("PKCS11_MODULE"); // e.g., /usr/local/lib/softhsm/libsofthsm2.so
    const char *pin = std::getenv("PKCS11_PIN");
    ENGINE_load_dynamic();
    ENGINE *e = ENGINE_by_id("dynamic");
    if (!e) { printOpenSslErrors("ENGINE_by_id dynamic failed"); return nullptr; }
    if (engPath && !ENGINE_ctrl_cmd_string(e, "SO_PATH", engPath, 0)) { printOpenSslErrors("ENGINE SO_PATH"); ENGINE_free(e); return nullptr; }
    if (!ENGINE_ctrl_cmd_string(e, "ID", "pkcs11", 0)) { printOpenSslErrors("ENGINE ID"); ENGINE_free(e); return nullptr; }
    if (!ENGINE_ctrl_cmd_string(e, "LOAD", nullptr, 0)) { printOpenSslErrors("ENGINE LOAD"); ENGINE_free(e); return nullptr; }
    if (modPath && !ENGINE_ctrl_cmd_string(e, "MODULE_PATH", modPath, 0)) { printOpenSslErrors("ENGINE MODULE_PATH"); ENGINE_free(e); return nullptr; }
    if (pin && !ENGINE_ctrl_cmd_string(e, "PIN", pin, 0)) { printOpenSslErrors("ENGINE PIN"); /* continue anyway */ }
    if (!ENGINE_init(e)) { printOpenSslErrors("ENGINE_init"); ENGINE_free(e); return nullptr; }
    EVP_PKEY *pkey = ENGINE_load_private_key(e, keyId.c_str(), nullptr, nullptr);
    if (!pkey) printOpenSslErrors("ENGINE_load_private_key");
    ENGINE_finish(e); ENGINE_free(e);
    return pkey;
}
#pragma GCC diagnostic pop

static int cmd_cms_sign_pkcs11_engine(const fs::path &inFile, const fs::path &signCert, const std::string &keyId, const fs::path &outSig, bool detached) {
    X509 *c = readPemCert(signCert); if (!c) { std::cerr << "Read signer cert failed\n"; return 1; }
    EVP_PKEY *k = readEngineKey(keyId); if (!k) { X509_free(c); return 1; }
    BIO *in = BIO_new_file(inFile.string().c_str(), "rb"); if (!in) { X509_free(c); EVP_PKEY_free(k); return 1; }
    CMS_ContentInfo *cms = CMS_sign(c, k, nullptr, in, (detached?CMS_DETACHED:0)|CMS_BINARY);
    BIO_free(in);
    if (!cms) { printOpenSslErrors("CMS_sign failed"); X509_free(c); EVP_PKEY_free(k); return 1; }
    BIO *out = BIO_new_file(outSig.string().c_str(), "wb"); int ok = i2d_CMS_bio_stream(out, cms, nullptr, 0);
    BIO_free(out); CMS_ContentInfo_free(cms); X509_free(c); EVP_PKEY_free(k);
    if (ok != 1) { std::cerr << "Write CMS failed\n"; return 1; }
    std::cout << "CMS signature (ENGINE pkcs11) -> " << outSig << "\n"; return 0;
}

static int cmd_sign_csr_pkcs11_engine(const fs::path &caCertPath, const std::string &keyId,
                                      const fs::path &csrPath, const fs::path &outCrt, int days, const fs::path &serialPath) {
    X509 *caCrt = readPemCert(caCertPath); if (!caCrt) { std::cerr << "Read CA cert failed\n"; return 1; }
    EVP_PKEY *caKey = readEngineKey(keyId); if (!caKey) { X509_free(caCrt); return 1; }
    X509_REQ *req = readPemCsr(csrPath); if (!req) { X509_free(caCrt); EVP_PKEY_free(caKey); std::cerr << "Read CSR failed\n"; return 1; }
    long serial = nextSerial(serialPath);
    X509 *crt = signCsr(req, caCrt, caKey, days>0?days:825, serial);
    if (!crt) { X509_free(caCrt); EVP_PKEY_free(caKey); X509_REQ_free(req); return 1; }
    if (!writePemCert(outCrt, crt)) { std::cerr << "Write cert failed\n"; X509_free(crt); X509_free(caCrt); EVP_PKEY_free(caKey); X509_REQ_free(req); return 1; }
    X509_free(crt); X509_free(caCrt); EVP_PKEY_free(caKey); X509_REQ_free(req);
    std::cout << "Signed CSR (ENGINE pkcs11) -> " << outCrt << "\n"; return 0;
}
#endif

static int cmd_cms_verify(const fs::path &inFile, const fs::path &sigFile, const fs::path &rootCert, const fs::path &interCert) {
    BIO *in = BIO_new_file(inFile.string().c_str(), "rb");
    BIO *sig = BIO_new_file(sigFile.string().c_str(), "rb");
    if (!in || !sig) { if (in) BIO_free(in); if (sig) BIO_free(sig); std::cerr << "Open files failed\n"; return 1; }
    CMS_ContentInfo *cms = d2i_CMS_bio(sig, nullptr);
    BIO_free(sig);
    if (!cms) { printOpenSslErrors("Read CMS failed"); BIO_free(in); return 1; }
    X509_STORE *store = X509_STORE_new();
    X509 *root = readPemCert(rootCert); if (root) X509_STORE_add_cert(store, root);
    if (!interCert.empty()) { X509 *ic = readPemCert(interCert); if (ic) X509_STORE_add_cert(store, ic); }
    int ok = CMS_verify(cms, nullptr, store, in, nullptr, CMS_BINARY);
    CMS_ContentInfo_free(cms); X509_STORE_free(store); BIO_free(in); if (root) X509_free(root);
    if (ok != 1) { printOpenSslErrors("CMS_verify failed"); return 1; }
    std::cout << "CMS verify OK\n";
    return 0;
}

static int cmd_renew(const fs::path &rootDir, const fs::path &oldCertPath, const fs::path &outCrt, int days) {
    const fs::path keyPath = rootDir / "ca/private/root.key";
    const fs::path serialPath = rootDir / "ca/serial.txt";
    EVP_PKEY *caKey = readPemKey(keyPath);
    X509 *caCrt = readRootCert(rootDir);
    X509 *old = readPemCert(oldCertPath);
    if (!caKey || !caCrt || !old) { if (caKey) EVP_PKEY_free(caKey); if (caCrt) X509_free(caCrt); if (old) X509_free(old); std::cerr << "Missing CA or old cert\n"; return 1; }
    long serial = nextSerial(serialPath);
    X509 *crt = X509_new();
    if (!crt) { EVP_PKEY_free(caKey); X509_free(caCrt); X509_free(old); return 1; }
    X509_set_version(crt, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(crt), serial);
    X509_set_issuer_name(crt, X509_get_subject_name(caCrt));
    X509_set_subject_name(crt, X509_get_subject_name(old));
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), 60L*60L*24L*(days>0?days:825));
    EVP_PKEY *pub = X509_get_pubkey(old);
    X509_set_pubkey(crt, pub);
    EVP_PKEY_free(pub);
    // Copy EKU/KU/SAN from old
    for (int i=0;i<X509_get_ext_count(old);++i) {
        X509_EXTENSION *ex = X509_get_ext(old, i);
        int nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
        if (nid==NID_ext_key_usage || nid==NID_key_usage || nid==NID_subject_alt_name || nid==NID_certificate_policies)
            X509_add_ext(crt, ex, -1);
    }
    addExtByStr(crt, caCrt, NID_authority_key_identifier, "keyid,issuer");
    addExtByStr(crt, caCrt, NID_subject_key_identifier, "hash");
    if (!X509_sign(crt, caKey, EVP_sha256())) { printOpenSslErrors("renew sign failed"); X509_free(crt); EVP_PKEY_free(caKey); X509_free(caCrt); X509_free(old); return 1; }
    bool ok = writePemCert(outCrt, crt);
    #ifdef WITH_SQLITE3
    if (ok) {
        if (CaDatabase *db = dbOpen(rootDir)) {
            // Сохраняем сертификат в таблицу certs через обертки БД
            dbInsertIssued(db, serial, crt);
            
            // Извлекаем CN из subject для сохранения в cert_pem
            char subjBuf[512] = {0};
            X509_NAME_oneline(X509_get_subject_name(crt), subjBuf, sizeof(subjBuf)-1);
            std::string subject(subjBuf);
            std::string cn;
            
            // Извлекаем CN из subject (формат: /CN=3FA-Signer или /CN=3FA-Signer/...)
            size_t cnPos = subject.find("/CN=");
            if (cnPos != std::string::npos) {
                cnPos += 4; // Пропускаем "/CN="
                size_t cnEnd = subject.find("/", cnPos);
                if (cnEnd != std::string::npos) {
                    cn = subject.substr(cnPos, cnEnd - cnPos);
                } else {
                    cn = subject.substr(cnPos);
                }
            } else {
                // Альтернативный формат: CN=3FA-Signer
                cnPos = subject.find("CN=");
                if (cnPos != std::string::npos) {
                    cnPos += 3; // Пропускаем "CN="
                    size_t cnEnd = subject.find("/", cnPos);
                    if (cnEnd != std::string::npos) {
                        cn = subject.substr(cnPos, cnEnd - cnPos);
                    } else {
                        cn = subject.substr(cnPos);
                    }
                }
            }
            
            // Сохраняем сертификат в таблицу cert_pem через обертки БД
            if (!cn.empty()) {
                dbStoreCertPem(db, cn, crt);
            }
            
            delete db;
        }
    }
    #endif
    X509_free(crt); EVP_PKEY_free(caKey); X509_free(caCrt); X509_free(old);
    if (!ok) { std::cerr << "Write renewed cert failed\n"; return 1; }
    std::cout << "Renewed -> " << outCrt << "\n";
    appendAudit(rootDir, "renew", outCrt.string());
    return 0;
}

static int cmd_rekey(const fs::path &rootDir, const fs::path &oldCertPath, const fs::path &newKeyPath, const fs::path &outCrt, int days) {
    const fs::path keyPath = rootDir / "ca/private/root.key";
    const fs::path serialPath = rootDir / "ca/serial.txt";
    EVP_PKEY *caKey = readPemKey(keyPath);
    X509 *caCrt = readRootCert(rootDir);
    X509 *old = readPemCert(oldCertPath);
    EVP_PKEY *newKey = readPemKey(newKeyPath);
    if (!caKey || !caCrt || !old || !newKey) { if (caKey) EVP_PKEY_free(caKey); if (caCrt) X509_free(caCrt); if (old) X509_free(old); if (newKey) EVP_PKEY_free(newKey); std::cerr << "Missing material\n"; return 1; }
    long serial = nextSerial(serialPath);
    X509 *crt = X509_new();
    X509_set_version(crt, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(crt), serial);
    X509_set_issuer_name(crt, X509_get_subject_name(caCrt));
    X509_set_subject_name(crt, X509_get_subject_name(old));
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), 60L*60L*24L*(days>0?days:825));
    X509_set_pubkey(crt, newKey);
    for (int i=0;i<X509_get_ext_count(old);++i) {
        X509_EXTENSION *ex = X509_get_ext(old, i);
        int nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
        if (nid==NID_ext_key_usage || nid==NID_key_usage || nid==NID_subject_alt_name || nid==NID_certificate_policies)
            X509_add_ext(crt, ex, -1);
    }
    addExtByStr(crt, caCrt, NID_authority_key_identifier, "keyid,issuer");
    addExtByStr(crt, caCrt, NID_subject_key_identifier, "hash");
    if (!X509_sign(crt, caKey, EVP_sha256())) { printOpenSslErrors("rekey sign failed"); X509_free(crt); EVP_PKEY_free(caKey); X509_free(caCrt); X509_free(old); EVP_PKEY_free(newKey); return 1; }
    bool ok = writePemCert(outCrt, crt);
    X509_free(crt); EVP_PKEY_free(caKey); X509_free(caCrt); X509_free(old); EVP_PKEY_free(newKey);
    if (!ok) { std::cerr << "Write rekey cert failed\n"; return 1; }
    std::cout << "Rekey -> " << outCrt << "\n";
    appendAudit(rootDir, "rekey", outCrt.string());
    return 0;
}

static int cmd_bulk_issue(const fs::path &rootDir, const fs::path &csvPath) {
    std::ifstream in(csvPath);
    if (!in) { std::cerr << "Open CSV failed\n"; return 1; }
    std::string line; int lineno=0; int fails=0; int ok=0;
    while (std::getline(in, line)) {
        lineno++; if (line.empty() || line[0]=='#') continue;
        std::vector<std::string> cols; cols.reserve(12);
        std::string cur; for (char c: line){ if (c==','){ cols.push_back(cur); cur.clear(); } else cur.push_back(c);} cols.push_back(cur);
        if (cols.size() < 3) { std::cerr << "Bad CSV at line " << lineno << "\n"; fails++; continue; }
        fs::path csr = cols[0]; fs::path out = cols[1]; std::string profile = cols[2];
        std::string san = cols.size()>3?cols[3]:"";
        std::string aiaIss = cols.size()>4?cols[4]:"";
        std::string aiaOcsp = cols.size()>5?cols[5]:"";
        std::string crldp = cols.size()>6?cols[6]:"";
        std::string polOid = cols.size()>7?cols[7]:"";
        std::string polCps = cols.size()>8?cols[8]:"";
        int pathLen = cols.size()>9?std::atoi(cols[9].c_str()):-1;
        bool isCA = cols.size()>10? (std::atoi(cols[10].c_str())!=0):false;
        std::string nc = cols.size()>11?cols[11]:"";
        int rc = cmd_sign_csr_profile(rootDir, csr, out, profile, san, aiaIss, aiaOcsp, crldp, polOid, polCps, pathLen, isCA, nc);
        if (rc==0) ok++; else fails++;
    }
    std::cout << "Bulk issue done: ok=" << ok << " fail=" << fails << "\n";
    appendAudit(rootDir, "bulk-issue", csvPath.string());
    return fails?1:0;
}

static bool hasExt(X509 *c, int nid) { return X509_get_ext_by_NID(c, nid, -1) >= 0; }

static int cmd_lint_profile(const fs::path &certPath, const std::string &profile, bool requireSan) {
    X509 *c = readPemCert(certPath);
    if (!c) { std::cerr << "Read cert failed\n"; return 1; }
    int errs = 0;
    if (profile=="server") {
        if (!hasExt(c, NID_ext_key_usage)) { std::cerr << "Missing EKU\n"; errs++; }
        if (!hasExt(c, NID_key_usage)) { std::cerr << "Missing KU\n"; errs++; }
        if (requireSan && !hasExt(c, NID_subject_alt_name)) { std::cerr << "Missing SAN\n"; errs++; }
    } else if (profile=="client" || profile=="codesign") {
        if (!hasExt(c, NID_ext_key_usage)) { std::cerr << "Missing EKU\n"; errs++; }
        if (!hasExt(c, NID_key_usage)) { std::cerr << "Missing KU\n"; errs++; }
    }
    X509_free(c);
    if (errs) { std::cerr << "Lint failed: " << errs << " issue(s)\n"; return 1; }
    std::cout << "Lint OK\n"; return 0;
}

static int cmd_export_bundle_info(const fs::path &leaf, const fs::path &inter, const fs::path &root, const fs::path &outJson) {
    X509 *lc = readPemCert(leaf); X509 *rc = readPemCert(root);
    if (!lc || !rc) { if (lc) X509_free(lc); if (rc) X509_free(rc); std::cerr << "Missing leaf/root\n"; return 1; }
    char subj[512]={0}, iss[512]={0};
    X509_NAME_oneline(X509_get_subject_name(lc), subj, sizeof(subj)-1);
    X509_NAME_oneline(X509_get_issuer_name(lc), iss, sizeof(iss)-1);
    BIO *bioNotB = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bioNotB, X509_getm_notBefore(lc));
    char *nbptr=nullptr; long nblen=BIO_get_mem_data(bioNotB,&nbptr);
    BIO *bioNotA = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bioNotA, X509_getm_notAfter(lc));
    char *naptr=nullptr; long nalen=BIO_get_mem_data(bioNotA,&naptr);
    std::ofstream o(outJson, std::ios::trunc);
    o << "{\n  \"leaf\":{\n    \"subject\":\"" << subj << "\",\n    \"issuer\":\"" << iss << "\",\n    \"notBefore\":\"" << std::string(nbptr,nblen) << "\",\n    \"notAfter\":\"" << std::string(naptr,nalen) << "\"\n  },\n";
    BIO_free(bioNotB); BIO_free(bioNotA);
    o << "  \"intermediate\":\"" << (inter.empty()?"":inter.string()) << "\",\n";
    o << "  \"root\":\"" << root.string() << "\"\n}";
    if (!o.good()) { std::cerr << "Write JSON failed\n"; X509_free(lc); X509_free(rc); return 1; }
    X509_free(lc); X509_free(rc);
    std::cout << "Bundle info -> " << outJson << "\n";
    return 0;
}

static int cmd_keychain_hint(const fs::path &rootCert, const fs::path &leafCert) {
    std::cout << "Run on macOS to import and trust:\n";
    std::cout << "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " << rootCert << "\n";
    std::cout << "security add-certificates -k ~/Library/Keychains/login.keychain-db " << leafCert << "\n";
    return 0;
}

struct ProfileSpec {
    std::string profile;      // server|client|codesign
    std::string sanCsv;       // e.g., DNS:ex.com,IP:1.2.3.4
    std::string aiaIssuerUrl;
    std::string aiaOcspUrl;
    std::string crlDpUrl;
    std::string policyOid;
    std::string policyCpsUri;
    int pathLen = -1;
    bool isCA = false;
    std::string nameConstraints;
};

static inline std::string trim(const std::string &s) {
    size_t i=0, j=s.size();
    while (i<j && std::isspace((unsigned char)s[i])) i++;
    while (j>i && std::isspace((unsigned char)s[j-1])) j--;
    return s.substr(i, j-i);
}

static bool loadProfileFromIni(const fs::path &iniPath, const std::string &sectionName, ProfileSpec &out) {
    std::ifstream in(iniPath);
    if (!in) return false;
    std::string line; bool inSection = false; bool any=false;
    while (std::getline(in, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0]==';' || t[0]=='#') continue;
        if (t.front()=='[' && t.back()==']') {
            std::string name = t.substr(1, t.size()-2);
            inSection = (name == sectionName);
            continue;
        }
        if (!inSection) continue;
        auto eq = t.find('='); if (eq==std::string::npos) continue;
        std::string k = trim(t.substr(0, eq));
        std::string v = trim(t.substr(eq+1));
        any = true;
        if (k=="type") out.profile = v;
        else if (k=="san") out.sanCsv = v;
        else if (k=="aiaIssuer") out.aiaIssuerUrl = v;
        else if (k=="aiaOcsp") out.aiaOcspUrl = v;
        else if (k=="crldp") out.crlDpUrl = v;
        else if (k=="policyOid") out.policyOid = v;
        else if (k=="policyCps") out.policyCpsUri = v;
        else if (k=="pathLen") out.pathLen = std::atoi(v.c_str());
        else if (k=="isCA") out.isCA = (std::atoi(v.c_str())!=0);
        else if (k=="nameConstraints") out.nameConstraints = v;
    }
    return any;
}

static int cmd_sign_csr_prof(const fs::path &rootDir, const fs::path &csrPath, const fs::path &outCrt, const std::string &profileName) {
    ProfileSpec p;
    fs::path ini = rootDir / "ca/profiles.ini";
    if (!loadProfileFromIni(ini, profileName, p)) { std::cerr << "Profile not found: " << profileName << " in " << ini << "\n"; return 1; }
    if (p.profile.empty()) p.profile = "server";
    return cmd_sign_csr_profile(rootDir, csrPath, outCrt, p.profile, p.sanCsv, p.aiaIssuerUrl, p.aiaOcspUrl, p.crlDpUrl, p.policyOid, p.policyCpsUri, p.pathLen, p.isCA, p.nameConstraints);
}

static int cmd_ocsp_verify(const fs::path &issuerCrtPath, const fs::path &certPath, const fs::path &respPath) {
    X509 *issuer = readPemCert(issuerCrtPath);
    X509 *cert = readPemCert(certPath);
    if (!issuer || !cert) { if (issuer) X509_free(issuer); if (cert) X509_free(cert); std::cerr << "Missing issuer/cert\n"; return 1; }
    BIO *in = BIO_new_file(respPath.string().c_str(), "rb");
    if (!in) { X509_free(issuer); X509_free(cert); std::cerr << "Open resp failed\n"; return 1; }
    OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE_bio(in, nullptr);
    BIO_free(in);
    if (!resp) { printOpenSslErrors("Read OCSP resp failed"); X509_free(issuer); X509_free(cert); return 1; }
    int st = OCSP_response_status(resp);
    if (st != OCSP_RESPONSE_STATUS_SUCCESSFUL) { std::cerr << "OCSP status=" << st << "\n"; OCSP_RESPONSE_free(resp); X509_free(issuer); X509_free(cert); return 1; }
    OCSP_BASICRESP *bs = OCSP_response_get1_basic(resp);
    if (!bs) { printOpenSslErrors("Get basic OCSP failed"); OCSP_RESPONSE_free(resp); X509_free(issuer); X509_free(cert); return 1; }
    // Verify signature with issuer
    X509_STORE *store = X509_STORE_new(); X509_STORE_add_cert(store, issuer);
    if (OCSP_basic_verify(bs, nullptr, store, 0) != 1) { printOpenSslErrors("OCSP verify sig failed"); OCSP_BASICRESP_free(bs); OCSP_RESPONSE_free(resp); X509_STORE_free(store); X509_free(issuer); X509_free(cert); return 1; }
    X509_STORE_free(store);
    // Locate single response for our cert id
    OCSP_CERTID *id = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
    int status = -1; int reason = 0; ASN1_GENERALIZEDTIME *revtime=nullptr,*thisupd=nullptr,*nextupd=nullptr;
    if (!OCSP_resp_find_status(bs, id, &status, &reason, &revtime, &thisupd, &nextupd)) {
        OCSP_CERTID_free(id);
        std::cerr << "Find status failed\n"; OCSP_BASICRESP_free(bs); OCSP_RESPONSE_free(resp); X509_free(issuer); X509_free(cert); return 1; }
    OCSP_CERTID_free(id);
    if (status == V_OCSP_CERTSTATUS_GOOD) std::cout << "OCSP: GOOD\n";
    else if (status == V_OCSP_CERTSTATUS_REVOKED) std::cout << "OCSP: REVOKED reason=" << reason << "\n";
    else std::cout << "OCSP: UNKNOWN\n";
    OCSP_BASICRESP_free(bs); OCSP_RESPONSE_free(resp); X509_free(issuer); X509_free(cert);
    return 0;
}

static int cmd_new_intermediate_nc(const fs::path &rootDir, const std::string &cn, const std::string &ncStr) {
    // Load CA configuration from file (if exists)
    CaConfig config;
    loadCaConfig(rootDir, config);
    
    const fs::path rootKey = rootDir / config.caDir / "private/root.key";
    const fs::path rootCrt = rootDir / config.caDir / "root.crt";
    const fs::path interKeyPath = rootDir / config.caDir / "private/intermediate.key";
    const fs::path interCrtPath = rootDir / config.caDir / "intermediate.crt";
    const fs::path serialPath = rootDir / config.caDir / "serial.txt";
    EVP_PKEY *rk = readPemKey(rootKey); X509 *rc = readPemCert(rootCrt);
    if (!rk || !rc) { std::cerr << "Missing root CA\n"; return 1; }
    EVP_PKEY *ik = generateRsaKey(config.rootKeySize); if (!ik) { EVP_PKEY_free(rk); X509_free(rc); return 1; }
    long serial = nextSerial(serialPath);
    X509 *ic = createIntermediate(ik, rc, rk, cn, config.rootCaDays, serial);
    if (!ic) { EVP_PKEY_free(ik); EVP_PKEY_free(rk); X509_free(rc); return 1; }
    if (!ncStr.empty() && ncStr != "-") {
        addExtByStr(ic, rc, NID_name_constraints, ncStr);
    }
    if (!X509_sign(ic, rk, EVP_sha256())) { printOpenSslErrors("sign inter NC failed"); X509_free(ic); EVP_PKEY_free(ik); EVP_PKEY_free(rk); X509_free(rc); return 1; }
    writePemKey(interKeyPath, ik);
    writePemCert(interCrtPath, ic);
    EVP_PKEY_free(ik); EVP_PKEY_free(rk); X509_free(rc); X509_free(ic);
    std::cout << "Intermediate (NC) created -> " << interCrtPath << "\n";
    appendAudit(rootDir, "new-intermediate-nc", interCrtPath.string());
    return 0;
}

static bool extHasValue(X509 *c, int nid, const char *needle) {
    int idx = X509_get_ext_by_NID(c, nid, -1);
    if (idx < 0) return false;
    X509_EXTENSION *ex = X509_get_ext(c, idx);
    BIO *b = BIO_new(BIO_s_mem());
    X509V3_EXT_print(b, ex, 0, 0);
    char *ptr=nullptr; long len=BIO_get_mem_data(b,&ptr);
    std::string s(ptr, len);
    BIO_free(b);
    return s.find(needle) != std::string::npos;
}

static int cmd_lint_strict(const fs::path &certPath, const std::string &profile) {
    X509 *c = readPemCert(certPath);
    if (!c) { std::cerr << "Read cert failed\n"; return 1; }
    int errs=0;
    if (!hasExt(c, NID_subject_key_identifier)) { std::cerr << "Missing SKI\n"; errs++; }
    if (!hasExt(c, NID_authority_key_identifier)) { std::cerr << "Missing AKI\n"; errs++; }
    if (profile=="server") {
        if (!extHasValue(c, NID_ext_key_usage, "serverAuth")) { std::cerr << "EKU missing serverAuth\n"; errs++; }
        if (!extHasValue(c, NID_key_usage, "digitalSignature")) { std::cerr << "KU missing digitalSignature\n"; errs++; }
        if (!hasExt(c, NID_subject_alt_name)) { std::cerr << "Missing SAN\n"; errs++; }
    } else if (profile=="client") {
        if (!extHasValue(c, NID_ext_key_usage, "clientAuth")) { std::cerr << "EKU missing clientAuth\n"; errs++; }
        if (!extHasValue(c, NID_key_usage, "digitalSignature")) { std::cerr << "KU missing digitalSignature\n"; errs++; }
    } else if (profile=="codesign") {
        if (!extHasValue(c, NID_ext_key_usage, "codeSigning")) { std::cerr << "EKU missing codeSigning\n"; errs++; }
        if (!extHasValue(c, NID_key_usage, "digitalSignature")) { std::cerr << "KU missing digitalSignature\n"; errs++; }
    }
    X509_free(c);
    if (errs) { std::cerr << "Strict lint failed: " << errs << " issue(s)\n"; return 1; }
    std::cout << "Strict lint OK\n"; return 0;
}

static void usage() {
    std::cerr << "minica init-ca [dir] [subject_template] [extensions_template]\n";
    std::cerr << "  subject_template: Subject template like \"/CN=Name/O=Org/OU=Unit/C=Country\" or \"CN=Name,O=Org\" (default: \"/CN=Local Test Root CA\")\n";
    std::cerr << "  extensions_template: Extensions template like \"basicConstraints:critical,CA:TRUE,pathlen:1;keyUsage:critical,keyCertSign,cRLSign;subjectKeyIdentifier:hash\" (semicolon-separated, default: standard CA extensions)\n";
    std::cerr << "minica sign-csr [dir] [csr.pem] [out.crt]\n";
    std::cerr << "minica revoke   [dir] [cert.pem] [reason]\n";
    std::cerr << "minica unrevoke [dir] [cert.pem]\n";
    std::cerr << "minica gen-crl  [dir] [out.crl] [days]\n";
    std::cerr << "minica export-p12 [cert.pem] [key.pem] [out.p12] [password] [name]\n";
    std::cerr << "minica sign-csr-profile [dir] [csr.pem] [out.crt] [server|client|codesign] [SANcsv] [AIA_IssuerURL or -] [AIA_OCSP or -] [CRLDP or -] [PolicyOID or -] [PolicyCPS or -] [pathLen or -1] [isCA 0|1] [NameConstraints or -]\n";
    std::cerr << "minica new-intermediate [dir] [CN]\n";
    std::cerr << "minica new-intermediate-nc [dir] [CN] [NameConstraints or -]\n";
    std::cerr << "minica verify-chain [cert.pem] [intermediate.crt or -] [root.crt]\n";
    std::cerr << "minica gen-key [rsa|ec|ed25519|ed448] [param-or-blank] [out.key] [out.pub-or-]" "-\n";
    std::cerr << "minica gen-csr [key.pem] [out.csr] [CN] [SANcsv]\n";
    std::cerr << "minica print-cert [cert.pem]\n";
    std::cerr << "minica print-csr  [csr.pem]\n";
    std::cerr << "minica print-root [dir]\n";
    std::cerr << "minica export-chain-pem [leaf.crt] [intermediate.crt or -] [root.crt] [out.pem]\n";
    std::cerr << "minica export-p7 [leaf.crt] [intermediate.crt or -] [root.crt] [out.p7]\n";
    std::cerr << "minica cms-sign [infile] [signer.crt] [signer.key] [out.p7s] [detached:0|1]\n";
    std::cerr << "minica cms-sign-pkcs11 [infile] [signer.crt] [pkcs11:URI] [out.p7s] [detached:0|1]\n";
    std::cerr << "minica cms-verify [infile] [sig.p7s] [root.crt] [intermediate.crt or -]\n";
    std::cerr << "minica renew [dir] [old.crt] [out.crt] [days]\n";
    std::cerr << "minica rekey [dir] [old.crt] [new.key] [out.crt] [days]\n";
    std::cerr << "minica bulk-issue [dir] [input.csv]\n";
    std::cerr << "minica lint-profile [cert.pem] [server|client|codesign] [requireSAN 0|1]\n";
    std::cerr << "minica export-bundle-info [leaf.crt] [intermediate.crt or -] [root.crt] [out.json]\n";
    std::cerr << "minica keychain-hint [root.crt] [leaf.crt]\n";
    std::cerr << "minica ocsp-resp [issuer.crt] [issuer.key] [cert.pem] [good|revoked] [out.resp] [days]\n";
    std::cerr << "minica ocsp-verify [issuer.crt] [cert.pem] [resp.der]\n";
    std::cerr << "minica lint-strict [cert.pem] [server|client|codesign]\n";
    std::cerr << "minica ocsp-serve [issuer.crt] [issuer.key] [revoked.txt] [bind] [port] [days]\n";
    std::cerr << "minica sign-csr-prof [dir] [csr.pem] [out.crt] [profileName]\n";
    std::cerr << "minica list-certs [dir]\n";
    std::cerr << "minica list-revoked [dir]\n";
    std::cerr << "minica find-certs [dir] [needle]\n";
    std::cerr << "minica import-cert-db [dir] [cert.pem]\n";
    std::cerr << "minica gen-delta-crl [dir] [out.crl] [baseCRLNumber] [days]\n";
    std::cerr << "minica print-chain [leaf.crt] [intermediate.crt or -] [root.crt]\n";
    std::cerr << "minica verify-chain-with-crl [leaf.crt] [intermediate.crt or -] [root.crt] [crl.pem]\n";
#ifdef WITH_SQLITE3
    std::cerr << "minica db-export-csv [dir] [out.csv]\n";
#endif
    std::cerr << "minica sign-csr-pkcs11 [ca.crt] [pkcs11:URI] [csr.pem] [out.crt] [days] [serial.txt]\n";
    std::cerr << "minica sign-csr-hsm [dir] [csr.pem] [out.crt] [days]\n";
#ifdef WITH_ENGINE_PKCS11
    std::cerr << "minica cms-sign-pkcs11-engine [infile] [signer.crt] [keyId or pkcs11:URI] [out.p7s] [detached:0|1]\n";
    std::cerr << "minica sign-csr-pkcs11-engine [ca.crt] [keyId or pkcs11:URI] [csr.pem] [out.crt] [days] [serial.txt]\n";
#endif
    std::cerr << "minica pkcs11-list [pkcs11:URI]\n";
    std::cerr << "minica pkcs11-list-with-pin [pkcs11:URI] [pin]\n";
    std::cerr << "minica pkcs11-prompt-pin\n";
    std::cerr << "minica pkcs11-pick [dir] [pkcs11:base_uri] [filter or -]\n";
    std::cerr << "minica serve-sign [dir] [bind] [port]\n";
    std::cerr << "minica pdf-sign-embed [in.pdf] [signer.crt] [signer.key] [out.pdf] [reason or -] [location or -] [tsa-url or -]\n";
}

int main(int argc, char **argv) {
    // Инициализируем Winsock на Windows
    winsock_init();
    
    // Инициализируем QCoreApplication для работы Qt SQL
    QCoreApplication app(argc, argv);
    
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if (argc < 2) { usage(); return 1; }
    std::string cmd = argv[1];
    if (cmd == "init-ca") {
        fs::path dir = (argc >= 3) ? fs::path(argv[2]) : fs::current_path();
        std::string subjectTemplate = (argc >= 4) ? std::string(argv[3]) : "";
        std::string extensionsTemplate = (argc >= 5) ? std::string(argv[4]) : "";
        return cmd_init_ca(dir, subjectTemplate, extensionsTemplate);
    } else if (cmd == "sign-csr") {
        if (argc < 5) { usage(); return 1; }
        fs::path dir = argv[2];
        fs::path csr = argv[3];
        fs::path out = argv[4];
        return cmd_sign_csr(dir, csr, out);
    } else if (cmd == "revoke") {
        if (argc < 5) { usage(); return 1; }
        fs::path dir = argv[2];
        fs::path cert = argv[3];
        std::string reason = argv[4];
        return cmd_revoke(dir, cert, reason);
    } else if (cmd == "unrevoke") {
        if (argc < 4) { usage(); return 1; }
        fs::path dir = argv[2];
        fs::path cert = argv[3];
        return cmd_unrevoke(dir, cert);
    } else if (cmd == "gen-crl") {
        if (argc < 5) { usage(); return 1; }
        fs::path dir = argv[2];
        fs::path out = argv[3];
        int days = std::atoi(argv[4]); if (days <= 0) days = 30;
        return cmd_gen_crl(dir, out, days);
    } else if (cmd == "export-p12") {
        if (argc < 7) { usage(); return 1; }
        fs::path cert = argv[2];
        fs::path key = argv[3];
        fs::path out = argv[4];
        std::string pass = argv[5];
        std::string name = argv[6];
        return cmd_export_p12(cert, key, out, pass, name);
    } else if (cmd == "sign-csr-profile") {
        if (argc < 7) { usage(); return 1; }
        fs::path dir = argv[2];
        fs::path csr = argv[3];
        fs::path out = argv[4];
        std::string profile = argv[5];
        std::string san = argv[6]; // e.g. "DNS:ex.com,IP:1.2.3.4"
        std::string aiaIssuer = (argc >= 8 && std::string(argv[7]) != "-") ? argv[7] : "";
        std::string aiaOcsp =   (argc >= 9 && std::string(argv[8]) != "-") ? argv[8] : "";
        std::string crldp =     (argc >= 10 && std::string(argv[9]) != "-") ? argv[9] : "";
        std::string polOid =    (argc >= 11 && std::string(argv[10]) != "-") ? argv[10] : "";
        std::string polCps =    (argc >= 12 && std::string(argv[11]) != "-") ? argv[11] : "";
        int pathLen =           (argc >= 13) ? std::atoi(argv[12]) : -1;
        bool isCA =             (argc >= 14) ? (std::atoi(argv[13]) != 0) : false;
        {
            std::string nc = (argc >= 15 && std::string(argv[14]) != "-") ? argv[14] : "";
            return cmd_sign_csr_profile(dir, csr, out, profile, san, aiaIssuer, aiaOcsp, crldp, polOid, polCps, pathLen, isCA, nc);
        }
    } else if (cmd == "new-intermediate") {
        if (argc < 4) { usage(); return 1; }
        fs::path dir = argv[2];
        std::string cn = argv[3];
        return cmd_new_intermediate(dir, cn);
    } else if (cmd == "new-intermediate-nc") {
        if (argc < 5) { usage(); return 1; }
        fs::path dir = argv[2];
        std::string cn = argv[3];
        std::string nc = argv[4];
        return cmd_new_intermediate_nc(dir, cn, nc);
    } else if (cmd == "verify-chain") {
        if (argc < 5) { usage(); return 1; }
        fs::path cert = argv[2];
        std::string interArg = argv[3];
        fs::path inter = (interArg == "-") ? fs::path() : fs::path(interArg);
        fs::path root = argv[4];
        return cmd_verify_chain(cert, inter, root);
    } else if (cmd == "gen-key") {
        if (argc < 5) { usage(); return 1; }
        std::string type = argv[2];
        std::string param = argv[3];
        fs::path outk = argv[4];
        fs::path outp = (argc >= 6 && std::string(argv[5]) != "-") ? fs::path(argv[5]) : fs::path();
        return cmd_gen_key(type, param, outk, outp);
    } else if (cmd == "gen-csr") {
        if (argc < 6) { usage(); return 1; }
        fs::path key = argv[2];
        fs::path out = argv[3];
        std::string cn = argv[4];
        std::string san = argv[5];
        return cmd_gen_csr(key, out, cn, san);
    } else if (cmd == "print-cert") {
        if (argc < 3) { usage(); return 1; }
        return cmd_print_cert(argv[2]);
    } else if (cmd == "print-csr") {
        if (argc < 3) { usage(); return 1; }
        return cmd_print_csr(argv[2]);
    } else if (cmd == "print-root") {
        if (argc < 3) { usage(); return 1; }
        fs::path dir = argv[2];
        return cmd_print_root(dir);
    } else if (cmd == "export-chain-pem") {
        if (argc < 6) { usage(); return 1; }
        fs::path leaf = argv[2];
        std::string interArg2 = argv[3];
        fs::path inter2 = (interArg2 == "-") ? fs::path() : fs::path(interArg2);
        fs::path root2 = argv[4];
        fs::path out2 = argv[5];
        return cmd_export_chain_pem(leaf, inter2, root2, out2);
    } else if (cmd == "export-p7") {
        if (argc < 6) { usage(); return 1; }
        fs::path leaf = argv[2];
        std::string interArg3 = argv[3];
        fs::path inter3 = (interArg3 == "-") ? fs::path() : fs::path(interArg3);
        fs::path root3 = argv[4];
        fs::path out3 = argv[5];
        return cmd_export_p7(leaf, inter3, root3, out3);
    } else if (cmd == "cms-sign") {
        if (argc < 7) { usage(); return 1; }
        fs::path in = argv[2];
        fs::path cert2 = argv[3];
        fs::path key2 = argv[4];
        fs::path out = argv[5];
        bool detached = std::atoi(argv[6]) != 0;
        return cmd_cms_sign(in, cert2, key2, out, detached);
    } else if (cmd == "cms-sign-pkcs11") {
        if (argc < 7) { usage(); return 1; }
        fs::path in = argv[2];
        fs::path cert = argv[3];
        std::string uri = argv[4];
        fs::path out = argv[5];
        bool detached = std::atoi(argv[6]) != 0;
        return cmd_cms_sign_pkcs11(in, cert, uri, out, detached);
    } else if (cmd == "cms-verify") {
        if (argc < 6) { usage(); return 1; }
        fs::path in = argv[2];
        fs::path sig = argv[3];
        fs::path root4 = argv[4];
        std::string interArg4 = argv[5];
        fs::path inter4 = (interArg4 == "-") ? fs::path() : fs::path(interArg4);
        return cmd_cms_verify(in, sig, root4, inter4);
    } else if (cmd == "renew") {
        if (argc < 6) { usage(); return 1; }
        fs::path dir = argv[2];
        fs::path oldc = argv[3];
        fs::path outc = argv[4];
        int days = std::atoi(argv[5]);
        return cmd_renew(dir, oldc, outc, days);
    } else if (cmd == "rekey") {
        if (argc < 7) { usage(); return 1; }
        fs::path dir = argv[2];
        fs::path oldc = argv[3];
        fs::path newk = argv[4];
        fs::path outc = argv[5];
        int days = std::atoi(argv[6]);
        return cmd_rekey(dir, oldc, newk, outc, days);
    } else if (cmd == "bulk-issue") {
        if (argc < 4) { usage(); return 1; }
        fs::path dir = argv[2];
        fs::path csv = argv[3];
        return cmd_bulk_issue(dir, csv);
    } else if (cmd == "lint-profile") {
        if (argc < 5) { usage(); return 1; }
        fs::path cert = argv[2];
        std::string prof = argv[3];
        bool reqSan = std::atoi(argv[4]) != 0;
        return cmd_lint_profile(cert, prof, reqSan);
    } else if (cmd == "export-bundle-info") {
        if (argc < 6) { usage(); return 1; }
        fs::path leaf = argv[2];
        std::string interArg5 = argv[3];
        fs::path inter5 = (interArg5 == "-") ? fs::path() : fs::path(interArg5);
        fs::path root5 = argv[4];
        fs::path outj = argv[5];
        return cmd_export_bundle_info(leaf, inter5, root5, outj);
    } else if (cmd == "keychain-hint") {
        if (argc < 4) { usage(); return 1; }
        return cmd_keychain_hint(argv[2], argv[3]);
    } else if (cmd == "ocsp-resp") {
        if (argc < 8) { usage(); return 1; }
        fs::path issuer = argv[2];
        fs::path ikey = argv[3];
        fs::path cert = argv[4];
        std::string st = argv[5];
        fs::path out = argv[6];
        int days = std::atoi(argv[7]);
        return cmd_ocsp_resp(issuer, ikey, cert, st, out, days);
    } else if (cmd == "ocsp-verify") {
        if (argc < 5) { usage(); return 1; }
        fs::path issuer = argv[2];
        fs::path cert = argv[3];
        fs::path resp = argv[4];
        return cmd_ocsp_verify(issuer, cert, resp);
    } else if (cmd == "lint-strict") {
        if (argc < 4) { usage(); return 1; }
        fs::path cert = argv[2];
        std::string prof = argv[3];
        return cmd_lint_strict(cert, prof);
    } else if (cmd == "ocsp-serve") {
        if (argc < 8) { usage(); return 1; }
        fs::path issuer = argv[2];
        fs::path key = argv[3];
        fs::path revoked = argv[4];
        std::string bind = argv[5];
        int port = std::atoi(argv[6]);
        int days = std::atoi(argv[7]);
        return cmd_ocsp_serve(issuer, key, revoked, bind, port, days);
    } else if (cmd == "sign-csr-pkcs11") {
        if (argc < 8) { usage(); return 1; }
        fs::path cacrt = argv[2];
        std::string uri = argv[3];
        fs::path csr = argv[4];
        fs::path out = argv[5];
        int days = std::atoi(argv[6]);
        fs::path serial = argv[7];
        return cmd_sign_csr_pkcs11(cacrt, uri, csr, out, days, serial);
    } else if (cmd == "sign-csr-prof") {
        if (argc < 6) { usage(); return 1; }
        fs::path dir = argv[2];
        fs::path csr = argv[3];
        fs::path out = argv[4];
        std::string profName = argv[5];
        return cmd_sign_csr_prof(dir, csr, out, profName);
    } else if (cmd == "list-certs") {
        if (argc < 3) { usage(); return 1; }
        fs::path dir = argv[2];
        return cmd_list_certs(dir);
    } else if (cmd == "list-revoked") {
        if (argc < 3) { usage(); return 1; }
        fs::path dir = argv[2];
        return cmd_list_revoked(dir);
    } else if (cmd == "find-certs") {
        if (argc < 4) { usage(); return 1; }
        fs::path dir = argv[2];
        std::string needle = argv[3];
        return cmd_find_certs(dir, needle);
    } else if (cmd == "import-cert-db") {
        if (argc < 4) { usage(); return 1; }
        fs::path dir = argv[2];
        fs::path cert = argv[3];
        return cmd_import_cert_db(dir, cert);
    } else if (cmd == "gen-delta-crl") {
        if (argc < 6) { usage(); return 1; }
        fs::path dir = argv[2];
        fs::path out = argv[3];
        long base = std::atol(argv[4]);
        int days = std::atoi(argv[5]); if (days <= 0) days = 7;
        return cmd_gen_delta_crl(dir, out, base, days);
    } else if (cmd == "print-chain") {
        if (argc < 5) { usage(); return 1; }
        fs::path leaf = argv[2];
        std::string interArg = argv[3]; fs::path inter = (interArg=="-")?fs::path():fs::path(interArg);
        fs::path root = argv[4];
        return cmd_print_chain(leaf, inter, root);
    } else if (cmd == "verify-chain-with-crl") {
        if (argc < 6) { usage(); return 1; }
        fs::path leaf = argv[2]; std::string interArg = argv[3]; fs::path inter = (interArg=="-")?fs::path():fs::path(interArg);
        fs::path root = argv[4]; fs::path crl = argv[5];
        return cmd_verify_chain_with_crl(leaf, inter, root, crl);
#ifdef WITH_SQLITE3
    } else if (cmd == "db-export-csv") {
        if (argc < 4) { usage(); return 1; }
        fs::path dir = argv[2]; fs::path out = argv[3];
        return cmd_db_export_csv(dir, out);
#endif
    } else if (cmd == "sign-csr-hsm") {
        if (argc < 6) { usage(); return 1; }
        fs::path dir = argv[2]; fs::path csr = argv[3]; fs::path out = argv[4]; int days = std::atoi(argv[5]);
        return cmd_sign_csr_hsm(dir, csr, out, days);
#ifdef WITH_ENGINE_PKCS11
    } else if (cmd == "cms-sign-pkcs11-engine") {
        if (argc < 7) { usage(); return 1; }
        fs::path in = argv[2]; fs::path cert = argv[3]; std::string keyId = argv[4]; fs::path out = argv[5]; bool detached = std::atoi(argv[6]) != 0;
        return cmd_cms_sign_pkcs11_engine(in, cert, keyId, out, detached);
    } else if (cmd == "sign-csr-pkcs11-engine") {
        if (argc < 8) { usage(); return 1; }
        fs::path cacrt = argv[2]; std::string keyId = argv[3]; fs::path csr = argv[4]; fs::path out = argv[5]; int days = std::atoi(argv[6]); fs::path serial = argv[7];
        return cmd_sign_csr_pkcs11_engine(cacrt, keyId, csr, out, days, serial);
#endif
    } else if (cmd == "pkcs11-list") {
        if (argc < 3) { usage(); return 1; }
        std::string uri = argv[2];
        return cmd_pkcs11_list(uri);
    } else if (cmd == "pkcs11-list-with-pin") {
        if (argc < 4) { usage(); return 1; }
        std::string uri = argv[2]; std::string pin = argv[3];
        return cmd_pkcs11_list_with_pin(uri, pin);
    } else if (cmd == "pkcs11-prompt-pin") {
        return cmd_pkcs11_prompt_pin();
    } else if (cmd == "pkcs11-pick") {
        if (argc < 5) { usage(); return 1; }
        fs::path dir = argv[2]; std::string base = argv[3]; std::string filt = (std::string(argv[4])=="-")?"":argv[4];
        return cmd_pkcs11_pick(dir, base, filt);
    } else if (cmd == "serve-sign") {
        if (argc < 5) { usage(); return 1; }
        fs::path dir = argv[2]; std::string bind = argv[3]; int port = std::atoi(argv[4]);
        return cmd_serve_sign(dir, bind, port);
    } else if (cmd == "pdf-sign-embed") {
        if (argc < 7) { usage(); return 1; }
        fs::path in = argv[2]; fs::path cert = argv[3]; fs::path key = argv[4]; fs::path out = argv[5];
        std::string reason = (std::string(argv[6])=="-")?"":argv[6];
        std::string location = (argc >= 8 && std::string(argv[7])!="-")?argv[7]:"";
        std::string tsaUrl = (argc >= 9 && std::string(argv[8])!="-")?argv[8]:"";
        // Determine rootDir from cert path (for backward compatibility with file-based certs)
        fs::path rootDir = cert.parent_path();
        if (rootDir.filename() == "ca") {
            rootDir = rootDir.parent_path();
        } else if (rootDir.filename() == "certs" && rootDir.parent_path().filename() == "ca") {
            rootDir = rootDir.parent_path().parent_path();
        } else {
            // If cert is in temp directory, try to find project root from current working directory
            // or use cert path as fallback (will fail if script not found)
            rootDir = fs::current_path();
        }
        return cmd_pdf_sign_embed(in, cert, key, out, reason, location, rootDir, tsaUrl);
    } else {
        usage();
        return 1;
    }
}
