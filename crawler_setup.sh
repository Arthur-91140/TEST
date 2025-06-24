#!/bin/bash

# Couleurs pour les logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[INFO] Début de l'installation du crawler web${NC}"

# Vérifier les dépendances système
echo -e "${GREEN}[INFO] Vérification et installation des dépendances${NC}"
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libcurl4-openssl-dev \
    libsqlite3-dev \
    libgumbo-dev \
    git \
    pkg-config

# Créer la structure du projet
PROJECT_DIR="web_crawler"
echo -e "${GREEN}[INFO] Création de la structure du projet dans ${PROJECT_DIR}${NC}"
mkdir -p ${PROJECT_DIR}/{src,include,build}
cd ${PROJECT_DIR}

# Télécharger toml++
echo -e "${GREEN}[INFO] Téléchargement de toml++${NC}"
git clone https://github.com/marzer/tomlplusplus.git external/tomlplusplus

# Créer le fichier CMakeLists.txt
echo -e "${GREEN}[INFO] Création du fichier CMakeLists.txt${NC}"
cat > CMakeLists.txt << 'EOF'
cmake_minimum_required(VERSION 3.10)
project(WebCrawler)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Trouver les packages
find_package(CURL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GUMBO REQUIRED gumbo)

# Inclure les headers
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/external/tomlplusplus/include
    ${CURL_INCLUDE_DIRS}
    ${GUMBO_INCLUDE_DIRS}
)

# Sources
set(SOURCES
    src/main.cpp
    src/crawler.cpp
    src/database.cpp
    src/config.cpp
    src/logger.cpp
    src/url_parser.cpp
    src/html_parser.cpp
)

# Exécutable
add_executable(crawler ${SOURCES})

# Lier les bibliothèques
target_link_libraries(crawler
    ${CURL_LIBRARIES}
    ${SQLite3_LIBRARIES}
    ${GUMBO_LIBRARIES}
    pthread
)

# Flags de compilation pour la performance
target_compile_options(crawler PRIVATE -O3 -march=native)
EOF

# Créer le fichier de configuration par défaut
echo -e "${GREEN}[INFO] Création du fichier de configuration par défaut${NC}"
cat > config.toml << 'EOF'
# Configuration du crawler web

[crawler]
# URL de départ
start_url = "https://example.com"

# Nombre de threads pour le crawling
threads = 10

# Délai entre les requêtes (en millisecondes)
delay_ms = 100

# User-Agent
user_agent = "MegaCrawler/1.0"

# Timeout pour les requêtes (en secondes)
timeout = 30

# Profondeur maximale (0 = illimité)
max_depth = 0

# Domaine spécifique (laisser vide pour crawler tous les domaines)
specific_domain = ""

[patterns]
# Patterns regex à rechercher (laisser vide pour désactiver)
# Exemples:
# email_pattern = "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
# phone_pattern = "\\+?[0-9]{1,3}[-. ]?\\(?[0-9]{1,4}\\)?[-. ]?[0-9]{1,4}[-. ]?[0-9]{1,9}"
patterns = []

[database]
# Chemin vers la base de données SQLite
path = "crawler.db"

[logging]
# Niveau de log: INFO, WARN, ERROR
level = "INFO"
# Fichier de log
file = "crawler.log"
EOF

# Créer logger.h
echo -e "${GREEN}[INFO] Création des fichiers header${NC}"
cat > include/logger.h << 'EOF'
#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <iomanip>

enum class LogLevel {
    INFO,
    WARN,
    ERROR
};

class Logger {
public:
    static Logger& getInstance();
    void init(const std::string& filename, LogLevel level);
    void log(LogLevel level, const std::string& message);
    
private:
    Logger() = default;
    std::ofstream file_;
    std::mutex mutex_;
    LogLevel min_level_ = LogLevel::INFO;
    
    std::string levelToString(LogLevel level);
    std::string getCurrentTime();
};
EOF

# Créer config.h
cat > include/config.h << 'EOF'
#pragma once
#include <string>
#include <vector>
#include <regex>

struct Config {
    // Crawler settings
    std::string start_url;
    int threads = 10;
    int delay_ms = 100;
    std::string user_agent = "Linux/1.0";
    int timeout = 30;
    int max_depth = 0;
    std::string specific_domain;
    
    // Patterns
    std::vector<std::regex> patterns;
    std::vector<std::string> pattern_strings;
    
    // Database
    std::string db_path = "crawler.db";
    
    // Logging
    std::string log_level = "INFO";
    std::string log_file = "crawler.log";
    
    bool loadFromFile(const std::string& filename);
};
EOF

# Créer database.h
cat > include/database.h << 'EOF'
#pragma once
#include <string>
#include <sqlite3.h>
#include <mutex>
#include <vector>

struct URLInfo {
    int id;
    std::string url;
    std::string parent_url;
    int depth;
    bool visited;
};

class Database {
public:
    Database(const std::string& path);
    ~Database();
    
    bool init();
    int insertURL(const std::string& url, const std::string& parent_url, int depth);
    bool markVisited(int id);
    std::vector<URLInfo> getUnvisitedURLs(int limit = 100);
    bool urlExists(const std::string& url);
    void insertPattern(const std::string& pattern, const std::string& url, const std::string& content);
    
private:
    sqlite3* db_;
    std::mutex mutex_;
    std::string path_;
};
EOF

# Créer crawler.h
cat > include/crawler.h << 'EOF'
#pragma once
#include <string>
#include <queue>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <thread>
#include <regex>
#include <condition_variable>
#include "config.h"
#include "database.h"

class Crawler {
public:
    Crawler(const Config& config, Database& db);
    void start();
    void stop();
    
private:
    Config config_;
    Database& db_;
    
    std::queue<URLInfo> url_queue_;
    std::unordered_set<std::string> seen_urls_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    
    std::atomic<bool> running_{false};
    std::vector<std::thread> workers_;
    
    void worker();
    void crawlURL(const URLInfo& url_info);
    std::string downloadPage(const std::string& url);
    void processPage(const std::string& url, const std::string& content, int depth);
    bool shouldCrawlDomain(const std::string& url);
};
EOF

# Créer url_parser.h
cat > include/url_parser.h << 'EOF'
#pragma once
#include <string>

class URLParser {
public:
    static std::string normalize(const std::string& url);
    static std::string getAbsoluteURL(const std::string& base, const std::string& relative);
    static std::string getDomain(const std::string& url);
    static bool isValidURL(const std::string& url);
};
EOF

# Créer html_parser.h
cat > include/html_parser.h << 'EOF'
#pragma once
#include <string>
#include <vector>
#include <regex>

class HTMLParser {
public:
    static std::vector<std::string> extractLinks(const std::string& html, const std::string& base_url);
    static std::vector<std::string> findPatterns(const std::string& html, const std::vector<std::regex>& patterns);
};
EOF

# Créer logger.cpp
echo -e "${GREEN}[INFO] Création des fichiers source${NC}"
cat > src/logger.cpp << 'EOF'
#include "logger.h"
#include <iostream>
#include <sstream>

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

void Logger::init(const std::string& filename, LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) {
        file_.close();
    }
    file_.open(filename, std::ios::app);
    min_level_ = level;
}

void Logger::log(LogLevel level, const std::string& message) {
    if (level < min_level_) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    std::string log_line = "[" + getCurrentTime() + "] [" + levelToString(level) + "] " + message;
    
    if (file_.is_open()) {
        file_ << log_line << std::endl;
        file_.flush();
    }
    
    // Aussi afficher dans la console
    if (level == LogLevel::ERROR) {
        std::cerr << "\033[0;31m" << log_line << "\033[0m" << std::endl;
    } else if (level == LogLevel::WARN) {
        std::cout << "\033[1;33m" << log_line << "\033[0m" << std::endl;
    } else {
        std::cout << "\033[0;32m" << log_line << "\033[0m" << std::endl;
    }
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

std::string Logger::getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}
EOF

# Créer config.cpp
cat > src/config.cpp << 'EOF'
#include "config.h"
#include "logger.h"
#include <toml++/toml.h>
#include <fstream>

bool Config::loadFromFile(const std::string& filename) {
    try {
        auto config = toml::parse_file(filename);
        
        // Crawler settings
        start_url = config["crawler"]["start_url"].value_or("https://example.com");
        threads = config["crawler"]["threads"].value_or(10);
        delay_ms = config["crawler"]["delay_ms"].value_or(100);
        user_agent = config["crawler"]["user_agent"].value_or("MegaCrawler/1.0");
        timeout = config["crawler"]["timeout"].value_or(30);
        max_depth = config["crawler"]["max_depth"].value_or(0);
        specific_domain = config["crawler"]["specific_domain"].value_or("");
        
        // Patterns
        if (auto patterns_array = config["patterns"]["patterns"].as_array()) {
            for (const auto& pattern : *patterns_array) {
                if (auto pattern_str = pattern.value<std::string>()) {
                    pattern_strings.push_back(*pattern_str);
                    patterns.emplace_back(*pattern_str);
                }
            }
        }
        
        // Database
        db_path = config["database"]["path"].value_or("crawler.db");
        
        // Logging
        log_level = config["logging"]["level"].value_or("INFO");
        log_file = config["logging"]["file"].value_or("crawler.log");
        
        return true;
    } catch (const toml::parse_error& err) {
        Logger::getInstance().log(LogLevel::ERROR, "Failed to parse config: " + std::string(err.what()));
        return false;
    }
}
EOF

# Créer database.cpp
cat > src/database.cpp << 'EOF'
#include "database.h"
#include "logger.h"
#include <sstream>

Database::Database(const std::string& path) : path_(path), db_(nullptr) {}

Database::~Database() {
    if (db_) {
        sqlite3_close(db_);
    }
}

bool Database::init() {
    if (sqlite3_open(path_.c_str(), &db_) != SQLITE_OK) {
        Logger::getInstance().log(LogLevel::ERROR, "Cannot open database: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }
    
    // Créer les tables
    const char* create_urls_table = R"(
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            parent_url TEXT,
            depth INTEGER DEFAULT 0,
            visited BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_visited ON urls(visited);
        CREATE INDEX IF NOT EXISTS idx_url ON urls(url);
    )";
    
    const char* create_patterns_table = R"(
        CREATE TABLE IF NOT EXISTS patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            url TEXT NOT NULL,
            content TEXT NOT NULL,
            found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    )";
    
    char* err_msg = nullptr;
    if (sqlite3_exec(db_, create_urls_table, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        Logger::getInstance().log(LogLevel::ERROR, "SQL error: " + std::string(err_msg));
        sqlite3_free(err_msg);
        return false;
    }
    
    if (sqlite3_exec(db_, create_patterns_table, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        Logger::getInstance().log(LogLevel::ERROR, "SQL error: " + std::string(err_msg));
        sqlite3_free(err_msg);
        return false;
    }
    
    // Optimisations pour la performance
    sqlite3_exec(db_, "PRAGMA synchronous = OFF", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA journal_mode = WAL", nullptr, nullptr, nullptr);
    
    return true;
}

int Database::insertURL(const std::string& url, const std::string& parent_url, int depth) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    const char* sql = "INSERT OR IGNORE INTO urls (url, parent_url, depth) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        Logger::getInstance().log(LogLevel::ERROR, "Failed to prepare statement");
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, url.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, parent_url.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, depth);
    
    int id = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        id = sqlite3_last_insert_rowid(db_);
    }
    
    sqlite3_finalize(stmt);
    return id;
}

bool Database::markVisited(int id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    const char* sql = "UPDATE urls SET visited = 1 WHERE id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, id);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return success;
}

std::vector<URLInfo> Database::getUnvisitedURLs(int limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<URLInfo> urls;
    
    const char* sql = "SELECT id, url, parent_url, depth FROM urls WHERE visited = 0 LIMIT ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return urls;
    }
    
    sqlite3_bind_int(stmt, 1, limit);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        URLInfo info;
        info.id = sqlite3_column_int(stmt, 0);
        info.url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        info.parent_url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        info.depth = sqlite3_column_int(stmt, 3);
        info.visited = false;
        urls.push_back(info);
    }
    
    sqlite3_finalize(stmt);
    return urls;
}

bool Database::urlExists(const std::string& url) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    const char* sql = "SELECT 1 FROM urls WHERE url = ? LIMIT 1";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, url.c_str(), -1, SQLITE_STATIC);
    bool exists = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    
    return exists;
}

void Database::insertPattern(const std::string& pattern, const std::string& url, const std::string& content) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    const char* sql = "INSERT INTO patterns (pattern, url, content) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return;
    }
    
    sqlite3_bind_text(stmt, 1, pattern.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, url.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, content.c_str(), -1, SQLITE_STATIC);
    
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}
EOF

# Créer url_parser.cpp
cat > src/url_parser.cpp << 'EOF'
#include "url_parser.h"
#include <algorithm>
#include <cctype>
#include <regex>

std::string URLParser::normalize(const std::string& url) {
    std::string normalized = url;
    
    // Convertir en minuscules le schéma et le domaine
    size_t scheme_end = normalized.find("://");
    if (scheme_end != std::string::npos) {
        size_t domain_end = normalized.find('/', scheme_end + 3);
        if (domain_end == std::string::npos) {
            domain_end = normalized.length();
        }
        
        std::transform(normalized.begin(), normalized.begin() + domain_end,
                      normalized.begin(), ::tolower);
    }
    
    // Supprimer le fragment
    size_t fragment = normalized.find('#');
    if (fragment != std::string::npos) {
        normalized = normalized.substr(0, fragment);
    }
    
    // Supprimer le slash final
    if (!normalized.empty() && normalized.back() == '/' && 
        std::count(normalized.begin(), normalized.end(), '/') > 2) {
        normalized.pop_back();
    }
    
    return normalized;
}

std::string URLParser::getAbsoluteURL(const std::string& base, const std::string& relative) {
    if (relative.empty()) return "";
    
    // URL absolue
    if (relative.find("://") != std::string::npos) {
        return relative;
    }
    
    // Protocole relatif
    if (relative.substr(0, 2) == "//") {
        size_t scheme_end = base.find("://");
        if (scheme_end != std::string::npos) {
            return base.substr(0, scheme_end) + ":" + relative;
        }
    }
    
    // Chemin absolu
    if (relative[0] == '/') {
        size_t scheme_end = base.find("://");
        if (scheme_end != std::string::npos) {
            size_t path_start = base.find('/', scheme_end + 3);
            if (path_start != std::string::npos) {
                return base.substr(0, path_start) + relative;
            } else {
                return base + relative;
            }
        }
    }
    
    // Chemin relatif
    size_t last_slash = base.rfind('/');
    if (last_slash != std::string::npos && last_slash > base.find("://") + 2) {
        return base.substr(0, last_slash + 1) + relative;
    }
    
    return base + "/" + relative;
}

std::string URLParser::getDomain(const std::string& url) {
    size_t scheme_end = url.find("://");
    if (scheme_end == std::string::npos) return "";
    
    size_t domain_start = scheme_end + 3;
    size_t domain_end = url.find('/', domain_start);
    
    if (domain_end == std::string::npos) {
        return url.substr(domain_start);
    }
    
    return url.substr(domain_start, domain_end - domain_start);
}

bool URLParser::isValidURL(const std::string& url) {
    static const std::regex url_regex(
        R"(^https?://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+$)"
    );
    return std::regex_match(url, url_regex);
}
EOF

# Créer html_parser.cpp
cat > src/html_parser.cpp << 'EOF'
#include "html_parser.h"
#include "url_parser.h"
#include <gumbo.h>
#include <regex>

static void extractLinksFromNode(GumboNode* node, const std::string& base_url, 
                                 std::vector<std::string>& links) {
    if (node->type != GUMBO_NODE_ELEMENT) return;
    
    GumboAttribute* href = nullptr;
    
    // Chercher les liens dans différentes balises
    if (node->v.element.tag == GUMBO_TAG_A ||
        node->v.element.tag == GUMBO_TAG_LINK) {
        href = gumbo_get_attribute(&node->v.element.attributes, "href");
    } else if (node->v.element.tag == GUMBO_TAG_IMG ||
               node->v.element.tag == GUMBO_TAG_SCRIPT ||
               node->v.element.tag == GUMBO_TAG_IFRAME) {
        href = gumbo_get_attribute(&node->v.element.attributes, "src");
    } else if (node->v.element.tag == GUMBO_TAG_OBJECT) {
        href = gumbo_get_attribute(&node->v.element.attributes, "data");
    }
    
    if (href) {
        std::string url = URLParser::getAbsoluteURL(base_url, href->value);
        if (!url.empty() && URLParser::isValidURL(url)) {
            links.push_back(URLParser::normalize(url));
        }
    }
    
    // Récursion sur les enfants
    GumboVector* children = &node->v.element.children;
    for (unsigned int i = 0; i < children->length; ++i) {
        extractLinksFromNode(static_cast<GumboNode*>(children->data[i]), base_url, links);
    }
}

std::vector<std::string> HTMLParser::extractLinks(const std::string& html, 
                                                  const std::string& base_url) {
    std::vector<std::string> links;
    
    GumboOutput* output = gumbo_parse(html.c_str());
    extractLinksFromNode(output->root, base_url, links);
    gumbo_destroy_output(&kGumboDefaultOptions, output);
    
    // Supprimer les doublons
    std::sort(links.begin(), links.end());
    links.erase(std::unique(links.begin(), links.end()), links.end());
    
    return links;
}

std::vector<std::string> HTMLParser::findPatterns(const std::string& html, 
                                                  const std::vector<std::regex>& patterns) {
    std::vector<std::string> matches;
    
    for (const auto& pattern : patterns) {
        std::sregex_iterator it(html.begin(), html.end(), pattern);
        std::sregex_iterator end;
        
        while (it != end) {
            matches.push_back(it->str());
            ++it;
        }
    }
    
    return matches;
}
EOF

# Créer crawler.cpp
cat > src/crawler.cpp << 'EOF'
#include "crawler.h"
#include "logger.h"
#include "url_parser.h"
#include "html_parser.h"
#include <curl/curl.h>
#include <chrono>
#include <sstream>

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

Crawler::Crawler(const Config& config, Database& db) 
    : config_(config), db_(db) {}

void Crawler::start() {
    running_ = true;
    
    // Ajouter l'URL de départ
    db_.insertURL(config_.start_url, "", 0);
    
    // Charger les URLs non visitées
    auto urls = db_.getUnvisitedURLs(1000);
    for (const auto& url : urls) {
        url_queue_.push(url);
    }
    
    // Démarrer les workers
    for (int i = 0; i < config_.threads; ++i) {
        workers_.emplace_back(&Crawler::worker, this);
    }
    
    Logger::getInstance().log(LogLevel::INFO, 
        "Crawler started with " + std::to_string(config_.threads) + " threads");
}

void Crawler::stop() {
    running_ = false;
    cv_.notify_all();
    
    for (auto& worker : workers_) {
        worker.join();
    }
    
    Logger::getInstance().log(LogLevel::INFO, "Crawler stopped");
}

void Crawler::worker() {
    while (running_) {
        URLInfo url_info;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            cv_.wait(lock, [this] { return !url_queue_.empty() || !running_; });
            
            if (!running_) break;
            if (url_queue_.empty()) continue;
            
            url_info = url_queue_.front();
            url_queue_.pop();
        }
        
        crawlURL(url_info);
        
        // Délai entre les requêtes
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.delay_ms));
    }
}

void Crawler::crawlURL(const URLInfo& url_info) {
    Logger::getInstance().log(LogLevel::INFO, "Crawling: " + url_info.url);
    
    // Vérifier si on doit crawler ce domaine
    if (!shouldCrawlDomain(url_info.url)) {
        Logger::getInstance().log(LogLevel::INFO, "Skipping domain: " + url_info.url);
        return;
    }
    
    // Télécharger la page
    std::string content = downloadPage(url_info.url);
    if (content.empty()) {
        return;
    }
    
    // Marquer comme visité
    db_.markVisited(url_info.id);
    
    // Traiter la page
    processPage(url_info.url, content, url_info.depth);
    
    // Recharger la queue si nécessaire
    if (url_queue_.size() < 100) {
        auto new_urls = db_.getUnvisitedURLs(1000);
        for (const auto& url : new_urls) {
            url_queue_.push(url);
        }
    }
}

std::string Crawler::downloadPage(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        Logger::getInstance().log(LogLevel::ERROR, "Failed to init CURL");
        return "";
    }
    
    std::string response;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, config_.user_agent.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config_.timeout);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        Logger::getInstance().log(LogLevel::ERROR, 
            "Failed to download " + url + ": " + curl_easy_strerror(res));
        response.clear();
    }
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    if (http_code >= 400) {
        Logger::getInstance().log(LogLevel::WARN, 
            "HTTP " + std::to_string(http_code) + " for " + url);
        response.clear();
    }
    
    curl_easy_cleanup(curl);
    return response;
}

void Crawler::processPage(const std::string& url, const std::string& content, int depth) {
    // Extraire les liens
    auto links = HTMLParser::extractLinks(content, url);
    
    for (const auto& link : links) {
        // Vérifier la profondeur maximale
        if (config_.max_depth > 0 && depth >= config_.max_depth) {
            continue;
        }
        
        // Insérer dans la base de données
        db_.insertURL(link, url, depth + 1);
    }
    
    Logger::getInstance().log(LogLevel::INFO, 
        "Found " + std::to_string(links.size()) + " links on " + url);
    
    // Rechercher les patterns si configurés
    if (!config_.patterns.empty()) {
        auto matches = HTMLParser::findPatterns(content, config_.patterns);
        
        for (size_t i = 0; i < matches.size() && i < config_.patterns.size(); ++i) {
            if (!matches[i].empty()) {
                db_.insertPattern(config_.pattern_strings[i], url, matches[i]);
                Logger::getInstance().log(LogLevel::INFO, 
                    "Pattern match found on " + url);
            }
        }
    }
}

bool Crawler::shouldCrawlDomain(const std::string& url) {
    if (config_.specific_domain.empty()) {
        return true;
    }
    
    std::string domain = URLParser::getDomain(url);
    return domain.find(config_.specific_domain) != std::string::npos;
}
EOF

# Créer main.cpp
cat > src/main.cpp << 'EOF'
#include <iostream>
#include <csignal>
#include <curl/curl.h>
#include "config.h"
#include "database.h"
#include "crawler.h"
#include "logger.h"

std::unique_ptr<Crawler> g_crawler;

void signalHandler(int signum) {
    Logger::getInstance().log(LogLevel::INFO, "Interrupt signal received");
    if (g_crawler) {
        g_crawler->stop();
    }
    exit(signum);
}

int main(int argc, char* argv[]) {
    // Gestionnaire de signaux
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Fichier de configuration
    std::string config_file = "config.toml";
    if (argc > 1) {
        config_file = argv[1];
    }
    
    // Charger la configuration
    Config config;
    if (!config.loadFromFile(config_file)) {
        std::cerr << "Failed to load configuration from " << config_file << std::endl;
        return 1;
    }
    
    // Initialiser le logger
    LogLevel log_level = LogLevel::INFO;
    if (config.log_level == "WARN") log_level = LogLevel::WARN;
    else if (config.log_level == "ERROR") log_level = LogLevel::ERROR;
    
    Logger::getInstance().init(config.log_file, log_level);
    Logger::getInstance().log(LogLevel::INFO, "Web Crawler starting...");
    
    // Initialiser CURL
    curl_global_init(CURL_GLOBAL_ALL);
    
    // Initialiser la base de données
    Database db(config.db_path);
    if (!db.init()) {
        Logger::getInstance().log(LogLevel::ERROR, "Failed to initialize database");
        return 1;
    }
    
    // Créer et démarrer le crawler
    g_crawler = std::make_unique<Crawler>(config, db);
    g_crawler->start();
    
    // Attendre l'arrêt
    Logger::getInstance().log(LogLevel::INFO, "Crawler is running. Press Ctrl+C to stop.");
    
    // Boucle principale
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    // Nettoyage
    curl_global_cleanup();
    
    return 0;
}
EOF

# Compiler le projet
echo -e "${GREEN}[INFO] Compilation du projet${NC}"
cd build
cmake ..
make -j$(nproc)

# Vérifier si la compilation a réussi
if [ -f "crawler" ]; then
    echo -e "${GREEN}[INFO] Compilation réussie!${NC}"
    cd ..
    echo -e "${GREEN}[INFO] Le crawler est prêt dans ${PROJECT_DIR}/build/crawler${NC}"
    echo -e "${GREEN}[INFO] Configuration dans ${PROJECT_DIR}/config.toml${NC}"
    echo -e "${YELLOW}[INFO] Pour lancer le crawler: cd ${PROJECT_DIR} && ./build/crawler${NC}"
else
    echo -e "${RED}[ERROR] La compilation a échoué${NC}"
    exit 1
fi
EOF
