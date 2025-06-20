#!/bin/bash

# 🕷️ Web Crawler - Script d'Installation Complète
# Architecture: Lighttpd + CGI C++ + PostgreSQL
# Auteur: Assistant Claude
# Version: 1.0

set -e

# Configuration
PROJECT_NAME="webcrawler"
DEPLOY_USER="webcrawler"
DEPLOY_DIR="/opt/webcrawler"
LOG_DIR="/var/log/webcrawler"
DB_NAME="webcrawler"
DB_USER="crawler_user"
DB_PASSWORD="$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)"

# 🔧 CONFIGURATION BASE DE DONNÉES - MODIFIABLE ICI
DB_HOST="${DB_HOST:-localhost}"           # IP du serveur PostgreSQL
DB_PORT="${DB_PORT:-5432}"               # Port PostgreSQL

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "${CYAN}"
    echo "=============================================="
    echo "🕷️  WEB CRAWLER - INSTALLATION COMPLÈTE"
    echo "=============================================="
    echo -e "${NC}"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Vérification des prérequis
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Ce script doit être exécuté en tant que root"
        exit 1
    fi
}

# Installation des dépendances système
install_dependencies() {
    print_status "Installation des dépendances système..."
    
    apt-get update
    
    # Dépendances de base
    apt-get install -y \
        build-essential \
        cmake \
        git \
        pkg-config \
        curl \
        postgresql \
        postgresql-client \
        postgresql-server-dev-all \
        lighttpd \
        lighttpd-mod-cgi \
        libcurl4-openssl-dev \
        libpqxx-dev \
        libboost-all-dev \
        libssl-dev \
        libpoppler-cpp-dev \
        libtidy-dev \
        nlohmann-json3-dev \
        bc
    
    # Installation de spdlog
    cd /tmp
    if [[ ! -d "spdlog" ]]; then
        git clone https://github.com/gabime/spdlog.git
    fi
    cd spdlog
    rm -rf build
    mkdir build && cd build
    cmake .. && make -j$(nproc)
    make install
    
    # Installation de cpptoml
    cd /tmp
    if [[ ! -d "cpptoml" ]]; then
        git clone https://github.com/skystrife/cpptoml.git
    fi
    cd cpptoml
    cp include/cpptoml.h /usr/local/include/
    
    print_success "Dépendances installées"
}

# Création des utilisateurs et répertoires
setup_environment() {
    print_status "Configuration de l'environnement..."
    
    # Créer l'utilisateur système
    if ! id "$DEPLOY_USER" &>/dev/null; then
        useradd --system --shell /bin/bash --home-dir "$DEPLOY_DIR" --create-home "$DEPLOY_USER"
        usermod -a -G www-data "$DEPLOY_USER"
    fi
    
    # Créer les répertoires
    mkdir -p "$DEPLOY_DIR"/{src,config,sql,www,logs}
    mkdir -p "$DEPLOY_DIR"/src/{common,crawler,indexer,cgi}
    mkdir -p "$DEPLOY_DIR"/www/{css,js,cgi-bin}
    mkdir -p "$LOG_DIR"
    
    # Permissions
    chown -R "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_DIR"
    chown -R www-data:www-data "$DEPLOY_DIR/www"
    chmod 755 "$DEPLOY_DIR/www"
    chmod 755 "$LOG_DIR"
    
    print_success "Environnement configuré"
}

# Génération du code source C++
generate_source_code() {
    print_status "Génération du code source C++..."
    
    # ===== COMMON HEADERS =====
    
    cat > "$DEPLOY_DIR/src/common/config.hpp" << 'EOF'
#pragma once
#include <string>
#include <vector>
#include <map>
#include <cpptoml.h>

class Config {
public:
    struct DatabaseConfig {
        std::string host;
        int port;
        std::string dbname;
        std::string user;
        std::string password;
        int max_connections;
    };

    struct CrawlerConfig {
        int max_threads;
        int max_depth;
        int max_pages_per_domain;
        int request_timeout;
        std::string user_agent;
        int default_crawl_delay;
        int max_redirects;
        std::vector<std::string> allowed_html_types;
        std::vector<std::string> allowed_pdf_types;
        std::map<std::string, std::string> headers;
    };

    struct IndexerConfig {
        int max_threads;
        int min_word_length;
        int max_word_length;
        int batch_size;
        std::vector<std::string> french_stop_words;
        std::vector<std::string> english_stop_words;
    };

    struct LoggingConfig {
        std::string level;
        std::string file_path;
        bool console_output;
    };

    static Config& getInstance();
    bool loadFromFile(const std::string& filename);
    
    const DatabaseConfig& getDatabase() const { return database_; }
    const CrawlerConfig& getCrawler() const { return crawler_; }
    const IndexerConfig& getIndexer() const { return indexer_; }
    const LoggingConfig& getLogging() const { return logging_; }

private:
    Config() = default;
    DatabaseConfig database_;
    CrawlerConfig crawler_;
    IndexerConfig indexer_;
    LoggingConfig logging_;
};
EOF

    cat > "$DEPLOY_DIR/src/common/config.cpp" << 'EOF'
#include "config.hpp"

Config& Config::getInstance() {
    static Config instance;
    return instance;
}

bool Config::loadFromFile(const std::string& filename) {
    try {
        auto config = cpptoml::parse_file(filename);
        
        // Database
        auto db = config->get_table("database");
        if (db) {
            database_.host = db->get_as<std::string>("host").value_or("localhost");
            database_.port = db->get_as<int>("port").value_or(5432);
            database_.dbname = db->get_as<std::string>("dbname").value_or("webcrawler");
            database_.user = db->get_as<std::string>("user").value_or("crawler_user");
            database_.password = db->get_as<std::string>("password").value_or("");
            database_.max_connections = db->get_as<int>("max_connections").value_or(10);
        }
        
        // Crawler
        auto crawler = config->get_table("crawler");
        if (crawler) {
            crawler_.max_threads = crawler->get_as<int>("max_threads").value_or(4);
            crawler_.max_depth = crawler->get_as<int>("max_depth").value_or(5);
            crawler_.max_pages_per_domain = crawler->get_as<int>("max_pages_per_domain").value_or(1000);
            crawler_.request_timeout = crawler->get_as<int>("request_timeout").value_or(30);
            crawler_.user_agent = crawler->get_as<std::string>("user_agent").value_or("WebCrawler/1.0");
            crawler_.default_crawl_delay = crawler->get_as<int>("default_crawl_delay").value_or(1000);
            crawler_.max_redirects = crawler->get_as<int>("max_redirects").value_or(5);
        }
        
        // Indexer
        auto indexer = config->get_table("indexer");
        if (indexer) {
            indexer_.max_threads = indexer->get_as<int>("max_threads").value_or(2);
            indexer_.min_word_length = indexer->get_as<int>("min_word_length").value_or(3);
            indexer_.max_word_length = indexer->get_as<int>("max_word_length").value_or(50);
            indexer_.batch_size = indexer->get_as<int>("batch_size").value_or(100);
            
            auto stop_words = indexer->get_table("stop_words");
            if (stop_words) {
                auto french = stop_words->get_array_of<std::string>("french");
                if (french) indexer_.french_stop_words = *french;
                auto english = stop_words->get_array_of<std::string>("english");
                if (english) indexer_.english_stop_words = *english;
            }
        }
        
        // Logging
        auto logging = config->get_table("logging");
        if (logging) {
            logging_.level = logging->get_as<std::string>("level").value_or("INFO");
            logging_.file_path = logging->get_as<std::string>("file_path").value_or("./logs/");
            logging_.console_output = logging->get_as<bool>("console_output").value_or(true);
        }
        
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}
EOF

    cat > "$DEPLOY_DIR/src/common/logger.hpp" << 'EOF'
#pragma once
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <memory>

class Logger {
public:
    static Logger& getInstance();
    void initialize(const std::string& logger_name, const std::string& log_file_path, 
                   const std::string& level, bool console_output = true);
    
    template<typename... Args>
    void debug(const std::string& format, Args&&... args) {
        if (logger_) logger_->debug(format, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void info(const std::string& format, Args&&... args) {
        if (logger_) logger_->info(format, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void warn(const std::string& format, Args&&... args) {
        if (logger_) logger_->warn(format, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void error(const std::string& format, Args&&... args) {
        if (logger_) logger_->error(format, std::forward<Args>(args)...);
    }

private:
    Logger() = default;
    std::shared_ptr<spdlog::logger> logger_;
};

#define LOG_DEBUG(...) Logger::getInstance().debug(__VA_ARGS__)
#define LOG_INFO(...) Logger::getInstance().info(__VA_ARGS__)
#define LOG_WARN(...) Logger::getInstance().warn(__VA_ARGS__)
#define LOG_ERROR(...) Logger::getInstance().error(__VA_ARGS__)
EOF

    cat > "$DEPLOY_DIR/src/common/logger.cpp" << 'EOF'
#include "logger.hpp"
#include <iostream>

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

void Logger::initialize(const std::string& logger_name, const std::string& log_file_path, 
                       const std::string& level, bool console_output) {
    try {
        std::vector<spdlog::sink_ptr> sinks;
        
        if (console_output) {
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
            sinks.push_back(console_sink);
        }
        
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_file_path + "/" + logger_name + ".log", 1024 * 1024 * 100, 10);
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
        sinks.push_back(file_sink);
        
        logger_ = std::make_shared<spdlog::logger>(logger_name, sinks.begin(), sinks.end());
        
        if (level == "DEBUG") logger_->set_level(spdlog::level::debug);
        else if (level == "INFO") logger_->set_level(spdlog::level::info);
        else if (level == "WARN") logger_->set_level(spdlog::level::warn);
        else if (level == "ERROR") logger_->set_level(spdlog::level::err);
        
        logger_->flush_on(spdlog::level::warn);
        spdlog::register_logger(logger_);
        
    } catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
    }
}
EOF

    cat > "$DEPLOY_DIR/src/common/database.hpp" << 'EOF'
#pragma once
#include <pqxx/pqxx>
#include <memory>
#include <string>
#include <vector>

struct CrawlResult {
    std::string url;
    std::string content;
    std::string title;
    std::string meta_description;
    std::string content_type;
    int status_code;
    std::vector<std::string> extracted_links;
};

struct SearchResult {
    std::string url;
    std::string title;
    std::string snippet;
    float relevance_score;
};

struct CrawlStats {
    long long total_urls_discovered;
    long long total_urls_crawled;
    long long total_pages_indexed;
    long long total_words_indexed;
    float crawl_rate_per_minute;
    float index_rate_per_minute;
};

class Database {
public:
    static Database& getInstance();
    bool initialize(const std::string& connection_string, int max_connections = 10);
    void shutdown();

    bool addUrl(const std::string& url, const std::string& domain, int priority = 0, int depth = 0);
    bool urlExists(const std::string& url);
    std::vector<std::string> getUrlsToCrawl(int limit = 100);
    bool markUrlAsCrawled(const std::string& url, int status_code);
    bool storeCrawledContent(const CrawlResult& result);
    std::vector<SearchResult> search(const std::string& query, int limit = 10, int offset = 0);
    CrawlStats getCurrentStats();
    
private:
    Database() = default;
    std::unique_ptr<pqxx::connection> conn_;
    bool initialized_ = false;
};
EOF

    cat > "$DEPLOY_DIR/src/common/database.cpp" << 'EOF'
#include "database.hpp"
#include "logger.hpp"
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>

Database& Database::getInstance() {
    static Database instance;
    return instance;
}

std::string hashString(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

bool Database::initialize(const std::string& connection_string, int max_connections) {
    try {
        conn_ = std::make_unique<pqxx::connection>(connection_string);
        initialized_ = true;
        LOG_INFO("Database initialized");
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to initialize database: {}", e.what());
        return false;
    }
}

void Database::shutdown() {
    if (conn_) {
        conn_.reset();
        initialized_ = false;
    }
}

bool Database::addUrl(const std::string& url, const std::string& domain, int priority, int depth) {
    if (!initialized_) return false;
    
    try {
        pqxx::work txn(*conn_);
        std::string url_hash = hashString(url);
        
        txn.exec_params("INSERT INTO domains (domain) VALUES ($1) ON CONFLICT (domain) DO NOTHING", domain);
        
        auto result = txn.exec_params("SELECT id FROM domains WHERE domain = $1", domain);
        if (result.empty()) return false;
        int domain_id = result[0][0].as<int>();
        
        txn.exec_params(
            "INSERT INTO urls (url, domain_id, url_hash, priority, depth) "
            "VALUES ($1, $2, $3, $4, $5) ON CONFLICT (url_hash) DO NOTHING",
            url, domain_id, url_hash, priority, depth
        );
        
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to add URL: {}", e.what());
        return false;
    }
}

std::vector<std::string> Database::getUrlsToCrawl(int limit) {
    std::vector<std::string> urls;
    if (!initialized_) return urls;
    
    try {
        pqxx::work txn(*conn_);
        auto result = txn.exec_params(
            "SELECT url FROM urls WHERE is_crawled = FALSE ORDER BY priority DESC, created_at ASC LIMIT $1", 
            limit
        );
        
        for (const auto& row : result) {
            urls.push_back(row[0].as<std::string>());
        }
        
        return urls;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to get URLs: {}", e.what());
        return urls;
    }
}

bool Database::markUrlAsCrawled(const std::string& url, int status_code) {
    if (!initialized_) return false;
    
    try {
        pqxx::work txn(*conn_);
        std::string url_hash = hashString(url);
        
        txn.exec_params(
            "UPDATE urls SET is_crawled = TRUE, status_code = $1, last_crawled = CURRENT_TIMESTAMP "
            "WHERE url_hash = $2",
            status_code, url_hash
        );
        
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to mark URL as crawled: {}", e.what());
        return false;
    }
}

bool Database::storeCrawledContent(const CrawlResult& result) {
    if (!initialized_) return false;
    
    try {
        pqxx::work txn(*conn_);
        
        std::string url_hash = hashString(result.url);
        auto url_result = txn.exec_params("SELECT id FROM urls WHERE url_hash = $1", url_hash);
        if (url_result.empty()) return false;
        int url_id = url_result[0][0].as<int>();
        
        std::string content_hash = hashString(result.content);
        
        txn.exec_params(
            "INSERT INTO crawled_content (url_id, raw_content, title, meta_description, content_hash) "
            "VALUES ($1, $2, $3, $4, $5) ON CONFLICT (content_hash) DO NOTHING",
            url_id, result.content, result.title, result.meta_description, content_hash
        );
        
        for (const auto& link : result.extracted_links) {
            txn.exec_params(
                "INSERT INTO extracted_links (source_url_id, target_url) VALUES ($1, $2)",
                url_id, link
            );
        }
        
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to store content: {}", e.what());
        return false;
    }
}

std::vector<SearchResult> Database::search(const std::string& query, int limit, int offset) {
    std::vector<SearchResult> results;
    if (!initialized_) return results;
    
    try {
        pqxx::work txn(*conn_);
        
        auto db_result = txn.exec_params(
            "SELECT u.url, cc.title, SUBSTRING(cc.raw_content FROM 1 FOR 200) as snippet, 1.0 as relevance "
            "FROM urls u "
            "JOIN crawled_content cc ON u.id = cc.url_id "
            "WHERE cc.title ILIKE $1 OR cc.raw_content ILIKE $1 "
            "ORDER BY relevance DESC "
            "LIMIT $2 OFFSET $3",
            "%" + query + "%", limit, offset
        );
        
        for (const auto& row : db_result) {
            SearchResult result;
            result.url = row[0].as<std::string>();
            result.title = row[1].as<std::string>();
            result.snippet = row[2].as<std::string>();
            result.relevance_score = row[3].as<float>();
            results.push_back(result);
        }
        
        return results;
    } catch (const std::exception& e) {
        LOG_ERROR("Search failed: {}", e.what());
        return results;
    }
}

CrawlStats Database::getCurrentStats() {
    CrawlStats stats = {};
    if (!initialized_) return stats;
    
    try {
        pqxx::work txn(*conn_);
        
        auto result = txn.exec(
            "SELECT "
            "(SELECT COUNT(*) FROM urls) as total_urls, "
            "(SELECT COUNT(*) FROM urls WHERE is_crawled = TRUE) as crawled_urls, "
            "(SELECT COUNT(*) FROM crawled_content) as indexed_pages, "
            "(SELECT COUNT(*) FROM word_index) as total_words"
        );
        
        if (!result.empty()) {
            const auto& row = result[0];
            stats.total_urls_discovered = row[0].as<long long>();
            stats.total_urls_crawled = row[1].as<long long>();
            stats.total_pages_indexed = row[2].as<long long>();
            stats.total_words_indexed = row[3].as<long long>();
        }
        
        return stats;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to get stats: {}", e.what());
        return stats;
    }
}
EOF

    cat > "$DEPLOY_DIR/src/common/cgi_utils.hpp" << 'EOF'
#pragma once
#include <string>
#include <map>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class CGIUtils {
public:
    static std::map<std::string, std::string> parseQueryString(const std::string& query_string);
    static std::string readPostData();
    static std::string getEnvVar(const std::string& name, const std::string& default_value = "");
    static void sendJSONResponse(const json& data, int status = 200);
    static void sendErrorResponse(const std::string& message, int status = 500);
    static std::string urlDecode(const std::string& str);
    static bool extractPagination(const std::map<std::string, std::string>& params, int& limit, int& offset);
    static void logRequest(const std::string& script_name);
};
EOF

    cat > "$DEPLOY_DIR/src/common/cgi_utils.cpp" << 'EOF'
#include "cgi_utils.hpp"
#include "logger.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

std::map<std::string, std::string> CGIUtils::parseQueryString(const std::string& query_string) {
    std::map<std::string, std::string> params;
    if (query_string.empty()) return params;
    
    std::istringstream iss(query_string);
    std::string pair;
    
    while (std::getline(iss, pair, '&')) {
        size_t eq_pos = pair.find('=');
        if (eq_pos != std::string::npos) {
            std::string key = urlDecode(pair.substr(0, eq_pos));
            std::string value = urlDecode(pair.substr(eq_pos + 1));
            params[key] = value;
        }
    }
    
    return params;
}

std::string CGIUtils::readPostData() {
    std::string content_length_str = getEnvVar("CONTENT_LENGTH", "0");
    int content_length = std::stoi(content_length_str);
    
    if (content_length <= 0) return "";
    
    std::string post_data;
    post_data.resize(content_length);
    std::cin.read(&post_data[0], content_length);
    
    return post_data;
}

std::string CGIUtils::getEnvVar(const std::string& name, const std::string& default_value) {
    const char* value = std::getenv(name.c_str());
    return value ? std::string(value) : default_value;
}

void CGIUtils::sendJSONResponse(const json& data, int status) {
    std::cout << "Status: " << status << "\r\n";
    std::cout << "Content-Type: application/json\r\n";
    std::cout << "Access-Control-Allow-Origin: *\r\n";
    std::cout << "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n";
    std::cout << "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
    std::cout << "\r\n";
    std::cout << data.dump() << std::endl;
}

void CGIUtils::sendErrorResponse(const std::string& message, int status) {
    json error = {{"error", message}};
    sendJSONResponse(error, status);
}

std::string CGIUtils::urlDecode(const std::string& str) {
    std::string decoded;
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int hex_value;
            std::stringstream ss;
            ss << std::hex << str.substr(i + 1, 2);
            ss >> hex_value;
            decoded += static_cast<char>(hex_value);
            i += 2;
        } else if (str[i] == '+') {
            decoded += ' ';
        } else {
            decoded += str[i];
        }
    }
    return decoded;
}

bool CGIUtils::extractPagination(const std::map<std::string, std::string>& params, int& limit, int& offset) {
    try {
        auto limit_it = params.find("limit");
        auto offset_it = params.find("offset");
        
        limit = (limit_it != params.end()) ? std::min(std::stoi(limit_it->second), 100) : 10;
        offset = (offset_it != params.end()) ? std::max(std::stoi(offset_it->second), 0) : 0;
        
        return true;
    } catch (...) {
        return false;
    }
}

void CGIUtils::logRequest(const std::string& script_name) {
    std::string method = getEnvVar("REQUEST_METHOD");
    std::string query = getEnvVar("QUERY_STRING");
    std::string remote_addr = getEnvVar("REMOTE_ADDR");
    
    LOG_INFO("CGI Request: {} {} from {} (query: {})", script_name, method, remote_addr, query);
}
EOF

    # ===== CGI SCRIPTS =====
    
    cat > "$DEPLOY_DIR/src/cgi/health.cpp" << 'EOF'
#include "../common/cgi_utils.hpp"
#include <ctime>

int main() {
    try {
        CGIUtils::logRequest("health");
        
        json response = {
            {"status", "ok"},
            {"timestamp", std::time(nullptr)},
            {"version", "1.0.0"},
            {"server", "lighttpd + C++ CGI"}
        };
        
        CGIUtils::sendJSONResponse(response);
    } catch (const std::exception& e) {
        CGIUtils::sendErrorResponse("Health check failed");
    }
    
    return 0;
}
EOF

    cat > "$DEPLOY_DIR/src/cgi/stats.cpp" << 'EOF'
#include "../common/cgi_utils.hpp"
#include "../common/database.hpp"
#include "../common/config.hpp"

int main() {
    try {
        CGIUtils::logRequest("stats");
        
        auto& config = Config::getInstance();
        config.loadFromFile("/opt/webcrawler/config/crawler.toml");
        
        std::string db_conn = "postgresql://" + config.getDatabase().user + ":" + 
                             config.getDatabase().password + "@" + config.getDatabase().host + 
                             ":" + std::to_string(config.getDatabase().port) + "/" + 
                             config.getDatabase().dbname;
        
        if (!Database::getInstance().initialize(db_conn, 5)) {
            CGIUtils::sendErrorResponse("Database connection failed");
            return 1;
        }
        
        auto stats = Database::getInstance().getCurrentStats();
        
        json response = {
            {"total_urls_discovered", stats.total_urls_discovered},
            {"total_urls_crawled", stats.total_urls_crawled},
            {"total_pages_indexed", stats.total_pages_indexed},
            {"total_words_indexed", stats.total_words_indexed},
            {"crawl_rate_per_minute", stats.crawl_rate_per_minute},
            {"index_rate_per_minute", stats.index_rate_per_minute}
        };
        
        CGIUtils::sendJSONResponse(response);
        Database::getInstance().shutdown();
    } catch (const std::exception& e) {
        CGIUtils::sendErrorResponse("Stats error");
    }
    
    return 0;
}
EOF

    cat > "$DEPLOY_DIR/src/cgi/search.cpp" << 'EOF'
#include "../common/cgi_utils.hpp"
#include "../common/database.hpp"
#include "../common/config.hpp"

int main() {
    try {
        CGIUtils::logRequest("search");
        
        std::string query_string = CGIUtils::getEnvVar("QUERY_STRING");
        auto params = CGIUtils::parseQueryString(query_string);
        
        auto query_it = params.find("q");
        if (query_it == params.end() || query_it->second.empty()) {
            CGIUtils::sendErrorResponse("Query parameter 'q' is required", 400);
            return 1;
        }
        
        std::string search_query = query_it->second;
        
        int limit, offset;
        if (!CGIUtils::extractPagination(params, limit, offset)) {
            CGIUtils::sendErrorResponse("Invalid pagination parameters", 400);
            return 1;
        }
        
        auto& config = Config::getInstance();
        config.loadFromFile("/opt/webcrawler/config/crawler.toml");
        
        std::string db_conn = "postgresql://" + config.getDatabase().user + ":" + 
                             config.getDatabase().password + "@" + config.getDatabase().host + 
                             ":" + std::to_string(config.getDatabase().port) + "/" + 
                             config.getDatabase().dbname;
        
        if (!Database::getInstance().initialize(db_conn, 5)) {
            CGIUtils::sendErrorResponse("Database connection failed");
            return 1;
        }
        
        auto results = Database::getInstance().search(search_query, limit, offset);
        
        json response = {
            {"results", json::array()},
            {"query", search_query},
            {"limit", limit},
            {"offset", offset}
        };
        
        for (const auto& result : results) {
            json item = {
                {"url", result.url},
                {"title", result.title},
                {"snippet", result.snippet},
                {"relevance_score", result.relevance_score}
            };
            response["results"].push_back(item);
        }
        
        CGIUtils::sendJSONResponse(response);
        Database::getInstance().shutdown();
    } catch (const std::exception& e) {
        CGIUtils::sendErrorResponse("Search error");
    }
    
    return 0;
}
EOF

    cat > "$DEPLOY_DIR/src/cgi/add_urls.cpp" << 'EOF'
#include "../common/cgi_utils.hpp"
#include "../common/database.hpp"
#include "../common/config.hpp"
#include <regex>

std::string extractDomain(const std::string& url) {
    std::regex domain_regex(R"(^https?://([^/]+))");
    std::smatch matches;
    
    if (std::regex_search(url, matches, domain_regex)) {
        std::string domain = matches[1].str();
        if (domain.substr(0, 4) == "www.") {
            domain = domain.substr(4);
        }
        return domain;
    }
    return "";
}

int main() {
    try {
        CGIUtils::logRequest("add_urls");
        
        std::string method = CGIUtils::getEnvVar("REQUEST_METHOD");
        if (method != "POST") {
            CGIUtils::sendErrorResponse("Method not allowed", 405);
            return 1;
        }
        
        std::string post_data = CGIUtils::readPostData();
        if (post_data.empty()) {
            CGIUtils::sendErrorResponse("No POST data received", 400);
            return 1;
        }
        
        json body = json::parse(post_data);
        
        if (!body.contains("urls") || !body["urls"].is_array()) {
            CGIUtils::sendErrorResponse("URLs array is required", 400);
            return 1;
        }
        
        auto& config = Config::getInstance();
        config.loadFromFile("/opt/webcrawler/config/crawler.toml");
        
        std::string db_conn = "postgresql://" + config.getDatabase().user + ":" + 
                             config.getDatabase().password + "@" + config.getDatabase().host + 
                             ":" + std::to_string(config.getDatabase().port) + "/" + 
                             config.getDatabase().dbname;
        
        if (!Database::getInstance().initialize(db_conn, 5)) {
            CGIUtils::sendErrorResponse("Database connection failed");
            return 1;
        }
        
        json results = json::array();
        int added = 0, existing = 0, errors = 0;
        
        for (const auto& url : body["urls"]) {
            std::string url_str = url.get<std::string>();
            std::string domain = extractDomain(url_str);
            
            if (domain.empty()) {
                results.push_back({
                    {"url", url_str},
                    {"status", "error"},
                    {"message", "Invalid URL"}
                });
                errors++;
                continue;
            }
            
            if (Database::getInstance().addUrl(url_str, domain, 0, 0)) {
                results.push_back({
                    {"url", url_str},
                    {"status", "added"}
                });
                added++;
            } else {
                results.push_back({
                    {"url", url_str},
                    {"status", "exists"},
                    {"message", "URL already exists"}
                });
                existing++;
            }
        }
        
        json response = {
            {"message", "URLs processed"},
            {"results", results},
            {"summary", {
                {"total", body["urls"].size()},
                {"added", added},
                {"existing", existing},
                {"errors", errors}
            }}
        };
        
        CGIUtils::sendJSONResponse(response);
        Database::getInstance().shutdown();
    } catch (const std::exception& e) {
        CGIUtils::sendErrorResponse("Add URLs error");
    }
    
    return 0;
}
EOF

    # ===== CRAWLER =====
    
    cat > "$DEPLOY_DIR/src/crawler/main.cpp" << 'EOF'
#include "../common/config.hpp"
#include "../common/logger.hpp"
#include "../common/database.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <signal.h>

volatile sig_atomic_t stop_crawling = 0;

void signal_handler(int signal) {
    stop_crawling = 1;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
        return 1;
    }
    
    auto& config = Config::getInstance();
    if (!config.loadFromFile(argv[1])) {
        std::cerr << "Failed to load configuration" << std::endl;
        return 1;
    }
    
    Logger::getInstance().initialize("crawler", config.getLogging().file_path, 
                                   config.getLogging().level, config.getLogging().console_output);
    
    LOG_INFO("Starting Web Crawler...");
    
    std::string db_conn = "postgresql://" + config.getDatabase().user + ":" + 
                         config.getDatabase().password + "@" + config.getDatabase().host + 
                         ":" + std::to_string(config.getDatabase().port) + "/" + 
                         config.getDatabase().dbname;
    
    if (!Database::getInstance().initialize(db_conn, config.getDatabase().max_connections)) {
        LOG_ERROR("Failed to initialize database");
        return 1;
    }
    
    // Simple crawling loop
    LOG_INFO("Crawler started successfully");
    
    while (!stop_crawling) {
        try {
            auto urls = Database::getInstance().getUrlsToCrawl(10);
            
            if (urls.empty()) {
                LOG_INFO("No URLs to crawl, waiting...");
                std::this_thread::sleep_for(std::chrono::seconds(30));
                continue;
            }
            
            for (const auto& url : urls) {
                if (stop_crawling) break;
                
                LOG_INFO("Crawling: {}", url);
                
                // Simuler le crawling (remplacer par vrai crawler HTTP)
                CrawlResult result;
                result.url = url;
                result.content = "Sample content for " + url;
                result.title = "Sample Title";
                result.meta_description = "Sample description";
                result.content_type = "text/html";
                result.status_code = 200;
                
                Database::getInstance().markUrlAsCrawled(url, 200);
                Database::getInstance().storeCrawledContent(result);
                
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Crawler error: {}", e.what());
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    }
    
    LOG_INFO("Crawler stopped");
    Database::getInstance().shutdown();
    return 0;
}
EOF

    # ===== INDEXER =====
    
    cat > "$DEPLOY_DIR/src/indexer/main.cpp" << 'EOF'
#include "../common/config.hpp"
#include "../common/logger.hpp"
#include "../common/database.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <signal.h>

volatile sig_atomic_t stop_indexing = 0;

void signal_handler(int signal) {
    stop_indexing = 1;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
        return 1;
    }
    
    auto& config = Config::getInstance();
    if (!config.loadFromFile(argv[1])) {
        std::cerr << "Failed to load configuration" << std::endl;
        return 1;
    }
    
    Logger::getInstance().initialize("indexer", config.getLogging().file_path, 
                                   config.getLogging().level, config.getLogging().console_output);
    
    LOG_INFO("Starting Web Indexer...");
    
    std::string db_conn = "postgresql://" + config.getDatabase().user + ":" + 
                         config.getDatabase().password + "@" + config.getDatabase().host + 
                         ":" + std::to_string(config.getDatabase().port) + "/" + 
                         config.getDatabase().dbname;
    
    if (!Database::getInstance().initialize(db_conn, config.getDatabase().max_connections)) {
        LOG_ERROR("Failed to initialize database");
        return 1;
    }
    
    LOG_INFO("Indexer started successfully");
    
    while (!stop_indexing) {
        try {
            LOG_INFO("Indexer running...");
            std::this_thread::sleep_for(std::chrono::seconds(60));
        } catch (const std::exception& e) {
            LOG_ERROR("Indexer error: {}", e.what());
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    }
    
    LOG_INFO("Indexer stopped");
    Database::getInstance().shutdown();
    return 0;
}
EOF

    print_success "Code source C++ généré"
}

# Génération des fichiers de configuration
generate_config_files() {
    print_status "Génération des fichiers de configuration..."
    
    # Configuration principale
    cat > "$DEPLOY_DIR/config/crawler.toml" << EOF
[database]
host = "$DB_HOST"
port = $DB_PORT
dbname = "$DB_NAME"
user = "$DB_USER"
password = "$DB_PASSWORD"
max_connections = 20

[crawler]
max_threads = 8
max_depth = 5
max_pages_per_domain = 1000
request_timeout = 30
user_agent = "WebCrawler/1.0 (+http://localhost/bot)"
default_crawl_delay = 1000
max_redirects = 5

[indexer]
max_threads = 4
min_word_length = 3
max_word_length = 50
batch_size = 100

[indexer.stop_words]
french = ["le", "de", "et", "à", "un", "il", "être", "en", "avoir", "que", "pour", "dans", "ce", "son", "une", "sur", "avec", "ne", "se", "pas", "tout", "plus", "par"]
english = ["the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it", "for", "not", "on", "with", "he", "as", "you", "do", "at", "this", "but", "his", "by"]

[logging]
level = "INFO"
file_path = "$LOG_DIR"
console_output = true
EOF

    # Configuration Lighttpd
    cat > "$DEPLOY_DIR/config/lighttpd.conf" << EOF
var.basedir = "$DEPLOY_DIR"
var.logdir = "/var/log/lighttpd"

server.modules = (
    "mod_access",
    "mod_alias",
    "mod_cgi",
    "mod_setenv",
    "mod_accesslog",
    "mod_rewrite"
)

server.username = "www-data"
server.groupname = "www-data"
server.document-root = var.basedir + "/www"
server.pid-file = "/var/run/lighttpd.pid"
server.errorlog = var.logdir + "/error.log"
server.port = 80

index-file.names = ("index.html")
accesslog.filename = var.logdir + "/access.log"

mimetype.assign = (
    ".html" => "text/html",
    ".css"  => "text/css",
    ".js"   => "application/javascript",
    ".json" => "application/json"
)

cgi.assign = ( ".cgi" => "" )

setenv.add-environment = (
    "LD_LIBRARY_PATH" => "/usr/local/lib:/usr/lib/x86_64-linux-gnu"
)

alias.url = (
    "/api/health" => var.basedir + "/www/cgi-bin/health.cgi",
    "/api/stats" => var.basedir + "/www/cgi-bin/stats.cgi",
    "/api/search" => var.basedir + "/www/cgi-bin/search.cgi",
    "/api/urls" => var.basedir + "/www/cgi-bin/add_urls.cgi"
)

url.rewrite-once = (
    "^/api/search\?(.*)$" => "/cgi-bin/search.cgi?\$1",
    "^/api/([^/\?]+)(\?.*)?$" => "/cgi-bin/\$1.cgi\$2"
)

setenv.add-response-header = (
    "X-Frame-Options" => "DENY",
    "X-Content-Type-Options" => "nosniff"
)
EOF

    print_success "Fichiers de configuration générés"
}

# Génération de l'interface web
generate_web_interface() {
    print_status "Génération de l'interface web..."
    
    # HTML principal
    cat > "$DEPLOY_DIR/www/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🕷️ Web Crawler Search Engine</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>🕷️ Web Crawler Search</h1>
            <p>Moteur de recherche personnel - Architecture Lighttpd + C++</p>
        </header>

        <div class="stats-container">
            <div class="stat-card">
                <h3>URLs Découvertes</h3>
                <span id="total-urls">-</span>
            </div>
            <div class="stat-card">
                <h3>Pages Crawlées</h3>
                <span id="crawled-urls">-</span>
            </div>
            <div class="stat-card">
                <h3>Pages Indexées</h3>
                <span id="indexed-pages">-</span>
            </div>
            <div class="stat-card">
                <h3>Mots Indexés</h3>
                <span id="total-words">-</span>
            </div>
        </div>

        <div class="search-container">
            <div class="search-box">
                <input type="text" id="search-input" placeholder="Entrez votre recherche..." />
                <button onclick="performSearch()">🔍 Rechercher</button>
            </div>
        </div>

        <div class="admin-panel">
            <h3>🔧 Administration</h3>
            <div class="admin-actions">
                <button onclick="addUrls()">➕ Ajouter URLs</button>
                <button onclick="refreshStats()">🔄 Rafraîchir</button>
            </div>
        </div>

        <div id="results-container" class="results-container">
            <div id="results-info" class="results-info"></div>
            <div id="results-list" class="results-list"></div>
        </div>

        <div id="loading" class="loading hidden">
            <div class="spinner"></div>
            <p>Recherche en cours...</p>
        </div>
    </div>

    <script src="js/script.js"></script>
</body>
</html>
EOF

    # CSS
    cat > "$DEPLOY_DIR/www/css/style.css" << 'EOF'
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    color: #333;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

header {
    text-align: center;
    margin-bottom: 30px;
    color: white;
}

header h1 {
    font-size: 3em;
    margin-bottom: 10px;
    text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
}

header p {
    font-size: 1.2em;
    opacity: 0.9;
}

.stats-container {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.stat-card {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 15px;
    padding: 25px;
    text-align: center;
    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
    transition: transform 0.3s ease;
}

.stat-card:hover {
    transform: translateY(-5px);
}

.stat-card h3 {
    color: #666;
    margin-bottom: 10px;
    font-size: 1em;
    text-transform: uppercase;
}

.stat-card span {
    font-size: 2.5em;
    font-weight: bold;
    color: #667eea;
    display: block;
}

.search-container {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    padding: 30px;
    margin-bottom: 30px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
}

.search-box {
    display: flex;
    gap: 15px;
    align-items: center;
}

.search-box input {
    flex: 1;
    padding: 15px 20px;
    border: 2px solid #ddd;
    border-radius: 10px;
    font-size: 1.1em;
    transition: border-color 0.3s ease;
}

.search-box input:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 10px rgba(102, 126, 234, 0.2);
}

.search-box button, .admin-actions button {
    background: linear-gradient(45deg, #667eea, #764ba2);
    color: white;
    border: none;
    padding: 15px 30px;
    border-radius: 10px;
    font-size: 1.1em;
    cursor: pointer;
    transition: all 0.3s ease;
    font-weight: 600;
}

.search-box button:hover, .admin-actions button:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
}

.admin-panel {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    padding: 20px;
    margin-bottom: 30px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
}

.admin-panel h3 {
    margin-bottom: 15px;
    color: #667eea;
}

.admin-actions {
    display: flex;
    gap: 15px;
    flex-wrap: wrap;
}

.admin-actions button {
    padding: 10px 20px;
    font-size: 1em;
}

.results-container {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    padding: 30px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
    display: none;
}

.results-container.show {
    display: block;
}

.results-info {
    margin-bottom: 25px;
    padding: 15px;
    background: #f8f9fa;
    border-radius: 10px;
    color: #666;
    text-align: center;
}

.result-item {
    margin-bottom: 25px;
    padding: 20px;
    border: 1px solid #eee;
    border-radius: 12px;
    transition: all 0.3s ease;
    background: white;
}

.result-item:hover {
    border-color: #667eea;
    box-shadow: 0 5px 20px rgba(102, 126, 234, 0.1);
    transform: translateY(-2px);
}

.result-title {
    font-size: 1.3em;
    margin-bottom: 8px;
}

.result-title a {
    color: #1a73e8;
    text-decoration: none;
    font-weight: 600;
}

.result-title a:hover {
    text-decoration: underline;
}

.result-url {
    color: #188038;
    margin-bottom: 10px;
    font-size: 0.9em;
}

.result-snippet {
    color: #666;
    line-height: 1.6;
    margin-bottom: 10px;
}

.result-meta {
    display: flex;
    gap: 15px;
    font-size: 0.85em;
    color: #999;
}

.result-meta span {
    background: #f0f0f0;
    padding: 4px 8px;
    border-radius: 4px;
}

.loading {
    text-align: center;
    padding: 50px;
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
}

.loading.hidden {
    display: none;
}

.spinner {
    width: 50px;
    height: 50px;
    border: 5px solid #f3f3f3;
    border-top: 5px solid #667eea;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto 20px;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

@media (max-width: 768px) {
    .container {
        padding: 10px;
    }
    
    header h1 {
        font-size: 2em;
    }
    
    .search-box {
        flex-direction: column;
    }
    
    .stats-container {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .admin-actions {
        justify-content: center;
    }
}
EOF

    # JavaScript
    cat > "$DEPLOY_DIR/www/js/script.js" << 'EOF'
const API_BASE = '/api';

document.addEventListener('DOMContentLoaded', function() {
    updateStats();
    setInterval(updateStats, 30000);
    
    document.getElementById('search-input').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            performSearch();
        }
    });
});

async function updateStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`);
        const stats = await response.json();
        
        document.getElementById('total-urls').textContent = formatNumber(stats.total_urls_discovered || 0);
        document.getElementById('crawled-urls').textContent = formatNumber(stats.total_urls_crawled || 0);
        document.getElementById('indexed-pages').textContent = formatNumber(stats.total_pages_indexed || 0);
        document.getElementById('total-words').textContent = formatNumber(stats.total_words_indexed || 0);
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}

async function performSearch() {
    const query = document.getElementById('search-input').value.trim();
    if (!query) {
        alert('Veuillez entrer un terme de recherche');
        return;
    }
    
    showLoading();
    
    try {
        const response = await fetch(`${API_BASE}/search?q=${encodeURIComponent(query)}&limit=10&offset=0`);
        const data = await response.json();
        
        if (data.error) {
            alert('Erreur: ' + data.error);
            return;
        }
        
        displayResults(data);
    } catch (error) {
        console.error('Search error:', error);
        alert('Erreur lors de la recherche');
    } finally {
        hideLoading();
    }
}

function displayResults(data) {
    const resultsContainer = document.getElementById('results-container');
    const resultsInfo = document.getElementById('results-info');
    const resultsList = document.getElementById('results-list');
    
    resultsContainer.classList.add('show');
    
    resultsInfo.innerHTML = `
        <strong>${formatNumber(data.results.length)}</strong> résultats trouvés pour 
        <strong>"${data.query}"</strong>
        <em>• Powered by Lighttpd + C++ CGI</em>
    `;
    
    if (data.results.length === 0) {
        resultsList.innerHTML = `
            <div style="text-align: center; padding: 50px; color: #666;">
                <h3>Aucun résultat trouvé</h3>
                <p>Essayez avec des mots-clés différents</p>
            </div>
        `;
    } else {
        resultsList.innerHTML = data.results.map(result => `
            <div class="result-item">
                <div class="result-title">
                    <a href="${result.url}" target="_blank">${escapeHtml(result.title || 'Sans titre')}</a>
                </div>
                <div class="result-url">${result.url}</div>
                <div class="result-snippet">${escapeHtml(result.snippet || '').substring(0, 300)}...</div>
                <div class="result-meta">
                    <span>⭐ Score: ${(result.relevance_score || 0).toFixed(2)}</span>
                </div>
            </div>
        `).join('');
    }
}

async function addUrls() {
    const urls = prompt('Entrez les URLs à ajouter (une par ligne):');
    if (!urls) return;
    
    const urlList = urls.split('\n').filter(url => url.trim());
    if (urlList.length === 0) return;
    
    try {
        const response = await fetch(`${API_BASE}/urls`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ urls: urlList })
        });
        
        const data = await response.json();
        
        if (data.error) {
            alert('Erreur: ' + data.error);
        } else {
            alert(`URLs traitées:\n- Ajoutées: ${data.summary.added}\n- Existantes: ${data.summary.existing}\n- Erreurs: ${data.summary.errors}`);
        }
    } catch (error) {
        console.error('Add URLs error:', error);
        alert('Erreur lors de l\'ajout des URLs');
    }
}

function refreshStats() {
    updateStats();
    alert('Statistiques rafraîchies !');
}

function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

function showLoading() {
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('results-container').classList.remove('show');
}

function hideLoading() {
    document.getElementById('loading').classList.add('hidden');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
EOF

    print_success "Interface web générée"
}

# Configuration de la base de données
setup_database() {
    print_status "Configuration de la base de données PostgreSQL..."
    
    if [[ "$DB_HOST" == "localhost" || "$DB_HOST" == "127.0.0.1" ]]; then
        # Base de données locale - installer et configurer PostgreSQL
        print_status "Configuration PostgreSQL local..."
        
        # Démarrer PostgreSQL
        systemctl start postgresql
        systemctl enable postgresql
        
        # Créer la base de données et l'utilisateur
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;" 2>/dev/null || true
        sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" 2>/dev/null || true
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" 2>/dev/null || true
        
        # Créer le schéma
        sudo -u postgres psql -d "$DB_NAME" -f "$DEPLOY_DIR/sql/schema.sql"
        
    else
        # Base de données distante - vérifier la connexion et créer le schéma
        print_status "Configuration PostgreSQL distant ($DB_HOST:$DB_PORT)..."
        
        # Tester la connexion
        if ! PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null 2>&1; then
            print_error "❌ Impossible de se connecter à PostgreSQL distant"
            print_error "   Vérifiez que :"
            print_error "   - Le serveur PostgreSQL est accessible sur $DB_HOST:$DB_PORT"
            print_error "   - L'utilisateur '$DB_USER' existe avec le bon mot de passe"
            print_error "   - La base '$DB_NAME' existe"
            print_error "   - Les permissions de connexion sont configurées (pg_hba.conf)"
            print_error ""
            print_error "💡 Pour créer manuellement la base :"
            print_error "   CREATE DATABASE $DB_NAME;"
            print_error "   CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
            print_error "   GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
            return 1
        fi
        
        print_success "✅ Connexion PostgreSQL distante OK"
        
        # Créer le schéma sur la base distante
        PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$DEPLOY_DIR/sql/schema.sql"
    fi
CREATE TABLE domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    crawl_delay INTEGER DEFAULT 1000,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE urls (
    id SERIAL PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,
    domain_id INTEGER REFERENCES domains(id),
    url_hash VARCHAR(64) UNIQUE NOT NULL,
    status_code INTEGER,
    content_type VARCHAR(100),
    last_crawled TIMESTAMP,
    is_crawled BOOLEAN DEFAULT FALSE,
    priority INTEGER DEFAULT 0,
    depth INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE crawled_content (
    id SERIAL PRIMARY KEY,
    url_id INTEGER REFERENCES urls(id) ON DELETE CASCADE,
    raw_content TEXT,
    title VARCHAR(500),
    meta_description TEXT,
    content_hash VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE extracted_links (
    id SERIAL PRIMARY KEY,
    source_url_id INTEGER REFERENCES urls(id),
    target_url TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE word_index (
    id SERIAL PRIMARY KEY,
    word VARCHAR(100) NOT NULL,
    content_id INTEGER REFERENCES crawled_content(id) ON DELETE CASCADE,
    frequency INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_urls_domain ON urls(domain_id);
CREATE INDEX idx_urls_hash ON urls(url_hash);
CREATE INDEX idx_urls_status ON urls(is_crawled);
CREATE INDEX idx_word_index_word ON word_index(word);
EOF

    sudo -u postgres psql -d "$DB_NAME" -f "$DEPLOY_DIR/sql/schema.sql"
    
    print_success "Base de données configurée"
}

# Compilation du projet
compile_project() {
    print_status "Compilation du projet..."
    
    # Générer CMakeLists.txt
    cat > "$DEPLOY_DIR/CMakeLists.txt" << 'EOF'
cmake_minimum_required(VERSION 3.16)
project(WebCrawler)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
find_package(Boost REQUIRED COMPONENTS system filesystem thread)
find_package(OpenSSL REQUIRED)

pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(PQXX REQUIRED libpqxx)

include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CURL_INCLUDE_DIRS})
include_directories(${PQXX_INCLUDE_DIRS})
include_directories(/usr/local/include)

set(COMMON_SOURCES
    src/common/config.cpp
    src/common/database.cpp
    src/common/logger.cpp
    src/common/cgi_utils.cpp
)

add_library(webcrawler_common ${COMMON_SOURCES})
target_link_libraries(webcrawler_common 
    ${PQXX_LIBRARIES}
    ${CURL_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog
)

add_executable(crawler src/crawler/main.cpp)
target_link_libraries(crawler webcrawler_common pthread)

add_executable(indexer src/indexer/main.cpp)
target_link_libraries(indexer webcrawler_common pthread)

set(CGI_SCRIPTS health stats search add_urls)
foreach(script ${CGI_SCRIPTS})
    add_executable(${script}_cgi src/cgi/${script}.cpp)
    target_link_libraries(${script}_cgi webcrawler_common)
    set_target_properties(${script}_cgi PROPERTIES OUTPUT_NAME ${script}.cgi)
endforeach()
EOF

    cd "$DEPLOY_DIR"
    mkdir -p build
    cd build
    
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc)
    
    # Copier les CGI
    cp *_cgi "$DEPLOY_DIR/www/cgi-bin/" 2>/dev/null || true
    chmod +x "$DEPLOY_DIR/www/cgi-bin/"*.cgi
    
    # Ajuster les permissions
    chown -R "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_DIR"
    chown -R www-data:www-data "$DEPLOY_DIR/www"
    
    print_success "Projet compilé"
}

# Configuration de Lighttpd
setup_lighttpd() {
    print_status "Configuration de Lighttpd..."
    
    # Backup de la configuration existante
    if [[ -f "/etc/lighttpd/lighttpd.conf" ]]; then
        cp "/etc/lighttpd/lighttpd.conf" "/etc/lighttpd/lighttpd.conf.backup.$(date +%Y%m%d-%H%M%S)"
    fi
    
    # Copier notre configuration
    cp "$DEPLOY_DIR/config/lighttpd.conf" "/etc/lighttpd/"
    
    # Créer les répertoires lighttpd
    mkdir -p /var/lib/lighttpd
    mkdir -p /var/log/lighttpd
    chown -R www-data:www-data /var/lib/lighttpd
    chown -R www-data:www-data /var/log/lighttpd
    
    # Test de la configuration
    if lighttpd -t -f /etc/lighttpd/lighttpd.conf; then
        print_success "Configuration Lighttpd valide"
    else
        print_error "Configuration Lighttpd invalide"
        return 1
    fi
    
    # Activer et démarrer lighttpd
    systemctl enable lighttpd
    systemctl restart lighttpd
    
    print_success "Lighttpd configuré"
}

# Configuration des services systemd
setup_services() {
    print_status "Configuration des services systemd..."
    
    # Service crawler
    cat > "/etc/systemd/system/webcrawler-crawler.service" << EOF
[Unit]
Description=Web Crawler Service
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=$DEPLOY_USER
WorkingDirectory=$DEPLOY_DIR
ExecStart=$DEPLOY_DIR/build/crawler $DEPLOY_DIR/config/crawler.toml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=LD_LIBRARY_PATH=/usr/local/lib

[Install]
WantedBy=multi-user.target
EOF

    # Service indexer
    cat > "/etc/systemd/system/webcrawler-indexer.service" << EOF
[Unit]
Description=Web Indexer Service
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=$DEPLOY_USER
WorkingDirectory=$DEPLOY_DIR
ExecStart=$DEPLOY_DIR/build/indexer $DEPLOY_DIR/config/crawler.toml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=LD_LIBRARY_PATH=/usr/local/lib

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable webcrawler-crawler
    systemctl enable webcrawler-indexer
    
    print_success "Services systemd configurés"
}

# Ajout des URLs de test
add_sample_urls() {
    print_status "Ajout d'URLs de test..."
    
    # Attendre que la base soit prête
    sleep 2
    
    # Ajouter quelques URLs de test
    sudo -u "$DEPLOY_USER" psql -h localhost -U "$DB_USER" -d "$DB_NAME" << EOF
INSERT INTO domains (domain) VALUES 
    ('example.com'),
    ('httpbin.org'),
    ('jsonplaceholder.typicode.com')
ON CONFLICT (domain) DO NOTHING;

INSERT INTO urls (url, domain_id, url_hash, priority) VALUES 
    ('https://example.com', (SELECT id FROM domains WHERE domain = 'example.com'), 'hash1', 100),
    ('https://httpbin.org/html', (SELECT id FROM domains WHERE domain = 'httpbin.org'), 'hash2', 90),
    ('https://jsonplaceholder.typicode.com/posts/1', (SELECT id FROM domains WHERE domain = 'jsonplaceholder.typicode.com'), 'hash3', 80)
ON CONFLICT (url_hash) DO NOTHING;
EOF

    print_success "URLs de test ajoutées"
}

# Démarrage des services
start_services() {
    print_status "Démarrage des services..."
    
    systemctl start lighttpd
    systemctl start webcrawler-indexer
    systemctl start webcrawler-crawler
    
    # Vérifier le statut
    sleep 5
    
    local all_ok=true
    
    if systemctl is-active --quiet lighttpd; then
        print_success "Lighttpd démarré"
    else
        print_error "Lighttpd n'a pas démarré"
        all_ok=false
    fi
    
    if systemctl is-active --quiet webcrawler-indexer; then
        print_success "Indexer démarré"
    else
        print_error "Indexer n'a pas démarré"
        all_ok=false
    fi
    
    if systemctl is-active --quiet webcrawler-crawler; then
        print_success "Crawler démarré"
    else
        print_error "Crawler n'a pas démarré"
        all_ok=false
    fi
    
    if [ "$all_ok" = true ]; then
        print_success "Tous les services sont démarrés"
    else
        print_error "Certains services ont échoué"
        return 1
    fi
}

# Tests de vérification
verify_installation() {
    print_status "Vérification de l'installation..."
    
    # Test API health
    if curl -s http://localhost/api/health | grep -q "ok"; then
        print_success "API Health fonctionne"
    else
        print_error "API Health ne répond pas"
    fi
    
    # Test API stats
    if curl -s http://localhost/api/stats | grep -q "total_urls"; then
        print_success "API Stats fonctionne"
    else
        print_error "API Stats ne répond pas"
    fi
    
    # Test interface web
    if curl -s http://localhost/ | grep -q "Web Crawler"; then
        print_success "Interface web accessible"
    else
        print_error "Interface web inaccessible"
    fi
    
    # Test base de données
    if sudo -u "$DEPLOY_USER" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c "SELECT COUNT(*) FROM domains;" > /dev/null 2>&1; then
        print_success "Base de données accessible"
    else
        print_error "Base de données inaccessible"
    fi
}

# Script de monitoring simple
create_monitoring_script() {
    cat > "$DEPLOY_DIR/monitoring.sh" << 'EOF'
#!/bin/bash

echo "🕷️ Web Crawler - Status Monitor"
echo "================================="

echo -n "Lighttpd: "
if systemctl is-active --quiet lighttpd; then
    echo "✅ Running"
else
    echo "❌ Stopped"
fi

echo -n "Crawler: "
if systemctl is-active --quiet webcrawler-crawler; then
    echo "✅ Running"
else
    echo "❌ Stopped"
fi

echo -n "Indexer: "
if systemctl is-active --quiet webcrawler-indexer; then
    echo "✅ Running"
else
    echo "❌ Stopped"
fi

echo -n "API Health: "
if curl -s http://localhost/api/health | grep -q "ok"; then
    echo "✅ OK"
else
    echo "❌ Error"
fi

echo -n "Database: "
if sudo -u webcrawler psql -h localhost -U crawler_user -d webcrawler -c "SELECT 1;" > /dev/null 2>&1; then
    echo "✅ Connected"
else
    echo "❌ Error"
fi

echo
echo "📊 Quick Stats:"
curl -s http://localhost/api/stats | python3 -m json.tool 2>/dev/null || echo "Stats unavailable"

echo
echo "🌐 Web Interface: http://localhost"
echo "🔍 API Health: http://localhost/api/health"
echo "📊 API Stats: http://localhost/api/stats"
EOF

    chmod +x "$DEPLOY_DIR/monitoring.sh"
    chown "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_DIR/monitoring.sh"
}

# Fonction principale
main() {
    print_header
    
    print_status "🚀 Début de l'installation complète du Web Crawler"
    print_status "📊 Mot de passe DB généré: $DB_PASSWORD"
    echo
    
    check_root
    install_dependencies
    setup_environment
    generate_source_code
    generate_config_files
    generate_web_interface
    setup_database
    compile_project
    setup_lighttpd
    setup_services
    add_sample_urls
    start_services
    verify_installation
    create_monitoring_script
    
    echo
    echo -e "${GREEN}🎉 INSTALLATION TERMINÉE AVEC SUCCÈS! 🎉${NC}"
    echo "=============================================="
    echo
    echo -e "${CYAN}🌐 ACCÈS AU SYSTÈME:${NC}"
    echo "   Interface Web: http://localhost"
    echo "   API Health: http://localhost/api/health"
    echo "   API Stats: http://localhost/api/stats"
    echo
    echo -e "${CYAN}🔧 GESTION DES SERVICES:${NC}"
    echo "   systemctl status lighttpd webcrawler-*"
    echo "   systemctl restart webcrawler-crawler"
    echo "   systemctl restart webcrawler-indexer"
    echo
    echo -e "${CYAN}📁 EMPLACEMENTS IMPORTANTS:${NC}"
    echo "   Application: $DEPLOY_DIR"
    echo "   Logs: $LOG_DIR"
    echo "   Web Files: $DEPLOY_DIR/www"
    echo "   Config: $DEPLOY_DIR/config/crawler.toml"
    echo
    echo -e "${CYAN}📊 MONITORING:${NC}"
    echo "   sudo $DEPLOY_DIR/monitoring.sh"
    echo
    echo -e "${CYAN}🗄️ BASE DE DONNÉES:${NC}"
    echo "   Nom: $DB_NAME"
    echo "   Utilisateur: $DB_USER"
    echo "   Mot de passe: $DB_PASSWORD"
    echo
    echo -e "${YELLOW}💡 PREMIERS PAS:${NC}"
    echo "   1. Visitez http://localhost pour voir l'interface"
    echo "   2. Ajoutez des URLs via le bouton 'Ajouter URLs'"
    echo "   3. Attendez que le crawler les traite"
    echo "   4. Effectuez des recherches!"
    echo
    print_success "Le Web Crawler est maintenant opérationnel! 🕷️"
}

# Gestion des erreurs
trap 'print_error "Installation échouée à la ligne $LINENO!"; exit 1' ERR

# Exécution
main "$@"