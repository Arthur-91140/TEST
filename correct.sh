#!/bin/bash

# Script pour corriger les erreurs de compilation dans config.cpp

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_DIR="web_crawler"

echo -e "${GREEN}[INFO] Correction des erreurs de compilation dans config.cpp${NC}"

# Vérifier que le projet existe
if [ ! -d "$PROJECT_DIR" ]; then
    echo -e "${RED}[ERROR] Le répertoire $PROJECT_DIR n'existe pas${NC}"
    exit 1
fi

cd $PROJECT_DIR

# Corriger config.cpp avec les bonnes concaténations de chaînes
echo -e "${GREEN}[INFO] Correction des erreurs de concaténation de chaînes${NC}"
cat > src/config.cpp << 'EOF'
#include "config.h"
#include "logger.h"
#include <toml++/toml.h>
#include <fstream>
#include <string>

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
        
        // Patterns - CORRECTION MAJEURE
        patterns.clear();
        pattern_strings.clear();
        
        // Vérifier si la section patterns existe
        if (config.contains("patterns")) {
            // Méthode 1: patterns individuels (email_pattern, phone_pattern, etc.)
            if (auto email_pattern = config["patterns"]["email_pattern"].value<std::string>()) {
                try {
                    std::regex test_regex(*email_pattern);
                    pattern_strings.push_back("email_pattern");
                    patterns.emplace_back(*email_pattern);
                    Logger::getInstance().log(LogLevel::INFO, "Loaded email pattern: " + *email_pattern);
                } catch (const std::regex_error& e) {
                    Logger::getInstance().log(LogLevel::ERROR, 
                        std::string("Invalid email regex pattern: ") + e.what());
                }
            }
            
            if (auto phone_pattern = config["patterns"]["phone_pattern"].value<std::string>()) {
                try {
                    std::regex test_regex(*phone_pattern);
                    pattern_strings.push_back("phone_pattern");
                    patterns.emplace_back(*phone_pattern);
                    Logger::getInstance().log(LogLevel::INFO, "Loaded phone pattern: " + *phone_pattern);
                } catch (const std::regex_error& e) {
                    Logger::getInstance().log(LogLevel::ERROR, 
                        std::string("Invalid phone regex pattern: ") + e.what());
                }
            }
            
            // Méthode 2: patterns sous forme de tableau
            if (auto patterns_array = config["patterns"]["patterns"].as_array()) {
                int pattern_idx = 0;
                for (const auto& pattern : *patterns_array) {
                    if (auto pattern_str = pattern.value<std::string>()) {
                        try {
                            std::regex test_regex(*pattern_str);
                            pattern_strings.push_back("pattern_" + std::to_string(pattern_idx++));
                            patterns.emplace_back(*pattern_str);
                            Logger::getInstance().log(LogLevel::INFO, "Loaded pattern: " + *pattern_str);
                        } catch (const std::regex_error& e) {
                            Logger::getInstance().log(LogLevel::ERROR, 
                                std::string("Invalid regex pattern '") + *pattern_str + "': " + e.what());
                        }
                    }
                }
            }
        }
        
        // Database
        db_path = config["database"]["path"].value_or("crawler.db");
        
        // Logging
        log_level = config["logging"]["level"].value_or("INFO");
        log_file = config["logging"]["file"].value_or("crawler.log");
        
        Logger::getInstance().log(LogLevel::INFO, 
            "Configuration loaded successfully. Patterns: " + std::to_string(patterns.size()));
        
        return true;
    } catch (const toml::parse_error& err) {
        Logger::getInstance().log(LogLevel::ERROR, std::string("Failed to parse config: ") + err.what());
        return false;
    } catch (const std::exception& e) {
        Logger::getInstance().log(LogLevel::ERROR, std::string("Error loading config: ") + e.what());
        return false;
    }
}
EOF

# Corriger également html_parser.cpp pour les mêmes erreurs potentielles
echo -e "${GREEN}[INFO] Vérification et correction de html_parser.cpp${NC}"
cat > src/html_parser.cpp << 'EOF'
#include "html_parser.h"
#include "url_parser.h"
#include "logger.h"
#include <gumbo.h>
#include <regex>
#include <algorithm>
#include <string>

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
    
    if (patterns.empty()) {
        return matches;
    }
    
    // Nettoyer le HTML (enlever les balises) pour une meilleure recherche
    std::string clean_text = html;
    
    try {
        // Remplacer les balises HTML par des espaces
        std::regex tag_regex("<[^>]*>");
        clean_text = std::regex_replace(clean_text, tag_regex, " ");
        
        // Décoder les entités HTML basiques
        std::regex amp_regex("&amp;");
        clean_text = std::regex_replace(clean_text, amp_regex, "&");
        std::regex lt_regex("&lt;");
        clean_text = std::regex_replace(clean_text, lt_regex, "<");
        std::regex gt_regex("&gt;");
        clean_text = std::regex_replace(clean_text, gt_regex, ">");
        std::regex quot_regex("&quot;");
        clean_text = std::regex_replace(clean_text, quot_regex, "\"");
        std::regex nbsp_regex("&nbsp;");
        clean_text = std::regex_replace(clean_text, nbsp_regex, " ");
        
        // Normaliser les espaces
        std::regex whitespace_regex("\\s+");
        clean_text = std::regex_replace(clean_text, whitespace_regex, " ");
        
    } catch (const std::exception& e) {
        Logger::getInstance().log(LogLevel::ERROR, 
            std::string("Error cleaning HTML: ") + e.what());
        clean_text = html; // Fallback vers HTML original
    }
    
    // Rechercher les patterns dans le texte nettoyé
    for (const auto& pattern : patterns) {
        try {
            std::sregex_iterator it(clean_text.begin(), clean_text.end(), pattern);
            std::sregex_iterator end;
            
            while (it != end) {
                std::string match = it->str();
                // Nettoyer le match (supprimer espaces en début/fin)
                match.erase(0, match.find_first_not_of(" \t\n\r"));
                match.erase(match.find_last_not_of(" \t\n\r") + 1);
                
                // Éviter les doublons et les matches vides
                if (!match.empty() && 
                    std::find(matches.begin(), matches.end(), match) == matches.end()) {
                    matches.push_back(match);
                }
                ++it;
            }
        } catch (const std::exception& e) {
            Logger::getInstance().log(LogLevel::ERROR, 
                std::string("Error applying regex pattern: ") + e.what());
        }
    }
    
    return matches;
}
EOF

# Corriger également crawler.cpp pour les mêmes erreurs potentielles
echo -e "${GREEN}[INFO] Vérification et correction de crawler.cpp${NC}"
cat > src/crawler.cpp << 'EOF'
#include "crawler.h"
#include "logger.h"
#include "url_parser.h"
#include "html_parser.h"
#include <curl/curl.h>
#include <chrono>
#include <sstream>
#include <string>

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
    Logger::getInstance().log(LogLevel::INFO, 
        "Loaded " + std::to_string(config_.patterns.size()) + " search patterns");
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
        std::lock_guard<std::mutex> lock(queue_mutex_);
        for (const auto& url : new_urls) {
            url_queue_.push(url);
        }
        if (!new_urls.empty()) {
            cv_.notify_all();
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
            std::string("Failed to download ") + url + ": " + curl_easy_strerror(res));
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
        
        if (!matches.empty()) {
            Logger::getInstance().log(LogLevel::INFO, 
                "Found " + std::to_string(matches.size()) + " pattern matches on " + url);
            
            // Sauvegarder les matches avec leur pattern correspondant
            for (size_t i = 0; i < matches.size(); ++i) {
                // Trouver quel pattern a matché
                std::string pattern_name = "unknown";
                for (size_t p = 0; p < config_.patterns.size(); ++p) {
                    try {
                        std::smatch match_result;
                        if (std::regex_search(matches[i], match_result, config_.patterns[p])) {
                            pattern_name = (p < config_.pattern_strings.size()) 
                                ? config_.pattern_strings[p] 
                                : "pattern_" + std::to_string(p);
                            break;
                        }
                    } catch (const std::exception& e) {
                        Logger::getInstance().log(LogLevel::ERROR, 
                            std::string("Error matching pattern: ") + e.what());
                    }
                }
                
                db_.insertPattern(pattern_name, url, matches[i]);
                
                Logger::getInstance().log(LogLevel::INFO, 
                    "Pattern '" + pattern_name + "' matched: " + matches[i].substr(0, 100) + 
                    (matches[i].length() > 100 ? "..." : ""));
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

# Recompiler le projet
echo -e "${GREEN}[INFO] Recompilation du projet après correction des erreurs${NC}"
cd build
make clean
make -j$(nproc)

# Vérifier la compilation
if [ -f "crawler" ]; then
    echo -e "${GREEN}[SUCCESS] Erreurs de compilation corrigées avec succès!${NC}"
    cd ..
    echo ""
    echo -e "${GREEN}=== Corrections appliquées ===${NC}"
    echo -e "${YELLOW}✓${NC} Erreurs de concaténation de chaînes corrigées"
    echo -e "${YELLOW}✓${NC} Inclusion de <string> ajoutée"
    echo -e "${YELLOW}✓${NC} Utilisation de std::string() pour les conversions"
    echo -e "${YELLOW}✓${NC} Compilation réussie"
    echo ""
    echo -e "${GREEN}=== Fichiers prêts à utiliser ===${NC}"
    echo -e "${YELLOW}•${NC} Exécutable: ./build/crawler"
    echo -e "${YELLOW}•${NC} Configuration: config_example.toml"
    echo -e "${YELLOW}•${NC} Script d'analyse: ./query_results.sh"
    echo ""
    echo -e "${GREEN}=== Prochaines étapes ===${NC}"
    echo -e "${YELLOW}1.${NC} cp config_example.toml config.toml"
    echo -e "${YELLOW}2.${NC} Éditer config.toml avec vos paramètres"
    echo -e "${YELLOW}3.${NC} ./build/crawler config.toml"
    echo -e "${YELLOW}4.${NC} ./query_results.sh (pour voir les résultats)"
else
    echo -e "${RED}[ERROR] La compilation a encore échoué${NC}"
    echo -e "${YELLOW}Vérifiez les erreurs ci-dessus${NC}"
    exit 1
fi
EOF