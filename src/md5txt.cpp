/**
 * @file md5json.cpp
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-23
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */
#include <iostream>
#include <filesystem>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>

#include "m5dtxt.h"
#include "debug.h"

namespace fs = std::filesystem;
#define JSON_FILE_NAME "md5.txt"

int calculate_md5(const std::string& filePath, std::string &md5_value) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return -1;
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr) != 1) {
        std::cerr << "Failed to initialize digest context" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    char buffer[4096];
    size_t bytesRead;
    while ((bytesRead = (size_t)file.read(buffer, sizeof(buffer)).gcount()) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
            std::cerr << "Failed to update digest context" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return -1;
        }
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength;
    if (EVP_DigestFinal_ex(mdctx, digest, &digestLength) != 1) {
        std::cerr << "Failed to finalize digest" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < digestLength; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }
    md5_value = oss.str();
    return 0;
}

// 递归遍历文件夹并将文件名和MD5值存储在map中
std::map<std::string, std::string> list_files_and_calculate_md5(const std::string& dir_path) {
    std::map<std::string, std::string> file_md5_map;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(dir_path)) {
            if (entry.is_regular_file() && entry.path().filename() != JSON_FILE_NAME) {
                int ret;
                std::string filePath = entry.path().string();
                // std::string fileName = entry.path().filename().string();
                std::string md5Value; 
                ret = calculate_md5(filePath, md5Value);
                if(ret != 0)
                    continue;
                file_md5_map[filePath] = md5Value;
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "General error: " << e.what() << std::endl;
    }
    return file_md5_map;
}

int md5txt_generate(const char *dir_path){
    std::map<std::string, std::string> 
        map_tab = list_files_and_calculate_md5(dir_path);

    /* 以 <file_path>:<md5_value>\n的格式写入 md5.txt */
    std::ofstream outfile(std::string(dir_path) + "/md5.txt");
    if (!outfile.is_open()) {
        perror("Failed to open md5.txt");
        return -1;
    }

    for(auto &item : map_tab){
        outfile << item.first << ":" << item.second << "\n";
    }

    outfile.close();
    return 0;
}


int md5txt_check(const char *dir_path){
    std::map<std::string, std::string> 
        map_tab = list_files_and_calculate_md5(dir_path);
    
    /* 读取md5.txt,与map_tab中的项进行对比 */
    std::ifstream infile(std::string(dir_path) + "/md5.txt");
    if (!infile.is_open()) {
        perror("Failed to open md5.txt");
        return -1;
    }

    std::string line;
    while (std::getline(infile, line)) {
        size_t pos = line.find(':');
        if (pos == std::string::npos) {
            std::cerr << "Invalid line in md5.txt: " << line << std::endl;
            return -1;
        }

        std::string file_path = line.substr(0, pos);
        std::string expected_md5 = line.substr(pos + 1);

        if (map_tab.find(file_path) == map_tab.end()) {
            std::cerr << "File not found: " << file_path << std::endl;
            return -1;
        }

        std::string actual_md5 = map_tab[file_path];
        if (actual_md5 != expected_md5) {
            std::cerr << "MD5 mismatch for file: " << file_path 
                      << ". Expected: " << expected_md5 
                      << ", Got: " << actual_md5 << std::endl;
            return -1;
        }
    }

    infile.close();
    return 0;
}