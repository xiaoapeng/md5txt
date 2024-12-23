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
#include <unistd.h>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>

#include <string.h>
#include "m5dtxt.h"
#include "debug.h"

#define JSON_FILE_NAME "md5.txt"

#include <functional>
#include <algorithm>
#include <dirent.h>
// 判断是否是文件夹

#define throw_if(condition) \
    do { \
        if (condition) { \
            throw std::runtime_error("Condition failed: " #condition); \
        } \
    } while (0)

inline bool is_folder(const char* dir_name){
	throw_if(nullptr==dir_name);
	auto dir =opendir(dir_name);
	if(dir){
		closedir(dir);
		return true;
	}
	return false;
}
#ifdef _WIN32
inline char file_sepator(){
	return '\\';
}
#else
inline char file_sepator(){
	return '/';
}
#endif
// 判断是否是文件夹
inline bool is_folder(const std::string &dir_name){
	throw_if(dir_name.empty());
	return is_folder(dir_name.data());
}
using file_filter_type=std::function<bool(const char*,const char*)>;
/*
 * 列出指定目录的所有文件(不包含目录)执行，对每个文件执行filter过滤器，
 * filter返回true时将文件名全路径加入std::vector
 * sub为true时为目录递归
 * 返回每个文件的全路径名
*/
static  std::vector<std::string> for_each_file(const std::string&dir_name,file_filter_type filter,bool sub=false){
	std::vector<std::string> v;
	auto dir =opendir(dir_name.data());
	struct dirent *ent;
	if(dir){
		while ((ent = readdir (dir)) != NULL) {
			std::string file_path = std::string(dir_name).append({ file_sepator() }).append(ent->d_name);
			if(sub){
				if ( 0== strcmp (ent->d_name, "..") || 0 == strcmp (ent->d_name, ".")){
					continue;
				}else if(is_folder(file_path)){
					auto r= for_each_file(file_path,filter,sub);
					v.insert(v.end(),r.begin(),r.end());
					continue;
				}
			}
			if (sub||!is_folder(file_path))//如果是文件，则调用过滤器filter
				if(filter(dir_name.data(),ent->d_name))
					v.emplace_back(file_path);
		}
		closedir(dir);
	}
	return v;
}

const static  file_filter_type default_ls_filter=[](const char*,const char*){return true;};
/*
 * 列出指定目录的所有文件
 * sub为true时为目录递归
 * 返回每个文件的全路径名
 */
inline std::vector<std::string> ls(const std::string&dir_name, bool sub = true) {
	return for_each_file(dir_name, default_ls_filter, sub);
}

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
        auto file_list = ls(dir_path);
        for (const auto& entry : file_list) {
            std::string filePath = entry;
            std::string fileName = entry.substr(entry.find_last_of("/\\") + 1); // 提取文件名
            if ( fileName != JSON_FILE_NAME) {
                int ret;
                std::string md5Value; 
                ret = calculate_md5(filePath, md5Value);
                if(ret != 0)
                    continue;
                file_md5_map[filePath] = md5Value;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "General error: " << e.what() << std::endl;
    }
    return file_md5_map;
}

int md5txt_generate(const char *dir_path){
    char current_dir[PATH_MAX];
    int ret;

    if(getcwd(current_dir, sizeof(current_dir)) == NULL){
        return -1;
    }
    
    ret = chdir(dir_path);
    if(ret < 0) return -1;

    std::map<std::string, std::string> 
        map_tab = list_files_and_calculate_md5(".");

    /* 以 <file_path>:<md5_value>\n的格式写入 md5.txt */
    std::ofstream outfile(std::string(".") + "/md5.txt");
    if (!outfile.is_open()) {
        perror("Failed to open md5.txt");
        ret = -1;
        goto out;
    }

    for(auto &item : map_tab){
        outfile << item.first << ":" << item.second << "\n";
    }

    outfile.close();
out:
    ret = chdir(current_dir);
    return ret;
}


int md5txt_check(const char *dir_path){
    int ret = 0;
    char current_dir[PATH_MAX];
    std::string line;
    std::map<std::string, std::string> 
        map_tab;
    std::ifstream infile(std::string(".") + "/md5.txt");


    if(getcwd(current_dir, sizeof(current_dir)) == NULL){
        return -1;
    }
    
    ret = chdir(dir_path);
    if(ret < 0) return -1;

    map_tab = list_files_and_calculate_md5(std::string("."));
    
    /* 读取md5.txt,与map_tab中的项进行对比 */
    if (!infile.is_open()) {
        perror("Failed to open md5.txt");
        ret = -1;
        goto out;
    }

    while (std::getline(infile, line)) {
        size_t pos = line.find(':');
        if (pos == std::string::npos) {
            std::cerr << "Invalid line in md5.txt: " << line << std::endl;
            ret = -1;
            goto out_close_file;
        }

        std::string file_path = line.substr(0, pos);
        std::string expected_md5 = line.substr(pos + 1);

        if (map_tab.find(file_path) == map_tab.end()) {
            std::cerr << "File not found: " << file_path << std::endl;
            ret = -1;
            goto out_close_file;
        }

        std::string actual_md5 = map_tab[file_path];
        if (actual_md5 != expected_md5) {
            std::cerr << "MD5 mismatch for file: " << file_path 
                      << ". Expected: " << expected_md5 
                      << ", Got: " << actual_md5 << std::endl;
            ret = -1;
            goto out_close_file;
        }
    }
out_close_file:
    infile.close();
out:
    ret = chdir(current_dir);
    return ret;
}