/**
 * @file m5djson.h
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-23
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */
#ifndef _M5DJSON_H_
#define _M5DJSON_H_

/**
 * @brief                   对应目录所有文件生成md5.json文件
 * @param  dir_path         要生成md5.json的文件目录
 * @return int              0:成功
 */
int md5txt_generate(const char *dir_path);

/**
 * @brief                   对应目录所有文件校验md5.json文件
 * @param  dir_path         要校验md5.json的文件目录
 * @return int              0:成功
 */
int md5txt_check(const char *dir_path);

#endif // _M5DJSON_H_