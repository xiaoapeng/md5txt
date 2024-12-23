/**
 * @file main.c
 * @brief 测试主逻辑
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @version 1.0
 * @date 2023-04-11
 * 
 * @copyright Copyright (c) 2023  simon.xiaoapeng@gmail.com
 * 
 * @par 修改日志:
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "m5dtxt.h"
#include "memctrl.h"
#include "debug.h"
#include "argparse.h"


static const char* const usages[] = {
    "md5txt <dir> [-g]",
    NULL,
};

int main(int argc, const char* argv[]){
    int is_generate = 0;
    int ret = -1;
    struct argparse argparse;
    const char *dir_path = NULL;
    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("基本命令"),
        OPT_BOOLEAN('g', "generate", &is_generate, "生成md5.txt", NULL, 0, 0),
        OPT_END(),
    };
    debug_init();
    
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse, 
            "\n本程序用来生成md5.txt文件, 用来校验文件完整性。 ", 
            NULL);
    argc = argparse_parse(&argparse, argc, argv);
    if(argc != 1)
        goto help;
    dir_path = argv[0];

    if(is_generate){
        ret = md5txt_generate(dir_path);
    }else{
        ret = md5txt_check(dir_path);
    }

    return ret;
help:
    argparse_help_cb_no_exit(&argparse, options);
    exit(ret);
}