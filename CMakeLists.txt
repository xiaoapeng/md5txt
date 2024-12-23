cmake_minimum_required(VERSION 3.1)


# include("/home3/pengym/codebuild/MC116-19090.1000.00.02.23.03/fibo_sdk/nushine/E7_test/cmake/gcc.cmake")

#设置C++版本号
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)


project(md5txt LANGUAGES C CXX ASM)

add_compile_options(
    "$<$<CONFIG:Debug>:-g;-O0>"
    "$<$<CONFIG:Release>:-g;-O3>"
    "$<$<CONFIG:MinSizeRel>:-g;-Os>"
    "$<$<CONFIG:RelWithDebInfo>:-g;-Os>"
)


set( TARGET_FLAGS 
    "-Wall"
    "-Wextra"
    "-Wconversion"
    "-Wsign-conversion"
    "-Wno-psabi"
)

# 指定生成目标cd in	
add_executable(md5txt
	"${PROJECT_SOURCE_DIR}/src/general/debug.c"
	"${PROJECT_SOURCE_DIR}/src/general/argparse.c"
	"${PROJECT_SOURCE_DIR}/src/main.cpp"
	"${PROJECT_SOURCE_DIR}/src/md5txt.cpp"
)


target_compile_options(md5txt PRIVATE ${TARGET_FLAGS})
target_include_directories(md5txt PRIVATE 
	"${PROJECT_SOURCE_DIR}/src/include/"
	"${PROJECT_SOURCE_DIR}/src/general/inc/"
)


# 指定库
target_link_libraries( md5txt
	"-lpthread"
	# "-lssl"
	"-lcrypto"
)
