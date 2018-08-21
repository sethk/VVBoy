cmake_minimum_required(VERSION 3.9)
project(vvboy)

add_compile_options(-Wall -Wextra -Wformat -Werror)
set(CMAKE_C_FLAGS_RELEASE "-O3")
find_library(EDIT_LIB edit)
link_libraries(${EDIT_LIB})
find_package(SDL2 REQUIRED)
find_package(OpenGL REQUIRED)
include_directories(${SDL2_INCLUDE_DIRS})
link_libraries(${SDL2_LIBRARIES} ${OPENGL_LIBRARIES})
set(COMMON_SOURCES common.c rom.c)
#set(COMMON_SOURCES ${COMMON_SOURCES} vip_draw.c)
set(COMMON_SOURCES ${COMMON_SOURCES} vip_draw_slow.c)
set(TK_SOURCES tk_sdl.c)
#set(TK_SOURCES tk_null.c)
set(IMGUI_DIR vendor/cimgui)
include_directories(${IMGUI_DIR})
set(IMGUI_SOURCES ${IMGUI_DIR}/cimgui/cimgui.cpp ${IMGUI_DIR}/cimgui/fontAtlas.cpp ${IMGUI_DIR}/cimgui/drawList.cpp
        ${IMGUI_DIR}/imgui/imgui.cpp ${IMGUI_DIR}/imgui/imgui_draw.cpp ${IMGUI_DIR}/imgui/imgui_demo.cpp
        vendor/cimgui_sdl_opengl3/imgui_impl_sdl_gl3.cpp)
set(VVBOY_SOURCES vvboy.c)
set(VVBDIS_SOURCES vvbdis.c tk_null.c)
set(ALL_SOURCES ${COMMON_SOURCES} ${TK_SOURCES} ${VVBOY_SOURCES} ${VVBDIS_SOURCES})
set(GEN_HEADERS vvboy.h common.h rom.h vvbdis.h)
add_executable(makeheaders vendor/makeheaders/makeheaders.c)
target_compile_options(makeheaders PUBLIC -Wno-sign-compare -Wno-unused-parameter -Wno-unused-function
        -Wno-unused-const-variable)
target_compile_definitions(makeheaders PUBLIC -DDEBUG)
add_custom_target(GenHeaders
        COMMAND makeheaders -v ${ALL_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        BYPRODUCTS ${GEN_HEADERS}
        DEPENDS makeheaders ${ALL_SOURCES})

add_executable(vvbdis ${VVBDIS_SOURCES} vvbdis.h ${COMMON_SOURCES} ${IMGUI_SOURCES})
target_compile_definitions(vvbdis PRIVATE DEBUG_TTY)
add_dependencies(vvbdis GenHeaders)
add_executable(vvboy ${VVBOY_SOURCES} vvboy.h ${COMMON_SOURCES} ${TK_SOURCES} ${IMGUI_SOURCES})
add_dependencies(vvboy GenHeaders)
