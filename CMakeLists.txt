### Project
cmake_minimum_required(VERSION 3.9)
project(vvboy)

### Compile Flags
add_compile_options(-Wall -Wextra -Wformat -Werror)
set(CMAKE_C_FLAGS_RELEASE "-O3")
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -fno-inline -O0")
#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")

### Generated Headers
set(GEN_HEADERS vvboy.h common.h rom.h vvbdis.h)

### Main Targets
add_executable(vvbdis)
add_executable(vvboy)

### Switches
set(TOOLKIT GLFW)
#set(TOOLKIT SDL)

### OpenGL
find_package(OpenGL REQUIRED)
target_link_libraries(vvboy PRIVATE ${OPENGL_LIBRARIES})
target_link_libraries(vvbdis PRIVATE ${OPENGL_LIBRARIES})

### Platform: Unix
#add_compile_definitions(vvboy PRIVATE DEBUG_TTY)
find_library(EDIT_LIB edit)
target_link_libraries(vvboy PRIVATE ${EDIT_LIB})
target_link_libraries(vvbdis PRIVATE ${EDIT_LIB})

### Platform: macOS
add_compile_definitions(GL_SILENCE_DEPRECATION)
# add_executable(VVBoy MACOSX_BUNDLE ...
set(OS_SOURCES os_macos.m)
set(GEN_HEADERS ${GEN_HEADERS} os_macos.h)
find_library(APPKIT AppKit)
target_link_libraries(vvboy PRIVATE ${APPKIT})

### ImGui
set(IMGUI_DIR vendor/cimgui)
include_directories(${IMGUI_DIR})
set(IMGUI_SOURCES ${IMGUI_DIR}/cimgui/cimgui.cpp ${IMGUI_DIR}/cimgui/fontAtlas.cpp ${IMGUI_DIR}/cimgui/drawList.cpp
        ${IMGUI_DIR}/imgui/imgui.cpp ${IMGUI_DIR}/imgui/imgui_draw.cpp ${IMGUI_DIR}/imgui/imgui_demo.cpp)

### Toolkit
if(${TOOLKIT} STREQUAL GLFW)
    find_package(glfw3 REQUIRED)
    target_link_libraries(vvboy PRIVATE glfw)
    target_link_libraries(vvbdis PRIVATE glfw)
    target_compile_definitions(vvboy PRIVATE GLFW_INCLUDE_NONE)
    target_compile_definitions(vvbdis PRIVATE GLFW_INCLUDE_NONE)
    set(TK_SOURCES tk_glfw.c)
    set(IMGUI_SOURCES ${IMGUI_SOURCES} vendor/cimgui_glfw_opengl3/imgui_impl_glfw_gl3.cpp)
elseif(${TOOLKIT} STREQUAL SDL)
    find_package(SDL2 REQUIRED)
    target_include_directories(vvboy PRIVATE ${SDL2_INCLUDE_DIRS})
    target_include_directories(vvbdis PRIVATE ${SDL2_INCLUDE_DIRS})
    target_link_libraries(vvboy PRIVATE ${SDL2_LIBRARIES})
    target_link_libraries(vvbdis PRIVATE ${SDL2_LIBRARIES})
    set(TK_SOURCES tk_sdl.c)
    set(IMGUI_SOURCES ${IMGUI_SOURCES} vendor/cimgui_sdl_opengl3/imgui_impl_sdl_gl3.cpp)
else()
    set(TK_SOURCES tk_null.c)
endif()

### Sources
set(COMMON_SOURCES common.c rom.c vip.c events.c)
#set(COMMON_SOURCES ${COMMON_SOURCES} vip_draw.c)
#set(COMMON_SOURCES ${COMMON_SOURCES} vip_draw_slow.c)
set(VVBOY_SOURCES vvboy.c)
set(VVBDIS_SOURCES vvbdis.c tk_null.c os_null.c)
set(ALL_SOURCES ${COMMON_SOURCES} ${TK_SOURCES} ${VVBOY_SOURCES} ${VVBDIS_SOURCES} ${OS_SOURCES})
target_sources(vvbdis PRIVATE ${VVBDIS_SOURCES} vvbdis.h ${COMMON_SOURCES} ${IMGUI_SOURCES})
target_sources(vvboy PRIVATE ${VVBOY_SOURCES} vvboy.h ${COMMON_SOURCES} ${OS_SOURCES} ${TK_SOURCES} ${IMGUI_SOURCES})

### Automatic Header Generation
add_executable(makeheaders vendor/makeheaders/makeheaders.c)
target_compile_options(makeheaders PUBLIC -Wno-sign-compare -Wno-unused-parameter -Wno-unused-function
        -Wno-unused-const-variable)
target_compile_definitions(makeheaders PUBLIC DEBUG)
add_custom_target(GenHeaders
        COMMAND makeheaders -v ${ALL_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        BYPRODUCTS ${GEN_HEADERS}
        DEPENDS makeheaders ${ALL_SOURCES})
add_dependencies(vvbdis GenHeaders)
add_dependencies(vvboy GenHeaders)

### Resource Files
file(COPY ${IMGUI_DIR}/imgui/misc/fonts/Roboto-Medium.ttf DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY gamecontrollerdb.txt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
