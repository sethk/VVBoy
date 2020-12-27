### Project
cmake_minimum_required(VERSION 3.9)
project(vvboy)

### Options
option(DEBUG_TTY "Enable debugger on the tty" OFF)

### Main Targets
add_executable(vvbdis)
add_executable(vvboy)

### Compile Flags
if(MSVC)
	set(COMMON_C_FLAGS /W1 /GR- /EHsc) # /WX
else()
	set(COMMON_C_FLAGS -Wall -Wextra -Wformat) # -Werror
	set(CMAKE_C_FLAGS_RELEASE "-O3")
	#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -fno-inline -O0")
	#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
endif()
target_compile_options(vvbdis PRIVATE ${COMMON_C_FLAGS})
target_compile_options(vvboy PRIVATE ${COMMON_C_FLAGS})

### Switches
#set(TOOLKIT GLFW)
set(TOOLKIT SDL)

### OpenGL
find_package(OpenGL REQUIRED)
target_link_libraries(vvboy PRIVATE ${OPENGL_LIBRARIES})
target_link_libraries(vvbdis PRIVATE ${OPENGL_LIBRARIES})

set(OS_SOURCES os_common.c)

if(UNIX)
	### Platform: Unix
	add_compile_definitions(vvboy PRIVATE DEBUG_TTY=${DEBUG_TTY} HAVE_LIBEDIT _SEARCH_PRIVATE)
	find_library(EDIT_LIB edit)
	target_link_libraries(vvboy PRIVATE ${EDIT_LIB})
	target_link_libraries(vvbdis PRIVATE ${EDIT_LIB})
	set(BSD_SOURCES "")
	set(OS_SOURCES ${OS_SOURCES} os_unix.c)
else()
	add_compile_definitions(vvboy PRIVATE DEBUG_TTY=0 HAVE_LIBEDIT=0)
	#add_subdirectory(vendor/libedit)
	#include_directories(vendor/libedit/src)
	set(BSD_DIR vendor/bsd-libc)
	set(BSD_SOURCES ${BSD_DIR}/getopt.c ${BSD_DIR}/tsearch.c ${BSD_DIR}/tfind.c ${BSD_DIR}/tdelete.c)
	target_include_directories(vvboy PUBLIC ${BSD_DIR})
	target_include_directories(vvbdis PUBLIC ${BSD_DIR})
endif()

if(NOT APPLE)
	set(BSD_SOURCES ${BSD_SOURCES} vendor/darwin-libplatform/memset_pattern.c)
endif()

if(APPLE)
	### Platform: macOS
	add_compile_definitions(GL_SILENCE_DEPRECATION)
	# add_executable(VVBoy MACOSX_BUNDLE ...
	set(OS_SOURCES ${OS_SOURCES} os_macos.m)
	find_library(APPKIT AppKit)
	target_link_libraries(vvboy PRIVATE ${APPKIT})
endif()

if(WIN32)
	### Platform: Windows
	set(OS_SOURCES ${OS_SOURCES} os_windows.c)
	target_sources(vvboy PRIVATE utf-8.exe.manifest)
	#target_link_options(vvboy PRIVATE /SUBSYSTEM:WINDOWS)
	set_target_properties(vvboy PROPERTIES LINK_FLAGS /SUBSYSTEM:WINDOWS)
	target_sources(vvbdis PRIVATE utf-8.exe.manifest)

	target_compile_definitions(vvboy PRIVATE WIN32_LEAN_AND_MEAN)
	target_compile_definitions(vvbdis PRIVATE WIN32_LEAN_AND_MEAN)

	target_link_libraries(vvboy PRIVATE ComCtl32)
	target_link_libraries(vvbdis PRIVATE ComCtl32)
endif()

### ImGui
set(IMGUI_DIR vendor/cimgui)
#add_subdirectory(${IMGUI_DIR})
target_include_directories(vvboy PUBLIC ${IMGUI_DIR})
target_include_directories(vvbdis PUBLIC ${IMGUI_DIR})
set(IMGUI_SOURCES ${IMGUI_DIR}/cimgui/cimgui.cpp ${IMGUI_DIR}/cimgui/fontAtlas.cpp ${IMGUI_DIR}/cimgui/drawList.cpp
        ${IMGUI_DIR}/imgui/imgui.cpp ${IMGUI_DIR}/imgui/imgui_draw.cpp ${IMGUI_DIR}/imgui/imgui_demo.cpp)

### gl3w
set(GL3W_DIR vendor/cimgui/imgui/examples/libs/gl3w)
include_directories(${GL3W_DIR})
set(GL3W_SOURCES ${GL3W_DIR}/GL/gl3w.c)

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
	set(SDL_SHARED_ENABLED_BY_DEFAULT OFF)
	set(SDL2_BUILD_DIR vendor/SDL2/build)
	add_subdirectory(vendor/SDL2 ${SDL2_BUILD_DIR})
	#find_package(SDL2 REQUIRED)
	target_include_directories(vvboy PUBLIC vendor/SDL2/include)
	target_include_directories(vvbdis PUBLIC vendor/SDL2/include)
	target_link_libraries(vvboy PRIVATE SDL2-static)
	target_link_libraries(vvbdis PRIVATE SDL2-static)
	# TODO: Only static-link Release target
	set(TK_SOURCES tk_sdl.c)
	set(IMGUI_SOURCES ${IMGUI_SOURCES} vendor/cimgui_sdl_opengl3/imgui_impl_sdl_gl3.cpp)
else()
    set(TK_SOURCES tk_null.c)
endif()

### Sources
set(COMMON_SOURCES main.c rom.c nvc.c imgui.c gl.c mem.c sram.c wram.c cpu.c vip.c vsu.c debug.c events.c)
set(COMMON_HEADERS types.h)
#set(COMMON_SOURCES ${COMMON_SOURCES} vip_draw.c)
#set(COMMON_SOURCES ${COMMON_SOURCES} vip_draw_slow.c)
set(VVBOY_SOURCES vvboy.c)
set(VVBDIS_SOURCES vvbdis.c)
set(ALL_SOURCES ${COMMON_SOURCES} ${TK_SOURCES} ${VVBOY_SOURCES} ${VVBDIS_SOURCES} ${OS_SOURCES} ${BSD_SOURCES})
target_sources(vvbdis PRIVATE ${VVBDIS_SOURCES} ${COMMON_SOURCES} ${COMMON_HEADERS} ${OS_SOURCES} ${TK_SOURCES} ${IMGUI_SOURCES} ${GL3W_SOURCES} ${OS_SOURCES} ${BSD_SOURCES})
target_sources(vvboy PRIVATE ${VVBOY_SOURCES} ${COMMON_SOURCES} ${COMMON_HEADERS} ${OS_SOURCES} ${TK_SOURCES} ${IMGUI_SOURCES} ${GL3W_SOURCES} ${OS_SOURCES} ${BSD_SOURCES})

### Automatic Header Generation
add_executable(makeheaders vendor/makeheaders/makeheaders.c)
if(MSVC)
	#target_compile_options(makeheaders PUBLIC /W3 /wd4459 /wd4100 /wd4820 /wd4242 /wd4244 /wd4710)
	target_compile_options(makeheaders PUBLIC /W3 /wd4267)
	target_compile_definitions(makeheaders PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
	target_compile_options(makeheaders PUBLIC -Wno-sign-compare -Wno-unused-parameter -Wno-unused-function -Wno-unused-const-variable)
endif()
target_compile_definitions(makeheaders PUBLIC DEBUG)
string(REGEX REPLACE "/\\.c$/" GEN_HEADERS ${ALL_SOURCES})
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

### CTags and CScope support
include(vendor/tags.cmake)
