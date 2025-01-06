### Project
cmake_minimum_required(VERSION 3.10)
project(VVBoy)

### Options
option(DEBUG_TTY "Enable debugger on the tty" OFF)

### Compile Flags
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
	set(COMMON_C_FLAGS /W1 /GR- /EHsc) # /WX
else()
	set(COMMON_C_FLAGS -Wall -Wextra -Wformat -Wshadow) # -Werror
	#set(COMMON_C_FLAGS -Weverything) # -Werror
	set(CMAKE_C_FLAGS_RELEASE -O3)
	#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -fno-inline -O0")
	#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
endif()

### Main Targets
add_executable(vvbdis)
add_executable(VVBoy)

target_compile_options(vvbdis PRIVATE ${COMMON_C_FLAGS})
target_compile_options(VVBoy PRIVATE ${COMMON_C_FLAGS})

### Switches
#set(TOOLKIT GLFW)
set(TOOLKIT SDL)

### OpenGL
find_package(OpenGL REQUIRED)
target_link_libraries(VVBoy PRIVATE ${OPENGL_LIBRARIES})
target_link_libraries(vvbdis PRIVATE ${OPENGL_LIBRARIES})

set(OS_SOURCES OS_Common.cc)

if(UNIX)
	### Platform: Unix
	add_compile_definitions(VVBoy PRIVATE DEBUG_TTY=${DEBUG_TTY} HAVE_LIBEDIT)
	find_library(EDIT_LIB edit)
	target_link_libraries(VVBoy PRIVATE ${EDIT_LIB})
	target_link_libraries(vvbdis PRIVATE ${EDIT_LIB})
	set(BSD_SOURCES "")
	list(APPEND OS_SOURCES OS_Unix.cc)
else()
	add_compile_definitions(VVBoy PRIVATE DEBUG_TTY=0 HAVE_LIBEDIT=0)
	#add_subdirectory(vendor/libedit)
	#include_directories(vendor/libedit/src)
	set(BSD_DIR vendor/bsd-libc)
	set(BSD_SOURCES ${BSD_DIR}/getopt.c ${BSD_DIR}/tsearch.c ${BSD_DIR}/tfind.c ${BSD_DIR}/tdelete.c)
	target_include_directories(VVBoy PUBLIC ${BSD_DIR})
	target_include_directories(vvbdis PUBLIC ${BSD_DIR})
endif()

if(NOT APPLE)
	list(APPEND BSD_SOURCES vendor/darwin-libplatform/memset_pattern.c)
endif()

if(APPLE)
	### Platform: macOS
	add_compile_definitions(GL_SILENCE_DEPRECATION)
	# add_executable(VVBoy MACOSX_BUNDLE ...
	list(APPEND OS_SOURCES OS_macOS.mm)
	find_library(APPKIT AppKit)
	target_link_libraries(VVBoy PRIVATE ${APPKIT})
endif()

if(WIN32)
	### Platform: Windows
	list(APPEND OS_SOURCES OS_Windows.cc)
	target_sources(VVBoy PRIVATE utf-8.exe.manifest)
	#target_link_options(VVBoy PRIVATE /SUBSYSTEM:WINDOWS)
	set_target_properties(VVBoy PROPERTIES LINK_FLAGS /SUBSYSTEM:WINDOWS)
	target_sources(vvbdis PRIVATE utf-8.exe.manifest)

	target_compile_definitions(VVBoy PRIVATE WIN32_LEAN_AND_MEAN)
	target_compile_definitions(vvbdis PRIVATE WIN32_LEAN_AND_MEAN)

	target_link_libraries(VVBoy PRIVATE ComCtl32)
	target_link_libraries(vvbdis PRIVATE ComCtl32)
endif()

### ImGui
set(IMGUI_DIR vendor/cimgui)
#add_subdirectory(${IMGUI_DIR})
target_include_directories(VVBoy PUBLIC ${IMGUI_DIR})
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
    target_link_libraries(VVBoy PRIVATE glfw)
    target_link_libraries(vvbdis PRIVATE glfw)
    target_compile_definitions(VVBoy PRIVATE GLFW_INCLUDE_NONE)
    target_compile_definitions(vvbdis PRIVATE GLFW_INCLUDE_NONE)
    set(TK_SOURCES TK_Glfw.cc)
	list(APPEND IMGUI_SOURCES vendor/cimgui_glfw_opengl3/imgui_impl_glfw_gl3.cpp)
	target_compile_definitions(VVBoy PRIVATE TOOLKIT_GLFW)
elseif(${TOOLKIT} STREQUAL SDL)
	set(SDL_SHARED_ENABLED_BY_DEFAULT OFF)
	set(SDL2_BUILD_DIR vendor/SDL2/build)
	add_subdirectory(vendor/SDL2 ${SDL2_BUILD_DIR})
	#find_package(SDL2 REQUIRED)
	target_include_directories(VVBoy PUBLIC vendor/SDL2/include)
	target_include_directories(vvbdis PUBLIC vendor/SDL2/include)
	target_link_libraries(VVBoy PRIVATE SDL2-static)
	target_link_libraries(vvbdis PRIVATE SDL2-static)
	# TODO: Only static-link Release target
	set(TK_SOURCES TK_SDL.cc)
	list(APPEND IMGUI_SOURCES vendor/cimgui_sdl_opengl3/imgui_impl_sdl_gl3.cpp)
	target_compile_definitions(VVBoy PRIVATE TOOLKIT_SDL)
else()
    set(TK_SOURCES TK_Null.cc)
endif()

set(COMMON_SOURCES BitSet.cc RingBuf.cc Emu.cc ROM.cc NVC.cc ImGUI.cc GL.cc Memory.cc SRAM.cc WRAM.cc CPU.cc VIP.cc VSU.cc VSUThread.cc Debug.cc Events.cc)
set(COMMON_HEADERS Types.hh)
#set(COMMON_SOURCES ${COMMON_SOURCES} VIP_Draw.cc)
#set(COMMON_SOURCES ${COMMON_SOURCES} Vip_Draw_Slow.cc)
set(VVBOY_SOURCES VVBoy.cc)
set(VVBDIS_SOURCES VVBDis.cc)
set(ALL_CXX_SOURCES ${COMMON_SOURCES} ${OS_SOURCES} ${TK_SOURCES} ${VVBOY_SOURCES} ${VVBDIS_SOURCES} ${BSD_SOURCES})
target_sources(vvbdis PRIVATE ${VVBDIS_SOURCES} ${COMMON_SOURCES} ${COMMON_HEADERS} ${OS_SOURCES} ${TK_SOURCES} ${IMGUI_SOURCES} ${GL3W_SOURCES} ${OS_SOURCES} ${BSD_SOURCES})
target_sources(VVBoy PRIVATE ${VVBOY_SOURCES} ${COMMON_SOURCES} ${COMMON_HEADERS} ${OS_SOURCES} ${TK_SOURCES} ${IMGUI_SOURCES} ${GL3W_SOURCES} ${OS_SOURCES} ${BSD_SOURCES})

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
list(TRANSFORM ALL_CXX_SOURCES REPLACE "\.(cc|mm)$" ".Gen.hh" OUTPUT_VARIABLE GEN_HEADERS)
list(TRANSFORM ALL_CXX_SOURCES REPLACE "(.*)\.(cc|mm)$" "\\1.\\2:\\1.Gen.hh" OUTPUT_VARIABLE MAKEHEADERS_ARGS)
add_custom_target(GenHeaders
        COMMAND makeheaders -v ${MAKEHEADERS_ARGS}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        BYPRODUCTS ${GEN_HEADERS}
        DEPENDS makeheaders ${ALL_CXX_SOURCES}
		COMMENT "Generating header files...")
# Doesn't work: set_target_properties(GenHeaders PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${GEN_HEADERS}") # Deprecated name
# Doesn't work: set_target_properties(GenHeaders PROPERTIES ADDITIONAL_CLEAN_FILES "${GEN_HEADERS}")
add_dependencies(vvbdis GenHeaders)
add_dependencies(VVBoy GenHeaders)

### Resource Files
set(RESOURCE_FILES ${IMGUI_DIR}/imgui/misc/fonts/Roboto-Medium.ttf gamecontrollerdb.txt)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/include)
foreach(_resource_path ${RESOURCE_FILES})
	get_filename_component(_out_resource_name ${_resource_path} NAME)
	string(CONCAT _out_resource_header ${CMAKE_BINARY_DIR}/include/${_out_resource_name} ".h")
	add_custom_command(OUTPUT ${_out_resource_header}
		MAIN_DEPENDENCY ${_resource_path}
		COMMAND xxd -include -name ${_out_resource_name} ${CMAKE_SOURCE_DIR}/${_resource_path} ${_out_resource_header}
		COMMENT "Generating resource files...")
	list(APPEND _out_resource_headers ${_out_resource_header})
endforeach()
add_custom_target(Resources DEPENDS ${_out_resource_headers})
add_dependencies(VVBoy Resources)
target_include_directories(VVBoy PUBLIC ${CMAKE_BINARY_DIR}/include)
target_include_directories(vvbdis PUBLIC ${CMAKE_BINARY_DIR}/include)

### CTags and CScope support
include(vendor/tags.cmake)
