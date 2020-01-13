### Project
cmake_minimum_required(VERSION 3.9)
project(vvboy)

### Compile Flags
add_compile_options(-Wall -Wextra -Wformat -Werror)
set(CMAKE_C_FLAGS_RELEASE "-O3")
#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")

### Main Targets
add_executable(vvbdis)
add_executable(vvboy)

### External Dependencies
find_package(SDL2 REQUIRED)
find_package(OpenGL REQUIRED)
target_include_directories(vvboy PRIVATE ${SDL2_INCLUDE_DIRS})
target_include_directories(vvbdis PRIVATE ${SDL2_INCLUDE_DIRS})
target_link_libraries(vvboy PRIVATE ${SDL2_LIBRARIES} ${OPENGL_LIBRARIES})
target_link_libraries(vvbdis PRIVATE ${SDL2_LIBRARIES} ${OPENGL_LIBRARIES})

### Platform: Unix
#add_compile_definitions(vvboy PRIVATE DEBUG_TTY)
find_library(EDIT_LIB edit)
target_link_libraries(vvboy PRIVATE ${EDIT_LIB})
target_link_libraries(vvbdis PRIVATE ${EDIT_LIB})

### Platform: macOS
add_compile_definitions(GL_SILENCE_DEPRECATION)
# add_executable(VVBoy MACOSX_BUNDLE ...
set(OS_SOURCES os_macos.m)
find_library(APPKIT AppKit)
target_link_libraries(vvboy PRIVATE ${APPKIT})

### ImGui
set(IMGUI_DIR vendor/cimgui)
include_directories(${IMGUI_DIR})
set(IMGUI_SOURCES ${IMGUI_DIR}/cimgui/cimgui.cpp ${IMGUI_DIR}/cimgui/fontAtlas.cpp ${IMGUI_DIR}/cimgui/drawList.cpp
        ${IMGUI_DIR}/imgui/imgui.cpp ${IMGUI_DIR}/imgui/imgui_draw.cpp ${IMGUI_DIR}/imgui/imgui_demo.cpp
        vendor/cimgui_sdl_opengl3/imgui_impl_sdl_gl3.cpp)

### Sources
set(COMMON_SOURCES common.c rom.c vip.c events.c)
#set(COMMON_SOURCES ${COMMON_SOURCES} vip_draw.c)
#set(COMMON_SOURCES ${COMMON_SOURCES} vip_draw_slow.c)
set(TK_SOURCES tk_sdl.c)
#set(TK_SOURCES tk_null.c)
set(VVBOY_SOURCES vvboy.c)
set(VVBDIS_SOURCES vvbdis.c tk_null.c os_null.c)
set(ALL_SOURCES ${COMMON_SOURCES} ${TK_SOURCES} ${VVBOY_SOURCES} ${VVBDIS_SOURCES} ${OS_SOURCES})
set(GEN_HEADERS vvboy.h common.h rom.h vvbdis.h)
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
