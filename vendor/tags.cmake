#
# (C) Copyright 2018 Tillmann Heidsieck
#
# SPDX-License-Identifier: MIT
#

find_program(CTAGS ctags)
find_program(CSCOPE cscope)

function(tags_add_dir _dir)
	get_property(_subdirlist DIRECTORY "${_dir}" PROPERTY SUBDIRECTORIES)
	foreach(_sd ${_subdirlist})
		tags_add_dir(${_sd})
	endforeach()

	get_property(_targets_list DIRECTORY "${_dir}" PROPERTY BUILDSYSTEM_TARGETS)
	foreach(_tgt ${_targets_list})
		get_property(_t_cflags TARGET ${_tgt} PROPERTY COMPILE_FLAGS)
		get_property(_t_incdir TARGET ${_tgt} PROPERTY INCLUDE_DIRECTORIES)
		get_property(_t_files  TARGET ${_tgt} PROPERTY SOURCES)
		get_property(_t_defs   TARGET ${_tgt} PROPERTY COMPILE_DEFINITIONS)

		list(APPEND _all_source_files ${_t_files})
		string(REGEX REPLACE "${CMAKE_SOURCE_DIR}/" "" _t_files "${_t_files}")
		string(REGEX REPLACE ";" "\n" _t_files "${_t_files}")

		string(REGEX REPLACE ";" "\n" _t_defs "${_t_defs}")
		string(REGEX REPLACE "^([^=]+)$" "\\1=1" _t_defs "${_t_defs}")
	endforeach()
	set(_all_source_files ${_all_source_files} PARENT_SCOPE)
	set(_all_definitions ${_all_definitions} PARENT_SCOPE)
endfunction()

if(CTAGS OR CSCOPE)
	set(SOURCES_LIST "${CMAKE_BINARY_DIR}/source_files.lst")
	set(CTAGS_IDENTIFIER_LIST "${CMAKE_BINARY_DIR}/identifier.lst")
	set(_all_source_files "")
	set(_all_definitions "")

	file(REMOVE "${SOURCES_LIST}")
	file(REMOVE "${CTAGS_IDENTIFIER_LIST}")

	tags_add_dir(${CMAKE_SOURCE_DIR})

	list(SORT _all_source_files)
	list(REMOVE_DUPLICATES _all_source_files)
	string(REGEX REPLACE "${CMAKE_SOURCE_DIR}/" "" _asf "${_all_source_files}")
	string(REGEX REPLACE ";" "\n" _asf "${_asf}")
	file(APPEND ${SOURCES_LIST} "\n${_asf}")

	string(REGEX REPLACE "${CMAKE_SOURCE_DIR}/" "" _t_extra "${TAGS_EXTRA_FILES}")
	string(REGEX REPLACE ";" "\n" _t_extra "${_t_extra}")
	file(APPEND ${SOURCES_LIST} "\n${_t_extra}")

	string(REGEX REPLACE ";" "\n" _all_definitions "${_all_definitions}")
	string(REGEX REPLACE "^([^=]+)$" "\\1=1" _all_definitions "${_all_definitions}")
	file(APPEND ${CTAGS_IDENTIFIER_LIST} "\n${_all_definitions}")

	add_custom_target(tags)
	#add_custom_target(tags ALL)
endif()

if(CTAGS)
	if (NOT CTAGS_TAG_FILE)
		set(CTAGS_TAG_FILE "${CMAKE_SOURCE_DIR}/tags" CACHE STRING "ctags output file")
	endif()

	add_custom_target(ctags
		COMMAND ctags --extra=+q --c-kinds=+lpx --fields=afikmsSzt
		-I ${CTAGS_IDENTIFIER_LIST} -f ${CTAGS_TAG_FILE} -L ${SOURCES_LIST}
		DEPENDS ${_all_source_files}
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
		VERBATIM)
	#add_custom_command(TARGET ctags
	#	COMMAND ${CMAKE_SOURCE_DIR}/support/gen_types.sh ${CTAGS_TAG_FILE} ${CMAKE_SOURE_DIR}
	#	DEPENDS ${CTAGS_TAG_FILE}
	#	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	#	)
	add_dependencies(tags ctags)
endif()

if(CSCOPE)
	add_custom_target(cscope
		COMMAND cscope -Rb ${CSCOPE_INCLUDES} -k -i ${SOURCES_LIST}
		DEPENDS ${_all_source_files}
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
		VERBATIM)
	add_dependencies(tags cscope)
endif()
