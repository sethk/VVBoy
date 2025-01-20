BUILD_TYPE?= Debug
CMAKE_DIR = cmake-build-${BUILD_TYPE}
MAKEFLAGS+= -j8

ALL_TARGETS = all VVBoy tags clean
.PHONY: ${ALL_TARGETS}
#.DEFAULT: VVBoy

${ALL_TARGETS}: ${CMAKE_DIR}
	cd ${CMAKE_DIR} && ${MAKE} $@

${CMAKE_DIR}:
	mkdir -p ${CMAKE_DIR}
	cd ${CMAKE_DIR} && cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ..

.PHONY: clean/cmake-cache
clean/cmake-cache:
	rm -f ${CMAKE_DIR}/CMakeCache.txt

.PHONY: distclean
distclean:
	rm -rf ${CMAKE_DIR}

ifdef ROM_FILE
  ifeq '$(patsubst /%,X%,${ROM_FILE})' 'X'
    RUN_ARGS+= "${ROM_FILE}"
  else
    RUN_ARGS+= "${PWD}/${ROM_FILE}"
  endif
endif

.PHONY: VVBoy/run
VVBoy/run: VVBoy
	@echo Use make run ROM_FILE=...
	cd ${CMAKE_DIR} && ./$< ${RUN_ARGS}

.PHONY: run
run: VVBoy/run

.PHONY: VVBoy/debug
VVBoy/debug: VVBoy
	cd ${CMAKE_DIR} && lldb $< -- ${RUN_ARGS}

.PHONY: debug
debug: VVBoy/debug

#CC_ANALYZER = /usr/local/Cellar/llvm35/3.5.1/share/clang-3.5/tools/scan-build/ccc-analyzer
#
#tags:: $(SRCS)
#	ctags --c-kinds=+p $^
#
#lint: $(SRCS)
#	$(CC_ANALYZER) $(CFLAGS) -fsyntax-only $(SRCS)
