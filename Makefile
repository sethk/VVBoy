BUILD_TYPE?= debug
CMAKE_DIR = cmake-build-${BUILD_TYPE}

ALL_TARGETS = all vvboy tags clean
.PHONY: ${ALL_TARGETS}
#.DEFAULT: vvboy

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

.PHONY: vvboy/run
vvboy/run: vvboy
	cd ${CMAKE_DIR} && ./$<

.PHONY: run
run: vvboy/run

.PHONY: vvboy/debug
vvboy/debug: vvboy
	cd ${CMAKE_DIR} && lldb $<

.PHONY: debug
debug: vvboy/debug

#CC_ANALYZER = /usr/local/Cellar/llvm35/3.5.1/share/clang-3.5/tools/scan-build/ccc-analyzer
#
#tags:: $(SRCS)
#	ctags --c-kinds=+p $^
#
#lint: $(SRCS)
#	$(CC_ANALYZER) $(CFLAGS) -fsyntax-only $(SRCS)
