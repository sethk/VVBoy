CFLAGS?= -pipe -Wall -O0 -g -fno-inline
TARGET = vvboy
SRCS = main.c
OBJS := $(SRCS:%.c=%.o)
LDLIBS = -ledit
CC_ANALYZER = /usr/local/Cellar/llvm35/3.5.1/share/clang-3.5/tools/scan-build/ccc-analyzer

all: $(TARGET)

vvboy: main.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean::
	rm -f $(TARGET) $(OBJS)

tags:: $(SRCS)
	ctags $^

lint: $(SRCS)
	$(CC_ANALYZER) $(CFLAGS) -fsyntax-only $(SRCS)
