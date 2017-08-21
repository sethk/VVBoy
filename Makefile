DEBUG = 1

CFLAGS?= -pipe -Wall
ifdef DEBUG
    CFLAGS+= -O0 -g -fno-inline
else
    CFLAGS+= -O3
endif
TARGET = vvboy
SRCS = main.c
HEADERS = main.h
OBJS := $(SRCS:%.c=%.o)
LDLIBS = -ledit
CC_ANALYZER = /usr/local/Cellar/llvm35/3.5.1/share/clang-3.5/tools/scan-build/ccc-analyzer

all: $(TARGET)

vvboy: main.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean::
	rm -f $(TARGET) $(OBJS) .depend tags

main.h: vendor/makeheaders/makeheaders $(SRCS)
	vendor/makeheaders/makeheaders $(SRCS)

$(TARGET): .depend

.depend: $(SRCS)
	mkdep $^

-include .depend

tags:: $(SRCS) $(HEADERS)
	ctags --c-kinds=+p $^

lint: $(SRCS)
	$(CC_ANALYZER) $(CFLAGS) -fsyntax-only $(SRCS)
