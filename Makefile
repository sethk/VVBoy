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
LDLIBS = -ledit
CC_ANALYZER = /usr/local/Cellar/llvm35/3.5.1/share/clang-3.5/tools/scan-build/ccc-analyzer

USE_SDL = yes

ifeq ($(USE_SDL),yes)
    SRCS+= tk_sdl.c
    CFLAGS+= `sdl2-config --cflags`
    LDLIBS+= `sdl2-config --libs`
endif

OBJS := $(SRCS:%.c=%.o)

all: $(TARGET)

vvboy: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean::
	rm -f $(TARGET) $(OBJS) .depend tags

main.h tk_sdl.h: vendor/makeheaders/makeheaders $(SRCS)
	vendor/makeheaders/makeheaders $(SRCS)

$(OBJS): .depend

.depend: $(SRCS)
	mkdep $(CFLAGS) $^

-include .depend

tags:: $(SRCS) $(HEADERS)
	ctags --c-kinds=+p $^

lint: $(SRCS)
	$(CC_ANALYZER) $(CFLAGS) -fsyntax-only $(SRCS)
