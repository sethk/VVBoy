DEBUG = 1

CFLAGS?= -pipe -Wall
ifdef DEBUG
    CFLAGS+= -O0 -g -fno-inline
else
    CFLAGS+= -O3
endif
TARGET = vvboy
SRCS = main.c
HEADERS = tk.h
LDLIBS = -ledit
CC_ANALYZER = /usr/local/Cellar/llvm35/3.5.1/share/clang-3.5/tools/scan-build/ccc-analyzer

USE_SDL = yes

ifeq ($(USE_SDL),yes)
    SRCS+= tk_sdl.c
    CFLAGS+= `sdl2-config --cflags`
    LDLIBS+= `sdl2-config --libs`
else
    SRCS+= tk_null.c
endif

OBJS := $(SRCS:%.c=%.o)
GEN_HEADERS := $(SRCS:%.c=%.h)

all: $(TARGET) tags

.headers-stamp: $(SRCS) $(HEADERS)
	vendor/makeheaders/makeheaders $(SRCS) $(HEADERS)
	touch .headers-stamp

$(TARGET): .headers-stamp $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)

clean::
	rm -f $(TARGET) $(OBJS) $(GEN_HEADERS) .headers-stamp tags

tags:: $(SRCS)
	ctags --c-kinds=+p $^

lint: $(SRCS)
	$(CC_ANALYZER) $(CFLAGS) -fsyntax-only $(SRCS)
