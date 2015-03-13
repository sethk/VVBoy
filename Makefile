CFLAGS?= -pipe -Wall -O0 -g
TARGET = vvboy
OBJS = main.o
LDLIBS = -ledit

all: $(TARGET)

vvboy: main.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET) $(OBJS)
