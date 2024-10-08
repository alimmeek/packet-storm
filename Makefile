PRODUCT := packet-storm
BUILDDIR := ./build

HDRS := $(wildcard ./src/*.h)
SRCS := $(wildcard ./src/*.c)
BINARY := $(BUILDDIR)/$(PRODUCT)
OBJS := $(SRCS:./%.c=$(BUILDDIR)/%.o)

CC := gcc

CFLAGS := -O3 -D"MAX_THREADS=${PROC_COUNT}" -Wno-unused-result
LDFLAGS := -lpthread -lpcap

.PHONY: all clean

all: $(BINARY)

clean:
	rm -rf $(BUILDDIR)

$(BINARY): $(OBJS)
	echo $(OBJS)
	@echo linking $@
	$(maketargetdir)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILDDIR)/%.o : ./%.c
	@echo compiling $<
	$(maketargetdir)
	$(CC) $(CFLAGS) -c -o $@ $<

define maketargetdir
	-@mkdir -p $(dir $@) > /dev/null 2>&1
endef