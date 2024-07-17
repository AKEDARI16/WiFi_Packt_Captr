# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -g

# Linker flags (libraries)
LDFLAGS = -lpcap -lpthread

# Target executable name
TARGET = main

# Source files
SRCS = main.c connect_pkt.c scan_pkt.c pkt_cap.c handshake.c

# Object files generated from source files
OBJS = $(SRCS:.c=.o)

# Header files
HDRS = MtlPktLyzer.h scan.h handshake.h

# Phony targets (targets not associated with actual files)
.PHONY: all clean force

# Default target, depends on the target executable
all: $(TARGET)

# Rule to build the target executable from object files
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule to build object files from source files
%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

# Phony target to force rebuilding other targets
force:
	@true

# Clean target to remove compiled files
clean:
	rm -f $(OBJS) $(TARGET)
