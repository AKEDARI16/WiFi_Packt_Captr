# Compiler
CC = gcc

# Compiler flags
#CFLAGS = -Wall -Wextra -g
CFLAGS += -Iinclude
# Linker flags (libraries)
LDFLAGS = -lpcap -lpthread

# Target executable name
TARGET = MtlNetLyzer

# Function to recursively find files
rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))

# Source files
SRCS = $(call rwildcard,src/,*.c)

# Object files directory
OBJDIR = obj

# Object files generated from source files
OBJS = $(patsubst src/%.c, $(OBJDIR)/%.o, $(SRCS))

# Header files
HDRS = $(call rwildcard,include/,*.h)

# Phony targets (targets not associated with actual files)
.PHONY: all clean force

# Default target, depends on the target executable
all: $(TARGET)

# Rule to build the target executable from object files
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	
# Rule to build object files from source files
$(OBJDIR)/%.o: src/%.c $(HDRS) | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Phony target to force rebuilding other targets
force:
	@true

# Clean target to remove compiled files
clean:
	rm -f $(OBJS) $(TARGET)
#debug_file_path := $(shell pwd)/log/cap_debug.log
 
# Export the debug_file_path variable so it can be used in other parts of the Makefile
#export debug_file_path