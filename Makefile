SHELL=/bin/bash

CC := emcc
CL := emcc
LFLAGS := $(LFLAGS) -static

ifndef TARGET_DIR
TARGET_DIR := ./
endif
ifndef TARGET_NAME
TARGET_NAME := out
endif

TARGET := $(TARGET_NAME).html
BUILD_DIR := $(TARGET_DIR)/build_dir
SRC_DIRS := $(SRC_DIRS)

SRCS := $(shell find $(SRC_DIRS) -maxdepth 1 -name "*.c")
#OBJS := $(addsuffix .o, $(shell basename -a $(SRCS)))
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

INC_DIRS := $(INC_DIRS) #$(shell find $(SRC_DIRS) -type d | sed -e 's,^\$(BUILD_DIR)/*,,' )
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CFLAGS := $(INC_FLAGS) -MMD -MP $(CFLAGS)

gnu/linux: mkdirs $(BUILD_DIR)/$(TARGET)
	cd $(BUILD_DIR); tar -zcvf $(TARGET_NAME)_wasm.tar.gz ./*js ./*wasm
	mv $(BUILD_DIR)/$(TARGET_NAME)_wasm.tar.gz $(TARGET_DIR)

mkdirs:
	mkdir -p $(BUILD_DIR) $(addprefix $(BUILD_DIR),$(SRC_DIRS))

$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CL) $(OBJS) -o $@ $(LFLAGS)

$(BUILD_DIR)/%.c.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.cpp.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

all: gnu/linux

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
