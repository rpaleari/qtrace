# Points to the root of Google Test
GTEST_DIR = /usr/src/gtest

# Where to find user code
SOURCE_DIR = ../
QEMU_DIR = $(SOURCE_DIR)/../

# Flags passed to the preprocessor
CPPFLAGS += -isystem $(GTEST_DIR)/include -I$(SOURCE_DIR) -I$(QEMU_DIR) \
	-I$(QEMU_DIR)/i386-softmmu -I$(QEMU_DIR)/i386-linux-user \
	-I$(QEMU_DIR)/x86_64-softmmu -I$(QEMU_DIR)/x86_64-linux-user \
	-I$(QEMU_DIR)/include -std=c++11

# Flags passed to the C++ compiler
CXXFLAGS += -g -Wall -Wextra -pthread

# All tests produced by this Makefile
UNITTESTS = intervals_unittest shadow_unittest taintengine_unittest
TAINTTESTS_32 := $(basename $(wildcard taint/x86*.S))
TAINTTESTS_64 := $(basename $(wildcard taint/x64*.S))

# All Google Test headers
GTEST_HEADERS = /usr/include/gtest/*.h \
                /usr/include/gtest/internal/*.h

# House-keeping build targets
all : taint unit
taint: $(TAINTTESTS_32) $(TAINTTESTS_64)
unit: $(UNITTESTS)

clean :
	-rm $(UNITTESTS)
	-rm $(TAINTTESTS_32) $(TAINTTESTS_64)
	-rm gtest.a gtest_main.a *.o

# Builds gtest.a and gtest_main.a
GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)

gtest-all.o: $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest-all.cc

gtest_main.o: $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest_main.cc

gtest.a: gtest-all.o
	$(AR) $(ARFLAGS) $@ $^

gtest_main.a: gtest-all.o gtest_main.o
	$(AR) $(ARFLAGS) $@ $^

# Rules for building unit tests
%_unittest.o: %_unittest.cc $(SOURCE_DIR)/%.h $(GTEST_HEADERS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(UNITTESTS): %_unittest: %_unittest.o gtest_main.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -lpthread $^ -o $@

# Rules for build taint analysis tests
$(TAINTTESTS_32): %: %.S
	$(CXX) -m32 -nostdlib -o $@ $^
$(TAINTTESTS_64): %: %.S
	$(CXX) -nostdlib -o $@ $^

# Additional dependencies
intervals_unittest: $(SOURCE_DIR)/trace/intervals.o
syscall_unittest: $(SOURCE_DIR)/trace/tainted.o
shadow_unittest: $(SOURCE_DIR)/taint/shadow.o
taintengine_unittest: $(SOURCE_DIR)/taint/taintengine.o $(SOURCE_DIR)/taint/shadow.o $(SOURCE_DIR)/logging.o
