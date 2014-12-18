# QTrace Makefile will take care of prepending PLUGIN_DIR to these paths
plugin-objs = main.o memory.o serialize.o manager.o callbacks.o syscall.o \
	pb/syscall.pb.o

protobuf-files = $(PLUGIN_DIR)/pb/syscall.pb.cc $(PLUGIN_DIR)/pb/syscall.pb.h

# These are generated files that QTrace main Makefile removes during cleanup
plugin-generated = $(protobuf-files)

# Add depedency on protobuf library
LDFLAGS += -lprotobuf

$(PLUGIN_DIR)/pb/syscall.pb.cc: $(PLUGIN_DIR)/pb/syscall.proto
	protoc $^ --cpp_out=$(CURDIR)/

$(PLUGIN_DIR)/pb/syscall.pb.h: $(PLUGIN_DIR)/pb/syscall.pb.cc

$(PLUGIN_DIR)/pb/syscall.pb.o: $(protobuf-files)
	$(CC) $(CPPFLAGS) -c -o $@ $<

$(PLUGIN_DIR)/serialize.o: $(PLUGIN_DIR)/pb/syscall.pb.h
