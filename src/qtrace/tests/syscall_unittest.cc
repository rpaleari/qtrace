#include <gtest/gtest.h>

#include "trace/syscall.h"
#include "trace/intervals.h"

class SyscallTest : public testing::Test {
protected:
  virtual void SetUp() {
    SyscallArg *arg = new SyscallArg();
    arg->addr = 0x0badb00b;
    arg->offset = 0;
    arg->indata.add(DataInterval(0, 3, "\xbe\xba\xfe\xca"), false);
    syscall_.addArgument(arg);
  }

  Syscall syscall_(0, 0, 0, 0);
};

TEST_F(SyscallTest, InitiallyEmpty) {
  Syscall emptysyscall(0, 0, 0, 0);
  EXPECT_EQ(0, emptysyscall.args.size());
}

TEST_F(SyscallTest, NewArgument) {
  ASSERT_EQ(1, syscall_.args.size());
  EXPECT_EQ(4, syscall_.args[0]->getSize());
}

TEST_F(SyscallTest, Candidate) {
  // Add this argument and candidate pointer
  syscall_.addCandidate(syscall_.args[0], 0);
  EXPECT_TRUE(syscall_.hasCandidate(0xcafebabe));

  // Remove the candidate
  syscall_.removeCandidate(0xcafebabe);
  EXPECT_FALSE(syscall_.hasCandidate(0xcafebabe));
}

TEST_F(SyscallTest, ActualizeCandidate) {
  // Create a candidate pointer
  syscall_.addCandidate(syscall_.args[0], 0);
  EXPECT_TRUE(syscall_.hasCandidate(0xcafebabe));
  EXPECT_EQ(0, syscall_.args[0]->ptrs.size());

  // Actualize the candidate pointer
  syscall_.actualizeCandidate(0xcafebabe, 0xdeadbeef, 4, DirectionIn);
  EXPECT_FALSE(syscall_.hasCandidate(0xcafebabe));
  EXPECT_EQ(1, syscall_.args[0]->ptrs.size());
}

TEST_F(SyscallTest, ForeignCandidate) {
  // Add a foreign candidate pointer
  syscall_.addForeignCandidate(0xdeadbeef, 0x41424344, 0xbadbabe);
  EXPECT_TRUE(syscall_.hasForeignCandidate(0x41424344));
  EXPECT_EQ(0, syscall_.foreign_ptrs.size());

  // Actualize the foreign candidate pointer
  syscall_.actualizeForeignCandidate(0x41424344);
  EXPECT_FALSE(syscall_.hasForeignCandidate(0x41424344));
  EXPECT_EQ(1, syscall_.foreign_ptrs.size());
}

TEST_F(SyscallTest, ForeignCleanup) {
  // Add a candidate syscall data pointer and actualize it
  syscall_.addCandidate(syscall_.args[0], 0);
  syscall_.actualizeCandidate(0xcafebabe, 0xdeadbeef, 4, DirectionIn);
  EXPECT_EQ(1, syscall_.args[0]->ptrs.size());

  // Add an actualized foreign data pointer with the same value
  syscall_.addForeignCandidate(0xcafebabe, 0xdeadbeef, 0x0badbabe);
  syscall_.actualizeForeignCandidate(0xdeadbeef);
  EXPECT_EQ(1, syscall_.foreign_ptrs.size());

  // Trigger foreign pointers cleanup
  syscall_.cleanupForeignPointers();
  EXPECT_EQ(0, syscall_.foreign_ptrs.size());
  EXPECT_EQ(1, syscall_.args[0]->ptrs.size());
}
