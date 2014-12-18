#include <gtest/gtest.h>

#include "taint/taintengine.h"

const int TEST_TAINTLABEL = 0x0badb00b;

TEST(TaintEngineTest, Init) {
  TaintEngine engine;

  for (target_ulong regno = 0; regno < NUM_CPU_REGS; regno++) {
      ASSERT_FALSE(engine.isTaintedRegister(false, regno));
  }

  for (target_ulong regno = 0; regno < NUM_TMP_REGS; regno++) {
      ASSERT_FALSE(engine.isTaintedRegister(true, regno));
  }

  ASSERT_FALSE(engine.isTaintedMemory(0xcafebabe));
}

TEST(TaintEngineTest, RegisterAddLabel) {
  const bool istmpreg = false;
  const target_ulong regno = 1;

  TaintEngine engine;

  ASSERT_FALSE(engine.isTaintedRegister(istmpreg, regno));

  engine.setTaintedRegister(TEST_TAINTLABEL, istmpreg, regno);

  EXPECT_TRUE(engine.isTaintedRegister(istmpreg, regno));
  EXPECT_TRUE(engine.isTaintedRegister(istmpreg, regno, 0, 1));
  EXPECT_TRUE(engine.isTaintedRegister(istmpreg, regno, 
                                       sizeof(target_ulong) - 1, 1));
  EXPECT_TRUE(engine.isTaintedRegister(istmpreg, regno, 0, 4));
  EXPECT_FALSE(engine.isTaintedRegister(!istmpreg, regno));
}

TEST(TaintEngineTest, MemoryAddLabel) {
  const target_ulong addr = 0xcafebabe;
  const int size = 4;

  TaintEngine engine;

  ASSERT_FALSE(engine.isTaintedMemory(addr));

  engine.setTaintedMemory(TEST_TAINTLABEL, addr, size);

  for (unsigned int offset = 0; offset < size; offset++) {
    EXPECT_TRUE(engine.isTaintedMemory(addr + offset));
  }

  EXPECT_FALSE(engine.isTaintedMemory(addr-1));
  EXPECT_FALSE(engine.isTaintedMemory(addr+size));
}

TEST(TaintPropagationMove, RegisterToRegister) {
  const bool istmpreg = true;
  const target_ulong srcreg = 1, dstreg = 4, clearreg = 5;

  TaintEngine engine;

  engine.setTaintedRegister(TEST_TAINTLABEL, istmpreg, srcreg);  
  ASSERT_TRUE(engine.isTaintedRegister(istmpreg, srcreg));
  ASSERT_FALSE(engine.isTaintedRegister(istmpreg, dstreg));

  engine.moveR2R(istmpreg, srcreg, istmpreg, dstreg);

  EXPECT_TRUE(engine.isTaintedRegister(istmpreg, srcreg));
  EXPECT_TRUE(engine.isTaintedRegister(istmpreg, dstreg));
  EXPECT_TRUE(engine.hasRegisterLabel(istmpreg, dstreg, TEST_TAINTLABEL));

  // Check register is also properly cleared
  engine.moveR2R(istmpreg, clearreg, istmpreg, dstreg);
  EXPECT_FALSE(engine.isTaintedRegister(istmpreg, dstreg));
}

TEST(TaintPropagationMove, RegisterToMemory) {
  // Source
  const bool istmpreg = false;
  const target_ulong regno = 1, clearreg = 2;

  // Destination
  const target_ulong addr = 0xcafebabe;
  const int size = 4;

  TaintEngine engine;

  engine.setTaintedRegister(TEST_TAINTLABEL, istmpreg, regno);  
  ASSERT_TRUE(engine.isTaintedRegister(istmpreg, regno));
  for (int offset = 0; offset < size; offset++) {
    ASSERT_FALSE(engine.isTaintedMemory(addr + offset));
  }

  engine.moveR2M(istmpreg, regno, addr, size);

  EXPECT_TRUE(engine.isTaintedRegister(istmpreg, regno));
  for (int offset = 0; offset < size; offset++) {
    EXPECT_TRUE(engine.isTaintedMemory(addr + offset));
  }

  // Check memory is also properly cleared
  engine.moveR2M(istmpreg, clearreg, addr, size);
  for (int offset = 0; offset < size; offset++) {
    EXPECT_FALSE(engine.isTaintedMemory(addr + offset));
  }
}

TEST(TaintPropagationMove, RegisterToMemory8bit) {
  // Source
  const bool istmpreg = false;
  const target_ulong regno = 1;

  // Destination
  const target_ulong addr = 0xcafebabe;

  TaintEngine engine;

  engine.setTaintedRegister(TEST_TAINTLABEL, istmpreg, regno);  
  ASSERT_TRUE(engine.isTaintedRegister(istmpreg, regno));
  ASSERT_FALSE(engine.isTaintedMemory(addr));

  engine.moveR2M(istmpreg, regno, addr, 1);

  EXPECT_TRUE(engine.isTaintedRegister(istmpreg, regno));
  EXPECT_TRUE(engine.isTaintedMemory(addr));
  EXPECT_FALSE(engine.isTaintedMemory(addr - 1));
  EXPECT_FALSE(engine.isTaintedMemory(addr + 1));
}

TEST(TaintPropagationMove, MemoryToRegister) {
  // Source
  const target_ulong addr = 0xcafebabe;
  const int size = 4;

  // Destination
  const bool istmpreg = true;
  const target_ulong regno = 3;

  TaintEngine engine;

  engine.setTaintedMemory(TEST_TAINTLABEL, addr, size);  
  for (int offset = 0; offset < size; offset++) {
    ASSERT_TRUE(engine.isTaintedMemory(addr + offset));
  }
  ASSERT_FALSE(engine.isTaintedRegister(istmpreg, regno));

  engine.moveM2R(addr, size, istmpreg, regno);

  EXPECT_TRUE(engine.isTaintedRegister(istmpreg, regno));
  for (int offset = 0; offset < size; offset++) {
    EXPECT_TRUE(engine.isTaintedMemory(addr + offset));
  }

  // Check register is also properly cleared
  engine.moveM2R(addr+size, size, istmpreg, regno);
  EXPECT_FALSE(engine.isTaintedRegister(istmpreg, regno));
}

TEST(TaintPropagationMove, MemoryToRegister8bit) {
  // Source
  const target_ulong addr = 0xcafebabe;

  // Destination
  const bool istmpreg = true;
  const target_ulong regno = 3;

  TaintEngine engine;

  engine.setTaintedMemory(TEST_TAINTLABEL, addr, 1);
  ASSERT_TRUE(engine.isTaintedMemory(addr));
  ASSERT_FALSE(engine.isTaintedRegister(istmpreg, regno));

  engine.moveM2R(addr, 1, istmpreg, regno);

  EXPECT_TRUE(engine.isTaintedRegister(istmpreg, regno));
}

TEST(TaintPropagationCombine, RegisterToRegister) {
  const bool istmpreg = true;
  const target_ulong srcreg = 1, dstreg = 4;

  TaintEngine engine;

  engine.setTaintedRegister(TEST_TAINTLABEL, istmpreg, srcreg);
  engine.setTaintedRegister(TEST_TAINTLABEL+1, istmpreg, dstreg);

  ASSERT_TRUE(engine.isTaintedRegister(istmpreg, srcreg));
  ASSERT_TRUE(engine.isTaintedRegister(istmpreg, dstreg));

  ASSERT_TRUE(engine.hasRegisterLabel(istmpreg, srcreg, TEST_TAINTLABEL));
  ASSERT_FALSE(engine.hasRegisterLabel(istmpreg, srcreg, TEST_TAINTLABEL+1));
  ASSERT_FALSE(engine.hasRegisterLabel(istmpreg, dstreg, TEST_TAINTLABEL));
  ASSERT_TRUE(engine.hasRegisterLabel(istmpreg, dstreg, TEST_TAINTLABEL+1));

  engine.combineR2R(istmpreg, srcreg, istmpreg, dstreg);

  EXPECT_TRUE(engine.hasRegisterLabel(istmpreg, srcreg, TEST_TAINTLABEL));
  EXPECT_FALSE(engine.hasRegisterLabel(istmpreg, srcreg, TEST_TAINTLABEL+1));
  EXPECT_TRUE(engine.hasRegisterLabel(istmpreg, dstreg, TEST_TAINTLABEL));
  EXPECT_TRUE(engine.hasRegisterLabel(istmpreg, dstreg, TEST_TAINTLABEL+1));
}

TEST(TaintPropagationCombine, RegisterToMemory) {
  // Source
  const bool istmpreg = false;
  const target_ulong regno = 1;

  // Destination
  const target_ulong addr = 0xcafebabe;
  const int size = 4;

  TaintEngine engine;

  engine.setTaintedRegister(TEST_TAINTLABEL, istmpreg, regno);
  engine.setTaintedMemory(TEST_TAINTLABEL+1, addr, size);

  ASSERT_TRUE(engine.hasRegisterLabel(istmpreg, regno, TEST_TAINTLABEL));
  ASSERT_FALSE(engine.hasRegisterLabel(istmpreg, regno, TEST_TAINTLABEL+1));
  for (int offset = 0; offset < size; offset++) {
    ASSERT_FALSE(engine.hasMemoryLabel(addr + offset, TEST_TAINTLABEL));
    ASSERT_TRUE(engine.hasMemoryLabel(addr + offset, TEST_TAINTLABEL+1));
  }

  engine.combineR2M(istmpreg, regno, addr, size);

  ASSERT_TRUE(engine.hasRegisterLabel(istmpreg, regno, TEST_TAINTLABEL));
  ASSERT_FALSE(engine.hasRegisterLabel(istmpreg, regno, TEST_TAINTLABEL+1));
  for (int offset = 0; offset < size; offset++) {
    ASSERT_TRUE(engine.hasMemoryLabel(addr + offset, TEST_TAINTLABEL));
    ASSERT_TRUE(engine.hasMemoryLabel(addr + offset, TEST_TAINTLABEL+1));
  }
}

TEST(TaintPropagationCombine, MemoryToRegister) {
  // Source
  const target_ulong addr = 0xcafebabe;
  const int size = 4;

  // Destination
  const bool istmpreg = true;
  const target_ulong regno = 3;

  TaintEngine engine;

  engine.setTaintedRegister(TEST_TAINTLABEL, istmpreg, regno);
  engine.setTaintedMemory(TEST_TAINTLABEL+1, addr, size);

  ASSERT_TRUE(engine.hasRegisterLabel(istmpreg, regno, TEST_TAINTLABEL));
  ASSERT_FALSE(engine.hasRegisterLabel(istmpreg, regno, TEST_TAINTLABEL+1));
  for (int offset = 0; offset < size; offset++) {
    ASSERT_FALSE(engine.hasMemoryLabel(addr + offset, TEST_TAINTLABEL));
    ASSERT_TRUE(engine.hasMemoryLabel(addr + offset, TEST_TAINTLABEL+1));
  }

  engine.combineM2R(addr, size, istmpreg, regno);

  for (int offset = 0; offset < size; offset++) {
    ASSERT_FALSE(engine.hasMemoryLabel(addr + offset, TEST_TAINTLABEL));
    ASSERT_TRUE(engine.hasMemoryLabel(addr + offset, TEST_TAINTLABEL+1));
  }
  ASSERT_TRUE(engine.hasRegisterLabel(istmpreg, regno, TEST_TAINTLABEL));
  ASSERT_TRUE(engine.hasRegisterLabel(istmpreg, regno, TEST_TAINTLABEL+1));
}
