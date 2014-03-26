#include <gtest/gtest.h>

#include "../shadow.h"

TEST(TaintLocationTest, AddLabel) {
  TaintLocation loc;

  int label = 0xbadb00b;
  
  EXPECT_FALSE(loc.hasLabel(label));
  EXPECT_FALSE(loc.isTainted());

  loc.addLabel(label);

  EXPECT_TRUE(loc.hasLabel(label));
  EXPECT_TRUE(loc.isTainted());
}

TEST(TaintLocationTest, Assign) {
  TaintLocation loc1, loc2;

  int label = 0xbadb00b;
  loc2.addLabel(label);

  EXPECT_FALSE(loc1.isTainted());
  EXPECT_FALSE(loc1.hasLabel(label));
  EXPECT_TRUE(loc2.isTainted());

  loc1.set(loc2);

  EXPECT_TRUE(loc1.isTainted());
  EXPECT_TRUE(loc2.isTainted());
  EXPECT_TRUE(loc1.hasLabel(label));
  EXPECT_TRUE(loc2.hasLabel(label));
}

TEST(TaintLocationTest, Combine) {
  TaintLocation loc1, loc2;

  loc1.addLabel(1);
  loc1.addLabel(2);
  EXPECT_TRUE(loc1.isTainted());
  EXPECT_TRUE(loc1.hasLabel(1));
  EXPECT_TRUE(loc1.hasLabel(2));
  EXPECT_FALSE(loc1.hasLabel(3));
  EXPECT_FALSE(loc1.hasLabel(4));

  loc2.addLabel(2);
  loc2.addLabel(3);
  loc2.addLabel(4);
  EXPECT_TRUE(loc2.isTainted());
  EXPECT_FALSE(loc2.hasLabel(1));
  EXPECT_TRUE(loc2.hasLabel(2));
  EXPECT_TRUE(loc2.hasLabel(3));
  EXPECT_TRUE(loc2.hasLabel(4));

  loc1.combine(loc2);

  EXPECT_TRUE(loc1.hasLabel(1));
  EXPECT_TRUE(loc1.hasLabel(2));
  EXPECT_TRUE(loc1.hasLabel(3));
  EXPECT_TRUE(loc1.hasLabel(4));

  EXPECT_FALSE(loc2.hasLabel(1));
  EXPECT_TRUE(loc2.hasLabel(2));
  EXPECT_TRUE(loc2.hasLabel(3));
  EXPECT_TRUE(loc2.hasLabel(4));
}

TEST(ShadowMemoryTest, TaintAddress) {
  ShadowMemory mem;

  target_ulong addr = 0xcafebabe;
  int label = 0xbadb00b;

  EXPECT_FALSE(mem.isTaintedAddress(addr));
  mem.addLabel(addr, label);
  EXPECT_TRUE(mem.isTaintedAddress(addr));
}

TEST(TaintRegisterTest, Initialize) {
  ShadowRegister reg(4);

  EXPECT_EQ(4, reg.getSize());
  EXPECT_FALSE(reg.isTainted());
}
