#include <gtest/gtest.h>

#include "../intervals.h"

// Check that a new intervals set is really empty
TEST(DataIntervalSetTest, InitiallyEmpty) {
  DataIntervalSet intervals;
  EXPECT_TRUE(intervals.isEmpty());
  EXPECT_EQ(0, intervals.getMaxLength());
}

// Sanity checks over a set of disjoint intervals
TEST(DataIntervalSetTest, Disjoint) {
  DataIntervalSet intervals;

  intervals.add(DataInterval(0, 1, "ab"), true);
  intervals.add(DataInterval(4, 5, "cd"), true);

  ASSERT_TRUE(!intervals.isEmpty());
  ASSERT_EQ(6, intervals.getMaxLength());
  ASSERT_EQ(2, intervals.getNumDataIntervals());
}

// Coalescing consecutive intervals
TEST(DataIntervalSetTest, ConsecutiveRight) {
  DataIntervalSet int1;
  int1.add(DataInterval(0, 1, "ab"), true);
  int1.add(DataInterval(2, 3, "cd"), true);

  ASSERT_TRUE(!int1.isEmpty());
  ASSERT_EQ(4, int1.getMaxLength());
  ASSERT_EQ(1, int1.getNumDataIntervals());

  DataIntervalSet int2;
  int2.add(DataInterval(0, 1, "ab"), false);
  int2.add(DataInterval(2, 3, "cd"), false);

  ASSERT_TRUE(!int2.isEmpty());
  ASSERT_EQ(4, int2.getMaxLength());
  ASSERT_EQ(1, int2.getNumDataIntervals());
}

// Coalescing consecutive intervals
TEST(DataIntervalSetTest, ConsecutiveLeft) {
  DataIntervalSet int1;
  int1.add(DataInterval(2, 3, "cd"), true);
  int1.add(DataInterval(0, 1, "ab"), true);

  ASSERT_TRUE(!int1.isEmpty());
  ASSERT_EQ(4, int1.getMaxLength());
  ASSERT_EQ(1, int1.getNumDataIntervals());

  DataIntervalSet int2;
  int2.add(DataInterval(2, 3, "cd"), false);
  int2.add(DataInterval(0, 1, "ab"), false);

  ASSERT_TRUE(!int2.isEmpty());
  ASSERT_EQ(4, int2.getMaxLength());
  ASSERT_EQ(1, int2.getNumDataIntervals());
}

// Coalescing overlapping intervals
TEST(DataIntervalSetTest, Overlap) {
  DataIntervalSet intervals;

  intervals.add(DataInterval(2, 4, "abc"), true);
  intervals.add(DataInterval(3, 5, "def"), true);

  ASSERT_TRUE(!intervals.isEmpty());
  ASSERT_EQ(6, intervals.getMaxLength());
  ASSERT_EQ(1, intervals.getNumDataIntervals());
}

// Read tests for the "overwrite" merge policy
TEST(DataIntervalSetTest, ReadSuccess) {
  char buffer[5];
  memset(buffer, 0, sizeof(buffer));

  DataIntervalSet intervals;
  intervals.add(DataInterval(2, 6, "abcde"), true);

  int r;
  r = intervals.read(2, sizeof(buffer)-1, 
		     reinterpret_cast<unsigned char*>(buffer));
  ASSERT_EQ(0, r);
  EXPECT_STREQ("abcd", buffer);

  r = intervals.read(3, sizeof(buffer)-1, 
		     reinterpret_cast<unsigned char*>(buffer));
  ASSERT_EQ(0, r);
  EXPECT_STREQ("bcde", buffer);
}

// Read tests for the "overwrite" merge policy, overlapping intervals
TEST(DataIntervalSetTest, ReadOverwrite) {
  char buffer[5];
  memset(buffer, 0, sizeof(buffer));

  // Right overlap
  DataIntervalSet intervals1;
  intervals1.add(DataInterval(2, 6, "abcde"), true);
  intervals1.add(DataInterval(4, 8, "12345"), true);

  int r;
  r = intervals1.read(3, sizeof(buffer)-1, 
		      reinterpret_cast<unsigned char*>(buffer));
  ASSERT_EQ(0, r);
  EXPECT_STREQ("b123", buffer);

  // Left overlap
  DataIntervalSet intervals2;
  intervals2.add(DataInterval(4, 8, "12345"), true);
  intervals2.add(DataInterval(2, 6, "abcde"), true);

  r = intervals2.read(4, sizeof(buffer)-1, 
		      reinterpret_cast<unsigned char*>(buffer));
  ASSERT_EQ(0, r);
  EXPECT_STREQ("cde4", buffer);
}

// Read tests for the "preserve" merge policy, overlapping intervals
TEST(DataIntervalSetTest, ReadNoOverwrite) {
  char buffer[6];
  memset(buffer, 0, sizeof(buffer));

  // Right overlap
  DataIntervalSet intervals1;
  intervals1.add(DataInterval(2, 6, "abcde"), false);
  intervals1.add(DataInterval(4, 8, "12345"), false);

  int r;
  r = intervals1.read(3, sizeof(buffer)-1, 
		      reinterpret_cast<unsigned char*>(buffer));
  ASSERT_EQ(0, r);
  EXPECT_STREQ("bcde4", buffer);

  // Left overlap
  DataIntervalSet intervals2;
  intervals2.add(DataInterval(4, 8, "12345"), false);
  intervals2.add(DataInterval(2, 6, "abcde"), false);

  r = intervals2.read(2, sizeof(buffer)-1, 
		      reinterpret_cast<unsigned char*>(buffer));
  ASSERT_EQ(0, r);
  EXPECT_STREQ("ab123", buffer);
}

// Read tests for the "preserve" merge policy, multiple overlapping intervals
TEST(DataIntervalSetTest, ReadNoOverwriteMulti) {
  char buffer[10];
  memset(buffer, 0, sizeof(buffer));

  // One interval overlapping with two others
  DataIntervalSet intervals1;
  intervals1.add(DataInterval(2, 4, "abc"), false);
  intervals1.add(DataInterval(7, 9, "def"), false);
  intervals1.add(DataInterval(3, 8, "345678"), false);

  int r;
  r = intervals1.read(4, 5,
		      reinterpret_cast<unsigned char*>(buffer));
  ASSERT_EQ(0, r);
  EXPECT_STREQ("c56de", buffer);

  // One interval overlapping with three others
  memset(buffer, 0, sizeof(buffer));
  DataIntervalSet intervals2;

  intervals2.add(DataInterval(2, 3, "ab"), false);
  intervals2.add(DataInterval(5, 6, "cd"), false);
  intervals2.add(DataInterval(8, 9, "ef"), false);
  intervals2.add(DataInterval(3, 8, "123456"), false);

  r = intervals2.read(3, 6,
		      reinterpret_cast<unsigned char*>(buffer));
  ASSERT_EQ(0, r);
  EXPECT_STREQ("b2cd5e", buffer);
}

// Read tests on a non-mapped interval
TEST(DataIntervalSetTest, ReadFail) {
  DataIntervalSet intervals;
  char buffer[5];

  intervals.add(DataInterval(2, 6, "abcde"), true);

  int r = intervals.read(4, sizeof(buffer), 
			 reinterpret_cast<unsigned char*>(buffer));
  ASSERT_NE(0, r);
}
