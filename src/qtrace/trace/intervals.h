//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//
// This module provides two classes:
//
// - DataInterval, representing a discrete memory interval [low, high],
//   associated with a buffer "data" that represents the contents of the
//   region. Remember endpoints are included.
//
// - DataIntervalSet, a vector of Interval object supporting the coalescence of
//   overlapped or consecutive memory intervals.

#ifndef SRC_QTRACE_TRACE_INTERVALS_H_
#define SRC_QTRACE_TRACE_INTERVALS_H_

#include <vector>
#include <string>
#include <cassert>

class DataInterval {
 private:
  unsigned int low_, high_;
  std::string data_;
 public:
  explicit DataInterval(unsigned int low, unsigned int high,
                        const std::string &data)
    : low_(low), high_(high), data_(data) {
    assert(high_ >= low_);
    assert(getLength() == data_.length());
  }

  bool operator<(const DataInterval &other) const {
    return low_ < other.getLow();
  }

  unsigned int getLow() const { return low_; }
  unsigned int getHigh() const { return high_; }
  unsigned int getLength() const { return high_ - low_ + 1; }
  const std::string& getData() const { return data_; }
};

class DataIntervalSet {
 private:
  std::vector<DataInterval> elements_;

 public:
  explicit DataIntervalSet() { }

  std::vector<DataInterval>::iterator begin() { return elements_.begin(); }
  std::vector<DataInterval>::iterator end()   { return elements_.end(); }

  // Get the number of intervals in this set
  unsigned int getNumDataIntervals() const { return elements_.size(); }

  // Check if this set is empty
  bool isEmpty() const { return elements_.empty(); }

  // Flush this intervals set
  void flush() { elements_.clear(); }

  // Add an interval to this set, coalescing overlapped intervals. Parameter
  // "overwrite" can be used to control whether the data stored in the new
  // "interval" object should have higher precedence (and thus overwrite) than
  // existing intervals.
  void add(const DataInterval &interval, bool overwrite);

  // Get the maximum length of this intervals set, defined as zero if the set
  // is empty, or as the greater upper limit + 1 (as all intervals include the
  // endpoints) otherwise
  unsigned int getMaxLength() const;

  // Read "size" bytes starting from offset "start" into buffer "buffer". If a
  // sub-interval of [start, start+size-1] is not present in this set, -1 is
  // returned. Otherwise, data is written into "buffer" and function returns 0.
  int read(unsigned int start, unsigned int size, unsigned char *buffer) const;
};

#endif  // SRC_QTRACE_TRACE_INTERVALS_H_
