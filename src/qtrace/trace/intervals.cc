//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/trace/intervals.h"

#include <algorithm>
#include <cstring>

void DataIntervalSet::add(const DataInterval &interval, bool overwrite) {
  unsigned int low  = interval.getLow();
  unsigned int high = interval.getHigh();

  // Find overlapped intervals
  std::vector<int> overlaps;
  int index_min = -1, index_max = -1;
  unsigned int newlow = low, newhigh = high;
  int i = 0;
  for (auto it = elements_.begin(); it != elements_.end(); it++, i++) {
    unsigned int overlap_low  = it->getLow();
    unsigned int overlap_high = it->getHigh();

    // The "+1"s address the requirements that we are dealing with discrete
    // intervals, thus {(1,2)} u {(3,4)} = {(1,4)}
    if ((overlap_low <= low && low <= overlap_high + 1) ||
        (overlap_low <= high + 1 && high <= overlap_high) ||
        (overlap_low >= low && overlap_high <= high)) {
      overlaps.push_back(i);

      // Update the new interval limits
      if (overlap_low < newlow) {
        index_min = i;
        newlow  = overlap_low;
      }

      if (overlap_high > newhigh) {
        index_max = i;
        newhigh = overlap_high;
      }
    }
  }

  // Compute the new data chunk
  std::string data;
  if (index_min >= 0 && newlow < low) {
    // Prepend first (low - newlow) characters
    data += elements_[index_min].getData().substr(0, low - newlow);
  }

  data += interval.getData();

  if (!overwrite) {
    for (auto it = overlaps.begin(); it != overlaps.end(); it++) {
      unsigned int overlap_low  = elements_[*it].getLow();
      unsigned int overlap_high = elements_[*it].getHigh();

      // Process only "true" overlaps, not adjacent intervals
      if ((low != overlap_high + 1) && (overlap_low != high + 1)) {
        // Compute the size of the overlapped region
        unsigned int overlap_size =
          std::min(overlap_high, high) - std::max(overlap_low, low) + 1;

        // Index of the first overlapped byte inside "data"
        unsigned int overlap_dststart =
          std::max(low, overlap_low) - newlow;

        // Index of the first overlapped data byte inside the overlapped
        // interval
        unsigned int overlap_srcstart =
          std::max(low, overlap_low) - overlap_low;

        data.replace(overlap_dststart,
                     overlap_size,
                     elements_[*it].getData(),
                     overlap_srcstart,
                     overlap_size);
      }
    }
  }

  if (index_max >= 0 && newhigh > high) {
    // Append last (newhigh - high) characters
    std::string tmp = elements_[index_max].getData();
    data += tmp.substr(tmp.length() - (newhigh - high));
  }

  // Remove overlapped intervals
  for (auto it = overlaps.begin(); it != overlaps.end(); it++) {
    elements_.erase(elements_.begin() + *it);
  }

  // Insert merged element
  elements_.push_back(DataInterval(newlow, newhigh, data));
}

unsigned int DataIntervalSet::getMaxLength() const {
  unsigned int size = 0;

  for (auto it = elements_.begin(); it != elements_.end(); it++) {
    if (it->getHigh() >= size) {
      size = it->getHigh() + 1;
    }
  }

  return size;
}

int DataIntervalSet::read(unsigned int start, unsigned int size,
                          unsigned char *buffer) const {
  int r = -1;

  unsigned int end = start + size - 1;
  for (auto it = elements_.begin(); it != elements_.end(); it++) {
    if (it->getLow() <= start && end <= it->getHigh()) {
      unsigned int offset = start - it->getLow();
      memcpy(buffer, it->getData().c_str()+offset, size);
      r = 0;
      break;
    }
  }

  return r;
}
