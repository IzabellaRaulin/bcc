/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <cstdarg>
#include <cstdio>

#include "PyPerfLoggingHelper.h"

namespace ebpf {
namespace pyperf {

static uint64_t setVerbosityLevel = 9;

void setVerbosity(uint64_t verbosityLevel) {
  setVerbosityLevel = verbosityLevel;
}

void logInfo(uint64_t logLevel, const char* fmt, ...) {

  if (logLevel <= 2 ) {
    va_list va;
    va_start(va, fmt);
    // dopisane - iza
    FILE * pFile; 
    pFile = fopen("/tmp/gprofiler_tmp/izahelperfile.txt","a");
    if (pFile) {
      std::vfprintf(pFile, fmt, va);
      fclose (pFile);
      va_end(va);
    }  
    //koniec
  }

  if (logLevel > setVerbosityLevel) {
    return;
  }

  va_list va;
  va_start(va, fmt);
  std::vfprintf(stderr, fmt, va);

  va_end(va);
  
}


}  // namespace pyperf
}  // namespace ebpf
