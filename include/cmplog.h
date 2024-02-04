/*
   american fuzzy lop++ - cmplog header
   ------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#ifndef _AFL_CMPLOG_H
#define _AFL_CMPLOG_H

#include "config.h"

#define CMPLOG_LVL_MAX 3

#define CMP_MAP_W 65536
#define CMP_MAP_H 32
#define CMP_MAP_RTN_H (CMP_MAP_H / 2)

#define SHAPE_BYTES(x) (x + 1)

#define CMP_TYPE_INS 1
#define CMP_TYPE_RTN 2

struct cmp_header {

  unsigned hits : 6;       // up to 63 entries, we have CMP_MAP_H = 32
  unsigned shape : 6;      // 63 bytes, we support 32 max
  unsigned type : 2;       // 4, we use 3: none, rtn, cmp
  unsigned attribute : 4;  // 16 for arithmetic comparison types
  unsigned reserved : 6;

} __attribute__((packed));

struct cmp_operands {

  u64 v0;
  u64 v1;
  u64 v0_128;
  u64 v1_128;
  u64 unused;
  u8  unused1;
  u8  unused2;

} __attribute__((packed));

struct cmpfn_operands {

  u8 v0[32];
  u8 v0_len;
  u8 v1[32];
  u8 v1_len;

} __attribute__((packed));

typedef struct cmp_operands cmp_map_list[CMP_MAP_H];

struct cmp_map {

  struct cmp_header   headers[CMP_MAP_W];
  struct cmp_operands log[CMP_MAP_W][CMP_MAP_H];

};

/* Execs the child */

struct afl_forkserver;
void cmplog_exec_child(struct afl_forkserver *fsrv, char **argv);

#endif

