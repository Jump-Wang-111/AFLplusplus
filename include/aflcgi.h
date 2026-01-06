#ifndef __AFLCGI_H
#define __AFLCGI_H

#include <regex.h>
#include <execinfo.h>
#include "map.h"
// #include <pthread.h>
/* Keeping buffer */
// typedef struct buffer {
//   char  *data;      /* Buffer keeping the data */
//   u32   size;       /* Size of buffer */
// } buffer;

#define SHM_CGI_FD_ENV_VAR    "__AFL_SHM_CGI_FD_ID"
#define SHM_CGI_RE_ENV_VAR    "__AFL_SHM_CGI_RE_ID"

#define ENV_NAME_MAX_LEN 128
#define MAX_TEMP_STR 256
#define REGEX_STR_LEN 256
#define ENV_MAX_LEN  4096
#define FD_ENTRY_LEN 4096 * 4

#define NEW_ENV_FLAG        "NEW_ENV"

typedef enum {
  TYPE_FIX,       // Fix (eg AUTH_TYPE)
  TYPE_RANGE,     // Dict (eg HTTP_VER, METHOD)
  TYPE_HYBRID,    // Hybrid (eg CONTENT_TYPE, dict + random)
  TYPE_RANDOM     // Random (Unknown Key)
} VarType;

typedef struct {
  char    *key;             // 环境变量名 "CONTENT_TYPE"
  VarType type;             // 默认类型
  int     num_candidates;   // 候选值数量
  char    **candidates;     // 候选值数组 {"application/json", ...}
  char    *default_val;     // 默认值 (用于 Fix 或初始化)
} cgi_var_def_t;

// ID 映射枚举 (替代字符串比较)
enum {
  // Fix
  HTTP_USERNAME,
  HTTP_PASSWORD,
  SERVER_ADMIN,
  AUTH_TYPE,
  HTTPS,
  REMOTE_USER,
  HTTP_X_REQUESTED_WITH,
  HTTP_CONNECTION,
  HTTP_CACHE_CONTROL,

  // Range
  PATH_INFO,
  REQUEST_METHOD,
  HTTP_X_HTTP_METHOD_OVERRIDE,
  SERVER_PROTOCOL,

  // Hybrid
  CONTENT_TYPE,

  KNOWN_VAR_COUNT
};

typedef struct {
  int   def_id;           // 对应全局表的 ID (-1 表示未知变量/纯随机)
  char  *key;             // 变量名 (指向 buffer 或 常量区)
  char  unknown_key[64];  // 如果 Key 是未知的，备份在这里
  char  *val;             // 当前值指针 (核心！会随变异动态指向不同位置)
} cgi_entry_t;

#define MAX_ENV_VARS 128
typedef struct {
  int         count;                  // 当前有多少个变量
  cgi_entry_t items[MAX_ENV_VARS];    // 数组替代链表
} cgi_request_t;

extern cgi_var_def_t g_var_defs[KNOWN_VAR_COUNT];


typedef struct regex_env {
  u8        all_regex_map[1 << 12];
  char      all_regex_val[1 << 12][1 << 8];

  char      env_name[128];
  u8        path_info_map[1 << 12];
  int       num_of_regex;
  char      path_info_str[1 << 12][1 << 8];
  char      path_info_r[1 << 12][1 << 8];
} regex_env;


/* Different policy of mutating*/
enum {
  FIX,
  RANGE,
  RANDOM
};

// enum {
//   HTTP_USERNAME,
//   HTTP_PASSWORD,
//   SERVER_ADMIN,
//   AUTH_TYPE,
//   HTTPS,
//   REMOTE_USER,
//   HTTP_X_REQUESTED_WITH,
//   HTTP_CONNECTION,
//   HTTP_CACHE_CONTROL,
//   FIX_COUNT
// };

// enum {
//   PATH_INFO,
//   REQUEST_METHOD,
//   HTTP_X_HTTP_METHOD_OVERRIDE,
//   // CONTENT_TYPE,
//   SERVER_PROTOCOL,
//   RANGE_COUNT
// };

enum {
  GET,
  POST,
  PUT,
  HEAD,
  DELETE,
  PATCH,
  METHOD_COUNT
};

enum {
  DEFAULT,
  MODERN_APIS,
  FILE_UPLOADS,
  XML,
  RAW,
  CONTENT_TYPE_COUNT
};

enum {
  HTTP1_0,
  HTTP1_1,
  HTTP2_0,
  HTTP_VER_COUNT
};

#endif