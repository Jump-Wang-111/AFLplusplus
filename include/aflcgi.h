#ifndef __AFLCGI_H
#define __AFLCGI_H

#include <regex.h>
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

/* Keeping a pair of key-value */
typedef struct cgi_pair {
  char              *key;
  char              *value;
  struct cgi_pair   *next;
} cgi_pair;

typedef struct regex_env {
  u8        all_regex_map[1 << 12];
  char      all_regex_val[1 << 12][1 << 8];

  char      env_name[128];
  u8        path_info_map[1 << 12];
  int       num_of_regex;
  char      path_info_str[1 << 12][1 << 8];
  char      path_info_r[1 << 12][1 << 8];
} regex_env;

typedef struct range_env {
  char      *key;
  int       *num;
  char      **value;
} range_env;

/* Different policy of mutating*/
enum {
  FIX,
  RANGE,
  RANDOM
};

enum {
  HTTP_USERNAME,
  HTTP_PASSWORD,
  FIX_COUNT
};

enum {
  KEY,
  VALUE,
  PAIR_ELEM_COUNT
};

enum {
  PATH_INFO,
  REQUEST_METHOD,
  HTTP_X_HTTP_METHOD_OVERRIDE,
  RANGE_COUNT
};

enum {
  GET,
  POST,
  PUT,
  HEAD,
  DELETE,
  PATCH,
  METHOD_COUNT
};

extern char			  *cgi_fix[FIX_COUNT][PAIR_ELEM_COUNT];
extern range_env  cgi_range[RANGE_COUNT];

#endif