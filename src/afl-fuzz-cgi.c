#include "afl-fuzz.h"

/* =========================================================
   1. Candidate Arrays (候选值数据源)
   ========================================================= */

// HTTP Methods
static char *c_methods[METHOD_COUNT] = {
	[GET] 		= "GET", 
	[POST] 		= "POST", 
	[PUT] 		= "PUT", 
	[HEAD] 		= "HEAD", 
	[DELETE] 	= "DELETE", 
	[PATCH] 	= "PATCH"
};

// HTTP Protocols
static char *c_protocols[] = {
	[HTTP1_0]	= "HTTP/1.0", 
	[HTTP1_1]	= "HTTP/1.1", 
	[HTTP2_0]	= "HTTP/2.0"
};

// Content Types (用于 Hybrid 模式的字典部分)
static char *c_content_types[] = {
    "application/x-www-form-urlencoded; type=123", // Default
    "application/json; charset=utf-8",                  // Modern APIs
    "multipart/form-data; boundary=---------------------------12345",               // File uploads
    "text/xml; action=123",                          // SOAP/XML-RPC
    "text/plain"                         // Raw data
};

// Path Info (这里提供一些基础默认值，如果你有动态 Regex 生成的路径，
// 可以在运行时通过 init_range 函数覆盖这里的指针)
static char *c_paths[] = {
    "/index.html",
    "/admin",
    "/login",
    "/api/v1/user",
};

char *g_path_info[1 << 12];

// Usernames mapping to roles, we guess the role from reverse engineering: 
// "admin"->4, "operator"->3, "user"->2, "guest"->1
static char *c_usernames[] = {
    "admin",    // Role 4
    "operator", // Role 3
    "user",     // Role 2
    "guest"     // Role 1
};

static char *c_auth_values[] = {
    "Basic YWRtaW46YWRtaW4=",         // admin:admin
    "Basic b3BlcmF0b3I6b3BlcmF0b3I=", // operator:operator
    "Basic dXNlcjp1c2Vy",             // user:user
    "Basic Z3Vlc3Q6Z3Vlc3Q="          // guest:guest
};

// Passwords (kept simple to match usernames for convenience)
// static char *c_passwords[] = {
//     "admin",
//     "operator",
//     "user",
//     "guest"
// };

/* 辅助宏：计算数组长度 */
#define ARR_SIZE(x) (sizeof(x) / sizeof((x)[0]))


/* =========================================================
   2. Global Variable Definitions (全局定义表)
   ========================================================= */

cgi_var_def_t g_var_defs[KNOWN_VAR_COUNT] = {

    /* =========================================================
	   [FIX] Variable Definitions (AFL++ Side)
	
	   These are OPTIONAL variables. They are not guaranteed to exist 
	   in every request, but when they do, they usually hold specific 
	   standard values to trigger specific server configurations 
	   (e.g., SSL mode, Authenticated mode).
       ========================================================= */
    
    // [HTTP_USERNAME] = { 
    //     .key = "HTTP_USERNAME", 
    //     .type = TYPE_FIX, 
    //     .default_val = "admin" 
    // },
    
    [HTTP_PASSWORD] = { 
        .key = "HTTP_PASSWORD", 
        .type = TYPE_FIX, 
        .default_val = "password" // 或者 "password"
    },
    
    [SERVER_ADMIN] = { 
        .key = "SERVER_ADMIN", 
        .type = TYPE_FIX, 
        .default_val = "admin@localhost" 
    },
    
    [AUTH_TYPE] = { 
        .key = "AUTH_TYPE", 
        .type = TYPE_FIX, 
        .default_val = "Basic" 
    },
    
    [HTTPS] = { 
        .key = "HTTPS", 
        .type = TYPE_FIX, 
        .default_val = "on" 
    },
    
    [REMOTE_USER] = { 
        .key = "REMOTE_USER", 
        .type = TYPE_FIX, 
        .default_val = "admin" 
    },
    
    [HTTP_X_REQUESTED_WITH] = { 
        .key = "HTTP_X_REQUESTED_WITH", 
        .type = TYPE_FIX, 
        .default_val = "XMLHttpRequest" 
    },
    
    [HTTP_CONNECTION] = { 
        .key = "HTTP_CONNECTION", 
        .type = TYPE_FIX, 
        .default_val = "keep-alive" 
    },
    
    [HTTP_CACHE_CONTROL] = { 
        .key = "HTTP_CACHE_CONTROL", 
        .type = TYPE_FIX, 
        .default_val = "no-cache" 
    },

    /* =========================================================
   	   [RANGE] Variable Definitions (AFL++ Side)
       ========================================================= */
    /* 需要定义 Candidates 数组和数量，Type 为 TYPE_RANGE */

    [PATH_INFO] = { 
        .key = "PATH_INFO", 
        .type = TYPE_RANGE, 
        .num_candidates = ARR_SIZE(c_paths), 
        .candidates = c_paths 
        /* 注意：如果你依然使用共享内存动态加载 path_info，
           需要在 setup_cgi_regex_shmem 中覆盖这里的 candidates 指针 */
    },

    [REQUEST_METHOD] = { 
        .key = "REQUEST_METHOD", 
        .type = TYPE_RANGE, 
        .num_candidates = ARR_SIZE(c_methods), 
        .candidates = c_methods 
    },

    [HTTP_X_HTTP_METHOD_OVERRIDE] = { 
        .key = "HTTP_X_HTTP_METHOD_OVERRIDE", 
        .type = TYPE_RANGE, 
        .num_candidates = ARR_SIZE(c_methods), 
        .candidates = c_methods 
    },

    [SERVER_PROTOCOL] = { 
        .key = "SERVER_PROTOCOL", 
        .type = TYPE_RANGE, 
        .num_candidates = ARR_SIZE(c_protocols), 
        .candidates = c_protocols 
    },

	[HTTP_USERNAME] = { 
        .key = "HTTP_USERNAME", 
        .type = TYPE_RANGE, 
        .num_candidates = ARR_SIZE(c_usernames),
        .candidates = c_usernames
    },
    
    // [HTTP_PASSWORD] = { 
    //     .key = "HTTP_PASSWORD", 
    //     .type = TYPE_RANGE, 
    //     .num_candidates = ARR_SIZE(c_passwords),
    //     .candidates = c_passwords
    // },

    /* --- Hybrid Variables (混合模式) --- */
    /* 既有 Candidates 用于 Range 注入，也允许随机变异 */

    [CONTENT_TYPE] = { 
        .key = "CONTENT_TYPE", 
        .type = TYPE_HYBRID, 
        .num_candidates = ARR_SIZE(c_content_types), 
        .candidates = c_content_types,
        .default_val = "application/x-www-form-urlencoded" // 默认值
    },

	[HTTP_AUTHORIZATION] = { 
        .key = "HTTP_AUTHORIZATION", 
        .type = TYPE_HYBRID, 
        .num_candidates = ARR_SIZE(c_auth_values), 
        .candidates = c_auth_values,
        .default_val = "Basic YWRtaW46YWRtaW4=" 
    }
};


void print_stack_trace() {

    void *buffer[100];

    int nptrs = backtrace(buffer, 100);

    char** strings = backtrace_symbols(buffer, nptrs);

    if (strings == NULL) {

        perror("backtrace_symbols");
        exit(EXIT_FAILURE);

    }

    for (int i = 0; i < nptrs; i++) {

        printf("%s\n", strings[i]);

    }

    free(strings);

}

void debug_cgi_request(struct queue_entry *q) {
	DEBUGF("[CGI FUZZ] Debug cgi req\n");
	cgi_request_t *req = &q->cgi_req;
	for (int i = 0; i < req->count; i++) {
		cgi_entry_t *item = &req->items[i];
		DEBUGF("[CGI FUZZ] key:%s, value:%s, id:%d\n", item->key, item->val, item->def_id);
	}
}

void debug_mutated_blob(u8 *blob, u32 len) {
	DEBUGF("[CGI FUZZ] Debug mutated blob:\n");
	u8 *p = blob;
	while (p - blob < len) {
		DEBUGF("[CGI FUZZ] %s\n", (char *)p);
		p += strlen(p) + 1;
	}
}

// 快速查找 ID (O(N) 但 N 很小，极快)
int lookup_var_id(char *key) {
    for (int i = 0; i < KNOWN_VAR_COUNT; i++) {
        if (strcmp(g_var_defs[i].key, key) == 0) return i;
    }
    return -1;
}

u8 in_cgi_req(struct queue_entry *q, char *name) {
	cgi_request_t *req = &q->cgi_req;

	char first_char = name[0];
	for (int i = 0; i < req->count; i++) {
		cgi_entry_t *item = &req->items[i];
		
		if (unlikely(!item->key)) continue;

		if (item->key[0] == first_char && strcmp(item->key, name) == 0) {
            return 1;
        }
	}

	return 0;
}

// 【解析】将二进制流解析为结构体 (无 malloc，全是原位指针)
// blob_buf不为0时，重定向fix类型，提取需要变异的部分拷贝到blob_buf
u32 cgi_parse_input(struct queue_entry *q, u8 *in_buf, u32 len, u8 *blob_buf) {
    
    cgi_request_t *req = &q->cgi_req; 
    req->count = 0;

    u8 *cursor = in_buf;
    u8 *end = in_buf + len;

	u8 *blob_cursor = blob_buf;

	if (getenv("AFL_DEBUG")) {
		DEBUGF("[CGI FUZZ] Beging cgi_parse_input:\n");
		DEBUGF("%s\n", (char *)in_buf);
	}

    while (cursor < end && req->count < MAX_ENV_VARS) {
        
        // 处理多余的空行，即连续的\n
		while (cursor < end && *cursor == '\n') cursor++;
		
		// 寻找当前行的结束位置
        u8 *next_line = (u8*)memchr(cursor, '\n', end - cursor);
        u8 *line_end = next_line ? next_line : end;
		u8 *eq = (u8*)memchr(cursor, '=', line_end - cursor);

        if (!eq) {
			// 没有找到 '=', 这行格式不合法，跳过
			cursor = line_end + 1; // 移动到下一行
			continue;
		} 
		// 1. 定位 Key
        char *key = (char*)cursor;
        *eq = '\0'; // 原地切断 Key

        // 2. 定位 Value
        char *val = (char*)(eq + 1);
        u8 *nl = (u8*)memchr((u8*)val, '\n', end - (u8*)val);
		size_t vlen;
        
        if (nl) {
            *nl = '\0'; // 原地切断 Value
			vlen = nl - (u8*)val;
            cursor = nl + 1;
        } else {
			vlen = end - (u8*)val;
            cursor = end; // 最后一行
        }

        // 3. 填充 Entry
        cgi_entry_t *item = &req->items[req->count++];
        item->key = key;
        item->val = val;
        
        // 4. 关联元数据
		int id = lookup_var_id(key);
        item->def_id = id;

		// 常规解析到此为止
		if (!blob_buf) continue;

		// 如果传递了blob_buf将按类型解析，填充blob_buf用于fuzz
		if (id >= 0) {
            item->key = g_var_defs[id].key; // 修正为静态 Key
        } else {
            // 未知 Key，备份下来，防止 in_buf 被释放或覆盖
            strncpy(item->unknown_key, key, 63);
            item->unknown_key[63] = '\0';
            item->key = item->unknown_key;
        }
        
		u8 is_random = 1;
        if (id >= 0 && g_var_defs[id].type == TYPE_FIX) {
            item->val = g_var_defs[id].default_val;
			is_random = 0;
        }

		if (id >= 0 && g_var_defs[id].type == TYPE_RANGE) {
            is_random = 0;
        }

		if (is_random) {
			memcpy(blob_cursor, val, vlen);
			blob_cursor += vlen;
			*blob_cursor++ = '\0'; 
		}
    }

	if (getenv("AFL_DEBUG")) {
		debug_cgi_request(q);
		debug_mutated_blob(blob_buf, blob_cursor - blob_buf);
	}
	return blob_cursor - blob_buf;
}

/* 统一重组函数：
   1. 如果 mutated_blob == NULL -> 这里的逻辑是 Trim/Save (使用 item->val)
   2. 如果 mutated_blob != NULL -> 这里的逻辑是 Fuzzing (从 blob 读取值)
*/
u8* __attribute__((hot))
cgi_recombine_input(afl_state_t *afl, u8 *mutated_blob, u32 blob_len, u32 *out_len) {
    
    cgi_request_t *req = &afl->queue_cur->cgi_req;
    
	// 计算所需总长度,只多不少
	size_t total_len = 0;
	for (int i = 0; i < req->count; i++) {
		cgi_entry_t *item = &req->items[i];
		
		if (unlikely(!item->key)) item->key = "";
		if (unlikely(!item->val)) item->val = "";

		total_len += strlen(item->key);
		total_len += 1; // '='
		total_len += strlen(item->val);
		total_len += 1; // '\n'
	}
	total_len += 1; // null terminator
	total_len += blob_len;	// random val size
	total_len += ENV_MAX_LEN; // 冗余

	u8 *new_buf = afl_realloc(AFL_BUF_PARAM(new), total_len);
	if (unlikely(!new_buf)) {
        FATAL("Unable to allocate memory for recombine_input (%zu bytes)", total_len);
    }

	u8 *out = new_buf;

	// Trim/Save
	if (!mutated_blob) {

		for (int i = 0; i < req->count; i++) {
			cgi_entry_t *item = &req->items[i];
			
			size_t k_len = strlen(item->key);
        	size_t v_len = strlen(item->val);

			memcpy(out, item->key, k_len);
			out += k_len;
			*out++ = '=';

			memcpy(out, item->val, v_len);
			out += v_len;
			*out++ = '\n';
		}

		*out_len = (u32)(out - new_buf);
		*out = '\0'; // 补上结尾

		if(getenv("AFL_DEBUG")){
			DEBUGF("[CGI FUZZ] After trim--new_buf_len:%u\n", *out_len);
			DEBUGF("[CGI FUZZ] After trim--new_buf:%s\n", new_buf);
		} 

		return new_buf;
	}

    // For fuzz
	if (getenv("AFL_DEBUG")) {
		debug_mutated_blob(mutated_blob, blob_len);
	}
	
    u8 *blob_cursor = mutated_blob;
    u8 *blob_end = mutated_blob + blob_len;

    for (int i = 0; i < req->count; i++) {
        cgi_entry_t *item = &req->items[i];
        int id = item->def_id;
        
        // 1. 写入 Key
        size_t k_len = strlen(item->key);
        memcpy(out, item->key, k_len);
        out += k_len;
        *out++ = '=';

        // 2. 写入 Val
        char *src_val_ptr = NULL;
        size_t src_val_len = 0;

        // 如果是 FIX/RANGE 变量，使用指针中的值
        if (id >= 0 && (g_var_defs[id].type == TYPE_FIX || g_var_defs[id].type == TYPE_RANGE)) {
            src_val_ptr = item->val;
            src_val_len = strlen(src_val_ptr);
			memcpy(out, src_val_ptr, src_val_len);
			out += src_val_len;
			*out++ = '\n';
			continue;
        }

		// 其他变量从变异中取
		if (blob_cursor < blob_end) {
			u8 *next_null = memchr(blob_cursor, '\0', blob_end - blob_cursor);
			if (next_null) {
				src_val_len = next_null - blob_cursor;
				src_val_ptr = (char*)blob_cursor;
				blob_cursor = next_null + 1; // 跳过 \0
			} else {
				// 没有分隔符了，取剩余全部
				src_val_len = blob_end - blob_cursor;
				src_val_ptr = (char*)blob_cursor;
				blob_cursor = blob_end;
			}
		} 
		
		if (src_val_len > 0) {
			memcpy(out, src_val_ptr, src_val_len);
			out += src_val_len;
		}
		*out++ = '\n';
    }
    
	*out_len = (u32)(out - new_buf);
    *out = '\0';

	if(getenv("AFL_DEBUG")){
		DEBUGF("[CGI FUZZ] Ready to fuzz--new_buf_len:%u\n", *out_len);
		DEBUGF("[CGI FUZZ] Ready to fuzz--new_buf:%s\n", new_buf);
	}

    return new_buf;
}

void cgi_optimize_structure(afl_state_t *afl) {
	cgi_request_t *req = &afl->queue_cur->cgi_req;

	// 双指针遍历，i 是当前考察的元素
    for (int i = 0; i < req->count; i++) {

        int should_delete = 0;
        cgi_entry_t *curr = &req->items[i];
		// if (getenv("AFL_DEBUG")) {
		// 	DEBUGF("[CGI FUZZ] Optimize, curr idx:%u, key: %s\n", i, curr->key);
		// }

        if (curr->key == NULL || curr->key[0] == '\0' || curr->key[0] == '\n') {
            should_delete = 1;
			goto SHOULD_DELETE;
        }
		
		// --- 策略 A: 检查重复 Key (保留第一个) ---
        // 向前扫描 0 到 i-1，看是否出现过
        for (int j = 0; j < i; j++) {
            if (strcmp(req->items[j].key, curr->key) == 0) {
                should_delete = 1;
                break;
            }
        }

        // --- 策略 B: 检查空值 (可选) ---
        // if (strlen(curr->val) == 0) should_delete = 1;
SHOULD_DELETE:
        if (should_delete) {
            // [数组删除操作]
            // 如果不是最后一个元素，需要把后面的向前搬移
            if (i < req->count - 1) {
                // 计算需要移动的内存大小: (剩余元素数量) * sizeof(entry)
                size_t move_size = (req->count - 1 - i) * sizeof(cgi_entry_t);
                memmove(&req->items[i], &req->items[i+1], move_size);
            }
            
            // 数量减一
            req->count--;
            
            // 关键：i 回退一步，因为原来的 i+1 现在变成了 i，下轮需要重新检查它
            i--; 
        }
		
		// if (getenv("AFL_DEBUG")) {
		// 	DEBUGF("[CGI FUZZ] Optimize, curr idx:%u, should delete: %u\n", i, should_delete);
		// }
	}
}

// TODO: 检查trim逻辑
/* Trim 逻辑：解析 -> 格式化清洗 -> 写回
   利用 recombine_input(NULL) 模式实现
*/
u8 trim_cgi_input(afl_state_t *afl, struct queue_entry *q, u8 *in_buf) {
    
    if (unlikely(afl->disable_trim)) return 0;
    
	u32 orig_len = q->len;

    // 解析 (Parse)
    // 建立骨架，item->val 指向 in_buf
    cgi_parse_input(q, in_buf, q->len, NULL);
    
	// 去重等操作
	cgi_optimize_structure(afl);

    // 清洗重组 (Sanitize / Serialize)
    // 【核心】传入 NULL，告诉 recombine 使用结构体里的原始值
    // 这样就完成了 "Text -> Struct -> Clean Text" 的过程
	u32 clean_len = 0;
    u8 *clean_buf = cgi_recombine_input(afl, NULL, 0, &clean_len); 

    // 3. 检查并写回磁盘 (Commit)
    // 只要长度变了（通常是变小），或者你想强制格式化，就写回
    if (clean_len != orig_len) {

		if(getenv("AFL_DEBUG")){
			DEBUGF("[CGI FUZZ] Len changed after trim, write back\n");
		}
        
        s32 fd = open(q->fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) PFATAL("Unable to open '%s'", q->fname);
        
        ck_write(fd, clean_buf, clean_len, q->fname);
        close(fd);

        // 更新 Input len
        q->len = clean_len;
        
    }
	else {
		memcpy(in_buf, clean_buf, clean_len);
	}

    // 返回 0 表示 Trim 完成（我们不需要 AFL 原生的二进制 Trim 循环）
    return 0;
}

void setup_cgi_feedback_shmem(afl_state_t *afl) {

	afl->cgi_feedback = ck_alloc(sizeof(sharedmem_t));

	// we need to set the non-instrumented mode to not overwrite the SHM_ENV_VAR
	u8 *map = afl_shm_init(afl->cgi_feedback, 32 * FD_ENTRY_LEN + sizeof(u32) * 5, 1);
	memset(map, 0, 32 * FD_ENTRY_LEN + sizeof(u32) * 5);

	if (!map) { FATAL("BUG: Zero return from cgi_shm_init."); }

	u8 *shm_str = alloc_printf("%d", afl->cgi_feedback->shm_id);
	setenv(SHM_CGI_FD_ENV_VAR, shm_str, 1);
	ck_free(shm_str);

	afl->fsrv.shmem_cgi_fb_num = (u32 *)map;
	afl->fsrv.shmem_cgi_fb_stage = map + sizeof(u32);
	afl->fsrv.shmem_cgi_fb_target = map + sizeof(u32) * 2;
	afl->fsrv.shmem_cgi_fb_pair = map + sizeof(u32) * 3;
	afl->fsrv.shmem_cgi_fb_tlen = map + sizeof(u32) * 4;
	afl->fsrv.shmem_cgi_fb_buf = map + sizeof(u32) * 5;
}

void init_range(afl_state_t *afl) {
	// cgi_range[PATH_INFO].key		= afl->fsrv.shmem_cgi_regex->env_name;
	// cgi_range[PATH_INFO].num		= &(afl->fsrv.shmem_cgi_regex->num_of_regex);
	// for (int i = 0; i < 4096; i++) {
	// 	cgi_range[PATH_INFO].value[i] = afl->fsrv.shmem_cgi_regex->path_info_str[i];
	// }

	g_var_defs[PATH_INFO].num_candidates = afl->fsrv.shmem_cgi_regex->num_of_regex;
	g_var_defs[PATH_INFO].candidates = g_path_info;
	for (int i = 0; i < 4096; i++) {
		g_var_defs[PATH_INFO].candidates[i] = afl->fsrv.shmem_cgi_regex->path_info_str[i];
	}
	// cgi_range[PATH_INFO].value	= afl->fsrv.shmem_cgi_regex->path_info_str;
}

void setup_cgi_regex_shmem(afl_state_t *afl) {
  
	afl->cgi_regex = ck_alloc(sizeof(sharedmem_t));

	// we need to set the non-instrumented mode to not overwrite the SHM_ENV_VAR
	u8 *map = afl_shm_init(afl->cgi_regex, sizeof(regex_env), 1);
	memset(map, 0, sizeof(regex_env));

	if (!map) { FATAL("BUG: Zero return from cgi_shm_init."); }

	u8 *shm_str = alloc_printf("%d", afl->cgi_regex->shm_id);
	setenv(SHM_CGI_RE_ENV_VAR, shm_str, 1);
	ck_free(shm_str);

	afl->fsrv.shmem_cgi_regex = (regex_env *)map;
	strcpy((afl->fsrv.shmem_cgi_regex)->env_name, "PATH_INFO");

	init_range(afl);
}

void save_to_queue(afl_state_t *afl, void *mem, u32 len) {

	s32 fd;
	u8 *queue_fn = "";
	#ifndef SIMPLE_FILES

    if (!afl->afl_env.afl_sha1_filenames) {

      queue_fn = alloc_printf(
          "%s/queue/id:%06u,%s%s%s", afl->out_dir, afl->queued_items,
          describe_op(afl, 2,
                      NAME_MAX - strlen("id:000000,")),
          afl->file_extension ? "." : "",
          afl->file_extension ? (const char *)afl->file_extension : "");

    } else {

      const char *hex = sha1_hex(mem, len);
      queue_fn = alloc_printf(
          "%s/queue/%s%s%s", afl->out_dir, hex, afl->file_extension ? "." : "",
          afl->file_extension ? (const char *)afl->file_extension : "");
      ck_free((char *)hex);

    }

	#else

    queue_fn = alloc_printf(
        "%s/queue/id_%06u", afl->out_dir, afl->queued_items,
        afl->file_extension ? "." : "",
        afl->file_extension ? (const char *)afl->file_extension : "");

	#endif                                                    /* ^!SIMPLE_FILES */
	
	fd = permissive_create(afl, queue_fn);
	if (likely(fd >= 0)) {

		ck_write(fd, mem, len, queue_fn);
		close(fd);

	}

	add_to_queue(afl, queue_fn, len, 0);
}

void save_interesting(afl_state_t *afl, struct queue_entry *q) {

	/* Check new env */
	char *cgi_feedback_buf    =   afl->fsrv.shmem_cgi_fb_buf;

	struct stat st;
	u8 *fn = q->fname, *mem;
	s32 fd;
	u32 len, needed_size, now_size;

	if (lstat(fn, &st) || access(fn, R_OK))
		PFATAL("Unable to access '%s'", fn);

	now_size = needed_size = len = st.st_size;
	mem = ck_alloc(len);
	
	fd = open(fn, O_RDONLY);
	if (fd < 0) PFATAL("Unable to open '%s'", fn);

	ck_read(fd, mem, len, fn);
	close(fd);

	// DEBUGF("Queue id: %d.\n", q->id);
	for (int i = 0; i < *(afl->fsrv.shmem_cgi_fb_num); i++) {

		char *env_name = cgi_feedback_buf + i*FD_ENTRY_LEN;
		if (in_cgi_req(q, env_name)) continue;

		needed_size += strlen(env_name);
		needed_size += strlen(NEW_ENV_FLAG);
		needed_size += 3;

		if (needed_size > now_size) {
			mem = ck_realloc(mem, needed_size);
			now_size = needed_size;
		}

		sprintf(mem + len, "%s=%s\n", env_name, NEW_ENV_FLAG);

		// save_to_queue(afl, mem, strlen(mem));
		save_if_interesting(afl, mem, strlen(mem), 0xff);
		afl->queued_imported += 1;
		// DEBUGF("Successful add new queue.\n");

		needed_size = len;
	}

	ck_free(mem);
}

void save_data(afl_state_t *afl) {
	FILE *fp;

	fp = fopen("path_info.txt", "w");
	if (fp == NULL) {
		perror("Error opening file");
		return;
	}
	for (int j = 0; j < g_var_defs[PATH_INFO].num_candidates; j++) {
		fprintf(fp, "%s\n", g_var_defs[PATH_INFO].candidates[j]);
	}
	fclose(fp);

	fp = fopen("lose_env.txt", "w");
	if (fp == NULL) {
		perror("Error opening file");
		return;
	}
	for (int j = 0; j < *(afl->fsrv.shmem_cgi_fb_num); j++) {
		fprintf(fp, "%s\n", afl->fsrv.shmem_cgi_fb_buf + j*FD_ENTRY_LEN);
	}
	fclose(fp);
}

void generate_regex(afl_state_t *afl) {

	for (int i = 0; i < afl->fsrv.shmem_cgi_regex->num_of_regex; i++) {
		map_set(&afl->cgi_regex_dedupe_map, afl->fsrv.shmem_cgi_regex->path_info_r[i], 1);
	}

	const char *key;
	map_iter_t iter = map_iter(&afl->cgi_regex_dedupe_map);

	int i = 0;
	while ((key = map_next(&afl->cgi_regex_dedupe_map, &iter))) {
		strcpy(afl->fsrv.shmem_cgi_regex->path_info_r[i], key);
		i++;
	}
	afl->fsrv.shmem_cgi_regex->num_of_regex = i;
	g_var_defs[PATH_INFO].num_candidates = i;
	// DEBUGF("[CGI FUZZ] Now num of PATH_INFO: %d\n", g_var_defs[PATH_INFO].num_candidates);

	pid_t pid = fork();
    if (pid < 0) {
        WARNF("fork failed");
        return;
    }
	if (pid == 0) {
        execlp("python3", "python3", "./plugin/random_regex.py", (char *)NULL);
        WARNF("execlp failed");
        return;
    } else {

        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            OKF("Regex process exited with status %d\n", WEXITSTATUS(status));
        } else {
            WARNF("Regex process did not exit cleanly\n");
        }
    }

}

void check_and_gen_regex(afl_state_t *afl) {
	
	time_t current_time = time(NULL);
	
	if (difftime(current_time, afl->last_gen_time) >= 600) {
		if (getenv("AFL_DEBUG"))
			DEBUGF("Gen regex, cur time: %ld, last time: %ld\n", current_time, afl->last_gen_time);
		generate_regex(afl);
		afl->last_gen_time = current_time;
	}

}

u8 hook_fuzz_one(afl_state_t *afl) {

	u8 skip = fuzz_one(afl);

	/*	TODO: change generate_regex.
		Generating regex now only run once.
	*/ 
	check_and_gen_regex(afl);

	save_data(afl);
	
	// save_interesting(afl, afl->queue_cur);

	// DEBUGF("One round over...\n");

	return skip;
}

/* 	When we change the logic of afl, crashes will 
	not only occur in common_fuzz_stuff, we need 
	to handle these additional crashes ourselves.
	We copy keep_as_crash in save_if_interesting() here.  */

void save_crash(afl_state_t *afl, void *mem, u32 len) {

	u8  fn[PATH_MAX];
	s32 fd;

	++afl->total_crashes;

	if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) return;

	// if (likely(!afl->non_instrumented_mode)) {

	// 	if (unlikely(!classified)) {

	// 		classify_counts(&afl->fsrv);
	// 		classified = 1;

	// 	}

	// 	simplify_trace(afl, afl->fsrv.trace_bits);

	// }

	if (unlikely(!afl->saved_crashes) &&
			(afl->afl_env.afl_no_crash_readme != 1)) {

		write_crash_readme(afl);

	}

#ifndef SIMPLE_FILES

	if (!afl->afl_env.afl_sha1_filenames) {

		snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s%s%s",
							afl->out_dir, afl->saved_crashes, afl->fsrv.last_kill_signal,
							describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")),
							afl->file_extension ? "." : "",
							afl->file_extension ? (const char *)afl->file_extension : "");

	} else {

		const char *hex = sha1_hex(mem, len);
		snprintf(fn, PATH_MAX, "%s/crashes/%s%s%s", afl->out_dir, hex,
							afl->file_extension ? "." : "",
							afl->file_extension ? (const char *)afl->file_extension : "");
		ck_free((char *)hex);

	}

#else

	snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u%s%s", afl->out_dir,
						afl->saved_crashes, afl->fsrv.last_kill_signal,
						afl->file_extension ? "." : "",
						afl->file_extension ? (const char *)afl->file_extension : "");

#endif                                                    /* ^!SIMPLE_FILES */
	
	++afl->saved_crashes;

#ifdef INTROSPECTION
	if (afl->custom_mutators_count && afl->current_custom_fuzz) {

		LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

			if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

				const char *ptr = el->afl_custom_introspection(el->data);

				if (ptr != NULL && *ptr != 0) {

					fprintf(afl->introspection_file, "UNIQUE_CRASH CUSTOM %s = %s\n",
									ptr, afl->queue_top->fname);

				}

			}

		});

	} else if (afl->mutation[0] != 0) {

		fprintf(afl->introspection_file, "UNIQUE_CRASH %s\n", afl->mutation);

	}

#endif
	if (unlikely(afl->infoexec)) {

		// if the user wants to be informed on new crashes - do that
#if !TARGET_OS_IPHONE
		// we dont care if system errors, but we dont want a
		// compiler warning either
		// See
		// https://stackoverflow.com/questions/11888594/ignoring-return-values-in-c
		(void)(system(afl->infoexec) + 1);
#else
        WARNF("command execution unsupported");
#endif

      }

	afl->last_crash_time = get_cur_time();
	afl->last_crash_execs = afl->fsrv.total_execs;
	
	fd = permissive_create(afl, fn);
  if (fd >= 0) {

    ck_write(fd, mem, len, fn);
    close(fd);

  }
}


void feedback_stage2(afl_state_t *afl, char *env, char *env_name, u8 *out_buf, u32 len) {
	
	// char *eq = strchr(env, '=');
	// if (!eq) {
	// 	WARNF("Error in feedback stage2: No \'=\' in feedback env str.");
	// 	return;
	// }
	// char *info = eq + 1;

	if (!strcmp(env_name, "PATH_INFO")) {
		DEBUGF("Skip PATH_INFO in feedback stage2");
		return;
	}

	char *info = env;
	char fb_all[64][ENV_MAX_LEN];
	char func_all[64][128];

	for (int i = 0; i < *(afl->fsrv.shmem_cgi_fb_pair); i++) {

		char func[128];
		char fb[ENV_MAX_LEN];
		
		info += sprintf(func, "%s", info) + 1;
		// strcpy(func, info);
		info += sprintf(fb, "%s", info) + 1;
		// strcpy(fb, info + strlen(func) + 1);
		strcpy(fb_all[i], fb);
		strcpy(func_all[i], func);

		for (int ii = 0; ii < i; ii++) {
			if (!strcmp(fb_all[ii], fb) && !strcmp(func_all[ii], func)) {
				if (getenv("AFL_DEBUG")) {
					DEBUGF("Same feedback, skip\n");
				}
				goto next_loop;
			}
		}

		int needed_size = len;
		char temp[ENV_MAX_LEN];

		if (!strcmp(func, "strcmp") || !strcmp(func, "strncmp") || !strcmp(func, "strcasecmp") || !strcmp(func, "strncasecmp")) {
			needed_size += sprintf(temp, "%s=%s\n", env_name, fb) + 1;
			out_buf = afl_realloc(AFL_BUF_PARAM(new), needed_size);
			sprintf(out_buf + len, "%s=%s\n", env_name, fb);
		}
		if (!strcmp(func, "strstr")) {
			needed_size += sprintf(temp, "%s=aaa%saaa\n", env_name, fb) + 1;
			out_buf = afl_realloc(AFL_BUF_PARAM(new), needed_size);
			sprintf(out_buf + len, "%s=aaa%saaa\n", env_name, fb);
		}
		if (!strcmp(func, "strtok")) {
			needed_size += sprintf(temp, "%s=aaa%saaa\n", env_name, fb) + 1;
			out_buf = afl_realloc(AFL_BUF_PARAM(new), needed_size);
			sprintf(out_buf + len, "%s=aaa%saaa\n", env_name, fb);
		}
		if (!strcmp(func, "regexec")) {

			char cmd[4096];
			snprintf(cmd, sizeof(cmd), "python3 ./plugin/gen_regex_one.py %s", fb);

			FILE *fp = popen(cmd, "r");
			char buffer[4096];
			fgets(buffer, sizeof(buffer), fp);
			pclose(fp);
			
			needed_size += snprintf(temp, sizeof(temp), "%s=%s\n", env_name, buffer) + 1;
			out_buf = afl_realloc(AFL_BUF_PARAM(new), needed_size);
			sprintf(out_buf + len, "%s=%s\n", env_name, buffer);

		}

		if (getenv("AFL_DEBUG")) {
			DEBUGF("FB stage2, new env: %s\n", out_buf + len);
			DEBUGF("FB tlen: %d\n", *(afl->fsrv.shmem_cgi_fb_tlen));
		}

		u8 ret = common_fuzz_stuff(afl, out_buf, needed_size - 1);
next_loop:
	}
	
	// if (ret) return ret;
}


u8 __attribute__((hot)) 
hook_common_fuzz_stuff(afl_state_t *afl, u8 *out_buf, u32 len) {
	
	memset(afl->fsrv.shmem_cgi_fb_num, 0, sizeof(u32) * 5);
	// int   cgi_feedback_num		= *(afl->fsrv.shmem_cgi_fb_num);
	// int   cgi_feedback_stage	= *(afl->fsrv.shmem_cgi_fb_stage);
	// int   cgi_feedback_target	= *(afl->fsrv.shmem_cgi_fb_target);
	char *cgi_feedback_buf    	=   afl->fsrv.shmem_cgi_fb_buf;

	u32 input_len;
	out_buf = cgi_recombine_input(afl, out_buf, len, &input_len);
	if (out_buf == 0) return 0;

	/* Feedback stage 0 */
	u32 old_qd = afl->queued_discovered;
	*(afl->fsrv.shmem_cgi_fb_stage) = 0;

	u8 ret = common_fuzz_stuff(afl, out_buf, input_len);
	if (ret) {
		DEBUGF("common_fuzz_stuff return %d\n", ret);
		return ret;
	}

	// only if this input is a new path, then we need to do feedback
	if (afl->queued_discovered == old_qd) return ret;

	u32 needed_size = input_len; // or afl_alloc_bufsize(out_buf) ?

	for (int i = 0; i < *(afl->fsrv.shmem_cgi_fb_num); i++) {
		
		/* 10% percent do feedback */
		// if (rand_below(afl, 100) < 90) continue;

		/*  change feedbak
			1st time: env_name
			2nd time: env_name=target */ 
		char *env = cgi_feedback_buf + i*FD_ENTRY_LEN;
		
		char env_name[ENV_NAME_MAX_LEN];
		strcpy(env_name, env);
		
		if (in_cgi_req(afl->queue_cur, env_name)) continue;

		needed_size += strlen(env);
		needed_size += strlen(NEW_ENV_FLAG);
		needed_size += 3;

		out_buf = afl_realloc(AFL_BUF_PARAM(new), needed_size);

		sprintf(out_buf + input_len, "%s=%s\n", env, NEW_ENV_FLAG);
		
		if (getenv("AFL_DEBUG")) {
			DEBUGF("Try new env: %s\n", env);
			DEBUGF("Now out_buf: %s\n", out_buf);
		}

		/* Feedback stage 1 */
		*(afl->fsrv.shmem_cgi_fb_stage) = 1;
		*(afl->fsrv.shmem_cgi_fb_target) = i;
		*(afl->fsrv.shmem_cgi_fb_pair) = 0;
		*(afl->fsrv.shmem_cgi_fb_tlen) = 0;
		ret = common_fuzz_stuff(afl, out_buf, needed_size - 1); /* needed_size include '\0' when calculate len for afl_realloc */
		*(afl->fsrv.shmem_cgi_fb_stage) = 0;
		if (ret) return ret;

		/* Feedback stage 2 */
		if (strcmp(env, env_name)) {
			*(afl->fsrv.shmem_cgi_fb_stage) = 2;
			feedback_stage2(afl, env, env_name, out_buf, input_len);
			*(afl->fsrv.shmem_cgi_fb_stage) = 0;
		}

		needed_size = input_len;

	}

	return 0;

}

u8 hook_calibrate_case(afl_state_t *afl, struct queue_entry *q, u8 *use_mem,
                  u32 handicap, u8 from_queue) {
	
	int temp = *(afl->fsrv.shmem_cgi_fb_stage);
	
	*(afl->fsrv.shmem_cgi_fb_stage) = 2;
	u8 res = calibrate_case(afl, q, use_mem, handicap, from_queue);
	*(afl->fsrv.shmem_cgi_fb_stage) = temp;
	
	return res;
}