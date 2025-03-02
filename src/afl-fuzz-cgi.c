#include "afl-fuzz.h"

char *method[METHOD_COUNT] = {
	[GET] 		= "GET", 
	[POST] 		= "POST", 
	[PUT] 		= "PUT", 
	[HEAD] 		= "HEAD", 
	[DELETE] 	= "DELETE", 
	[PATCH] 	= "PATCH"
};

int 		method_count = METHOD_COUNT;
char 		*path_info[1 << 12];

range_env cgi_range[RANGE_COUNT] = {
	[PATH_INFO]                     = {"PATH_INFO", 0, path_info},
	[REQUEST_METHOD]                = {"REQUEST_METHOD", &method_count, method},
	[HTTP_X_HTTP_METHOD_OVERRIDE]   = {"HTTP_X_HTTP_METHOD_OVERRIDE", &method_count, method}
};

char		*cgi_fix[FIX_COUNT][PAIR_ELEM_COUNT] = {
	[HTTP_USERNAME]					=	{"HTTP_USERNAME", "admin"},
	[HTTP_PASSWORD]					=	{"HTTP_PASSWORD", "admin"},
	[SERVER_ADMIN]					=	{"SERVER_ADMIN", "admin@example.com"},
	[SERVER_PORT]					=	{"SERVER_PORT", "443"},
	[SERVER_SOFTWARE]				=	{"SERVER_SOFTWARE", "AFL"}
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

void debug_pair_list(cgi_pair *list) {
	DEBUGF("Debug pailist:\n");
	while (list != NULL) {
		DEBUGF("%s=%s\n", list->key, list->value);
		list = list->next;
	}
}

int add_pair_list(cgi_pair **list, cgi_pair *pair) {

	if (*list == NULL) {
		*list = pair;
		return 1;
	}

	pair->next = *list;
	*list = pair;

	return 0;
}

void free_pair_list(cgi_pair *list) {
	
	while (list != NULL)
	{
		cgi_pair *tmp = list;
		list = list->next;
		if (tmp->key) { 
			if(getenv("AFL_DEBUG")) DEBUGF("free key: %s\n", tmp->key);
			free(tmp->key); 
			tmp->key = NULL; 
		}
		if (tmp->value) { 
			if(getenv("AFL_DEBUG")) DEBUGF("free value: %s\n", tmp->value);
			free(tmp->value); 
			tmp->value = NULL; 
		}
		free(tmp);
		tmp = NULL;
	}

}

u8 in_pair_list(cgi_pair *list, char *name) {
	
	while (list != NULL) {
		if (!strcmp(list->key, name)) return 1;
		list = list->next;  
	}

	return 0;
}

u8 in_all_pair_list(struct queue_entry *q, char *name) {

	if (in_pair_list(q->fix_pair_list, name) ||
		in_pair_list(q->range_pair_list, name) ||
		in_pair_list(q->random_pair_list, name))
		return 1;
	
	return 0;
}

u32 size_pair2str(cgi_pair *l) {
  
	u32 len = 0;
	while (l != NULL) {
		len += strlen(l->key);
		len += strlen(l->value);
		len += 3;
		l = l->next;
	}

	return len;
}

u8* pair2str(u8 *buf, cgi_pair *l) {
  
	while (l != NULL) {
		char *p = strchr(l->value, '\n');
		if (p != NULL) *p = '\0';

		buf += sprintf(buf, "%s=%s\n", l->key, l->value);
		l = l->next;
	}
  
	return buf;
}

u32 size_array2str(cgi_pair *l, char **array, int array_size) {
	
	u32 len = 0;
	while (l != NULL) {
		// DEBUGF("%s\n", l->key);
		len += strlen(l->key);
		len += 2;
		l = l->next;
	}

	for (int i = 0; i < array_size; i++) {
		if (array[i]) {
			len += strlen(array[i]);
			// DEBUGF("%s\n", array[i]);
		}
	}

	return len;
}

u8* random_array2str(u8 *buf, cgi_pair *l, char **array, int array_size) {
  
	for (int i = 0; i < array_size; i++) {

		char *p = strchr(array[i], '\n');
		if (p != NULL) *p = '\0';

		buf += sprintf(buf, "%s=%s\n", l->key, array[i]);
		l = l->next;
	}
  
	return buf;
}

u8* range_array2str(u8 *buf, cgi_pair *l, char **array, int array_size) {
  
	for (int i = 0; i < array_size; i++) {
		if (!array[i]) continue;
		
		// char *p = strchr(array[i], '\n');
		// if (p != NULL) *p = '\0';

		buf += sprintf(buf, "%s=%s\n", cgi_range[i].key, array[i]);
	}
  
	return buf;
}

/* Trim input testcase*/
void trim_cgi_input(struct queue_entry *q, u8 *in_buf) {
    
	// DEBUGF("trim_in_buf: %s\n", in_buf);
	u8 *st = in_buf, *ed, *tmp, *buf_end = in_buf + q->len;

	/* Trim input to pairs */
	while (st < buf_end)
	{
		tmp = st;
		while (*tmp != '=') tmp++;

		ed = tmp;
		while (*ed != '\n') ed++;

		cgi_pair *pair = malloc(sizeof(cgi_pair));
		
		pair->key = malloc(tmp - st + 1);
		*tmp++ = '\0';
		strcpy(pair->key, st);
		
		pair->value = malloc(ed - tmp + 1);
		*ed++ = '\0';
		strcpy(pair->value, tmp);
		// if (getenv("CGI_DEBUG"))
		//   fprintf(stderr, "%s=%s\n", pair->key, pair->value);
		
		pair->next = NULL;

		for (int i = 0; i < FIX_COUNT; i++) {
			if (!strcmp(cgi_fix[i][KEY], pair->key)) {
				
				free(pair->value);
				pair->value = malloc(strlen(cgi_fix[i][VALUE]) + 1);
				strcpy(pair->value, cgi_fix[i][VALUE]);

				add_pair_list(&q->fix_pair_list, pair);

				goto NEXT_PAIR;
			}
		}

		for (int i = 0; i < RANGE_COUNT; i++) {
			if (!strcmp(cgi_range[i].key, pair->key)) {
				
				add_pair_list(&q->range_pair_list, pair);
				q->range_pair_array[i] = pair->value;
				
				goto NEXT_PAIR;
			}
		}
		
		add_pair_list(&q->random_pair_list, pair);

NEXT_PAIR:
		st = ed;
	}
	
}

/* Restructure input*/
void restructure_inbuf(struct queue_entry *q, u8 *in_buf) {
	
	cgi_pair *l = q->random_pair_list;
	u8 *p = in_buf;
	while (l != NULL)
	{
		// p += sprintf(p, "%s", l->key);
		strcpy(p, l->value);
		p += strlen(l->value);

		// free(l->value);
		// l->value = NULL;

		*p++ = '\0';
		l = l->next;
	}
	*p = 0;
	q->len = p - in_buf;
	
}

u8* __attribute__((hot))
recombine_input(afl_state_t *afl, u8 *out_buf, u32 len) {

	u8 *st = out_buf, *ed = out_buf + len, *tmp = st;

	// DEBUGF("orign out buf:%s\n", out_buf);
	/*  Check the result of mutate.
		If out_buf cannot be devided into random_pair_list,
		(afl break the struct of cgi input)
		we will return
	*/
	cgi_pair *l = afl->queue_cur->random_pair_list;
	char random_array[MAX_TEMP_STR][ENV_MAX_LEN];
	
	char *ra[MAX_TEMP_STR];
	for (int i = 0; i < MAX_TEMP_STR; i++) {
		ra[i] = random_array[i];
	}
	
	int n = 0;
	while (l != NULL) {
		if (tmp >= ed) break;

		int size = strlen(tmp);
		// if (size == 0) { tmp++; continue; }

		strncpy(random_array[n], tmp, ENV_MAX_LEN);
		// snprintf(random_array[n], ENV_MAX_LEN, "%s=%s", l->key, tmp);

		if (++n > MAX_TEMP_STR) break;

		tmp += size + 1;
		l = l->next;
	}
	
	if (n >= MAX_TEMP_STR || l != NULL) return 0;

	/* Recombine input from lists and arrays*/
	len = 0;
	len += size_pair2str(afl->queue_cur->fix_pair_list);
	len += size_array2str(afl->queue_cur->range_pair_list, afl->queue_cur->range_pair_array, RANGE_COUNT);
	len += size_array2str(afl->queue_cur->random_pair_list, ra, n);

	/* We do not want to affect out_buf in fuzz_one, so we alloc a new space for fuzz, named new_buf */
	u8 *new_buf = afl_realloc(AFL_BUF_PARAM(new), len);

	u8 *tmp_buf = new_buf;
	tmp_buf = pair2str(tmp_buf, afl->queue_cur->fix_pair_list);
	tmp_buf = range_array2str(tmp_buf, afl->queue_cur->range_pair_list, afl->queue_cur->range_pair_array, RANGE_COUNT);
	tmp_buf = random_array2str(tmp_buf, afl->queue_cur->random_pair_list, ra, n);

	if(getenv("AFL_DEBUG")) DEBUGF("new_buf:%s\n", new_buf);
	// print_stack_trace();
	return new_buf;
}

void setup_cgi_feedback_shmem(afl_state_t *afl) {

	afl->cgi_feedback = ck_alloc(sizeof(sharedmem_t));

	// we need to set the non-instrumented mode to not overwrite the SHM_ENV_VAR
	u8 *map = afl_shm_init(afl->cgi_feedback, ENV_NAME_MAX_LEN * ENV_MAX_LEN + sizeof(u32) * 5, 1);
	memset(map, 0, ENV_NAME_MAX_LEN * ENV_MAX_LEN + sizeof(u32) * 5);

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
	cgi_range[PATH_INFO].key		= afl->fsrv.shmem_cgi_regex->env_name;
	cgi_range[PATH_INFO].num		= &(afl->fsrv.shmem_cgi_regex->num_of_regex);
	for (int i = 0; i < 4096; i++) {
		cgi_range[PATH_INFO].value[i] = afl->fsrv.shmem_cgi_regex->path_info_str[i];
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

		char *env_name = cgi_feedback_buf + i*ENV_MAX_LEN;
		if (in_all_pair_list(q, env_name)) continue;

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
	for (int j = 0; j < *(cgi_range[PATH_INFO].num); j++) {
		fprintf(fp, "%s\n", cgi_range[PATH_INFO].value[j]);
	}
	fclose(fp);

	fp = fopen("lose_env.txt", "w");
	if (fp == NULL) {
		perror("Error opening file");
		return;
	}
	for (int j = 0; j < *(afl->fsrv.shmem_cgi_fb_num); j++) {
		fprintf(fp, "%s\n", afl->fsrv.shmem_cgi_fb_buf + j*ENV_MAX_LEN);
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
	char *info = env;
	char fb_all[64][128];
	char func_all[64][128];

	for (int i = 0; i < *(afl->fsrv.shmem_cgi_fb_pair); i++) {

		char func[128];
		char fb[128];
		
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
		char temp[256];

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

			char cmd[256];
			sprintf(cmd, "python3 ./plugin/random_regex.py %s", fb);

			FILE *fp = popen(cmd, "r");
			char buffer[128];
			fgets(buffer, sizeof(buffer), fp);
			pclose(fp);
			
			needed_size += sprintf(temp, "%s=%s\n", env_name, buffer) + 1;
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
	
	memset(afl->fsrv.shmem_cgi_fb_num, 0, ENV_MAX_LEN * ENV_NAME_MAX_LEN + sizeof(u32) * 5);
	// int   cgi_feedback_num		= *(afl->fsrv.shmem_cgi_fb_num);
	// int   cgi_feedback_stage	= *(afl->fsrv.shmem_cgi_fb_stage);
	// int   cgi_feedback_target	= *(afl->fsrv.shmem_cgi_fb_target);
	char *cgi_feedback_buf    	=   afl->fsrv.shmem_cgi_fb_buf;

	out_buf = recombine_input(afl, out_buf, len);
	if (out_buf == 0) return 0;

	len = strlen(out_buf);

	/* Feedback stage 0 */
	*(afl->fsrv.shmem_cgi_fb_stage) = 0;
	u8 ret = common_fuzz_stuff(afl, out_buf, len);
	if (ret) {
		DEBUGF("common_fuzz_stuff return %d\n", ret);
		return ret;
	}

	u32 needed_size = len; // or afl_alloc_bufsize(out_buf) ?

	DEBUGF("cgi_feedback_num:%d\n", *(afl->fsrv.shmem_cgi_fb_num));
	for (int i = 0; i < *(afl->fsrv.shmem_cgi_fb_num); i++) {
		
		/* 1% percent do feedback */
		// if (rand_below(afl, 100) < 99) continue;

		/* TODO: change feedbak
			1st time: env_name
			2nd time: env_name=target */ 
		char *env = cgi_feedback_buf + i*ENV_MAX_LEN;
		
		char env_name[ENV_NAME_MAX_LEN];
		strcpy(env_name, env);
		
		if (in_all_pair_list(afl->queue_cur, env_name)) continue;

		needed_size += strlen(env);
		needed_size += strlen(NEW_ENV_FLAG);
		needed_size += 3;

		out_buf = afl_realloc(AFL_BUF_PARAM(new), needed_size);

		sprintf(out_buf + len, "%s=%s\n", env, NEW_ENV_FLAG);
		
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
			feedback_stage2(afl, env, env_name, out_buf, len);
			*(afl->fsrv.shmem_cgi_fb_stage) = 0;
		}

		needed_size = len;

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