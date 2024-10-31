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

char			*cgi_fix[FIX_COUNT][PAIR_ELEM_COUNT] = {
	[HTTP_USERNAME]									=	{"HTTP_USERNAME", "admin"},
	[HTTP_PASSWORD]									=	{"HTTP_PASSWORD", "admin"}
};

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
		if (tmp->key) free(tmp->key); 
		if (tmp->value) free(tmp->value);
		free(tmp);
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

/* Trim input testcase*/
void trim_cgi_input(struct queue_entry *q, u8 *in_buf) {
    
	u8 *st = in_buf, *ed, *tmp, *buf_end = in_buf + q->len;

	/* Trim input to pairs */
	while (st < buf_end)
	{
		tmp = st;
		while (*tmp != '=') tmp++;

		ed = tmp;
		while (*ed != '\n') ed++;

		cgi_pair *pair = malloc(sizeof(cgi_pair));
		
		pair->key = malloc(tmp - st);
		*tmp++ = '\0';
		strcpy(pair->key, st);
		
		pair->value = malloc(ed - tmp);
		*ed++ = '\0';
		strcpy(pair->value, tmp);
		// if (getenv("CGI_DEBUG"))
		//   fprintf(stderr, "%s=%s\n", pair->key, pair->value);
		
		pair->next = NULL;

		for (int i = 0; i < FIX_COUNT; i++) {
			if (!strcmp(cgi_fix[i][KEY], pair->key)) {
				
				free(pair->value);
				pair->value = malloc(strlen(cgi_fix[i][VALUE]));
				strcpy(pair->value, cgi_fix[i][VALUE]);

				add_pair_list(&q->fix_pair_list, pair);

				goto NEXT_PAIR;
			}
		}

		for (int i = 0; i < RANGE_COUNT; i++) {
			if (!strcmp(cgi_range[i].key, pair->key)) {
				
				// add_pair_list(&q->range_pair_list, pair);
				q->range_pair_array[i] = pair->value;
				
				goto NEXT_PAIR;
			}
		}
		
		add_pair_list(&q->random_pair_list, pair);

NEXT_PAIR:
		st = ed;
	}

	/* Restructure input*/
	cgi_pair *l = q->random_pair_list;
	u8 *p = in_buf;
	while (l != NULL)
	{
		// p += sprintf(p, "%s", l->key);
		strcpy(p, l->value);
		p += strlen(l->value);

		free(l->value);
		l->value = NULL;

		*p++ = '\0';
		l = l->next;
	}
	*p = 0;
	q->len = p - in_buf;
}

u8* recombine_input(afl_state_t *afl, u8 *out_buf, u32 len) {

  u8 *st = out_buf, *ed = out_buf + len, *tmp = st;

	// DEBUGF("orign out buf:%s\n", *out_buf);
  /*  Check the result of mutate.
      If out_buf cannot be devided into random_pair_list,
      (afl break the struct of cgi input)
      we will return
  */
  cgi_pair *l = afl->queue_cur->random_pair_list;
  char tmp_str[MAX_TEMP_STR][ENV_MAX_LEN];
  int n = 0;
  
	while (l != NULL) {
    if (tmp >= ed) break;

    int size = strlen(tmp);
    if (size == 0) { tmp++; continue; }

    strncpy(tmp_str[n], tmp, ENV_MAX_LEN);

    if (++n > MAX_TEMP_STR) break;
    
    tmp += size + 1;
    l = l->next;
  }
	
  if (n >= MAX_TEMP_STR || l != NULL) return 0;
  
	/* Constructing random_pair_list */
  l = afl->queue_cur->random_pair_list;
  for (int i = 0; i < n && l != NULL; i++) {
    l->value = tmp_str[i];
    l = l->next;
  }

	/* Constructing range_pair_list */
	// free_pair_list(afl->queue_cur->range_pair_list);
	// afl->queue_cur->range_pair_list = NULL;

	for (int i = 0; i < RANGE_COUNT; i++) {
		if (!afl->queue_cur->range_pair_array[i]) continue;

		cgi_pair *pair = malloc(sizeof(cgi_pair));
		pair->key = malloc(strlen(cgi_range[i].key));
		strcpy(pair->key, cgi_range[i].key);
		pair->value = malloc(strlen(afl->queue_cur->range_pair_array[i]));
		strcpy(pair->value, afl->queue_cur->range_pair_array[i]);
		pair->next = NULL;

		add_pair_list(&afl->queue_cur->range_pair_list, pair);
	}

  /* Recombine input from lists */
  len = 0;
  len += size_pair2str(afl->queue_cur->fix_pair_list);
  len += size_pair2str(afl->queue_cur->range_pair_list);
  len += size_pair2str(afl->queue_cur->random_pair_list);

	u8 *new_buf = afl_realloc(AFL_BUF_PARAM(new), len);
  
	u8 *tmp_buf = new_buf;
  tmp_buf = pair2str(tmp_buf, afl->queue_cur->fix_pair_list);
  tmp_buf = pair2str(tmp_buf, afl->queue_cur->range_pair_list);
  tmp_buf = pair2str(tmp_buf, afl->queue_cur->random_pair_list);

	free_pair_list(afl->queue_cur->range_pair_list);
	afl->queue_cur->range_pair_list = NULL;

  l = afl->queue_cur->random_pair_list;
  while (l != NULL) {
    l->value = NULL;
    l = l->next;
  }
	// DEBUGF("new_buf:%s\n", new_buf);
  return new_buf;
}

void setup_cgi_feedback_shmem(afl_state_t *afl) {

  afl->cgi_feedback = ck_alloc(sizeof(sharedmem_t));

  // we need to set the non-instrumented mode to not overwrite the SHM_ENV_VAR
  u8 *map = afl_shm_init(afl->cgi_feedback, MAX_FILE + sizeof(u32), 1);
	memset(map, 0, MAX_FILE + sizeof(u32));

  if (!map) { FATAL("BUG: Zero return from cgi_shm_init."); }

  u8 *shm_str = alloc_printf("%d", afl->cgi_feedback->shm_id);
  setenv(SHM_CGI_FD_ENV_VAR, shm_str, 1);
  ck_free(shm_str);

  afl->fsrv.shmem_cgi_fb_num = (u32 *)map;
  afl->fsrv.shmem_cgi_fb_buf = map + sizeof(u32);
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
  u32   cgi_feedback_num    = *(afl->fsrv.shmem_cgi_fb_num);
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

	DEBUGF("Queue id: %d.\n", q->id);
	for (int i = 0; i < cgi_feedback_num; i++) {

		char *env_name = cgi_feedback_buf + i*ENV_NAME_MAX_LEN;
		if (in_all_pair_list(q, env_name)) continue;

		needed_size += strlen(env_name);
		needed_size += strlen("aaaaaa");
		needed_size += 3;

		if (needed_size > now_size) {
			mem = ck_realloc(mem, needed_size);
			now_size = needed_size;
		}

		sprintf(mem + len, "%s=%s\n", env_name, "aaaaaa");

		// save_to_queue(afl, mem, strlen(mem));
		save_if_interesting(afl, mem, strlen(mem), 0xff);
		afl->queued_imported += 1;
		DEBUGF("Successful add new queue.\n");

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
    fprintf(fp, "%s\n", afl->fsrv.shmem_cgi_fb_buf + j*ENV_NAME_MAX_LEN);
	}
	fclose(fp);
}

// typedef struct thread_args {
// 	afl_state_t		*afl;
// 	int						i;
// } thread_args;

// void* python_regex(void* arg) {
	
// 	thread_args *ta = (thread_args*)arg;
// 	afl_state_t *afl = ta->afl;
// 	int i = ta->i;
	
// 	FILE* fp;

// 	char command[REGEX_STR_LEN];
// 	sprintf(command, "python ./plugin/random_regex.py \"%s\" 2>> error_log.txt", afl->fsrv.shmem_cgi_regex->path_info_r[i]);
	
// 	fp = popen(command, "r");
// 	if (fp == NULL) {
// 		perror("popen");
// 		exit(1);
// 	}

// 	fgets(afl->fsrv.shmem_cgi_regex->path_info_str[i], REGEX_STR_LEN, fp);

// 	pclose(fp);
// 	return NULL;
// }

// void generate_regex(afl_state_t *afl) {
	
// 	pthread_t tid[1 << 12];
// 	for (int i = 0; i < *(cgi_range[PATH_INFO].num); i++) {
// 		thread_args ta;
// 		ta.afl = afl;
// 		ta.i = i;
// 		pthread_create(&tid[i], NULL, python_regex, (void*)&ta);
// 	}

// 	for (int i = 0; i < *(cgi_range[PATH_INFO].num); i++) {
// 		pthread_join(tid[i], NULL);
// 	}

// }

void generate_regex(afl_state_t *afl) {

	if (!afl->cgi_regex_done) return;

	FILE *fp[1 << 12];
	for (int i = 0; i < *(cgi_range[PATH_INFO].num); i++) {
      
		char command[REGEX_STR_LEN];
		sprintf(command, "python ./plugin/random_regex.py \"%s\" 2>> error_log.txt", afl->fsrv.shmem_cgi_regex->path_info_r[i]);
		
		fp[i] = popen(command, "r");
		if (fp[i] == NULL) {
			perror("popen");
			exit(1);
		}
    
	}

	for (int i = 0; i < *(cgi_range[PATH_INFO].num); i++) {

		fgets(afl->fsrv.shmem_cgi_regex->path_info_str[i], REGEX_STR_LEN, fp[i]);
		pclose(fp[i]);

	}
	afl->cgi_regex_done = 0;

}

u8 hook_fuzz_one(afl_state_t *afl) {

	memset(afl->fsrv.shmem_cgi_fb_num, 0, MAX_FILE + sizeof(u32));

	u8 skip = fuzz_one(afl);

	/* TODO: change generate_regex.
		Generating regex in the current way seems to 
		trigger OOM and kill the process due to too 
		many forks.
	*/ 
	generate_regex(afl);

	save_data(afl);
	
	save_interesting(afl, afl->queue_cur);

	// save_data(afl);

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


