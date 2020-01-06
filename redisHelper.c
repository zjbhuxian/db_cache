#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include "../../sr_module.h"

#include "redisHelper.h"

#define MAX_REDIS_SOCKS 1000

static int redis_init_socketpool(REDIS_INSTANCE* inst);
static void redis_poolfree(REDIS_INSTANCE* inst);
static int connect_single_socket(REDIS_SOCKET* redisocket, REDIS_INSTANCE* inst);
static int redis_close_socket(REDIS_INSTANCE* inst, REDIS_SOCKET* redisocket);

int redis_pool_create(const REDIS_CONFIG* config, REDIS_INSTANCE** instance)
{
	if(!config || config->endpoints == NULL || config->num_endpoints < 1 || !instance){
		LM_ERR(">>>ERR: Invalid parameter in [%s]\n", __FUNCTION__);
		return -1;
	}

	int i;
	char* host;
	char* auth;
	int port;
	REDIS_INSTANCE* inst;
	int ret = 0;

	size_t len_instance = sizeof(REDIS_INSTANCE);
	size_t len_config = sizeof(REDIS_CONFIG);
	size_t len_endpoint = sizeof(REDIS_ENDPOINT);
	size_t len_sum_endpoints = len_endpoint * config->num_endpoints;

	inst = (REDIS_INSTANCE*)malloc(len_instance+len_config);
	if(!inst){
		LM_ERR(">>>ERR: Failed to malloc memory for instance in %s\n", __FUNCTION__);
		return -1;
	}
	memset(inst, 0x00, len_instance+len_config);
	inst->config = (REDIS_CONFIG*)((char*)inst + len_instance);

	/* Fill config */
	inst->config->endpoints = (REDIS_ENDPOINT*)malloc(len_sum_endpoints);
	if(!(inst->config->endpoints)){
		LM_ERR(">>>ERR: Failed to malloc memory for endpoints in %s\n", __FUNCTION__);
		ret = -1;
		goto Err;
	}

	LM_DBG(">>>DBG: config->endpoints[0].host = %s\n", config->endpoints[0].host);
	LM_DBG(">>>DBG: config->endpoints[0].auth = %s\n", config->endpoints[0].auth);
	LM_DBG(">>>DBG: config->endpoints[0].port = %d\n", config->endpoints[0].port);

	memset(inst->config->endpoints, 0x00, len_sum_endpoints);
	memcpy(inst->config->endpoints, config->endpoints, len_sum_endpoints);

	LM_DBG(">>>DBG: inst->config->endpoints[0].host = %s\n", inst->config->endpoints[0].host);
	LM_DBG(">>>DBG: inst->config->endpoints[0].port = %d\n", inst->config->endpoints[0].port);

	inst->config->num_endpoints = config->num_endpoints;
	inst->config->connect_timeout = config->connect_timeout;
	inst->config->net_readwrite_timeout = config->net_readwrite_timeout;
	inst->config->num_redis_socks = config->num_redis_socks;
	inst->config->connect_failure_retry_delay = config->connect_failure_retry_delay;

	/* Check config */
	if(inst->config->num_redis_socks > MAX_REDIS_SOCKS){
		LM_ERR(">>>ERR: %s: Numbers of redis sockets (%d) cannot exceed MAX_REDIS_SOCKS (%d)\n", __FUNCTION__, inst->config->num_redis_socks, MAX_REDIS_SOCKS);
		ret = -1;
		goto Err;
	}

	if(inst->config->connect_timeout <= 0)
		inst->config->connect_timeout = 0;
	if(inst->config->net_readwrite_timeout <= 0)
		inst->config->net_readwrite_timeout = 0;
	if(inst->config->connect_failure_retry_delay <= 0)
		inst->config->connect_failure_retry_delay = 0;

	for(i = 0; i < inst->config->num_endpoints; ++i){
		host = inst->config->endpoints[i].host;
		auth = inst->config->endpoints[i].auth;
		port = inst->config->endpoints[i].port;
		if(host == NULL || strlen(host) == 0 || port <= 0 || port > 65535){
			LM_ERR(">>>ERR: Invalid redis endpoint @%d: %s:%d in %s\n", i, host, port, __FUNCTION__);
			ret = -1;
			goto Err;
		}
		if(auth == NULL || strlen(auth) == 0){
			LM_WARN(">>>WARNING: No auth string for @%d: %s:%d in %s\n", i, host, port, __FUNCTION__);
		}
		LM_INFO(">>>INFO: Got redis endpoint @%d: %s:%d in %s\n", i, host, port, __FUNCTION__);
	}

	LM_INFO(">>>INFO: Attempting to connect to above endpoints with connect_timeout %d net_readwrite_timeout %d in %s\n", inst->config->connect_timeout, inst->config->net_readwrite_timeout, __FUNCTION__);

	if(redis_init_socketpool(inst) < 0){
		LM_ERR(">>>ERR: Failed to redis_init_socketpool in %s\n", __FUNCTION__);
		ret = -1;
		goto Err;
	}

	*instance = inst;
	return 0;

Err:
	if(inst){
		redis_pool_destroy(inst);
	}
	return ret;
}

int redis_pool_destroy(REDIS_INSTANCE* instance)
{
	REDIS_INSTANCE* inst = instance;
	if(inst){
		if(inst->redis_pool)
			redis_poolfree(inst);

		if(inst->config){
			free(inst->config->endpoints);
		}

		free(inst);
		return 0;
	}

	return -1;
}

static int redis_init_socketpool(REDIS_INSTANCE* inst)
{
	if(!inst){
		LM_ERR(">>>ERR: inst is NULL in %s\n", __FUNCTION__);
		return -1;
	}

	int i, rcode;
	int success = 0;
	size_t len_socket = sizeof(REDIS_SOCKET);
	REDIS_SOCKET* redisocket;

	inst->connect_after = 0;
	inst->redis_pool = NULL;

	for(i = 0; i < inst->config->num_redis_socks; ++i){
		LM_DBG(">>>DBG: starting %d in %s\n", i, __FUNCTION__);

		redisocket = (REDIS_SOCKET*)malloc(len_socket);
		if(!redisocket){
			LM_ERR(">>>ERR: Failed to malloc memory for %d in %s\n", i, __FUNCTION__);
			continue;
		}
		memset(redisocket, 0x00, len_socket);

		redisocket->conn = NULL;
		redisocket->id = i;
		redisocket->backup = i % inst->config->num_endpoints;
		redisocket->state = sockunconnected;
		redisocket->inuse = 0;

		rcode = pthread_mutex_init(&redisocket->mutex, NULL);
		if(rcode != 0){
			LM_ERR(">>>ERR: Failed to init lock: returns (%d) in %s\n", rcode, __FUNCTION__);
			free(redisocket);
			continue;
		}

		if(time(NULL) > inst->connect_after){
			/*
			 * This sets the redisocket->state, and
			 * possibly also inst->connect_after
			 */
			if(connect_single_socket(redisocket, inst) == 0){
				success = 1;
			}
		}

		/* Add this socket to the list of sockets */
		redisocket->next = inst->redis_pool;
		inst->redis_pool = redisocket;
	}

	inst->last_used = NULL;
	if(!success){
		LM_WARN(">>>WARNING: Failed to connect to any redis server in %s\n", __FUNCTION__);
	}

	return 0;
}

static void redis_poolfree(REDIS_INSTANCE* inst)
{
	if(!inst){
		LM_ERR(">>>ERR: inst is NULL in %s\n", __FUNCTION__);
		return;
	}

	REDIS_SOCKET* cur;
	REDIS_SOCKET* next;

	for(cur = inst->redis_pool; cur; cur = next){
		next = cur->next;
		redis_close_socket(inst, cur);
	}

	inst->redis_pool = NULL;
	inst->last_used = NULL;
}

/*
 * Connect to a server. If error, set this socket's state to be
 * "sockunconnected" and set a grace period, during which we won't try
 * connecting again (to prevent unduly lagging the server and being
 * impolite to a server that may be having other issues). If
 * successful in connecting, set state to sockconnected.
 */
static int connect_single_socket(REDIS_SOCKET* redisocket, REDIS_INSTANCE* inst)
{
	int i;
	redisContext* con = NULL;
	redisReply* reply = NULL;
	struct timeval timeout[2];
	char* host;
	char* auth;
	char* auth_cmd = NULL;
	char* auth_model = "AUTH %s";
	int auth_flg = 0;
	size_t len = 0;
	int port;

	LM_DBG(">>>DBG: Attempting to connect #%d @%d in %s\n", redisocket->id, redisocket->backup, __FUNCTION__);

	/* convert timeout (ms) to timeval */
	timeout[0].tv_sec = inst->config->connect_timeout / 1000;
	timeout[0].tv_usec = 1000 * (inst->config->connect_timeout % 1000);
	timeout[1].tv_sec = inst->config->net_readwrite_timeout / 1000;
	timeout[1].tv_usec = 1000 * (inst->config->net_readwrite_timeout % 1000);

	for(i = 0; i < inst->config->num_endpoints; ++i){
		LM_DBG(">>>DBG: id:%d of %d\n", i, inst->config->num_endpoints);
		/*
		 * Get the target host and port from the backup index
		 */
		host = inst->config->endpoints[redisocket->backup].host;
		auth = inst->config->endpoints[redisocket->backup].auth;
		port = inst->config->endpoints[redisocket->backup].port;

		if(!auth || strlen(auth) == 0){
			LM_WARN(">>>WARNING: No auth string in %s\n", __FUNCTION__);
			auth_flg = 0;
		}else{
			auth_flg = 1;
		}

		LM_DBG(">>>DBG: host = [%s]\n", host);
		if(auth_flg == 1)
			LM_DBG(">>>DBG: auth = [%s]\n", auth);
		LM_DBG(">>>DBG: port = [%d]\n", port);

		con = redisConnectWithTimeout(host, port, timeout[0]);
		if(con && con->err == 0){
			LM_DBG(">>>DBG: Connected new redis handle #%d @%d in %s\n", redisocket->id, redisocket->backup, __FUNCTION__);
			redisocket->conn = con;
			redisocket->state = sockconnected;
			if(inst->config->num_endpoints > 1){
				/* Select the next _random_ endpoint as the new backup */
				redisocket->backup = (redisocket->backup + (1 + rand() % (inst->config->num_endpoints -1))) % inst->config->num_endpoints;
			}

			if(redisSetTimeout(con, timeout[1]) != REDIS_OK){
				LM_WARN(">>>WARNING: Failed to set timeout: blocking-mode: %d,%s in %s\n", (con->flags & REDIS_BLOCK), con->errstr, __FUNCTION__);
			}

			if(redisEnableKeepAlive(con) != REDIS_OK){
				LM_WARN(">>>WARNING: Failed to enable keepalive: %s in %s\n", con->errstr, __FUNCTION__);
			}

			/* Check auth */
			if(auth_flg == 1){
				len = strlen(auth) + strlen(auth_model) -1;
				auth_cmd = (char*)malloc(len);
				if(!auth_cmd){
					LM_ERR(">>>ERR: Failed to malloc memory in %s\n", __FUNCTION__);
					return -1; //!!!!!!!!!!!!!!!!
				}
				memset(auth_cmd, 0x00, len);
				sprintf(auth_cmd, auth_model, auth);
				auth_cmd[len-1] = '\0';

				LM_DBG(">>>DBG: auth_cmd [%s] in %s\n", auth_cmd, __FUNCTION__);
				reply = (redisReply*)redisCommand(con, auth_cmd);
				if(reply == NULL){
					LM_ERR(">>>ERR: [%d] in %s\n", REDIS_ERR, __FUNCTION__);
					if(auth_cmd){
						free(auth_cmd);
						auth_cmd = NULL;
					}
				}

				if(reply){
					freeReplyObject(reply);
					reply = NULL;
				}

				if(auth_cmd){
					free(auth_cmd);
					auth_cmd = NULL;
				}
			}

			return 0;
		}

		/* We have tried the last one but still fail */
		if(i == inst->config->num_endpoints -1)
			break;

		/* We have more backups to try */
		if(con){
			LM_WARN(">>>WARNING: Failed to connect redis handle #%d @%d: %s, tring backup in %s\n", redisocket->id, redisocket->backup, con->errstr, __FUNCTION__);
		}else{
			LM_WARN(">>>WARNING: Con't allocate redis handle #%d @%d, tring backup in %s\n", redisocket->id, redisocket->backup, __FUNCTION__);
		}

		redisocket->backup = (redisocket->backup + 1) % inst->config->num_endpoints;
	}

	/*
	 * Error, or SERVER_DOWN;
	 */
	if(con){
		LM_WARN(">>>WARNING: Failed to connect redis handle #%d @%d:%s in %s\n", redisocket->id, redisocket->backup, con->errstr, __FUNCTION__);
		redisFree(con);
	}else{
		LM_WARN(">>>WARNING: Can't allocate redis handle #%d @%d in %s\n", redisocket->id, redisocket->backup, __FUNCTION__);
	}

	redisocket->conn = NULL;
	redisocket->state = sockunconnected;
	redisocket->backup = (redisocket->backup + 1) % inst->config->num_endpoints;

	inst->connect_after = time(NULL) + inst->config->connect_failure_retry_delay;

	return -1;
}

int redis_test_socket(REDIS_SOCKET* redisocket, REDIS_INSTANCE* inst)
{
	if(!redisocket || !inst){
		LM_ERR(">>>ERR: Invalid parameter in %s\n", __FUNCTION__);
		return -1;
	}

	redisReply* reply = NULL;
	if((reply = (redisReply*)redis_command(redisocket, inst, "PING")) == NULL){
		freeReplyObject(reply);
		reply = NULL;
		return 0;
	}
	LM_DBG(">>>DBG: PING: %s in %s\n", reply->str, __FUNCTION__);
	
	freeReplyObject(reply);
	return 1;
}

static int redis_close_socket(REDIS_INSTANCE* inst, REDIS_SOCKET* redisocket)
{
	int rcode;
	(void)inst;

	LM_DBG(">>>DBG: Closing redis socket =%d #%d @%d in %s\n", redisocket->state, redisocket->id, redisocket->backup, __FUNCTION__);

	if(redisocket->inuse){
		LM_ERR(">>>ERR: Still in use, BUG? in %s\n", __FUNCTION__);
	}

	rcode = pthread_mutex_destroy(&redisocket->mutex);
	if(rcode != 0){
		LM_WARN(">>>WARNING: Failed to destroy lock: returns (%d) in %s\n", rcode, __FUNCTION__);
	}

	free(redisocket);

	return 0;
}

REDIS_SOCKET* redis_get_socket(REDIS_INSTANCE* inst)
{
	REDIS_SOCKET* cur, *start;
	int tried_to_connect = 0;
	int unconnected = 0;
	int rcode, locked;

	/*
	 * Start at the last place we left off.
	 */
	start = inst->last_used;
	if(!start)start = inst->redis_pool;

	cur = start;

	locked = 0;
	while(cur){
		/*
		 * If this socket is in use by another thread,
		 * skip it, and try another socket.
		 *
		 * If it isn't used, then grab it ourselves.
		 */
		if((rcode = pthread_mutex_trylock(&cur->mutex)) != 0){
			goto next;
		}/* else we now have the lock */
		else{
			locked = 1;
			LM_DBG(">>>DBG: Obtained lock with handle %d in %s\n", cur->id, __FUNCTION__);
		}

		if(cur->inuse == 1){
			if(locked){
				if((rcode = pthread_mutex_unlock(&cur->mutex)) != 0){
					LM_ERR(">>>ERR: Can not release lock with handle %d returns (%d) in %s\n", cur->id, rcode, __FUNCTION__);
				}else{
					LM_DBG(">>>DBG: Released lock with handle %d in %s\n", cur->id, __FUNCTION__);
				}
			}
			goto next;
		}else{
			cur->inuse = 1;
		}

		/*
		 * If we happen upon an unconnected socket, and
		 * this instance's grace period on 
		 * (re)connected has expired, then try to
		 * connect it. This should be really rare.
		 */
		if((cur->state == sockunconnected) && (time(NULL) > inst->connect_after)){
			LM_INFO(">>>INFO: Tring to (re)connect unconnected handle %d... in %s\n", cur->id, __FUNCTION__);
			tried_to_connect++;
			connect_single_socket(cur, inst);
		}

		/* If we still aren't connected, ignore this handle */
		if(cur->state == sockunconnected){
			LM_DBG(">>>DBG: Ignoring unconnected handle %d ... in %s\n", cur->id, __FUNCTION__);
			unconnected++;
			cur->inuse = 0;

			if((rcode = pthread_mutex_unlock(&cur->mutex)) != 0){
				LM_ERR(">>>ERR: Can not release lock with handle %d: returns (%d) in %s\n", cur->id, rcode, __FUNCTION__);
			}else{
				LM_DBG(">>>DBG: Released lock with handle %d in %s\n", cur->id, __FUNCTION__);
			}

			goto next;
		}

		/* Should be connected, grab it */
		LM_DBG(">>>DBG: Obtained redis socket id: %d in %s\n", cur->id, __FUNCTION__);

		if(unconnected != 0 || tried_to_connect != 0){
			LM_INFO(">>>INFO: Got socket %d after skipping %d unconnected handles, tried to reconnect %d though in %s\n", cur->id, unconnected, tried_to_connect, __FUNCTION__);
		}

		/*
		 * The socket is returned in the locked state.
		 * We also remember where we left off,
		 * so that the next search can start from here.
		 *
		 * Note that multiple threads MAY over-write the
		 * 'inst->last_used' variable. This is OK, 
		 * as it's a pointer only used for reading.
		 */
		inst->last_used = cur->next;
		return cur;

		/* Move along the list */
next:
		cur = cur->next;

		/*
		 * Because we didnt start at the start, once we hit
		 * the end of the linklist, we should go back to the 
		 * beginning and work toward the middle!
		 */
		if(!cur){
			cur = inst->redis_pool;
		}

		/*
		 * If we're at the socket we started
		 */
		if(cur == start){
			break;
		}
	}

	/*
	 * We get here if every redis handle is unconnected and 
	 * unconnectABLE, or in use 
	 */
	LM_WARN(">>>WARNING: There are no redis handles to use! skipped %d, tried to connect %d in %s\n", unconnected, tried_to_connect, __FUNCTION__);
	return NULL;
}

int redis_release_socket(REDIS_INSTANCE* inst, REDIS_SOCKET* redisocket)
{
	if(!inst || !redisocket){
		LM_ERR(">>>ERR: Invalid parameter in %s\n", __FUNCTION__);
		return -1;
	}

	int rcode;
	(void)inst;
	if(redisocket->inuse != 1){
		LM_ERR(">>>ERR: I'm NOT in use. Bug? in %s\n", __FUNCTION__);
	}
	redisocket->inuse = 0;

	if((rcode = pthread_mutex_unlock(&redisocket->mutex)) != 0){
		LM_ERR(">>>ERR: Can not release lock with handle %d: returns (%d) in %ld\n", redisocket->id, rcode, syscall(SYS_gettid));
	}else{
		LM_DBG(">>>DBG: Released lock with handle %d in %ld\n", redisocket->id, syscall(SYS_gettid));
	}

	LM_DBG(">>>DBG: Released redis socket id: %d in %s\n", redisocket->id, __FUNCTION__);

	return 0;
}

void* redis_command(REDIS_SOCKET* redisocket, REDIS_INSTANCE* inst, const char* format, ...)
{
	if(!redisocket || !inst){
		LM_ERR(">>>ERR: Invalid parameter in %s\n", __FUNCTION__);
		return (void*)NULL;
	}

	va_list ap;
	void* reply;
	va_start(ap, format);
	reply = redis_vcommand(redisocket, inst, format, ap);
	va_end(ap);
	return reply;
}

void* redis_vcommand(REDIS_SOCKET* redisocket, REDIS_INSTANCE* inst, const char* format, va_list ap)
{
	if(!redisocket || !inst){
		LM_ERR(">>>ERR: Invalid parameter in %s\n", __FUNCTION__);
		return (void*)NULL;
	}

	va_list ap2;
	void* reply;
	redisContext* con;

	va_copy(ap2, ap);

	/* Forward to hiredis API */ 
	con = redisocket->conn;
	reply = redisvCommand(con, format, ap);

	if(reply == NULL){
		/* Once an error is returned the context connot be reused and you should
		 * set up a new connection.
		 */

		/* Close the socket that failed */
		redisFree(con);

		/* reconnect the socket */
		if(connect_single_socket(redisocket, inst) < 0){
			LM_ERR(">>>ERR: Reconnect failed, server down? in %s\n", __FUNCTION__);
			goto quit;
		}

		/* retry on the newly connected socket */ 
		con = redisocket->conn;
		reply = redisvCommand(con, format, ap2);

		if(reply == NULL){
			LM_ERR(">>>ERR: Failed after reconnect: %s (%d) in %s\n", con->errstr, con->err, __FUNCTION__);
			/* do not need clean up here because the next caller will retry */
			goto quit;
		}
	}

quit:
	va_end(ap2);
	return reply;
}

redisContext* redis_connect(const char* ip, int port, const char* authstr, int timeout)
{
	if(!ip || port < 0 || timeout < 0){
		LM_ERR(">>>ERR: Invalid parameter in [%s].\n", __FUNCTION__);
		return NULL;
	}

	int auth_flg = 0;
	char* auth = NULL;
	size_t len = 0;
	struct timeval tv;
	redisReply* reply = NULL;

	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 1000;

	if(!authstr || strlen(authstr) == 0){
		LM_WARN(">>>WARNING: No authstr.\n");
		auth_flg = 0;
	}else{
		auth_flg = 1;
	}

	redisContext* redis_con = redisConnectWithTimeout(ip, port, tv);
	if(redis_con == NULL || redis_con->err != 0){
		if(redis_con){
			LM_ERR(">>>ERR: Failed to connect redis err[%d], errstr [%s]\n", redis_con->err, redis_con->errstr);
			redisFree(redis_con);
			redis_con = NULL;
		}

		LM_ERR(">>>ERR: Failed to redisConnect\n");
		return NULL;
	}

	if(REDIS_ERR == redisSetTimeout(redis_con, tv)){
		redisFree(redis_con);
		redis_con = NULL;
		return NULL; 
	}

	LM_DBG(">>>DBG: Successed to connect to redis [%s]:[%d]\n", ip, port);

	if(auth_flg == 1){
		len = strlen(authstr)+strlen("AUTH %s")+1;
		auth = (char*)malloc(len);
		if(!auth){
			LM_ERR(">>>ERR: Failed to malloc [%zd] memory in %s\n", len, __FUNCTION__);
			goto Err;
		}

		memset(auth, 0x00, len);
		sprintf(auth, "AUTH %s", authstr);
		auth[len-1] = '\0';

		LM_DBG(">>>DBG: auth: [%s]\n", auth);
		reply = (redisReply*)redisCommand(redis_con, auth);
		if(reply == NULL){
			LM_ERR(">>>ERR: [%d]\n", REDIS_ERR);
			goto Err;
		}

		if(redis_con->err != 0){
			LM_ERR(">>>ERR: [%d], errstr: [%s]\n", redis_con->err, redis_con->errstr);
			goto Err;
		}

		if(REDIS_REPLY_ERROR == reply->type){
			LM_ERR(">>>ERR: Cmd: [%s], errstr: [%s]\n", auth, reply->str);
			goto Err;
		}

		if(reply){
			freeReplyObject(reply);
			reply = NULL;
		}

		if(auth){
			free(auth);
			auth = NULL;
		}

		return redis_con;
	}

	return redis_con;

Err:
	if(redis_con){
		redisFree(redis_con);
		redis_con = NULL;
	}

	if(reply){
		freeReplyObject(reply);
		reply = NULL;
	}

	if(auth){
		free(auth);
		auth = NULL;
	}

	return NULL;
}

/* Notice: key-s: must be null-terminated
 * val->s: must be null-terminated
 * */
int redis_add(redisContext* ctx, const str* key, const str* val)
{
	if(!ctx || !key || !val || key->len == 0 || val->len == 0){
		LM_ERR(">>>ERR: Invalid parameter in %s\n", __FUNCTION__);
		return -1;
	}

	redisReply* reply = NULL;
	const char* cmd_model = "SET %s %s";
	char* cmd = NULL;
	size_t len = strlen(cmd_model) + key->len + val->len -3; // -4 + 1
	int ret = 0;

	cmd = (char*)malloc(len);
	if(!cmd){
		LM_ERR(">>>ERR: Failed to malloc memory with size [%zu] in %s", len, __FUNCTION__);
		ret = -1;
		goto Err;
	}

	memset(cmd, 0x00, len);
	sprintf(cmd, cmd_model, key->s, val->s);
	cmd[len-1] = '\0';

	LM_DBG(">>>DBG: add cmd [%s] in %s\n", cmd, __FUNCTION__);

	reply = (redisReply*)redisCommand(ctx, cmd);
	if(reply == NULL){
		if(ctx){
			LM_ERR(">>>ERR: [%d], [%s]\n", ctx->err, ctx->errstr);
			if(ctx->err == 3){
				LM_ERR(">>>ERR: Need to reconnect\n");
			}
		}
		ret = -1;
		goto Err;
	}

	if(ctx->err != 0){
		LM_ERR(">>>ERR: [%d], [%s]\n", ctx->err, ctx->errstr);
		ret = -1;
		goto Err;
	}

	if(REDIS_REPLY_ERROR == reply->type){
		LM_ERR(">>>ERR: [%s]\n", reply->str);
		ret = -1;
		goto Err;
	}

Err:
	if(cmd){
		free(cmd);
		cmd = NULL;
	}

	if(reply){
		freeReplyObject(reply);
		reply = NULL;
	}

	return ret;
}

/*Notice: key->s: must be null-terminated
 * */
int redis_get(redisContext* ctx, const str* key, char** retval)
{
	if(!ctx || !key || key->len == 0 ||  !retval){
		LM_ERR(">>>ERR: Invalid parameter in %s\n", __FUNCTION__);
		return -1;
	}

	redisReply* reply = NULL;
	const char* cmd_model = "GET %s";
	char* cmd = NULL;
	size_t len = strlen(cmd_model) + key->len -1; // -2 + 1 
	size_t ret_len = 0;
	int ret = 0;

	cmd = (char*)malloc(len);
	if(!cmd){
		LM_ERR(">>>ERR: Failed to malloc memory with size [%zu] in %s\n", len, __FUNCTION__);
		return -1;
	}
	memset(cmd, 0x00, len);
	sprintf(cmd, cmd_model, key->s);
	cmd[len-1] = '\0';

	LM_DBG(">>>DBG: cmd: [%s] in %s\n", cmd, __FUNCTION__);

	reply = (redisReply*)redisCommand(ctx, cmd);
	if(reply == NULL){
		if(ctx){
			LM_ERR(">>>ERR: [%d], [%s]\n", ctx->err, ctx->errstr);
			if(ctx->err == 3){
				LM_ERR(">>>ERR: Need to reconnect\n");
			}
		}
		ret = -1;
		goto Err;
	}

	if(ctx->err != 0){
		LM_ERR(">>>ERR: [%d], [%s]\n", ctx->err, ctx->errstr);
		ret = -1;
		goto Err;
	}

	if(REDIS_REPLY_ERROR == reply->type){
		LM_ERR(">>>ERR: [%s]\n", reply->str);
		ret = -1;
		goto Err;
	}

	if(reply && reply->type == REDIS_REPLY_STRING){
		ret_len = strlen(reply->str);
		if(ret_len > 0){
			*retval = (char*)malloc(ret_len+1);
			if(!(*retval)){
				LM_ERR(">>>ERR: Failed to malloc memory with size [%zu] in %s\n", ret_len+1, __FUNCTION__);
				ret = -1;
				goto Err;
			}
			memset(*retval, 0x00, ret_len+1);
			memcpy(*retval, reply->str, ret_len);
			(*retval)[ret_len] = '\0';
		}
	}else{
		LM_ERR(">>>ERR: Failed to get [%s]\n", key->s); // key->s with null-terminated
		*retval = NULL;
	}

Err:
	if(reply){
		freeReplyObject(reply);
		reply = NULL;
	}

	if(cmd){
		free(cmd);
		cmd = NULL;
	}

	return ret;
}

int redis_rm(redisContext* ctx, const char* key)
{
	return 0;
}

void redis_close(redisContext* con)
{
	if(con){
		redisFree(con);
		con = NULL;
	}
}
