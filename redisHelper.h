/* Add redis pool
 * Date: 2020-1-5
 */

#ifndef __REDISHELPER_H__
#define __REDISHELPER_H__

#include "hiredis/hiredis.h"

typedef struct redis_endpoint {
	char host[256];
	char auth[1024];
	int port;
}REDIS_ENDPOINT;

typedef struct redis_config {
	REDIS_ENDPOINT* endpoints;
	int num_endpoints;
	int connect_timeout;
	int net_readwrite_timeout;
	int num_redis_socks;
	int connect_failure_retry_delay;
}REDIS_CONFIG;

typedef struct redis_socket {
	int id;
	int backup;
	pthread_mutex_t mutex;
	int inuse;
	struct redis_socket* next;
	enum { sockunconnected, sockconnected } state;
	void* conn;
}REDIS_SOCKET;

typedef struct redis_instance {
	time_t connect_after;
	REDIS_SOCKET* redis_pool;
	REDIS_SOCKET* last_used;
	REDIS_CONFIG* config;
}REDIS_INSTANCE;

// APIs for redis
int redis_pool_create(const REDIS_CONFIG* config, REDIS_INSTANCE** instance);
int redis_pool_destroy(REDIS_INSTANCE* instance);

REDIS_SOCKET* redis_get_socket(REDIS_INSTANCE* instance);
int redis_release_socket(REDIS_INSTANCE* instance, REDIS_SOCKET* redisocket);

void* redis_command(REDIS_SOCKET* redisocket, REDIS_INSTANCE* instance, const char* format, ...);
void* redis_vcommand(REDIS_SOCKET* redisocket, REDIS_INSTANCE* instance, const char* format, va_list ap);

redisContext* redis_connect(const char* ip, int port, const char* authstring, int timeout);

int redis_test_socket(REDIS_SOCKET* redisocket, REDIS_INSTANCE* inst);
int redis_add(redisContext* ctx, const str* key, const str* val);
int redis_get(redisContext* ctx, const str* key, char** retval);
int redis_rm(redisContext* ctx, const char* key);
void redis_close(redisContext* ctx);

// Tools for key

#endif
