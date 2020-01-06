/** =================================================================
 * For store/fetch information of SIP via DB sqlite3
 * Created by zhou at 2019
 * ==================================================================*/
#include "../../sr_module.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "../../mod_fix.h"
#include "../../mem/mem.h"
#include "../../pvar.h"
#include "redisHelper.h"

static int mod_init(void); /* Module initialization function */
void mod_destroy(void); /* Module initialization function */

str* mystr_dup(const str* srcstr);
str* make_key(const str* callid, const char* type, const char* hname);
void mystr_free(str* pstr);

/* 
 * Module export variables 
 */
static char* redis_host = NULL;
static char* redis_auth = NULL;
static int redis_port = 6379;
static int redis_timeout = 0;
static int max_redis_socks = 30;
static int net_readwrite_timeout = 5000;
static int retry_delay = 1;
REDIS_INSTANCE* global_inst = NULL;

/*===================================================================================================
 * ver.1.0: store information by SIP-header-field
 *===================================================================================================*/
static int store_handle(const str* callid, const char* type, const char* hname, const str* hvalue);
static int fetch_handle(struct sip_msg* _msg, const str* callid, const char* type, const char* hname, char** retval);

static int store_callid(struct sip_msg *_msg, const char *incallid, const char *outcallid);
static int fetch_callid(struct sip_msg *_msg, const char *onecallid, char *theothercallid);

static int store_info(struct sip_msg* _msg, const char* callid, const char* type, const char* hname, const char* hvalue);
static int fetch_info(struct sip_msg* _msg, const char* callid, const char* type, const char* hname, char* hvalue);

/**
 * Convert string to gparam_p
 */
static int fixup_param_func_store_callid(void **param, int param_no);
static int fixup_param_func_fetch_callid(void **param, int param_no);
static int fixup_param_func_store_handle(void **param, int param_no);
static int fixup_param_func_fetch_handle(void **param, int param_no);

str* mystr_dup(const str* srcstr)
{
	if(!srcstr){
		LM_ERR(">>>ERR: Src str is NULL in %s\n", __FUNCTION__);
		return NULL;
	}

	size_t len_str = sizeof(str);
	size_t len_srcstr = srcstr->len;

	str* p = (str*)malloc(len_str + len_srcstr + 1);
	if(!p){
		LM_ERR(">>>ERR: Failed to malloc memory with size [%zu] in %s\n", len_str+len_srcstr+1, __FUNCTION__);
		return NULL;
	}

	memset(p, 0x00, len_str+len_srcstr+1);
	p->s = (char*)p + len_str;
	p->len = len_srcstr;
	memcpy(p->s, srcstr->s, len_srcstr);
	p->s[len_srcstr] = '\0';

	return p;
}

str* make_key(const str* callid, const char* type, const char* hname)
{
	if(!callid || !type || !hname){
		LM_ERR(">>>ERR: Invalid parameter in %s\n", __FUNCTION__);
		return NULL;
	}

	size_t len_str = sizeof(str);
	size_t len_type = strlen(type);
	size_t len_hname = strlen(hname);
	size_t len_key = callid->len + len_type + len_hname + 2; // like this: callid_type_hname, 2: duble "_"
	char* key_model = "%s_%s_%s";
	str* key = NULL;

	if(callid->len == 0 || len_type == 0 || len_hname == 0){
		LM_ERR(">>>ERR: Invalid parameter in %s\n", __FUNCTION__);
		return NULL;
	}

	key = (str*)malloc(len_str + len_key + 1);
	if(!key){
		LM_ERR(">>>ERR: Failed to malloc memory in %s\n", __FUNCTION__);
		return NULL;
	}
	memset(key, 0x00, len_str+len_key + 1);
	key->s = (char*)key + len_str;
	sprintf(key->s, key_model, callid->s, type, hname);
	key->s[len_key] = '\0';
	key->len = len_key;

	return key;
}

void mystr_free(str* pstr)
{
	if(pstr){
		free(pstr);
	}
}

static int store_handle(const str* callid, const char* type, const char* hname, const str* hvalue)
{
	if(!callid || !type || !hname || !hvalue || !global_inst){
		LM_ERR(">>>ERR: Invalid parameter in %s\n", __FUNCTION__);
		return -1;
	}

	int ret = 0;
	str* pkey = NULL;
	redisContext* con = NULL;
	REDIS_SOCKET* sock = NULL;

	pkey = make_key(callid, type, hname);
	if(!pkey){
		LM_ERR(">>>ERR: Failed to make key from [%s][%s] in %s\n", callid->s, type, __FUNCTION__);
		ret = -1;
		goto Err;
	}

	if((sock = redis_get_socket(global_inst)) == NULL){
		LM_ERR(">>>ERR: Falied to get socket in %s\n", __FUNCTION__);
		goto Err;
	}
	if(redis_test_socket(sock, global_inst) != 1){
		LM_ERR(">>>ERR: the socket can not be used.\n");
		goto Err;
	}
	//con = redis_connect(redis_host, redis_port, redis_auth, redis_timeout);
	con = (redisContext*)sock->conn;
	if(!con){
		LM_ERR(">>>ERR: Failed to connect to redis in %s\n", __FUNCTION__);
		ret = -1;
		goto Err;
	}

	ret = redis_add(con, pkey, hvalue);
	if(ret < 0){
		LM_ERR(">>>ERR: Failed to add to redis in %s\n", __FUNCTION__);
		goto Err;
	}

Err:
	//if(con){
	//	redisFree(con);
	//	con = NULL;
	//}
	if(sock){
		redis_release_socket(global_inst, sock);
	}

	if(pkey){
		mystr_free(pkey);
		pkey = NULL;
	}

	return ret;
}

static int fetch_handle(struct sip_msg* _msg, const str* callid, const char* type, const char* hname, char** retval)
{
	if(!callid || !type || !global_inst){
		LM_ERR(">>>ERR: Invalid parameter in %s\n", __FUNCTION__);
		return -1;
	}

	int ret = 0;
	str* pkey = NULL;
	redisContext* con = NULL;
	REDIS_SOCKET* sock = NULL;
	char* fetched_val = NULL;

	pv_spec_t* sp_dest;
	pv_value_t value;
	size_t len_ret = 0;

	pkey = make_key(callid, type, hname);
	if(!pkey){
		LM_ERR(">>>ERR: Failed to make key from [%s][%s] in %s\n", callid->s, type, __FUNCTION__);
		ret = -1;
		goto Err;
	}

	if((sock = redis_get_socket(global_inst)) == NULL){
		LM_ERR(">>>ERR: Failed to get socket in %s\n", __FUNCTION__);
		goto Err;
	}
	if(redis_test_socket(sock, global_inst) != 1){
		LM_ERR(">>>ERR: the socket can not be used.\n");
		goto Err;
	}
	//con = redis_connect(redis_host, redis_port, redis_auth, redis_timeout);
	con = (redisContext*)sock->conn;
	if(!con){
		LM_ERR(">>>ERR: Failed to connect to redis in %s\n", __FUNCTION__);
		ret = -1;
		goto Err;
	}

	ret = redis_get(con, pkey, &fetched_val);
	if(ret < 0){
		LM_ERR(">>>ERR: Failed to get from redis in %s\n", __FUNCTION__);
		goto Err;
	}

	if(!fetched_val){
		LM_ERR(">>>ERR: Fatched nothing in %s\n", __FUNCTION__);
		ret = -1;
		goto Err;
	}

	len_ret = strlen(fetched_val);
	value.rs.s = fetched_val;
	value.rs.len = len_ret;
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)(*retval);
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR(">>>ERR: failed to set fetch value [%s] in %s\n", hname, __FUNCTION__);
		ret = -1;
		goto Err;
	}

Err:
	if(sock){
		redis_release_socket(global_inst, sock);
		sock = NULL;
	}

	if(pkey){
		mystr_free(pkey);
		pkey = NULL;
	}

	if(fetched_val){
		free(fetched_val);
		fetched_val = NULL;
	}

	return ret;
}

int store_callid(struct sip_msg *_msg, const char *incallid, const char *outcallid)
{
	LM_DBG(">>>DBG: Entered %s\n", __FUNCTION__);
	if(!incallid || !outcallid || !global_inst){
		LM_ERR(">>>ERR: Invalid parameter in [%s]\n", __FUNCTION__);
		return 1;
	}

	str _incallid, _outcallid, *str_incallid = NULL, *str_outcallid = NULL;
	redisContext* con = NULL;
	REDIS_SOCKET* sock = NULL;
	int ret = 0;

	if(fixup_get_svalue(_msg, (gparam_p)incallid, &_incallid) < 0){
		LM_ERR(">>>ERR: bad value for 'incallid'\n");
		goto Err;
	}
	if(fixup_get_svalue(_msg, (gparam_p)outcallid, &_outcallid) < 0){
		LM_ERR(">>>ERR: bad value for 'incallid'\n");
		goto Err;
	}

	if(_incallid.len == 0 || _outcallid.len == 0){
		LM_ERR(">>>ERR: Invalid parameters(incallid, outcallid maybe empty) in %s\n", __FUNCTION__);
		goto Err;
	}

	str_incallid = mystr_dup(&_incallid);
	str_outcallid = mystr_dup(&_outcallid);

	if(!str_incallid || !str_outcallid){
		LM_ERR(">>>ERR: Failed to dup str\n");
		goto Err;
	}else{
		LM_DBG(">>>DBG: str_incallid->s [%s] with [%d] in %s\n", str_incallid->s, str_incallid->len, __FUNCTION__);
		LM_DBG(">>>DBG: str_outcallid->s [%s] with [%d] in %s\n", str_outcallid->s, str_outcallid->len, __FUNCTION__);
	}

	if((sock = redis_get_socket(global_inst)) == NULL){
		LM_ERR(">>>ERR: Failed to get socket in %s\n", __FUNCTION__);
		goto Err;
	}
	if(redis_test_socket(sock, global_inst) != 1){
		LM_ERR(">>>ERR: the socket can not be used.\n");
		goto Err;
	}
	con = (redisContext*)sock->conn;
	if(!con){
		LM_ERR(">>>ERR: Failed to get redisContext in %s\n", __FUNCTION__);
		goto Err;
	}

	ret = redis_add(con, str_incallid, str_outcallid);
	if(ret < 0){
		LM_ERR(">>>ERR: Failed to redis_add in %s\n", __FUNCTION__);
		goto Err;
	}

Err:
	if(str_incallid){
		mystr_free(str_incallid);
		str_incallid = NULL;
	}

	if(str_outcallid){
		mystr_free(str_outcallid);
		str_outcallid = NULL;
	}

	if(sock){
		redis_release_socket(global_inst, sock);
	}
	
	LM_DBG(">>>DBG: Get out %s\n", __FUNCTION__);
	return 1;
}

int fetch_callid(struct sip_msg *_msg, const char *onecallid, char *theothercallid)
{
	if(!onecallid || !theothercallid || !global_inst){
		LM_ERR(">>>ERR: Invalid parameters in %s\n", __FUNCTION__);
		return 1;
	}

	str _onecallid, *str_onecallid = NULL;
	REDIS_SOCKET* sock = NULL;
	redisContext* con = NULL;
	char* retval = NULL;
	if(fixup_get_svalue(_msg, (gparam_p)onecallid, &_onecallid) < 0){
		LM_ERR(">>>ERR: Bad value for 'onecallid' in %s\n", __FUNCTION__);
		return 1;
	}

	if(_onecallid.len == 0){
		LM_ERR(">>>ERR: onecallid is NULL in %s\n", __FUNCTION__);
		return 1;
	}

	str_onecallid = mystr_dup(&_onecallid);
	if(!str_onecallid){
		LM_ERR(">>>ERR: Failed to dup str in %s\n", __FUNCTION__);
		return 1;
	}else{
		LM_DBG(">>>DBG: Will fetch key [%s] from redis in %s\n", str_onecallid->s, __FUNCTION__);
	}

	if((sock = redis_get_socket(global_inst)) == NULL){
		LM_ERR(">>>ERR: Failed to get socket in %s\n", __FUNCTION__);
		goto Err;
	}

	if(redis_test_socket(sock, global_inst) != 1){
		LM_ERR(">>>ERR: the socket can not be used.\n");
		goto Err;
	}
	con = (redisContext*)sock->conn;
	if(!con){
		LM_ERR(">>>ERR: Failed to connect to redis in %s\n", __FUNCTION__);
		goto Err;
	}

	int ret = redis_get(con, str_onecallid, &retval);
	if(ret < 0){
		LM_ERR(">>>ERR: Failed to redis_get in %s\n", __FUNCTION__);
		goto Err;
	}

	if(!retval){
		LM_ERR(">>>ERR: Got nothing from redis via key [%s]\n", str_onecallid->s);
		goto Err;
	}else{
		LM_DBG(">>>DBG: get data [%s] from redis in %s\n", retval, __FUNCTION__);
	}

	pv_spec_t* sp_dest;
	pv_value_t value;

	value.rs.s = retval;
	value.rs.len = strlen(retval);
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)theothercallid;
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR("######## failed to set fetch callid\n");
		goto Err;
	}

Err:
	if(retval){
		LM_DBG(">>>DBG:FREE retval\n");
		free(retval);
		retval = NULL;
	}

	if(str_onecallid){
		LM_DBG(">>>DBG:FREE str_onecallid\n");
		mystr_free(str_onecallid);
		str_onecallid = NULL;
	}

	if(sock){
		LM_DBG(">>>DBG:FREE redis_release_socket\n");
		redis_release_socket(global_inst, sock);
	}

	return 1;
}


static int store_info(struct sip_msg *_msg, const char *callid,  const char *type, const char* hname, const char *hvalue)
{
	if(!callid || !type || strlen(type) == 0 || !hname || strlen(hname) == 0 || !hvalue || strlen(hvalue) == 0){
		LM_ERR(">>>ERR: Invalid parameters in %s\n", __FUNCTION__);
		return -1;
	}

	str _callid, _val, *str_callid = NULL, *str_val = NULL;
	if(fixup_get_svalue(_msg, (gparam_p)callid, &_callid) < 0){
		LM_ERR(">>>ERR: Bad value for 'callid' in %s\n", __FUNCTION__);
		goto Err;
	}
	if(fixup_get_svalue(_msg, (gparam_p)hvalue, &_val) < 0){
		LM_ERR(">>>ERR: Bad value for '%s' in %s\n", hvalue, __FUNCTION__);
		goto Err;
	}

	if(_callid.len == 0 || _val.len == 0){
		LM_ERR(">>>ERR: Invalid parameters in %s\n", __FUNCTION__);
		goto Err;
	}

	str_callid = mystr_dup(&_callid);
	if(!str_callid){
		LM_ERR(">>>ERR: Failed to dup str _callid in %s\n", __FUNCTION__);
		goto Err;
	}
	str_val = mystr_dup(&_val);
	if(!str_val){
		LM_ERR(">>>ERR: Failed to dup str in %s\n", __FUNCTION__);
		goto Err;
	}

	int ret = store_handle(str_callid, type, hname, str_val);
	if(ret < 0){
		LM_ERR(">>>ERR: Failed to store_handle in %s\n", __FUNCTION__);
		goto Err;
	}

Err:
	if(str_callid){
		mystr_free(str_callid);
		str_callid = NULL;
	}

	if(str_val){
		mystr_free(str_val);
		str_val = NULL;
	}

	return 1;
}

static int fetch_info(struct sip_msg *_msg, const char *callid, const char *type, const char* hname, char *retval)
{
	if(!callid || !type || strlen(type) == 0 || !hname || strlen(hname) == 0 || !retval){
		LM_ERR(">>>ERR: Invalid parameters in %s\n", __FUNCTION__);
		return 1;
	}

	str _callid, *str_callid = NULL;
	int ret = 0;

	if(fixup_get_svalue(_msg, (gparam_p)callid, &_callid) < 0){
		LM_ERR(">>>ERR: Bad value for 'callid' in %s\n", __FUNCTION__);
		goto Err;
	}

	if(_callid.len == 0){
		LM_ERR(">>>ERR: Invalid parameter in %s\n", __FUNCTION__);
		goto Err;
	}

	str_callid = mystr_dup(&_callid);
	if(!str_callid){
		LM_ERR(">>>ERR: Failed to dup str in %s\n", __FUNCTION__);
		goto Err;
	}

	ret = fetch_handle(_msg, str_callid, type, hname, &retval);
	if(ret < 0){
		LM_ERR(">>>ERR: Failed to fetch_handle in %s\n", __FUNCTION__);
		goto Err;
	}

Err:
	if(str_callid){
		mystr_free(str_callid);
		str_callid = NULL;
	}

	return 1;
}


static int fixup_param_func_store_callid(void **param, int param_no)
{
	if(param_no == 1){ 		// incallid
		return fixup_sgp(param);
	}else if(param_no == 2){ 	// outcallid
		return fixup_sgp(param);
	}else{			
		LM_ERR("####### wrong number of parameters.\n");
		return E_UNSPEC;
	}
}


static int fixup_param_func_fetch_callid(void **param, int param_no)
{
	pv_spec_t *sp;
	int ret;
	
	if(param_no == 1){ 		// onecallid
		return fixup_sgp(param);
	}else if(param_no == 2){ 	// theothercallid
		ret = fixup_pvar(param);
		if(ret < 0)return ret;
		sp = (pv_spec_t *)(*param);
		if(!pv_is_w(sp)){
			LM_ERR("######## output pvar must be writable! (given: %d)\n", pv_type(sp->type));
			return E_SCRIPT;
		}
		return 0;
	}else{			
		LM_ERR("####### wrong number of parameters.\n");
		return E_UNSPEC;
	}
}

static int fixup_param_func_store_handle(void **param, int param_no)
{
	if(param_no == 1){ 	// callid
		return fixup_sgp(param);
	}else if(param_no == 2){ // type
		return 0;
	}else if(param_no == 3){ // hname
		return 0;
	}else if(param_no == 4){ // hvalue
		return fixup_sgp(param);	
	}else{			
		LM_ERR(">>>ERR: wrong number of parameters in %s\n", __FUNCTION__);
		return E_UNSPEC;
	}
}

static int fixup_param_func_fetch_handle(void **param, int param_no)
{
	pv_spec_t *sp;
	int ret;
	
	if(param_no == 1){ // callid
		return fixup_sgp(param);
	}else if(param_no == 2){ //type
		return 0;
	}else if(param_no == 3){ //hname
		return 0;
	}else if(param_no == 4){ //hvalue
		ret = fixup_pvar(param);
		if(ret < 0)return ret;
		sp = (pv_spec_t *)(*param);
		if(!pv_is_w(sp)){
			LM_ERR(">>>ERR: output pvar must be writable! (given: %d)\n", pv_type(sp->type));
			return E_SCRIPT;
		}
		return 0;
	}else{			
		LM_ERR(">>>ERR: wrong number of parameters.\n");
		return E_UNSPEC;
	}
}

static param_export_t db_cache_params[] = {
	{"redis_host", 		STR_PARAM, &redis_host},
	{"redis_port", 		INT_PARAM, &redis_port},
	{"redis_auth", 		STR_PARAM, &redis_auth},
	{"redis_timeout", 		INT_PARAM, &redis_timeout},
	{"redis_max_socks", 		INT_PARAM, &max_redis_socks},
	{"redis_rwtimeout", 		INT_PARAM, &net_readwrite_timeout},
	{"redis_retry_delay", 		INT_PARAM, &retry_delay},
	{0,0,0}
};


static cmd_export_t cmds[] = {
	{"store_callid", (cmd_function)store_callid, 2, fixup_param_func_store_callid, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_callid", (cmd_function)fetch_callid, 2,fixup_param_func_fetch_callid,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_info", (cmd_function)store_info, 4,fixup_param_func_store_handle,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_info", (cmd_function)fetch_info, 4,fixup_param_func_fetch_handle,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{0,0,0,0,0,0}
};

/* Module interface */
struct module_exports exports = {
	"db_cache", 		/* module name */
	MOD_TYPE_DEFAULT,	/* class of this module */ 
	MODULE_VERSION,
	DEFAULT_DLFLAGS,	/* dlopen flags */
	0,			/* load function */
	NULL,			/* OpenSIPs module dependencies */
	cmds,			/* exported functions */
	0,			/* exported async functions */
	db_cache_params,	/* module parameters */
	0,			/* exported statistics */
	0,			/* exported MI functions */
	0,			/* exported pseudo-variables */
	0,			/* exported transformations */
	0,			/* extra processes */
	mod_init,		/* module initialization function */
	0,			/* response function */
	mod_destroy,			/* destroy function */
	0,			/* per-child init function */
};

static int mod_init(void)
{
	LM_DBG("initializing...\n");
	// create redis pool
	REDIS_ENDPOINT endpoint = {{0}, {0}, 6379};
	if(!redis_host || strlen(redis_host) == 0){
		LM_ERR(">>>ERR: host is NULL or empty\n");
		return -1;
	}

	size_t len = strlen(redis_host)+1;
	if(len > 256){
		LM_WARN(">>>WARNING: host is too long\n");
		len = 256;
	}
	memcpy(endpoint.host, redis_host, len);
	endpoint.host[len-1] = '\0';
	LM_DBG(">>>DBG: redis_host [%s] with size [%zu]\n", endpoint.host, len-1);

	if(!redis_auth || strlen(redis_auth) == 0){
		memset(endpoint.auth, 0x00, 1024);
		LM_WARN(">>>WARNING: auth is NULL or empty\n");
	}else{
		len = strlen(redis_auth)+1;
		if(len > 1024){
			LM_WARN(">>>WARNING: auth is too long\n");
			len = 1024;
		}
		memcpy(endpoint.auth, redis_auth, len);
		endpoint.auth[len-1] = '\0';
		LM_DBG(">>>DBG: redis_auth [%s] with size [%zu]\n", endpoint.auth, len-1);
	}
	
	if(redis_port <= 0 || redis_port > 65535){
		LM_ERR(">>>ERR: Invalid port \n");
		endpoint.port = 6379;
	}
	endpoint.port = redis_port;
	LM_DBG(">>>DBG: redis_port %d\n", endpoint.port);

	REDIS_CONFIG conf = {
		(REDIS_ENDPOINT*)&endpoint,
		1,
		redis_timeout,
		net_readwrite_timeout,
		max_redis_socks,
		retry_delay,
	};

	if(redis_pool_create(&conf, &global_inst) < 0){
		LM_ERR(">>>ERR: Failed to create redis_pool in %s\n", __FUNCTION__);
		return -1;
	}
	LM_DBG(">>>DBG: Successed to create redis pool in %s\n", __FUNCTION__);
	
	return 0;
}

void mod_destroy(void)
{
	// destroy redis pool
	if(global_inst){
		redis_pool_destroy(global_inst);
	}
}
