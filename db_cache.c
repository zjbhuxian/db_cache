/** =================================================================
 * For store/fetch information of SIP via DB sqlite3
 * Created by zhou at 2019
 * ==================================================================*/
#include "../../sr_module.h"
#include "sqlite3.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "../../mod_fix.h"
#include "../../mem/mem.h"
#include "../../pvar.h"
#include "tools.h"
#include "sem.h"

static int mod_init(void); /* Module initialization function */
void mod_destroy(void); /* Module initialization function */

static int semid = 0;
static int proj_id = 188;

void lock_handle(const char* fun);
void unlock_handle(const char* fun);

/* 
 * Module export variables 
 */
static char *db_file = 0;
const char *table_header = "tb_";

/*===================================================================================================
 * ver.1.0: store information by SIP-header-field
 *===================================================================================================*/
static int store_handle(const char *sql);
static int fetch_handle(const char *sql, char *ret);

static int store_header_field(struct sip_msg *_msg,
				const char *callid,
				const char *method, // INVITE, 180, 183, 200,...
				const char *hfname, // FROM, TO, ROUTE, SDP,...
				const char *hfcontext);	// CONTEXT of header-field to store

static int fetch_header_field(struct sip_msg *_msg,
				const char *callid,
				const char *method, // INVITE, 180, 183, 200,...
				const char *hfname, // FROM, TO, ROUTE, SDP,...
				char *hfcontext);   // CONTEXT to fetch

static int store_callid(struct sip_msg *_msg, const char *incallid, const char *outcallid);
static int fetch_callid(struct sip_msg *_msg, const char *onecallid, char *theothercallid);
static int store_sdp(struct sip_msg *_msg, const char *callid,  const char *type, const char *sdp);
static int fetch_sdp(struct sip_msg *_msg, const char *callid, const char *type, char *sdp);
static int store_route(struct sip_msg *_msg, const char *callid, const char *type, const char *route);
static int fetch_route(struct sip_msg *_msg, const char *callid, const char *type, char *route);
static int store_srcip(struct sip_msg *_msg, const char *callid, const char *type, const char *ip);
static int fetch_srcip(struct sip_msg *_msg, const char *callid, const char *type, char *ip);
static int store_destip(struct sip_msg *_msg, const char *callid,  const char *type, const char *ip);
static int fetch_destip(struct sip_msg *_msg, const char *callid, const char *type, char *ip);
static int store_from(struct sip_msg *_msg, const char *callid,  const char *type, const char *from);
static int fetch_from(struct sip_msg *_msg, const char *callid, const char *type, char *from);
static int store_to(struct sip_msg *_msg, const char *callid,  const char *type, const char *to);
static int fetch_to(struct sip_msg *_msg, const char *callid, const char *type, char *to);
static int store_pai(struct sip_msg *_msg, const char *callid,  const char *type, const char *pai);
static int fetch_pai(struct sip_msg *_msg, const char *callid, const char *type, char *pai);
static int store_bypass(struct sip_msg *_msg, const char *callid,  const char *type, const char *bypass);
static int fetch_bypass(struct sip_msg *_msg, const char *callid, const char *type, char *bypass);
static int store_pani(struct sip_msg *_msg, const char *callid,  const char *type, const char *pnai);
static int fetch_pani(struct sip_msg *_msg, const char *callid, const char *type, char *pnai);
static int store_ruser(struct sip_msg *_msg, const char *callid,  const char *type, const char *ruser);
static int fetch_ruser(struct sip_msg *_msg, const char *callid, const char *type, char *ruser);

/*======================================================================================================
 * Ver.2.0: store information by SIP-Method
 *=====================================================================================================*/ 
/* Store information of INVITE */
static int store_invite(struct sip_msg *_msg, const char *callid, const char *srcip, const char *ruri, 
			const char *from, const char *to, const char *route, const char *sdp, const char *pai, 
			const char *bypass, const char *servicetype, const char *other);
/* Store information of 180 */
static int store_180(struct sip_msg *_msg, const char *callid, const char *from, const char *to,
		     const char *sdp, const char *other);
/* Store information of 183 */
static int store_183(struct sip_msg *_msg, const char *callid, const char *from, const char *to,
		     const char *sdp, const char *other);
/* Store information of 200 */
static int store_200(struct sip_msg *_msg, const char *callid, const char *from, const char *fromtag, 
		     const char *totag, const char *to, const char *sdp, const char *other);
/* Store information of UPDATE */
static int store_update(struct sip_msg *_msg, const char *callid, const char *from, const char *to,
			const char *sdp, const char *other);
/* Fetch information from INVITE */
static int fetch_invite(struct sip_msg *_msg, const char *callid, const char *type, char *ret);
/* Fetch information from 180 */
static int fetch_180(struct sip_msg *_msg, const char *callid, const char *type, char *ret);
/* Fetch information from 183 */
static int fetch_183(struct sip_msg *_msg, const char *callid, const char *type, char *ret);
/* Fetch information from 200 */
static int fetch_200(struct sip_msg *_msg, const char *callid, const char *type, char *ret);
/* Fetch information from UPDATE */
static int fetch_update(struct sip_msg *_msg, const char *callid, const char *type, char *ret);

/**
 * Convert string to gparam_p
 */
static int fixup_param_func_store_callid(void **param, int param_no);
static int fixup_param_func_fetch_callid(void **param, int param_no);
static int fixup_param_func_store_sdp(void **param, int param_no);
static int fixup_param_func_fetch_sdp(void **param, int param_no);
static int fixup_param_func_store_invite(void **param, int param_no);
static int fixup_param_func_store_18x(void **param, int param_no);
static int fixup_param_func_store_200(void **param, int param_no);

/* SQL string for CREATE TABLE tb_callid to store relationship of incoming cal with outgoing call */
const char *sql_create_tb_callid = "CREATE TABLE IF NOT EXISTS tb_callid(incallid text, outcallid text)";

/* SQL string for CREATE TABLE tb_sdpinvite to store SDP information of INVITE */
const char *sql_create_tb_sdpinvite = "CREATE TABLE IF NOT EXISTS tb_sdpinvite(callid text primary key, sdp text)";

/* SQL string for CREATE TABLE tb_sdp183 to store SDP information of 183 */
const char *sql_create_tb_sdp183 = "CREATE TABLE IF NOT EXISTS tb_sdp183(callid text primary key, sdp text)";

/* SQL string for CREATE TABLE tb_sdp180 to store SDP information of 180 */
const char *sql_create_tb_sdp180 = "CREATE TABLE IF NOT EXISTS tb_sdp180(callid text primary key, sdp text)";

/* SQL string for CREATE TABLE tb_sdp200 to store SDP information of 200 */
const char *sql_create_tb_sdp200 = "CREATE TABLE IF NOT EXISTS tb_sdp200(callid text primary key, sdp text)";

/* SQL string for CREATE TABLE tb_routeinvite to store Route information of invite */
const char *sql_create_tb_routeinvite = "CREATE TABLE IF NOT EXISTS tb_routeinvite(callid text primary key, route text)";
const char *sql_create_tb_routecancel = "CREATE TABLE IF NOT EXISTS tb_routecancel(callid text primary key, route text)";
const char *sql_create_tb_srcipinvite = "CREATE TABLE IF NOT EXISTS tb_srcipinvite(callid text primary key, srcip text)";
const char *sql_create_tb_destipinvite = "CREATE TABLE IF NOT EXISTS tb_destipinvite(callid text primary key, destip text)";
const char *sql_create_tb_frominvite = "CREATE TABLE IF NOT EXISTS tb_frominvite(callid text primary key, _from text)";
const char *sql_create_tb_toinvite = "CREATE TABLE IF NOT EXISTS tb_toinvite(callid text primary key, _to text)";
const char *sql_create_tb_pai = "CREATE TABLE IF NOT EXISTS tb_pai(callid text primary key, pai text)";
const char *sql_create_tb_bypass = "CREATE TABLE IF NOT EXISTS tb_bypass(callid text primary key, bypass text)";
const char *sql_create_tb_pani = "CREATE TABLE IF NOT EXISTS tb_pani(callid text primary key, pani text)";
const char *sql_create_tb_ruser = "CREATE TABLE IF NOT EXISTS tb_ruser(callid text primary key, ruser text)";

/* SQL string for CREATE TABLE tb_invite to store information of INVITE */
const char *sql_create_tb_invite = "CREATE TABLE IF NOT EXISTS tb_invite(callid text primary key,	\
									 _srcip text, 			\
									 _ruri text, 			\
									 _from text, 			\
									 _to text, 			\
									 _route text, 			\
									 _sdp text, 			\
									 _pai text, 			\
									 _bypass text,	 		\
									 _servicetype text,		\
									 _other text)";

/* SQL string for CREATE TABLE tb_180 to store information of 180 message */
const char *sql_create_tb_180 = "CREATE TABLE IF NOT EXISTS tb_180(callid text primary key, 		\
								   _from text, 				\
								   _to text, 				\
								   _sdp text, 				\
								   _other text)";

/* SQL string for CREATE TABLE tb_183 to store information of 183 message */
const char *sql_create_tb_183 = "CREATE TABLE IF NOT EXISTS tb_183(callid text primary key, 		\
								   _from text, 				\
								   _to text, 				\
								   _sdp text, 				\
								   _other text)";

/* SQL string for CREATE TABLE tb_200 to store information of 200 message */
const char *sql_create_tb_200 = "CREATE TABLE IF NOT EXISTS tb_200(callid text primary key, 		\
								   _from text, 				\
								   _fromtag text,			\
								   _to text, 				\
								   _totag text,				\
								   _sdp text, 				\
								   _other text)";

/* SQL string for CREATE TABLE tb_update to store information of update message */
const char *sql_create_tb_update = "CREATE TABLE IF NOT EXISTS tb_update(callid text primary key, 	\
								   _from text, 				\
								   _to text, 				\
								   _sdp text, 				\
								   _other text)";

/* Initialize database */
static int init_db(void);

/* callback for query data from database */
static int cb_query(void *data, int argc, char **argv, char **azColName);
static int cb_query_callid(void *data, int argc, char **argv, char **azColName);

/* fixup_get_svalue */
static char *get_svalue(struct sip_msg *_msg, gparam_p _str);

char *get_svalue(struct sip_msg *_msg, gparam_p _str)
{
	char *s;
	int len;
	str s0;

	if(parse_headers(_msg, HDR_EOH_F, 0) == -1){
		LM_ERR("error while parsing message\n");
		return NULL;
	}

	if(_str){
		if(fixup_get_svalue(_msg, _str, &s0) != 0){
			LM_ERR("####### cannot print the format\n");
			return NULL;
		}
	}else{
		s0.len = 0;
		s0.s   = 0;
	}

	len = s0.len; // Not including null-termination
	s = (char *)pkg_malloc(len+1);
	if(!s){
		LM_ERR("####### no pkg memory left\n");
		return NULL;
	}

	memset(s, 0x00, len+1);
	memcpy(s, s0.s, len);
	s[len] = '\0';
	LM_INFO("###### s = [%s] with len [%d], type = [%d].\n", s,len, _str->type);

	return s;
}


int cb_query(void *data, int argc, char **argv, char **azColName)
{
	size_t len = 0;
	if(argc > 0 && argv != NULL){
		len = strlen(argv[0]);
		if(len > 0){
			memcpy(data, argv[0], len);	
			((char *)data)[len]='\0';
			LM_INFO("########## queried data [%s] with length [%zu].\n", (char *)data, len);
		}
	}
	return 0;
}

int cb_query_callid(void *data, int argc, char **argv, char **azColName)
{
	size_t len1 = 0;
	size_t len2 = 0;
	if(argc > 0 && argv != NULL){
		len1 = strlen(argv[0]);
		if(len1 > 0){
			if(((char**)data)[0] != NULL){
				memcpy(((char **)data)[0], argv[0], len1);
				((char **)data)[0][len1] = '\0';
			}	
		}
		if(argc > 1){
			len2 = strlen(argv[1]);
			if(len2 > 0){
				if(((char**)data)[1] != NULL){
					memcpy(((char **)data)[1], argv[1], len2);
					((char **)data)[1][len2] = '\0';
				}	
			}
		}
	}
	return 0;
}

int init_db(void)
{
	if(!db_file){
		LM_ERR("########## Invalid db_file\n");
		return 1;
	}

	int 	retcode;
	sqlite3 *db = 0;
	char 	*errMsg = "";

	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		sqlite3_close(db);
		LM_ERR("############ Could not open db_file [%s]\n", db_file);
		return 1;
	}	
	
	sqlite3_exec(db, sql_create_tb_callid, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_callid.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_callid, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_sdpinvite, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_sdpinvite.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_sdpinvite, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_sdp200, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_sdp200.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_sdp200, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_sdp180, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_sdp180.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_sdp180, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_sdp183, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_sdp183.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_sdp183, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_routeinvite, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_routeinvite.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_routeinvite, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_routecancel, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_routecancel.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_routecancel, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_srcipinvite, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_srcipinvite.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_srcipinvite, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_destipinvite, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_destipinvite.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_destipinvite, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_frominvite, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_frominvite.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_frominvite, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_toinvite, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_toinvite.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_toinvite, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_pai, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_pai.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_pai, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_bypass, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_bypass.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_bypass, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_pani, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_pani.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_pani, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_ruser, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_ruser.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_ruser, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_invite, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_invite.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_invite, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_180, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_180.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_180, error msg [%s].\n", errMsg);
	}
		
	sqlite3_exec(db, sql_create_tb_183, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_183.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_183, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_200, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_200.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_200, error msg [%s].\n", errMsg);
	}

	sqlite3_exec(db, sql_create_tb_update, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to create TABLE tb_update.\n");
	}else{
		LM_ERR("####### Failed to create TABLE tb_update, error msg [%s].\n", errMsg);
	}

	sqlite3_close(db);
	return 1;
}

int store_callid(struct sip_msg *_msg, const char *incallid, const char *outcallid)
{
	if(!db_file || !incallid || !outcallid){
		LM_ERR("######## Invalid parameter.\n");
		return 1;
	}
	char 	*_incallid = strlen(incallid) > 0 ? get_svalue(_msg, (gparam_p)incallid) : "";
	char 	*_outcallid = strlen(outcallid) > 0 ? get_svalue(_msg, (gparam_p)outcallid) : "";

	if(strcmp(_incallid, "")== 0 || strcmp(_outcallid, "") == 0){
		LM_ERR("Invalid parameters.\n");
		return 1;
	}

	char 	*sql = (char *)malloc(2048*sizeof(char));
	memset(sql, 0x00, 2048*sizeof(char));

	sqlite3 *db = 0;
	int 	retcode;
	char 	*errMsg = "";

	LM_INFO("######## _incallid,_outcallid = [%s,%s]\n", _incallid, _outcallid);
	sprintf(sql, "INSERT INTO tb_callid (incallid, outcallid) VALUES ('%s', '%s')", _incallid, _outcallid);
	LM_INFO("####### sql: [%s]\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("######## Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to INSERT...\n");
	}else{
		LM_ERR("####### Failed to INSERT...[%s]\n", errMsg);
	}	

Err:
	if(strlen(_incallid) > 0){
		pkg_free(_incallid);	
	}
	if(strlen(_outcallid) > 0){
		pkg_free(_outcallid);
	}
	if(sql!=NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

int fetch_callid(struct sip_msg *_msg, const char *onecallid, char *theothercallid)
{
	if(!db_file || !onecallid || !theothercallid){
		LM_ERR("####### Invalid parameters.\n");
		return 1;
	}

	sqlite3 *db = 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	pv_spec_t *sp_dest;
	pv_value_t value;
	char 	*_onecallid = strlen(onecallid) > 0 ? get_svalue(_msg, (gparam_p)onecallid) : "";

	size_t	sql_len = 2048 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	if(!sql){
		LM_ERR("############ Failed to malloc memory\n");
		return 1;
	}else{
		memset(sql, 0x00, sql_len);
	}

	size_t 	callid_len = 2048 * sizeof(char);
	char 	*data[2] = {NULL};
	char 	*pdata = NULL;
	data[0] = (char *)malloc(callid_len);
	data[1] = (char *)malloc(callid_len);
	if(!data[0] || !data[1]){
		LM_ERR("############ Failed to malloc memory\n");
		goto Err;
	}else{
		memset(data[0], 0x00, callid_len);
		memset(data[1], 0x00, callid_len);
	}

	sprintf(sql, "SELECT * FROM tb_callid WHERE incallid = '%s' or outcallid = '%s'", _onecallid, _onecallid);
	LM_INFO("######## sql: [%s]\n", sql);

	
	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("######## Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	//sqlite3_exec(db, sql, cb_query, (void*)data, &errMsg);
	sqlite3_exec(db, sql, cb_query_callid, (void*)data, &errMsg);
	if(errMsg == NULL){
		LM_INFO("####### Successed to query.\n");
	}else{
		LM_ERR("####### Failed to query [%s].\n", errMsg);
	}

	if(strcmp(_onecallid, data[0]) != 0){
		pdata = data[0];
	}else if(strcmp(_onecallid, data[1]) != 0){
		pdata = data[1];
	}else{
		LM_ERR("###### Queried data was wrong...\n");
		goto Err;
	}

	LM_INFO("######### query data [%s]\n", pdata);
	value.rs.s = pdata;
	value.rs.len = strlen(pdata);
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)theothercallid;
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR("######## failed to set fetch callid\n");
		goto Err;
	}

Err:
	if(pdata)pdata = NULL;
	if(data[0]){
		free(data[0]);
		data[0] = NULL;
	}
	if(data[1]){
		free(data[1]);
		data[1] = NULL;
	}
	if(db){
		sqlite3_close(db);
		db = 0;
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	unlock_handle(__FUNCTION__);
	return 1;
}

int store_sdp(struct sip_msg *_msg, const char *callid,  const char *type, const char *sdp)
{
	if(!db_file || !callid || !type || !sdp){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_sdp 	 = strlen(sdp) > 0 ? get_svalue(_msg, (gparam_p)sdp) : "";

	if(strcmp(_callid, "") == 0 || strcmp(_sdp, "") == 0){
		LM_ERR("Invalid parameters.\n");
		return 1;
	}

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t	sql_len = 4096 * sizeof(char);
	int 	iType 	= atoi(type);
	char *sql = (char *)malloc(sql_len);

	if(!sql){
		LM_ERR("###### Failed to malloc memory.\n");
		goto Err;
	}

	if(iType < 0 || iType > 3){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}

	memset(sql, 0x00, sql_len);
	if(iType == 0){ 	// tb_sdpinvite
		sprintf(sql, "INSERT INTO tb_sdpinvite(callid, sdp) VALUES ('%s', '%s')", _callid, _sdp);
	}else if(iType == 1){ 	// tb_sdp180
		sprintf(sql, "INSERT INTO tb_sdp180(callid, sdp) VALUES ('%s', '%s')", _callid, _sdp);
	}else if(iType == 2){	/// tb_sdp183
		sprintf(sql, "INSERT INTO tb_sdp183(callid, sdp) VALUES ('%s', '%s')", _callid, _sdp);
	}else if(iType == 3){   /// tb_sdp200
		sprintf(sql, "INSERT INTO tb_sdp200(callid, sdp) VALUES ('%s', '%s')", _callid, _sdp);
  }
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to INSERT.\n");
	}else{
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_sdp) > 0){
		pkg_free(_sdp);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

int fetch_sdp(struct sip_msg *_msg, const char *callid, const char *type, char *sdp)
{
	if(!db_file || !callid || !type || !sdp){
		LM_ERR("###### Invalid parameters.\n");
		return 1;
	}
	
	sqlite3 *db = 0;
	size_t	sql_len = 4096 * sizeof(char);
	char	*sql = (char *)malloc(sql_len);
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t 	retLen = 0;
	size_t 	sdp_len = 4096 * sizeof(char);
	char 	*data = (char *)malloc(sdp_len);
	pv_spec_t *sp_dest;
	pv_value_t value;
	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	int 	iType = atoi(type);

	if(!data || !sql){
		LM_ERR("####### Failed to malloc memory.\n");
		goto Err;
	}

	if(iType < 0 || iType > 3){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}

	memset(sql, 0x00, sql_len);
	if(iType == 0){
		sprintf(sql, "SELECT sdp FROM tb_sdpinvite WHERE callid = '%s'", _callid);
	}else if(iType == 1){
		sprintf(sql, "SELECT sdp FROM tb_sdp180 WHERE callid = '%s'", _callid);
	}else if(iType == 2){
		sprintf(sql, "SELECT sdp FROM tb_sdp183 WHERE callid = '%s'", _callid);
	}else if(iType == 3){
                sprintf(sql, "SELECT sdp FROM tb_sdp200 WHERE callid = '%s'", _callid);
        }
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	memset(data, 0x00, sdp_len);
	sqlite3_exec(db, sql, cb_query, (void*)data, &errMsg);
	if(errMsg == NULL){
		LM_INFO("##### Successed to query.\n");
	}else{
		LM_ERR("###### Failed to query [%s].\n", errMsg);
	}

	retLen = strlen(data);
	value.rs.s = data;
	value.rs.len = retLen;
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)sdp;
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR("######## failed to set fetch callid\n");
		goto Err;
	}

Err:
	if(data){
		free(data);
		data = NULL;
	}
	if(strlen(_callid) > 0){
		pkg_free(_callid);
		_callid = NULL;
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

static int store_route(struct sip_msg *_msg, const char *callid,  const char *type, const char *route)
{
	if(!db_file || !callid || !type || !route){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	sqlite3	*db 	= 0;
	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_route	 = strlen(route) > 0 ? get_svalue(_msg, (gparam_p)route) : "";

	if(strcmp(_callid, "") == 0 || strcmp(_route, "") == 0){
		LM_ERR("Invalid parameters.\n");
		return 1;
	}

	int 	retcode = 0;
	char 	*errMsg = "";
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	int 	iType 	= atoi(type);

	if(!sql){
		LM_ERR("###### Failed to malloc memory.\n");
		goto Err;
	}
	if(iType < 0 || iType > 1){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}
	
	memset(sql, 0x00, sql_len);
	if(iType == 0){ 	// tb_routeinvite
		sprintf(sql, "INSERT INTO tb_routeinvite(callid, route) VALUES ('%s', '%s')", _callid, _route);
	}else if(iType == 1){	// tb_routecancel
		sprintf(sql, "INSERT INTO tb_routecancel(callid, route) VALUES ('%s', '%s')", _callid, _route);
	}else{
		LM_ERR("###### Invalid Type[%d]\n", iType);
		goto Err;
	}
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	unlock_handle(__FUNCTION__);
	if(errMsg == NULL){
		LM_INFO("###### Successed to INSERT.\n");
	}else{
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_route) > 0){
		pkg_free(_route);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

static int fetch_route(struct sip_msg *_msg, const char *callid, const char *type, char *route)
{
	if(!db_file || !callid || !type || !route){
		LM_ERR("###### Invalid parameters.\n");
		return 1;
	}
	
	sqlite3 *db = 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t 	retLen = 0;
	pv_spec_t *sp_dest;
	pv_value_t value;
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	size_t 	route_len = 2048 * sizeof(char);
	char 	*data = (char *)malloc(route_len);
	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	int 	iType = atoi(type);

	if(!sql || !data){
		LM_ERR("####### Failed to malloc memory.\n");
		goto Err;
	}

	if(iType < 0 || iType > 2){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}

	memset(sql, 0x00, sql_len);
	if(iType == 0){
		sprintf(sql, "SELECT Route FROM tb_routeinvite WHERE callid = '%s'", _callid);
	}else if(iType == 1){
		sprintf(sql, "SELECT Route FROM tb_routecancel WHERE callid = '%s'", _callid);
	}else{
		LM_ERR("###### Invalid Type.[%d]\n", iType);
		goto Err;
	}
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	memset(data, 0x00, route_len);
	sqlite3_exec(db, sql, cb_query, (void*)data, &errMsg);
	if(errMsg == NULL){
		LM_INFO("##### Successed to query.\n");
	}else{
		LM_ERR("###### Failed to query [%s].\n", errMsg);
	}

	retLen = strlen(data);
	value.rs.s = data;
	value.rs.len = retLen;
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)route;
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR("######## failed to set fetch callid\n");
		goto Err;
	}

Err:
	if(data){
		free(data);
		data = NULL;
	}
	if(strlen(_callid) > 0){
		pkg_free(_callid);
		_callid = NULL;
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);

	return 1;
}

static int store_srcip(struct sip_msg *_msg, const char *callid,  const char *type, const char *ip)
{
	if(!db_file || !callid || !type || !ip){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_srcip	 = strlen(ip) > 0 ? get_svalue(_msg, (gparam_p)ip) : "";

	if(strcmp(_callid, "") == 0 || strcmp(_srcip, "") == 0){
		LM_ERR("Failed to store_srcip, invalid parameters.\n");
		return 1;
	}

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	int 	iType 	= atoi(type);

	if(!sql){
		LM_ERR("###### Failed to malloc memory.\n");
		goto Err;
	}
	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}
	
	// tb_srcipinvite
	memset(sql, 0x00, sql_len);
	sprintf(sql, "INSERT INTO tb_srcipinvite(callid, srcip) VALUES ('%s', '%s')", _callid, _srcip);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to INSERT.\n");
	}else{
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_srcip) > 0){
		pkg_free(_srcip);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

static int fetch_srcip(struct sip_msg *_msg, const char *callid, const char *type, char *ip)
{
	if(!db_file || !callid || !type || !ip){
		LM_ERR("###### Invalid parameters.\n");
		return 1;
	}
	
	sqlite3 *db = 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t 	retLen = 0;
	pv_spec_t *sp_dest;
	pv_value_t value;
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	size_t 	ip_len = 128 * sizeof(char);
	char 	*data = (char *)malloc(ip_len);
	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";

	if(!sql || !data){
		LM_ERR("####### Failed to malloc memory.\n");
		goto Err;
	}

	int iType = atoi(type);
	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}

	memset(sql, 0x00, sql_len);
	sprintf(sql, "SELECT srcip FROM tb_srcipinvite WHERE callid = '%s'", _callid);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	memset(data, 0x00, ip_len);
	sqlite3_exec(db, sql, cb_query, (void*)data, &errMsg);
	if(errMsg == NULL){
		LM_INFO("##### Successed to query.\n");
	}else{
		LM_ERR("###### Failed to query [%s].\n", errMsg);
	}

	retLen = strlen(data);
	value.rs.s = data;
	value.rs.len = retLen;
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)ip;
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR("######## failed to set fetch callid\n");
		goto Err;
	}

Err:
	if(data){
		free(data);
		data = NULL;
	}
	if(strlen(_callid) > 0){
		pkg_free(_callid);
		_callid = NULL;
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);

	return 1;
}

static int store_destip(struct sip_msg *_msg, const char *callid,  const char *type, const char *ip)
{
	if(!db_file || !callid || !type || !ip){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_destip = strlen(ip) > 0 ? get_svalue(_msg, (gparam_p)ip) : "";

	if(strcmp(_callid, "") == 0 || strcmp(_destip, "") == 0){
		LM_ERR("Failed to store_destip, invalid parameters.\n");
		return 1;
	}

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	int 	iType 	= atoi(type);

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}
	
	// tb_destipinvite
	memset(sql, 0x00, sql_len);
	sprintf(sql, "INSERT INTO tb_destipinvite(callid, destip) VALUES ('%s', '%s')", _callid, _destip);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to INSERT.\n");
	}else{
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_destip) > 0){
		pkg_free(_destip);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);

	return 1;
}

static int fetch_destip(struct sip_msg *_msg, const char *callid, const char *type, char *ip)
{
	if(!db_file || !callid || !type || !ip){
		LM_ERR("###### Invalid parameters.\n");
		return 1;
	}
	

	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	size_t 	ip_len = 2048;
	char 	*data = (char *)malloc(ip_len);
	sqlite3 *db = 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t 	retLen = 0;
	pv_spec_t *sp_dest;
	pv_value_t value;
	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	int 	iType = atoi(type);

	if(!sql || !data){
		LM_ERR("####### Failed to malloc memory.\n");
		goto Err;
	}

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}

	memset(sql, 0x00, sql_len);
	sprintf(sql, "SELECT destip FROM tb_destipinvite WHERE callid = '%s'", _callid);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	memset(data, 0x00, ip_len);
	sqlite3_exec(db, sql, cb_query, (void*)data, &errMsg);
	if(errMsg == NULL){
		LM_INFO("##### Successed to query.\n");
	}else{
		LM_ERR("###### Failed to query [%s].\n", errMsg);
	}

	retLen = strlen(data);
	value.rs.s = data;
	value.rs.len = retLen;
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)ip;
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR("######## failed to set fetch callid\n");
		goto Err;
	}

Err:
	if(data){
		free(data);
		data = NULL;
	}
	if(strlen(_callid) > 0){
		pkg_free(_callid);
		_callid = NULL;
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);

	return 1;
}

static int store_from(struct sip_msg *_msg, const char *callid,  const char *type, const char *from)
{
	if(!db_file || !callid || !type || !from){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_from	 = strlen(from) > 0 ? get_svalue(_msg, (gparam_p)from) : "";

	if(strcmp(_callid, "") == 0 || strcmp(_from, "") == 0){
		LM_ERR("Failed to store_from, invalid parameters.\n");
		return 1;
	}

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	int 	iType 	= atoi(type);

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}
	
	// tb_frominvite
	memset(sql, 0x00, sql_len);
	sprintf(sql, "INSERT INTO tb_frominvite(callid, _from) VALUES ('%s', '%s')", _callid, _from);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to INSERT.\n");
	}else{
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_from) > 0){
		pkg_free(_from);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);

	return 1;
}

static int fetch_from(struct sip_msg *_msg, const char *callid, const char *type, char *from)
{
	if(!db_file || !callid || !type || !from){
		LM_ERR("###### Invalid parameters.\n");
		return 1;
	}
	
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	size_t 	from_len = 2048 * sizeof(char);
	char 	*data = (char *)malloc(from_len);
	sqlite3 *db = 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t 	retLen = 0;
	pv_spec_t *sp_dest;
	pv_value_t value;
	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	int 	iType = atoi(type);

	if(!sql || !data){
		LM_ERR("####### Failed to malloc memory.\n");
		goto Err;
	}

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}

	memset(sql, 0x00, sql_len);
	sprintf(sql, "SELECT _from FROM tb_frominvite WHERE callid = '%s'", _callid);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	memset(data, 0x00, from_len);
	sqlite3_exec(db, sql, cb_query, (void*)data, &errMsg);
	if(errMsg == NULL){
		LM_INFO("##### Successed to query.\n");
	}else{
		LM_ERR("###### Failed to query [%s].\n", errMsg);
	}

	retLen = strlen(data);
	value.rs.s = data;
	value.rs.len = retLen;
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)from;
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR("######## failed to set fetch callid\n");
		goto Err;
	}

Err:
	if(data){
		free(data);
		data = NULL;
	}
	if(strlen(_callid) > 0){
		pkg_free(_callid);
		_callid = NULL;
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);

	return 1;
}

static int store_to(struct sip_msg *_msg, const char *callid,  const char *type, const char *to)
{
	if(!db_file || !callid || !type || !to){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_to	 = strlen(to) > 0 ? get_svalue(_msg, (gparam_p)to) : "";

	if(strcmp(_callid, "") == 0 || strcmp(_to, "") == 0){
		LM_ERR("Failed to store_to, invalid parameters.\n");
		return 1;
	}

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	int 	iType 	= atoi(type);

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}

	// tb_toinvite
	memset(sql, 0x00, sql_len);
	sprintf(sql, "INSERT INTO tb_toinvite(callid, _to) VALUES ('%s', '%s')", _callid, _to);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to INSERT.\n");
	}else{
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_to) > 0){
		pkg_free(_to);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

static int fetch_to(struct sip_msg *_msg, const char *callid, const char *type, char *to)
{
	if(!db_file || !callid || !type || !to){
		LM_ERR("###### Invalid parameters.\n");
		return 1;
	}
	
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	size_t 	to_len = 2048 * sizeof(char);
	char 	*data = (char *)malloc(to_len);
	sqlite3 *db = 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t 	retLen = 0;
	pv_spec_t *sp_dest;
	pv_value_t value;
	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	int 	iType = atoi(type);

	if(!sql || !data){
		LM_ERR("####### Failed to malloc memory.\n");
		goto Err;
	}

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}

	memset(sql, 0x00, sql_len);
	sprintf(sql, "SELECT _to FROM tb_toinvite WHERE callid = '%s'", _callid);
	LM_INFO("####### sql: [%s].\n", sql);


	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	memset(data, 0x00, to_len);
	sqlite3_exec(db, sql, cb_query, (void*)data, &errMsg);
	if(errMsg == NULL){
		LM_INFO("##### Successed to query.\n");
	}else{
		LM_ERR("###### Failed to query [%s].\n", errMsg);
	}

	retLen = strlen(data);
	value.rs.s = data;
	value.rs.len = retLen;
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)to;
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR("######## failed to set fetch callid\n");
		goto Err;
	}

Err:
	if(data){
		free(data);
		data = NULL;
	}
	if(strlen(_callid) > 0){
		pkg_free(_callid);
		_callid = NULL;
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);

	return 1;
}

static int store_pai(struct sip_msg *_msg, const char *callid,  const char *type, const char *pai)
{
	if(!db_file || !callid || !type || !pai){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_pai	 = strlen(pai) > 0 ? get_svalue(_msg, (gparam_p)pai) : "";

	if(strcmp(_callid, "") == 0 || strcmp(_pai, "") == 0){
		LM_ERR("Failed to store_pai, invalid parameters.\n");
		return 1;
	}

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	int 	iType 	= atoi(type);

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}
	
	// tb_pai
	memset(sql, 0x00, sql_len);
	sprintf(sql, "INSERT INTO tb_pai(callid, pai) VALUES ('%s', '%s')", _callid, _pai);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to INSERT.\n");
	}else{
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_pai) > 0){
		pkg_free(_pai);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

static int fetch_pai(struct sip_msg *_msg, const char *callid, const char *type, char *pai)
{
	if(!db_file || !callid || !type || !pai){
		LM_ERR("###### Invalid parameters.\n");
		return 1;
	}
	
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	size_t 	pai_len = 2048;
	char 	*data = (char *)malloc(pai_len);
	sqlite3 *db = 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t 	retLen = 0;
	pv_spec_t *sp_dest;
	pv_value_t value;
	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	int 	iType = atoi(type);

	if(!sql || !data){
		LM_ERR("####### Failed to malloc memory.\n");
		goto Err;
	}

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}

	memset(sql, 0x00, sql_len);
	sprintf(sql, "SELECT pai FROM tb_pai WHERE callid = '%s'", _callid);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	memset(data, 0x00, pai_len);
	sqlite3_exec(db, sql, cb_query, (void*)data, &errMsg);
	if(errMsg == NULL){
		LM_INFO("##### Successed to query.\n");
	}else{
		LM_ERR("###### Failed to query [%s].\n", errMsg);
	}

	retLen = strlen(data);
	value.rs.s = data;
	value.rs.len = retLen;
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)pai;
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR("######## failed to set fetch callid\n");
		goto Err;
	}

Err:
	if(data){
		free(data);
		data = NULL;
	}
	if(strlen(_callid) > 0){
		pkg_free(_callid);
		_callid = NULL;
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);

	return 1;
}

static int store_bypass(struct sip_msg *_msg, const char *callid,  const char *type, const char *bypass)
{
	if(!db_file || !callid || !type || !bypass){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_bypass = strlen(bypass) > 0 ? get_svalue(_msg, (gparam_p)bypass) : "";

	if(strcmp(_callid, "") == 0 || strcmp(_bypass, "") == 0){
		LM_ERR("Failed to store_bypass, invalid parameters.\n");
		return 1;
	}

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	int 	iType 	= atoi(type);

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}
	
	// tb_bypass
	memset(sql, 0x00, sql_len);
	sprintf(sql, "INSERT INTO tb_bypass(callid, bypass) VALUES ('%s', '%s')", _callid, _bypass);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to INSERT.\n");
	}else{
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_bypass) > 0){
		pkg_free(_bypass);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

static int fetch_bypass(struct sip_msg *_msg, const char *callid, const char *type, char *bypass)
{
	if(!db_file || !callid || !type || !bypass){
		LM_ERR("###### Invalid parameters.\n");
		return 1;
	}
	
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	size_t 	bypass_len = 128 * sizeof(char);
	char 	*data = (char *)malloc(bypass_len);
	sqlite3 *db = 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t 	retLen = 0;
	pv_spec_t *sp_dest;
	pv_value_t value;
	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	int 	iType = atoi(type);

	if(!sql || !data){
		LM_ERR("####### Failed to malloc memory.\n");
		goto Err;
	}

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}

	memset(sql, 0x00, sql_len);
	sprintf(sql, "SELECT bypass FROM tb_bypass WHERE callid = '%s'", _callid);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	memset(data, 0x00, bypass_len);
	sqlite3_exec(db, sql, cb_query, (void*)data, &errMsg);
	if(errMsg == NULL){
		LM_INFO("##### Successed to query.\n");
	}else{
		LM_ERR("###### Failed to query [%s].\n", errMsg);
	}

	retLen = strlen(data);
	value.rs.s = data;
	value.rs.len = retLen;
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)bypass;
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR("######## failed to set fetch callid\n");
		goto Err;
	}

Err:
	if(data){
		free(data);
		data = NULL;
	}
	if(strlen(_callid) > 0){
		pkg_free(_callid);
		_callid = NULL;
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);

	return 1;
}

static int store_pani(struct sip_msg *_msg, const char *callid,  const char *type, const char *pani)
{
	if(!db_file || !callid || !type || !pani){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_pani	 = strlen(pani) > 0 ? get_svalue(_msg, (gparam_p)pani) : "";

	if(strcmp(_callid, "") == 0 || strcmp(_pani, "") == 0){
		LM_ERR("Failed to store_pani, invalid parameters.\n");
		return 1;
	}

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	int 	iType 	= atoi(type);

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}
	
	// tb_pani
	memset(sql, 0x00, sql_len);
	sprintf(sql, "INSERT INTO tb_pani(callid, pani) VALUES ('%s', '%s')", _callid, _pani);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to INSERT.\n");
	}else{
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_pani) > 0){
		pkg_free(_pani);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

static int fetch_pani(struct sip_msg *_msg, const char *callid, const char *type, char *pani)
{
	if(!db_file || !callid || !type || !pani){
		LM_ERR("###### Invalid parameters.\n");
		return 1;
	}
	
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	size_t 	pani_len = 2048;
	char 	*data = (char *)malloc(pani_len);
	sqlite3 *db = 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t 	retLen = 0;
	pv_spec_t *sp_dest;
	pv_value_t value;
	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	int 	iType = atoi(type);

	if(!sql || !data){
		LM_ERR("####### Failed to malloc memory.\n");
		goto Err;
	}

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}

	memset(sql, 0x00, sql_len);
	sprintf(sql, "SELECT pani FROM tb_pani WHERE callid = '%s'", _callid);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	memset(data, 0x00, pani_len);
	sqlite3_exec(db, sql, cb_query, (void*)data, &errMsg);
	if(errMsg == NULL){
		LM_INFO("##### Successed to query.\n");
	}else{
		LM_ERR("###### Failed to query [%s].\n", errMsg);
	}

	retLen = strlen(data);
	value.rs.s = data;
	value.rs.len = retLen;
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)pani;
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR("######## failed to set fetch callid\n");
		goto Err;
	}

Err:
	if(data){
		free(data);
		data = NULL;
	}
	if(strlen(_callid) > 0){
		pkg_free(_callid);
		_callid = NULL;
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);

	return 1;
}

static int store_ruser(struct sip_msg *_msg, const char *callid,  const char *type, const char *ruser)
{
	if(!db_file || !callid || !type || !ruser){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_ruser = strlen(ruser) > 0 ? get_svalue(_msg, (gparam_p)ruser) : "";

	if(strcmp(_callid, "") == 0 || strcmp(_ruser, "") == 0){
		LM_ERR("Failed to store_ruser, invalid parameters.\n");
		return 1;
	}

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	int 	iType 	= atoi(type);

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}
	
	// tb_ruser
	memset(sql, 0x00, sql_len);
	sprintf(sql, "INSERT INTO tb_ruser(callid, ruser) VALUES ('%s', '%s')", _callid, _ruser);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg == NULL){
		LM_INFO("###### Successed to INSERT.\n");
	}else{
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_ruser) > 0){
		pkg_free(_ruser);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

static int fetch_ruser(struct sip_msg *_msg, const char *callid, const char *type, char *ruser)
{
	if(!db_file || !callid || !type || !ruser){
		LM_ERR("###### Invalid parameters.\n");
		return 1;
	}
	
	size_t	sql_len = 4096 * sizeof(char);
	char 	*sql = (char *)malloc(sql_len);
	size_t 	ruser_len = 2048;
	char 	*data = (char *)malloc(ruser_len);
	sqlite3 *db = 0;
	int 	retcode = 0;
	char 	*errMsg = "";
	size_t 	retLen = 0;
	pv_spec_t *sp_dest;
	pv_value_t value;
	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	int 	iType = atoi(type);

	if(!sql || !data){
		LM_ERR("####### Failed to malloc memory.\n");
		goto Err;
	}

	if(iType != 0){
		LM_ERR("###### Invalid Type.\n");
		goto Err;
	}

	memset(sql, 0x00, sql_len);
	sprintf(sql, "SELECT ruser FROM tb_ruser WHERE callid = '%s'", _callid);
	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		unlock_handle(__FUNCTION__);
		goto Err;
	}

	memset(data, 0x00, ruser_len);
	sqlite3_exec(db, sql, cb_query, (void*)data, &errMsg);
	if(errMsg == NULL){
		LM_INFO("##### Successed to query.\n");
	}else{
		LM_ERR("###### Failed to query [%s].\n", errMsg);
	}

	retLen = strlen(data);
	value.rs.s = data;
	value.rs.len = retLen;
	value.flags = PV_VAL_STR;
	sp_dest = (pv_spec_t *)ruser;
	
	if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
		LM_ERR("######## failed to set fetch callid\n");
		goto Err;
	}

Err:
	if(data){
		free(data);
		data = NULL;
	}
	if(strlen(_callid) > 0){
		pkg_free(_callid);
		_callid = NULL;
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);

	return 1;
}

//==============================================================================================================================
// store_invite
//==============================================================================================================================
static int store_invite(struct sip_msg *_msg, const char *callid, const char *srcip, const char *ruri,
			const char *from, const char *to, const char *route, const char *sdp, const char *pai,
			const char *bypass, const char *servicetype, const char *other)
{
	if(!db_file || !callid || !srcip || !ruri || !from || !to){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char	*_srcip = strlen(srcip) > 0 ? get_svalue(_msg, (gparam_p)srcip) : "";
	char	*_ruri = strlen(ruri) > 0 ? get_svalue(_msg, (gparam_p)ruri) : "";
	char 	*_from	 = strlen(from) > 0 ? get_svalue(_msg, (gparam_p)from) : "";
	char 	*_to	 = strlen(to) > 0 ? get_svalue(_msg, (gparam_p)to) : "";
	const char	*_route = route;
	const char	*_sdp = sdp;
	const char 	*_pai = pai;
	const char	*_bypass = bypass;
	const char 	*_servicetype = servicetype;
	const char 	*_other = other;

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";

	char *sql = (char *)malloc(4096*sizeof(char));
	memset(sql, 0x00, sizeof(char)*4096);

	sprintf(sql, "INSERT INTO tb_invite(callid, _srcip, _ruri, _from, _to, _route, _sdp, _pai, _bypass, _servicetype, _other)	\
			 VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')",
			_callid, _srcip, _ruri, _from, _to, _route, _sdp, _pai, _bypass, _servicetype, _other);

	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg != NULL){
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_srcip) > 0){
		pkg_free(_srcip);
	}
	if(strlen(_ruri) > 0){
		pkg_free(_ruri);
	}
	if(strlen(_from) > 0){
		pkg_free(_from);
	}
	if(strlen(_to) > 0){
		pkg_free(_to);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

//============================================================================================================================
//static int fetch_invite(struct sip_msg *_msg, const char *db_file, const char *callid, const char *type, char *ret);
//============================================================================================================================
static int fetch_invite(struct sip_msg *_msg, const char *callid, const char *type, char *ret)
{
	return 1;
}

static int store_180(struct sip_msg *_msg, const char *callid, const char *from, const char *to,
		     const char *sdp, const char *other)
{
	if(!db_file || !callid || !from || !to){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_from	 = strlen(from) > 0 ? get_svalue(_msg, (gparam_p)from) : "";
	char 	*_to	 = strlen(to) > 0 ? get_svalue(_msg, (gparam_p)to) : "";
	const char	*_sdp = sdp;
	const char 	*_other = other;

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";

	char *sql = (char *)malloc(4096*sizeof(char));
	memset(sql, 0x00, sizeof(char)*4096);

	sprintf(sql, "INSERT INTO tb_180(callid, _from, _to, _sdp, _other)	\
			 VALUES ('%s', '%s', '%s', '%s', '%s')",
			_callid, _from, _to, _sdp, _other);

	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg != NULL){
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_from) > 0){
		pkg_free(_from);
	}
	if(strlen(_to) > 0){
		pkg_free(_to);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

//============================================================================================================================
//static int fetch_180(struct sip_msg *_msg, const char *db_file, const char *callid, const char *type, char *ret);
//============================================================================================================================
static int fetch_180(struct sip_msg *_msg, const char *callid, const char *type, char *ret)
{
	return 1;
}

//============================================================================================================================
//static int store_183(struct sip_msg *_msg, const char *db_file, const char *callid, const char *from, const char *to,
//		     const char *sdp, const char *other);
//============================================================================================================================
static int store_183(struct sip_msg *_msg, const char *callid, const char *from, const char *to,
		     const char *sdp, const char *other)
{
	if(!db_file || !callid || !from || !to){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_from	 = strlen(from) > 0 ? get_svalue(_msg, (gparam_p)from) : "";
	char 	*_to	 = strlen(to) > 0 ? get_svalue(_msg, (gparam_p)to) : "";
	const char	*_sdp = sdp;
	const char 	*_other = other;

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";

	char *sql = (char *)malloc(4096*sizeof(char));
	memset(sql, 0x00, sizeof(char)*4096);

	sprintf(sql, "INSERT INTO tb_183(callid, _from, _to, _sdp, _other)	\
			 VALUES ('%s', '%s', '%s', '%s', '%s')",
			_callid, _from, _to, _sdp, _other);

	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg != NULL){
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_from) > 0){
		pkg_free(_from);
	}
	if(strlen(_to) > 0){
		pkg_free(_to);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

//============================================================================================================================
//static int fetch_183(struct sip_msg *_msg, const char *db_file, const char *callid, const char *type, char *ret);
//============================================================================================================================
static int fetch_183(struct sip_msg *_msg, const char *callid, const char *type, char *ret)
{
	return 1;
}

static int store_200(struct sip_msg *_msg, const char *callid, const char *from, const char *fromtag, 
		     const char *to, const char *totag, const char *sdp, const char *other)
{
	if(!db_file || !callid || !from || !fromtag || !to){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_from	 = strlen(from) > 0 ? get_svalue(_msg, (gparam_p)from) : "";
	char 	*_fromtag	 = strlen(fromtag) > 0 ? get_svalue(_msg, (gparam_p)fromtag) : "";
	char 	*_to	 = strlen(to) > 0 ? get_svalue(_msg, (gparam_p)to) : "";
	char 	*_totag	 = strlen(totag) > 0 ? get_svalue(_msg, (gparam_p)totag) : "";
	const char	*_sdp = sdp;
	const char 	*_other = other;

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";

	char *sql = (char *)malloc(4096*sizeof(char));
	memset(sql, 0x00, sizeof(char)*4096);

	sprintf(sql, "INSERT INTO tb_200(callid, _from, _fromtag, _to, _totag, _sdp, _other)	\
			 VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s')",
			_callid, _from, _fromtag, _to, _totag, _sdp, _other);

	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg != NULL){
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_from) > 0){
		pkg_free(_from);
	}
	if(strlen(_fromtag) > 0){
		pkg_free(_fromtag);
	}
	if(strlen(_to) > 0){
		pkg_free(_to);
	}
	if(strlen(_totag) > 0){
		pkg_free(_totag);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}


//============================================================================================================================
//static int fetch_200(struct sip_msg *_msg, const char *db_file, const char *callid, const char *type, char *ret);
//============================================================================================================================
static int fetch_200(struct sip_msg *_msg, const char *callid, const char *type, char *ret)
{
	return 1;
}

static int store_update(struct sip_msg *_msg, const char *callid, const char *from, const char *to,
			const char *sdp, const char *other)
{
	if(!db_file || !callid || !from || !to){
		LM_ERR("###### Invalid parameters\n");
		return -1;
	}

	char 	*_callid = strlen(callid) > 0 ? get_svalue(_msg, (gparam_p)callid) : "";
	char 	*_from	 = strlen(from) > 0 ? get_svalue(_msg, (gparam_p)from) : "";
	char 	*_to	 = strlen(to) > 0 ? get_svalue(_msg, (gparam_p)to) : "";
	const char	*_sdp = sdp;
	const char 	*_other = other;

	sqlite3	*db 	= 0;
	int 	retcode = 0;
	char 	*errMsg = "";

	char *sql = (char *)malloc(4096*sizeof(char));
	memset(sql, 0x00, sizeof(char)*4096);

	sprintf(sql, "INSERT INTO tb_update(callid, _from, _to, _sdp, _other)	\
			 VALUES ('%s', '%s', '%s', '%s', '%s')",
			_callid, _from, _to, _sdp, _other);

	LM_INFO("####### sql: [%s].\n", sql);

	lock_handle(__FUNCTION__);
	retcode = sqlite3_open(db_file, &db);
	if(retcode != SQLITE_OK){
		LM_ERR("###### Could not open db_file [%s].\n", db_file);
		goto Err;
	}

	sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if(errMsg != NULL){
		LM_ERR("###### Failed to INSERT [%s].\n", errMsg);
	}

Err:
	if(strlen(_callid) > 0){
		pkg_free(_callid);
	}
	if(strlen(_from) > 0){
		pkg_free(_from);
	}
	if(strlen(_to) > 0){
		pkg_free(_to);
	}
	if(sql != NULL){
		free(sql);
		sql = NULL;
	}
	sqlite3_close(db);
	unlock_handle(__FUNCTION__);
	return 1;
}

//============================================================================================================================
//static int fetch_update(struct sip_msg *_msg, const char *db_file, const char *callid, const char *type, char *ret);
//============================================================================================================================
static int fetch_update(struct sip_msg *_msg, const char *callid, const char *type, char *ret)
{
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

static int fixup_param_func_store_sdp(void **param, int param_no)
{
	if(param_no == 1){ 	// callid
		return fixup_sgp(param);
	}else if(param_no == 2){ // type
		return 0;
	}else if(param_no == 3){ // sdp
		return fixup_sgp(param);	
	}else{			
		LM_ERR("####### wrong number of parameters.\n");
		return E_UNSPEC;
	}
}

static int fixup_param_func_fetch_sdp(void **param, int param_no)
{
	pv_spec_t *sp;
	int ret;
	
	if(param_no == 1){ // callid
		return fixup_sgp(param);
	}else if(param_no == 2){ //type
		return 0;
	}else if(param_no == 3){ // sdp
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

static int fixup_param_func_store_invite(void **param, int param_no)
{
	if(param_no == 1){ // callid
		return fixup_sgp(param);
	}else if(param_no == 2){ // srcip
		return fixup_sgp(param);
	}else if(param_no == 3){ // ruri
		return fixup_sgp(param);
	}else if(param_no == 4){ // from
		return fixup_sgp(param);
	}else if(param_no == 5){ // to
		return fixup_sgp(param);
	}else if(param_no == 6 || param_no == 7 || param_no == 8 || param_no == 9 || param_no == 10 || param_no == 11){ // route,sdp,pai,bypass,servicetype,other
		return 0;
	}else{			
		LM_ERR("####### wrong number of parameters.\n");
		return E_UNSPEC;
	}
}

static int fixup_param_func_store_18x(void **param, int param_no)
{
	if(param_no == 1){ // callid
		return fixup_sgp(param);
	}else if(param_no == 2){ // from
		return fixup_sgp(param);
	}else if(param_no == 3){ // to
		return fixup_sgp(param);
	}else if(param_no == 4 || param_no == 5){ // sdp,other
		return 0;
	}else{			
		LM_ERR("####### wrong number of parameters.\n");
		return E_UNSPEC;
	}
}

static int fixup_param_func_store_200(void **param, int param_no)
{
	if(param_no == 1){ // callid
		return fixup_sgp(param);
	}else if(param_no == 2){ // from
		return fixup_sgp(param);
	}else if(param_no == 3){ // fromtag
		return fixup_sgp(param);
	}else if(param_no == 4){ // to
		return fixup_sgp(param);
	}else if(param_no == 5){ // totag
		return fixup_sgp(param);
	}else if(param_no == 6 || param_no == 7){ // sdp,other
		return 0;
	}else{			
		LM_ERR("####### wrong number of parameters.\n");
		return E_UNSPEC;
	}
}

static param_export_t db_cache_params[] = {
	{"db_file", 		STR_PARAM, &db_file},
	{0,0,0}
};


static cmd_export_t cmds[] = {
	{"store_callid", (cmd_function)store_callid, 2, fixup_param_func_store_callid, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_callid", (cmd_function)fetch_callid, 2,fixup_param_func_fetch_callid,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_sdp", (cmd_function)store_sdp, 3,fixup_param_func_store_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_sdp", (cmd_function)fetch_sdp, 3,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_route", (cmd_function)store_route, 3,fixup_param_func_store_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_route", (cmd_function)fetch_route, 3,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_srcip", (cmd_function)store_srcip, 3,fixup_param_func_store_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_srcip", (cmd_function)fetch_srcip, 3,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_destip", (cmd_function)store_destip, 3,fixup_param_func_store_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_destip", (cmd_function)fetch_destip, 3,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_from", (cmd_function)store_from, 3,fixup_param_func_store_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_from", (cmd_function)fetch_from, 3,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_to", (cmd_function)store_to, 3,fixup_param_func_store_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_to", (cmd_function)fetch_to, 3,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_pai", (cmd_function)store_pai, 3,fixup_param_func_store_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_pai", (cmd_function)fetch_pai, 3,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_bypass", (cmd_function)store_bypass, 3,fixup_param_func_store_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_bypass", (cmd_function)fetch_bypass, 3,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_pani", (cmd_function)store_pani, 3,fixup_param_func_store_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_pani", (cmd_function)fetch_pani, 3,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_ruser", (cmd_function)store_ruser, 3,fixup_param_func_store_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_ruser", (cmd_function)fetch_ruser, 3,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},

	{"store_invite", (cmd_function)store_invite, 11,fixup_param_func_store_invite,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	//{"fetch_invite", (cmd_function)fetch_invite, 4,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_180", (cmd_function)store_180, 5,fixup_param_func_store_18x,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	//{"fetch_180", (cmd_function)fetch_180, 4,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_183", (cmd_function)store_183, 5,fixup_param_func_store_18x,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	//{"fetch_183", (cmd_function)fetch_183, 4,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_200", (cmd_function)store_200, 7,fixup_param_func_store_200,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	//{"fetch_200", (cmd_function)fetch_200, 4,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_update", (cmd_function)store_update, 5,fixup_param_func_store_18x,0, REQUEST_ROUTE|ONREPLY_ROUTE},
	//{"fetch_update", (cmd_function)fetch_update, 4,fixup_param_func_fetch_sdp,0, REQUEST_ROUTE|ONREPLY_ROUTE},
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

void lock_handle(const char* fun){
	LM_INFO("P...in [%s]\n", fun);
	sem_p(semid);
}

void unlock_handle(const char* fun){
	LM_INFO("V...in [%s]\n", fun);
	sem_v(semid);
}

static int mod_init(void)
{
	LM_INFO("initializing...\n");
	init_db();

	semid = sem_init(proj_id);
	if(semid == -1){
		LM_ERR("Failed to create semid\n");
	}
	return 0;
}

void mod_destroy(void)
{
	sem_destroy(semid);
}
