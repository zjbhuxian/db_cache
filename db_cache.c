/**==============================================================================================
 * store/fetch module for opensips
 * created at 2019.11
 * =============================================================================================*/
#include <stdio.h>
#include <string.h>
#include "../../db/db.h"
#include "../../str.h"
#include "../../sr_module.h"
#include "../../mod_fix.h"
#include "../../msg_translator.h"
#include "../../parser/parse_content.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_pai.h"
#include "db_cache.h"

#define EMPTY_STR(val) val.s=""; val.len=0;

#define SIP_TABLE				"sip_info"
#define CALLID_TABLE		"callid_info"
#define NR_KEYS_SIP				12
#define NR_KEYS_CALLID		2	

#define CALLID_COL			"call_id"
#define SIPNAME_COL			"sip_name"
#define SRCIP_COL				"src_ip"
#define RURI_COL				"r_uri"
#define RUSER_COL				"r_user"
#define FROMURI_COL			"from_uri"
#define TOURI_COL				"to_uri"
#define ROUTE_COL				"route"
#define SDP_COL					"sdp"
#define PAI_COL					"pai"
#define PANI_COL				"pani"
#define OTHER_COL				"other"

#define INCALLID_COL		"in_callid"
#define OUTCALLID_COL		"out_callid"

static str db_url = STR_NULL;
static str sip_table = STR_NULL;
static str callid_table = STR_NULL;

/*! \brief sip_table
 * Columns of sip_table;
 */
static str callid_column = str_init(CALLID_COL);
static str sipname_column = str_init(SIPNAME_COL);
static str srcip_column = str_init(SRCIP_COL);
static str ruri_column = str_init(RURI_COL);
static str ruser_column = str_init(RUSER_COL);
static str fromuri_column = str_init(FROMURI_COL);
static str touri_column = str_init(TOURI_COL);
static str route_column = str_init(ROUTE_COL);
static str sdp_column = str_init(SDP_COL);
static str pai_column = str_init(PAI_COL);
static str pani_column = str_init(PANI_COL);
static str other_column = str_init(OTHER_COL);

/*! \brief callid_table
 * Columns of callid_table
 */
static str incallid_column = str_init(INCALLID_COL);
static str outcallid_column = str_init(OUTCALLID_COL);

/*! \brief Database functions
 * init/close
 */
static db_con_t* db_init(const str* db_url);
static void db_close(db_con_t* dbh);
//static void free_res(db_res_t* res);

/*! \brief
 * Fixup parameters
 */
static int fixup_param_func_store_test(void** param, int param_no);
static int fixup_param_func_store_callid(void** param, int param_no);
static int fixup_param_func_fetch_callid(void** param, int param_no);
static int fixup_param_func_store_sip(void** param, int param_no);
static int fixup_param_func_fetch(void** param, int param_no);

/*! \brief
 * Module init/destory
 */
static int mod_init(void);
static void destroy(void);

/*! \brief
 * For test
 */
static int store_fetch_test_f(struct sip_msg* _msg, const char* pvk, char* pvv, const char* num);

/*! \brief 
 * Handle process for storing/fetching
 */
static int store_handle(str* table, db_key_t* keys, db_val_t* vals, int num_keys);
static int fetch_column(struct sip_msg* _msg, str* column, const char* callid, const char* sip_name, char* result);
static int fetch_handle(str* table, db_con_t* db_con, db_key_t* keys, db_op_t* ops, db_val_t* vals, db_key_t* cs, int n, int nc, db_res_t** res);

/*! \brief
 * Fixup values for storing
 */
static int fixup_callid_values(str* sin, str* sout, void** pval);
static int set_output_val(struct sip_msg* _msg, db_res_t* res, char* ret);

/*! \brief
 *  Exported functions
 */
static int store_callid(struct sip_msg* _msg, const char* incallid, const char* outcallid);
static int fetch_callid(struct sip_msg* _msg, const char* callid, const char* type, char* theothercallid);
static int store_sip(struct sip_msg* _msg, const char* src_ip, const char* route, const char* sdp, const char* pani, const char* other);
static int fetch_route(struct sip_msg* _msg, const char* callid, const char* sip_name, char* route);
static int fetch_pai(struct sip_msg* _msg, const char* callid, const char* sip_name, char* pai);
static int fetch_pani(struct sip_msg* _msg, const char* callid, const char* sip_name, char* pani);
static int fetch_ruser(struct sip_msg* _msg, const char* callid, const char* sip_name, char* ruser);
static int fetch_from(struct sip_msg* _msg, const char* callid, const char* sip_name, char* result);
static int fetch_to(struct sip_msg* _msg, const char* callid, const char* sip_name, char* result);
static int fetch_sdp(struct sip_msg* _msg, const char* callid, const char* sip_name, char* result);
static int fetch_other(struct sip_msg* _msg, const char* callid, const char* sip_name, char* result);

db_func_t db_funcs;	/* Database functions */
db_key_t db_keys_sip[NR_KEYS_SIP];
db_key_t db_keys_callid[NR_KEYS_CALLID];

/*! \brief
 *  Exported parameters
 */
static param_export_t params[] = {
	{"db_url", STR_PARAM, &db_url.s	},
	{"sip_table", STR_PARAM, &sip_table.s	},
	{"callid_table", STR_PARAM, &callid_table.s	},
	{0,0,0}
};

static cmd_export_t cmds[] = {
	{"store_fetch_test", (cmd_function)store_fetch_test_f, 3, fixup_param_func_store_test, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_callid", (cmd_function)store_callid, 2, fixup_param_func_store_callid, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_callid", (cmd_function)fetch_callid, 3, fixup_param_func_fetch_callid, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_sip_info", (cmd_function)store_sip, 0, 0, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_sip_info", (cmd_function)store_sip, 1, fixup_param_func_store_sip, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_sip_info", (cmd_function)store_sip, 2, fixup_param_func_store_sip, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_sip_info", (cmd_function)store_sip, 3, fixup_param_func_store_sip, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_sip_info", (cmd_function)store_sip, 4, fixup_param_func_store_sip, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"store_sip_info", (cmd_function)store_sip, 5, fixup_param_func_store_sip, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_route", (cmd_function)fetch_route, 3, fixup_param_func_fetch, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_pai", (cmd_function)fetch_pai, 3, fixup_param_func_fetch, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_pani", (cmd_function)fetch_pani, 3, fixup_param_func_fetch, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_ruser", (cmd_function)fetch_ruser, 3, fixup_param_func_fetch, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_from", (cmd_function)fetch_from, 3, fixup_param_func_fetch, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_to", (cmd_function)fetch_to, 3, fixup_param_func_fetch, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_sdp", (cmd_function)fetch_sdp, 3, fixup_param_func_fetch, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"fetch_other", (cmd_function)fetch_other, 3, fixup_param_func_fetch, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
	"db_cache",
	MOD_TYPE_DEFAULT,/*!< class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /*!< dlopen flags */
	0,				 /*!< load function */
	0,           /*!< OpenSIPS module dependencies */
	cmds,       /*!< Exported functions */
	0,          /*!< Exported async functions */
	params,     /*!< Export parameters */
	0,  /*!< exported statistics */
	0,    /*!< exported MI functions */
	0,          /*!< exported pseudo-variables */
	0,          /*!< exported transformations */
	0,          /*!< extra processes */
	mod_init,   /*!< Module initialization function */
	0,          /*!< Response function */
	destroy,    /*!< Destroy function */
	0  /*!< Child initialization function */
};

static int mod_init(void)
{
	LM_INFO("Module db_cache loaded.\n");

	/* init db keys_sip */
	db_keys_sip[0] = &callid_column;
	db_keys_sip[1] = &sipname_column;
	db_keys_sip[2] = &srcip_column;
	db_keys_sip[3] = &ruri_column;
	db_keys_sip[4] = &ruser_column;
	db_keys_sip[5] = &fromuri_column;
	db_keys_sip[6] = &touri_column;
	db_keys_sip[7] = &route_column;
	db_keys_sip[8] = &sdp_column;
	db_keys_sip[9] = &pai_column;
	db_keys_sip[10] = &pani_column;
	db_keys_sip[11] = &other_column;

	/* init db_keys_callid */
	db_keys_callid[0] = &incallid_column;
	db_keys_callid[1] = &outcallid_column;

	db_url.len = strlen(db_url.s);
	if(db_url.s && db_url.len){
		/* Find a database module */
		if(db_bind_mod(&db_url, &db_funcs)){
			LM_ERR("Unable to bind database module\n");
			return -1;
		}

		/* Check db capabilities */
		if(!DB_CAPABILITY(db_funcs, DB_CAP_QUERY)){
			LM_ERR("Database modules does not provide all functions needed.\n");
			return -1;
		}
		if(!DB_CAPABILITY(db_funcs, DB_CAP_INSERT)){
			LM_ERR("Database modules does not provide all functions needed.\n");
			return -1;
		}
		if(!DB_CAPABILITY(db_funcs, DB_CAP_DELETE)){
			LM_ERR("Database modules does not provide all functions needed.\n");
			return -1;
		}
		if(!DB_CAPABILITY(db_funcs, DB_CAP_UPDATE)){
			LM_ERR("Database modules does not provide all functions needed.\n");
			return -1;
		}
		if(!DB_CAPABILITY(db_funcs, DB_CAP_REPLACE)){
			LM_ERR("Database modules does not provide all functions needed.\n");
			return -1;
		}
		if(!DB_CAPABILITY(db_funcs, DB_CAP_FETCH)){
			LM_ERR("Database modules does not provide all functions needed.\n");
			return -1;
		}
		if(!DB_CAPABILITY(db_funcs, DB_CAP_MULTIPLE_INSERT)){
			LM_ERR("Database modules does not provide all functions needed.\n");
			return -1;
		}
	}else{
		LM_ERR("db_url is not defined or empty.\n");
		return -1;
	}

	/* Check the sip_table */
	sip_table.len = strlen(sip_table.s);
	if(!sip_table.len){
		LM_ERR("sip_table is not defined or empty.\n");
		return -1;
	}

	callid_table.len = strlen(callid_table.s);
	if(!callid_table.len){
		LM_ERR("callid_table is not defined or empty.\n");
		return -1;
	}

	return 0;
}

static void destroy(void)
{
	// Nothing
}

static db_con_t* db_init(const str* db_url)
{
	if(!db_url || db_url->s == NULL || strcmp(db_url->s, "")==0 || db_url->len == 0){
		LM_ERR("Failed to db_init in db_cache: db_url is NULL.\n");
	}

	if(db_funcs.init == 0){
		LM_CRIT("Null database functions...\n");
		goto Err;
	}

	db_con_t* db_con = db_funcs.init(db_url);
	if(!db_con){
		LM_ERR("Unable to connect database.\n");
		goto Err;
	}

	return db_con;

Err:
	return NULL;
}

static void db_close(db_con_t* db_con)
{
	if(db_con && db_funcs.close){
		//db_funcs.close(db_con);
		//db_con = 0;
	}
}

static int fixup_param_func_store_test(void** param, int param_no)
{
	switch(param_no){
		case 1:
		case 2:
			return fixup_spve(param);
		case 3:
			return 0;
		default:
			LM_ERR("Uknown parameter.\n");
			return E_UNSPEC;
	}
}

static int fixup_param_func_store_callid(void** param, int param_no)
{
	switch(param_no){
		case 1:
		case 2:
			return fixup_sgp(param);
		default:
			LM_ERR("Wrong number of parameter.\n");
			return E_UNSPEC;
	}
}
static int fixup_param_func_fetch_callid(void** param, int param_no)
{
	pv_spec_t* sp;
	switch(param_no){
		case 1:
			return fixup_sgp(param);
		case 2:
			return 0;
		case 3:
			if(fixup_pvar(param) < 0){
				LM_ERR("Failed to fix pvar.\n");
				return -1;
			}
			sp = (pv_spec_t*)(*param);
			if(!pv_is_w(sp)){
				LM_ERR("Output pvar must be writable! (given:%d)\n", pv_type(sp->type));
				return E_SCRIPT;
			}
			return 0;
		default:
			LM_ERR("Wrong number of parameter.\n");
			return E_UNSPEC;
	}
}
static int fixup_param_func_store_sip(void** param, int param_no)
{
	switch(param_no){
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
			return fixup_sgp(param);
		default:
			LM_ERR("Wrong number of parameter.\n");
			return E_UNSPEC;
	}
}
static int fixup_param_func_fetch(void** param, int param_no)
{
	pv_spec_t* sp;
	switch(param_no){
		case 1:
			return fixup_sgp(param);
		case 2:
			return 0;
		case 3:
			if(fixup_pvar(param) < 0){
				LM_ERR("Failed to fixup_pvar...\n");
				return -1;
			}
			sp = (pv_spec_t*)(*param);
			if(!pv_is_w(sp)){
				LM_ERR("Output pvar must be writable! (given:%d)\n", pv_type(sp->type));
				return E_SCRIPT;
			}
			return 0;
		default:
			LM_ERR("Wrong number of parameter.\n");
			return E_UNSPEC;
	}
}

static int fixup_callid_values(str* sin, str* sout, void**pval)
{
	if(!sin || !sout || !pval){
		LM_ERR("Invalid parameters.\n");
		return -1;
	}

	size_t size = sizeof(db_val_t) * NR_KEYS_CALLID;
	db_val_t* pval_tmp = NULL;
	pval_tmp = (db_val_t*)pkg_malloc(size);
	if(!pval_tmp){
		LM_ERR("Failed to malloc memory.\n");
		return -1;
	}

	memset(pval_tmp, 0, size);
	pval_tmp[0].type = DB_STR;
	pval_tmp[0].val.str_val = *sin;
	pval_tmp[0].nul = 0;

	pval_tmp[1].type = DB_STR;
	pval_tmp[1].val.str_val = *sout;

	*pval = (void*)pval_tmp;

	return 0;
}

static int set_output_val(struct sip_msg* _msg, db_res_t* res, char* ret)
{
	if(!res || !ret){
		LM_ERR("Invalid parameters in set_output_val.\n");
		return -1;
	}

	int i;
	for(i = 0; i < RES_COL_N(res); ++i){
		LM_INFO("@@@@@ %s ", RES_NAMES(res)[i]->s);
	}

	pv_spec_t* sp_dest;
	pv_value_t value;
	size_t len;

	if(RES_ROW_N(res) > 0){
		if(RES_COL_N(res) > 0){
			if(RES_ROWS(res)[0].values[0].nul != 1){
				LM_INFO("@@@@@@@@@ !!!!! [%s]\n", RES_ROWS(res)[0].values[0].val.string_val);
				len = strlen(RES_ROWS(res)[0].values[0].val.string_val);
				if(len > 0){
					// warning: assignment discards 'const' qualifier from pointer target type
					value.rs.s = strndup(RES_ROWS(res)[0].values[0].val.string_val, len); // need free manually???? 
					value.rs.len = len;
					value.flags = PV_VAL_STR;
					sp_dest = (pv_spec_t*)ret;

					if(pv_set_value(_msg, sp_dest, 0, &value) != 0){
						LM_ERR("Failed to set_output_val.\n");
						return -1;
					}
				}
				//switch(RES_ROWS(res)[0].values[0].type){
				//	case DB_STRING:
				//		LM_INFO("@@@@@@@@@ !!!!! [%s]\n", RES_ROWS(res)[0].values[0].val.string_val);
				//		break;
				//	case DB_STR:
				//		LM_INFO("@@@@@@@@@ !!!!! [%s]\n", RES_ROWS(res)[0].values[0].val.str_val.s);
				//		break;
				//}
			}
		}
	}

	return 0;
}

static int store_handle(str* table, db_key_t* keys, db_val_t* vals, int num_keys)
{
	if(!table || !keys || !vals || num_keys == 0){
		LM_ERR("Invalid parameters.\n");
		return -1;
	}

	db_con_t* db_con = db_init(&db_url);
	if(!db_con){
		LM_ERR("Failed to db_init.\n");
		return -1;
	}
	LM_DBG("Get db_con [%p] in store_handle.\n", db_con);

	// use table
	if(db_funcs.use_table(db_con, table) < 0){
		LM_ERR("Failed to use_table [%s].\n", table->s);
		goto Err;
	}

	// execute
	if(db_funcs.insert(db_con, keys, vals, num_keys) < 0){
		LM_ERR("Failed to insert...\n");
		goto Err;
	}
	
	if(db_con){
		db_close(db_con);
		db_con = NULL;
	}
	return 0;
	
Err:
	if(db_con){
		LM_DBG("Release db_con [%p] in store_handle.\n", db_con);
		db_close(db_con);
		db_con = NULL;
	}
	return -1;
}

static int fetch_handle(str* table, db_con_t* db_con, db_key_t* keys, db_op_t* ops, db_val_t* vals, db_key_t* cs, int n, int nc, db_res_t** res)
{
	if(!table || !keys || !vals || !cs || n == 0 || nc == 0 || !res){
		LM_ERR("Invalid parameters.\n");
		return -1;
	}

	/*
	 * DEBUG PRINT
	*/
	int i;
	LM_DBG("fetch_handle, table=[%.*s]\n", table->len, table->s);
	for(i = 0; i < n; ++i){
		LM_DBG("fetch_handle, keys[%d] = [%.*s] = [%.*s]\n", i, keys[i]->len, keys[i]->s, vals[i].val.str_val.len, vals[i].val.str_val.s);
	}
	for(i = 0; i < nc; ++i){
		LM_DBG("fetch_handle, cs[%d] = [%.*s]\n", i, cs[i]->len, cs[i]->s);
	}

	// use table
	if(db_funcs.use_table(db_con, table) < 0){
		LM_ERR("Failed to use_table [%s]\n", table->s);
		goto Err;
	}

	// execute
	if(db_funcs.query(db_con, keys, ops, vals, cs, n, nc, NULL, res) < 0){
		LM_ERR("Failed to query.\n");
		goto Err;
	}
	LM_DBG("fetch_handle: RES_ROW_N(*res) = [%d]\n", RES_ROW_N(*res));
	return 0;

Err:
	return -1;
}

/*! \brief
 * Test functions
 */
static int store_fetch_test_f(struct sip_msg* _msg, const char* pvk, char* pvv, const char* num)
{
	if(!pvk || !pvv || !num){
		return -1;
	}

	str spvk;
	if(fixup_get_svalue(_msg, (gparam_p)pvk, &spvk) < 0){
		LM_ERR("Bad value for 'pvk'\n");
		return -1;
	}else{
		LM_INFO("(gparam_p)pvk->type = [%d]\n", ((gparam_p)pvk)->type); 
	}

	LM_INFO("pvk.s = [%s]\n", spvk.s);

	return 1;

}

static int store_callid(struct sip_msg* _msg, const char* incallid, const char* outcallid)
{
	if(!incallid || !outcallid){
		LM_ERR("Invalid parameters.\n");
		return 1;
	}

	str sin, sout;
	db_val_t* pvals = NULL;
	int ret = 0;
	if(fixup_get_svalue(_msg, (gparam_p)incallid, &sin) < 0){
		LM_ERR("Bad value for 'incallid'\n");
		goto End;
	}
	if(fixup_get_svalue(_msg, (gparam_p)outcallid, &sout) < 0){
		LM_ERR("Bad value for 'outcallid'\n");
		goto End;
	}

	// fixup_vals
	ret = fixup_callid_values(&sin, &sout, (void**)&pvals);
	if(ret < 0){
		LM_ERR("Failed to fixup callid values.\n");
		goto End;
	}

	ret = store_handle(&callid_table, db_keys_callid, pvals, NR_KEYS_CALLID);
	if(ret < 0){
		LM_ERR("Failed to store_handle_callid.\n");
		goto End;
	}

End:
	if(pvals){
		pkg_free(pvals);
		pvals = NULL;
	}
	return 1;
}

static int fetch_callid(struct sip_msg* _msg, const char* callid, const char* type, char* outputcallid)
{
	if(!callid || !type || !outputcallid){
		LM_ERR("Invalid parameters.\n");
		return 1;
	}

	int ret = 0;
	str scallid;
	int iType = atoi(type);
	db_con_t* db_con = NULL;

	db_key_t keys[1];
	db_op_t* ops = NULL;
	db_val_t vals[1];
	db_key_t cs[1];
	int n=1, nc = 1;
	db_res_t* res = NULL;

	if(iType < 0 || iType > 1){
		LM_ERR("Invalid type.\n");
		goto Err;
	}

	if(fixup_get_svalue(_msg, (gparam_p)callid, &scallid) < 0){
		LM_ERR("Bad value for 'incallid'\n");
		goto Err;
	}

	switch(iType){
		case 0:// fetch in_callid
			keys[0] = &outcallid_column;
			cs[0] = &incallid_column;
			break;
		case 1:// fetch out_callid
			keys[0] = &incallid_column;
			cs[0] = &outcallid_column;
			break;
		default:
			break;
	}
	vals[0].type = DB_STR;
	vals[0].val.str_val = scallid;

	db_con = db_init(&db_url);
	if(!db_con){
		LM_ERR("Failed to db_init.\n");
		goto Err;
	}
	LM_DBG("Get db_con [%p] in fetch_callid.\n", db_con);
	
	ret = fetch_handle(&callid_table, db_con, keys, ops, vals, cs, n, nc, &res);
	if(ret < 0){
		LM_ERR("Failed to fetch_handle.\n");
		goto Err;
	}

	ret = set_output_val(_msg, res, outputcallid);
	if(ret < 0){
		LM_ERR("Failed to set_output_val.\n");
		goto Err;
	}
	
Err:
	if(ops){
		pkg_free(ops);
		ops = NULL;
	}

	if(res){
		if(db_funcs.free_result){
			db_funcs.free_result(db_con, res);
		}
		res = NULL;
	}

	if(db_con){
		LM_DBG("Close db_con [%p] in fetch_callid.\n", db_con);
		db_close(db_con);
		db_con = NULL;
	}

	return 1;
}

static int store_sip(struct sip_msg* _msg, const char* src_ip, const char* route, const char* sdp, const char* pani, const char* other)
{
	sip_cache sc;
	int i = 0;
	int ret = 0;
	struct sip_uri pai;

	memset(&sc, 0, sizeof(sip_cache));
	// sip_name/ruri/ruser
	if(_msg->first_line.type == SIP_REQUEST){
		if(parse_sip_msg_uri(_msg)<0){
			LM_ERR("Failed to parse_sip_msg_uri...\n");
			return 1;
		}
		sc.sip_name = _msg->first_line.u.request.method;
		sc.ruri = _msg->first_line.u.request.uri;
		sc.ruser = _msg->parsed_uri.user;
	}else if(_msg->first_line.type == SIP_REPLY){
		sc.sip_name = _msg->first_line.u.reply.status;
		EMPTY_STR(sc.ruri);
		EMPTY_STR(sc.ruser);
	}else{
		LM_ERR("Unkown type [%i]\n", _msg->first_line.type);
		return 1;
	}
	// furi
	if(_msg->from){
		if(parse_from_header(_msg) == 0){
			//sc.furi.s = _msg->from->parsed;
			//sc.furi.len = strlen(_msg->from->parsed);
			sc.furi = _msg->from->body;
		}else{
			EMPTY_STR(sc.furi);
			LM_ERR("Failed to parse_from_header...\n");
			return 1;
		}
	}
	// callid
	if(_msg->callid){
		sc.callid = _msg->callid->body;
	}else{
		LM_ERR("No callid in msg...\n");
		EMPTY_STR(sc.callid);
		return 1;
	}
	// turi
	if(_msg->to){
		if(parse_to_header(_msg) == 0){
			//sc.turi.s = _msg->to->parsed;
			//sc.turi.len = strlen(_msg->to->parsed);
			sc.turi = _msg->to->body;
		}else{
			EMPTY_STR(sc.turi);
			LM_ERR("Failed to parse_to_header...\n");
			return 1;
		}
	}
	// pai
	if(_msg->pai && (parse_pai_header(_msg) == 0)){
		if (parse_uri(get_pai(_msg)->uri.s, get_pai(_msg)->uri.len, &pai)<0){
			LM_DBG("bad pai...\n");
		}else {
			LM_DBG("PARSE PAI: (%.*s)\n",get_pai(_msg)->uri.len, get_pai(_msg)->uri.s);
			sc.pai = get_pai(_msg)->uri;
		}
	}else{
		EMPTY_STR(sc.pai);
	}
	// src_ip
	if(src_ip && strcmp(src_ip, "") != 0){
		if(fixup_get_svalue(_msg, (gparam_p)src_ip, &sc.src_ip) < 0){
			LM_ERR("Bad value for 'src_ip'\n");
			EMPTY_STR(sc.src_ip);
			goto End;
		}
	}else{
		EMPTY_STR(sc.src_ip);
	}
	// route
	if(route && strcmp(route, "") != 0){
		if(fixup_get_svalue(_msg, (gparam_p)route, &sc.route) < 0){
			LM_ERR("Bad value for 'route'\n");
			EMPTY_STR(sc.route);
			goto End;
		}
	}else{
		EMPTY_STR(sc.route);
	}
	// sdp
	if(sdp && strcmp(sdp, "") != 0){
		if(fixup_get_svalue(_msg, (gparam_p)sdp, &sc.sdp) < 0){
			LM_ERR("Bad value for 'sdp'\n");
			EMPTY_STR(sc.sdp);
			goto End;
		}
	}else{
		EMPTY_STR(sc.sdp);
	}
	// pani
	if(pani && strcmp(pani, "") != 0){
		if(fixup_get_svalue(_msg, (gparam_p)pani, &sc.pani) < 0){
			LM_ERR("Bad value for 'pani'\n");
			EMPTY_STR(sc.pani);
			goto End;
		}
	}else{
		EMPTY_STR(sc.pani);
	}
	// other
	if(other && strcmp(other, "") != 0){
		if(fixup_get_svalue(_msg, (gparam_p)other, &sc.other) < 0){
			LM_ERR("Bad value for 'other'\n");
			EMPTY_STR(sc.other);
			goto End;
		}
	}else{
		EMPTY_STR(sc.other);
	}

	db_val_t vals[NR_KEYS_SIP];
	memset(vals, 0, sizeof(db_val_t) * NR_KEYS_SIP);

	for(i = 0; i < NR_KEYS_SIP; ++i){
		vals[i].type = DB_STR;
	}
	vals[0].val.str_val = sc.callid;
	LM_INFO("callid = [%i][%s]\n", sc.callid.len, sc.callid.s);
	vals[1].val.str_val = sc.sip_name;
	LM_INFO("sip_name = [%i][%s]\n", sc.sip_name.len, sc.sip_name.s);
	vals[2].val.str_val = sc.src_ip;
	LM_INFO("src_ip = [%i][%s]\n", sc.src_ip.len, sc.src_ip.s);
	vals[3].val.str_val = sc.ruri;
	LM_INFO("ruri = [%i][%s]\n", sc.ruri.len, sc.ruri.s);
	vals[4].val.str_val = sc.ruser;
	LM_INFO("ruser = [%i][%s]\n", sc.ruser.len, sc.ruser.s);
	vals[5].val.str_val = sc.furi;
	LM_INFO("furi = [%i][%s]\n", sc.furi.len, sc.furi.s);
	vals[6].val.str_val = sc.turi;
	LM_INFO("turi = [%i][%s]\n", sc.turi.len, sc.turi.s);
	vals[7].val.str_val = sc.route;
	LM_INFO("route = [%i][%s]\n", sc.route.len, sc.route.s);
	vals[8].val.str_val = sc.sdp;
	LM_INFO("sdp = [%i][%s]\n", sc.sdp.len, sc.sdp.s);
	vals[9].val.str_val = sc.pai;
	LM_INFO("pai = [%i][%s]\n", sc.pai.len, sc.pai.s);
	vals[10].val.str_val = sc.pani;
	LM_INFO("pani = [%i][%s]\n", sc.pani.len, sc.pani.s);
	vals[11].val.str_val = sc.other;
	LM_INFO("other = [%i][%s]\n", sc.other.len, sc.other.s);

	ret = store_handle(&sip_table, db_keys_sip, vals, NR_KEYS_SIP);
	if(ret < 0){
		LM_ERR("Failed to store_handle_callid.\n");
		goto End;
	}

End:
	return 1;
}

static int fetch_column(struct sip_msg* _msg, str* column, const char* callid, const char* sip_name, char* result)
{
	if(!callid || !column || !sip_name || !result){
		LM_ERR("Invalid parameters.\n");
		return 1;
	}

	if(strcmp(callid, "") == 0 || strcmp(sip_name, "") == 0){
		LM_ERR("Invalid parameters.\n");
		return 1;
	}

	int ret = 0;
	str scallid, ssn;
	db_con_t* db_con = NULL;

	db_key_t keys[2];
	db_op_t* ops = NULL;
	db_val_t vals[2];
	db_key_t cs[1];
	int n=2, nc = 1;
	db_res_t* res = NULL;


	if(fixup_get_svalue(_msg, (gparam_p)callid, &scallid) < 0){
		LM_ERR("Bad value for 'incallid'\n");
		goto Err;
	}

	size_t len = strlen(sip_name);
	ssn.s = strndup(sip_name, len);
	ssn.len = len;

	keys[0] = &callid_column;
	keys[1] = &sipname_column;
	cs[0] = column;

	vals[0].type = DB_STR;
	vals[0].val.str_val = scallid;
	vals[1].type = DB_STR;
	vals[1].val.str_val = ssn;

	db_con = db_init(&db_url);
	if(!db_con){
		LM_ERR("Failed to db_init.\n");
		goto Err;
	}
	LM_DBG("Get db_con [%p] in fetch_column.\n", db_con);
	
	ret = fetch_handle(&sip_table, db_con, keys, ops, vals, cs, n, nc, &res);
	if(ret < 0){
		LM_ERR("Failed to fetch_handle.\n");
		goto Err;
	}

	ret = set_output_val(_msg, res, result);
	if(ret < 0){
		LM_ERR("Failed to set_output_val.\n");
		goto Err;
	}
	
Err:
	if(ops){
		pkg_free(ops);
		ops = NULL;
	}

	if(res){
		if(db_funcs.free_result){
			db_funcs.free_result(db_con, res);
		}
		res = NULL;
	}

	if(db_con){
		LM_DBG("Close db_con [%p] in fetch_column.\n", db_con);
		db_close(db_con);
		db_con = NULL;
	}
	return 1;
}

static int fetch_route(struct sip_msg* _msg, const char* callid, const char* sip_name, char* route)
{
	return fetch_column(_msg, &route_column, callid, sip_name, route);
}

static int fetch_pai(struct sip_msg* _msg, const char* callid, const char* sip_name, char* pai)
{
	return fetch_column(_msg, &pai_column, callid, sip_name, pai);
}

static int fetch_pani(struct sip_msg* _msg, const char* callid, const char* sip_name, char* pani)
{
	return fetch_column(_msg, &pani_column, callid, sip_name, pani);
}

static int fetch_ruser(struct sip_msg* _msg, const char* callid, const char* sip_name, char* ruser)
{
	return fetch_column(_msg, &ruser_column, callid, sip_name, ruser);
}

static int fetch_from(struct sip_msg* _msg, const char* callid, const char* sip_name, char* result)
{
	return fetch_column(_msg, &fromuri_column, callid, sip_name, result);
}

static int fetch_to(struct sip_msg* _msg, const char* callid, const char* sip_name, char* result)
{
	return fetch_column(_msg, &touri_column, callid, sip_name, result);
}

static int fetch_sdp(struct sip_msg* _msg, const char* callid, const char* sip_name, char* result)
{
	return fetch_column(_msg, &sdp_column, callid, sip_name, result);
}

static int fetch_other(struct sip_msg* _msg, const char* callid, const char* sip_name, char* result)
{
	return fetch_column(_msg, &other_column, callid, sip_name, result);
}
