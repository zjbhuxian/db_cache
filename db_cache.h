#ifndef __DB_CACHE_H__
#define __DB_CACHE_H__
#include "../../str.h"

typedef struct _sip_cache {
	str callid;
	str sip_name;
	str	src_ip;
	str ruri;
	str ruser;
	str furi;
	str turi;
	str route;
	str sdp;
	str pai;
	str pani;
	str other;
}sip_cache, *psip_cache;

#endif
