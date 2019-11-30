# db_cache module used by opensips based version '2.4.6', aiming to store/fetch sip information
# Usage:
1) compile
#$>/opensips-2.4.6/modules/db_cache/
#$>make

2) install
#$>cp db_cache.so ../opensips/lib64/opensips/modules

3):
	a) loadmodule in opensips.cfg
		loadmodule "db_cache.so"

	b) configure mysql: db_url, sip_table, callid_table
		modparam("db_cache", "db_url", "mysql://opensips:opensipsrw@localhost/test")
		modparam("db_cache", "sip_table", "sip_info")
		modparam("db_cache", "callid_table", "callid_info")

	c) call the exported functions
		route{
			if(is_method("INVITE")){
				if(incoming from outside...){
					// store the invite information to table sip_info;
					$var(src_ip)="";
					$var(route)="";
					$var(sdp)="";
					$var(pani)="";
					$var(other)="";
					store_sip_info("$var(src_ip)", "$var(route)", "$var(sdp)", "$var(pani)", "$var(other)");

					# Add src-callid to request "INVITE" aiming to link the other new request sended by other as such as Asterisk
					append_hf("X-SRC-CALL-ID: $ci\r\n");
				}else{
					# incoming from inside, such as asterisk
					$var(incallid)="";
					if(is_present_hf("X-SRC-CALL-ID")){
						$var(incallid)=$(hdr(X-SRC-CALL-ID));
					}
					store_callid("$var(incallid)", "$ci");

					$var(route)="";
					$var(from)="";
					$var(to)="";
					$var(pai)="";
					$var(pani)="";
					$var(src_ip)="";
					fetch_route("$incallid", "INVITE", "$var(route)");
					xlog("fetched route is [$var(route)]\n");
					fetch_from("$incallid", "INVITE", "$var(from)");
					xlog("fetched from is [$var(from)]\n");
					fetch_to("$incallid", "INVITE", "$var(to)");
					xlog("fetched to is [$var(to)]\n");
				}
			}
		}

	d) tables...
		CREATE TABLE `sip_info`
		(
			`call_id` VARCHAR (255) NOT NULL,
			`sip_name` VARCHAR (32) NOT NULL,
			`src_ip` VARCHAR (64),
			`r_uri` VARCHAR (128),
			`r_user` VARCHAR (64),
			`from_uri` VARCHAR (128),
			`to_uri` VARCHAR (128),
			`route` VARCHAR (1024),
			`sdp` VARCHAR (2048),
			`pai` VARCHAR (128),
			`pani` VARCHAR (128),
			`other` VARCHAR (256),
			PRIMARY KEY (`call_id`, `sip_name`)
		)ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

		CREATE TABLE `callid_info`
		(
			`in_callid` VARCHAR (255) NOT NULL,
			`out_callid` VARCHAR (255) NOT NULL,
			CONSTRAINT PRIMARY KEY (`in_callid`)
		)ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
