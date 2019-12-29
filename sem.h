#ifndef __SEM_H__
#define __SEM_H__

#include "../../sr_module.h"
//#include "../../mod_fix.h"
#include <stdlib.h>
#include <string.h>
#include <sys/sem.h>
#include <string.h>
#include <sys/unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>

union semun
{
	int val;
};

key_t get_key(int proj_id);
int sem_init();
void sem_p(int semid);
void sem_v(int semid);
void sem_destroy(int semid);
#endif
