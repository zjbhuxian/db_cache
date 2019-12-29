#include "sem.h"

#define PATH_LEN 1024
key_t get_key(int proj_id)
{
	char path[PATH_LEN] = {0};
	if(!getcwd(path, PATH_LEN)){
		LM_ERR("Failed to get path.\n");
	}

	LM_INFO("Path: [%s]\n", path);
	key_t key = -1;
	key = ftok((const char*)path, proj_id);
	if(key == -1){
		LM_ERR("Failed to get key.\n");
	}

	return key;
}

int sem_init(int proj_id)
{
	key_t key = get_key(proj_id);
	if(key == -1){
		LM_ERR("Failed to get key.\n");
	}

	int semid = -1;
	semid = semget(key, 1, IPC_CREAT | IPC_EXCL | 0600);
	if(semid == -1){
		semid = semget(key, 1, IPC_CREAT | 0600);
		if(semid == -1){
			LM_ERR("Semget Error.\n");
		}
	}else{
		union semun a;
		a.val = 1;
		if(semctl(semid, 0, SETVAL, a) == -1){
			LM_ERR("Semctl init error.\n");
		}
	}

	return semid;
}

void sem_p(int semid)
{
	struct sembuf buf;
	buf.sem_num = 0;
	buf.sem_op = -1;
	buf.sem_flg = SEM_UNDO;
	if(semop(semid, &buf, 1) == -1){
		LM_ERR("P error.\n");
	}
}

void sem_v(int semid)
{
	struct sembuf buf;
	buf.sem_num = 0;
	buf.sem_op = 1;
	buf.sem_flg = SEM_UNDO;
	if(semop(semid, &buf, 1) == -1){
		LM_ERR("V error.\n");
	}
}

void sem_destroy(int semid)
{
	if(semctl(semid, 0, IPC_RMID) == -1){
		LM_ERR("Semctl destroy error.\n");
	}
}
