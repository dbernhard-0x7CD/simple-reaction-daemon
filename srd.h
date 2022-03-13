
#ifndef SRD_H
#define SRD_H

typedef struct action_t {
    const char*   name;
    const void*   object;
    int     delay;
} action_t;

typedef struct action_cmd_t {
    const char* command;
    const char* user;
} action_cmd_t;

int main();
int restart_service();
int restart_system();
int get_user_id(const char* username);
int run_command(const action_cmd_t* cmd);
int check_connectivity(const char* ip, int timeout);
int load_config(config_t *cfg, const char **ip, int *freq, int *timeout, int* count, action_t **actions);
void signal_handler(int);
char* escape_servicename(char*);

#endif
