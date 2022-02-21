
#ifndef SRD_H
#define SRD_H

typedef struct action_t {
    const char*   name;
    const char*   object;
    int     delay;
} action_t;

int main();
int has_root_access();
int restart_service();
int restart_system();
int check_connectivity(const char* ip, int timeout);
int load_config(config_t *cfg, const char **ip, int *freq, int *timeout, int* count, action_t **actions);

#endif
