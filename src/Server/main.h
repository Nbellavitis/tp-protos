
#include <stdbool.h>
#include "Auth/auth.h"
#include "constants.h"

#ifndef MAIN_H
#define MAIN_H


struct users* get_authorized_users(void);
int get_num_authorized_users(void);
bool add_user(const char* username, const char* password);
bool delete_user(const char* username);
bool change_user_password(const char* username, const char* new_password);
user_t * get_anon_user(void);
#endif