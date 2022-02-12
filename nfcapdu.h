#pragma once

#define S_SUCCESS       0x9000  // Command completed successfully

char *commands_generator(const char *text, int state);
char **commands_completion(const char *text, int start, int end);
static void sighandler(int sig);
int isblankline(char *line);
int apfu_initconfig();
void apdu_inithistory(char **file);
void apdu_closehistory(char *file);
void apdu_addhistory(char *line);
int strcardtransmit(nfc_device *pnd, const char *line, uint8_t *rapdu, size_t *rapdulen);
int listdevices();
static void print_hex(const uint8_t *pbtData, const size_t szBytes);
void failquit();
void printhelp(char *binname);
void showaliases();

