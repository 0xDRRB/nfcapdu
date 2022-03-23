#pragma once

#define S_SUCCESS       0x9000  // Command completed successfully
#define S_OK            0x9100  // OK (after additional data frame)
#define S_MORE          0x91af  // Additional data frame is expected to be sent

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

