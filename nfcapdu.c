#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <nfc/nfc.h>
#include <glib.h>

#include "color.h"
#include "nfcapdu.h"
#include "statusres.h"

#define CONFFILE    ".nfcapdurc"
#define HISTFILE    ".nfcapdu_history"



#define HISTSIZE             128
#define RAPDUMAXSZ           512
#define CAPDUMAXSZ           512
#define COLOR                  1
#define MODTYPE    NMT_ISO14443A
#define NBR              NBR_106

// Default conf values
int conf_histsize = HISTSIZE;
size_t conf_rapdumaxsz = RAPDUMAXSZ;
size_t conf_capdumaxsz = CAPDUMAXSZ;
int conf_color = COLOR;

nfc_modulation_type conf_modtype = MODTYPE;
nfc_baud_rate conf_nbr = NBR;

nfc_device *pnd;
nfc_context *context;
int haveconfig;
GKeyFile *ini;

char **aliaskeys;
gsize nbraliases;
char **words;
char *commands[] = { "quit", "alias", NULL };

char *rl_commands_generator(const char *text, int state)
{
	static int command_index, len;
	char *command;

	if(!state) {
		command_index = 0;
		len = strlen(text);
	}

	// search in wordlist
	while((command = words[command_index++])) {
		if(strncmp(command, text, len) == 0)
			return strdup(command);
	}

	return NULL;
}

char **rl_commands_completion(const char *text, int start, int end)
{
	// our list of completions is final - no path completion
	rl_attempted_completion_over = 1;
	return rl_completion_matches(text, rl_commands_generator);
}

static void sighandler(int sig)
{
    printf("Caught signal %d\n", sig);
    if(pnd != NULL) {
        nfc_abort_command(pnd);
        nfc_close(pnd);
    }
    nfc_exit(context);
    exit(EXIT_FAILURE);
}

int isblankline(char *line)
{
	char *ch;
	int is_blank = 1;

	for(ch=line; *ch!='\0'; ch++){
		if (!isspace(*ch)) {
			is_blank = 0;
			break;
		}
	}

	return is_blank;
}

// return 1 if we have config
int apfu_initconfig()
{
	char *home;
	char *cfile;
	int confpathsz;
	GError *err = NULL;

	if((home=getenv("HOME")) == NULL) {
		fprintf(stderr, "Unable to get $HOME\n");
		exit(EXIT_FAILURE);
	}

	confpathsz = strlen(home)+1+strlen(CONFFILE)+1;
	if((cfile=(char *) malloc(confpathsz)) == NULL) {
		fprintf(stderr, "Memory allocation error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(snprintf(cfile, confpathsz, "%s/%s", home, CONFFILE) != confpathsz-1) {
		fprintf(stderr, "Configuration file path error\n");
	}

	ini = g_key_file_new();
	if(g_key_file_load_from_file(ini, cfile, G_KEY_FILE_KEEP_COMMENTS, &err) == FALSE) {
		fprintf(stderr, "Error loading ini file: %s\n", err->message);
		g_key_file_free(ini);
		if(err != NULL) g_clear_error(&err);
		free(cfile);
		return(0);
	}

	free(cfile);

	return(1);
}

void apdu_inithistory(char **file)
{
	char *home;
	char *p;
	int histpathsz;

	if((home=getenv("HOME")) == NULL) {
		fprintf(stderr, "Unable to get $HOME\n");
		exit(EXIT_FAILURE);
	}

	histpathsz = strlen(home)+1+strlen(HISTFILE)+1;
	if((p=(char *) malloc(histpathsz)) == NULL) {
		fprintf(stderr, "Memory allocation error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(snprintf(p, histpathsz, "%s/%s", home, HISTFILE) != histpathsz-1) {
		fprintf(stderr, "History file path error\n");
	}

	if(read_history(p) != 0) {
		if(errno == ENOENT) {
			write_history(p);
		} else {
			fprintf(stderr, "load hist error %u: %s\n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	stifle_history(conf_histsize);

	*file = p;
}

void apdu_closehistory(char *file)
{
	if(write_history(file) != 0) {
		fprintf(stderr, "write history error: %s\n", strerror(errno));
	}
	free(file);
}

void apdu_addhistory(char *line)
{
	HIST_ENTRY *entry = history_get(history_length);
	if((!entry) || (strcmp(entry->line, line) != 0))
		add_history(line);
}

// Transmit ADPU from hex string
int strcardtransmit(nfc_device *pnd, const char *line, uint8_t *rapdu, size_t *rapdulen)
{
    int res;
    size_t szPos;
	uint8_t *capdu = NULL;
	size_t capdulen = 0;
	*rapdulen = conf_rapdumaxsz;

	uint32_t temp;
	int indx = 0;
	char buf[5] = {0};

	uint16_t status;

	// linelen >0 & even
	if(!strlen(line) || strlen(line) > conf_capdumaxsz*2)
		return(-1);

	if(!(capdu = malloc(strlen(line)/2))) {
		fprintf(stderr, "malloc list error: %s\n", strerror(errno));
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

    while (line[indx]) {
        if(line[indx] == '\t' || line[indx] == ' ') {
            indx++;
            continue;
        }

        if(isxdigit(line[indx])) {
            buf[strlen(buf) + 1] = 0x00;
            buf[strlen(buf)] = line[indx];
        } else {
            // if we have symbols other than spaces and hex
			free(capdu);
			printf("Invalid hex string! No matching alias.\n");
            return(-1);
        }

        if(strlen(buf) >= 2) {
            sscanf(buf, "%x", &temp);
            capdu[capdulen] = (uint8_t)(temp & 0xff);
            *buf = 0;
            capdulen++;
        }
        indx++;
    }

	// error if partial hex bytes
	if(strlen(buf) > 0) {
		free(capdu);
		printf("Invalid hex string!\n");
		return(-1);
	}

	printf("%s=> ", conf_color ? YELLOW : "" );
	for (szPos = 0; szPos < capdulen; szPos++) {
		printf("%02x ", capdu[szPos]);
	}
	printf("%s\n", conf_color ? RESET : "");

    if((res = nfc_initiator_transceive_bytes(pnd, capdu, capdulen, rapdu, *rapdulen, -1)) < 0) {
        printf("nfc_initiator_transceive_bytes error! %s\n", nfc_strerror(pnd));
		*rapdulen = 0;
        return(-1);
    }

	if(capdu) free(capdu);

	status = (rapdu[res-2] << 8) | rapdu[res-1];

	if(status == S_SUCCESS) {
		printf("%s<= ", conf_color ? GREEN : "");
	} else {
		printf("%s<= ", conf_color ? RED : "");
	}

	for (szPos = 0; szPos < res; szPos++) {
		printf("%02x ", rapdu[szPos]);
	}
	printf("%s\n", conf_color ? RESET : "");

	if(status != S_SUCCESS) {
		printf("Error: %s (0x%04x)\n", strstatus(status), status);
		return(-1);
	}

	*rapdulen = (size_t)res;

	return(0);
}

int listdevices()
{
	size_t device_count;
	nfc_connstring devices[8];

	// Scan readers/devices
	device_count = nfc_list_devices(context, devices, sizeof(devices)/sizeof(*devices));
	if(device_count <= 0) {
		fprintf(stderr, "Error: No NFC device found\n");
		return(0);
	}

	printf("Available readers/devices:\n");
	for(size_t d = 0; d < device_count; d++) {
		printf("  %lu: ", d);
		if(!(pnd = nfc_open (context, devices[d]))) {
			printf("nfc_open() failed\n");
		} else {
			printf("%s (connstring=\"%s\")\n", nfc_device_get_name(pnd), nfc_device_get_connstring(pnd));
			nfc_close(pnd);
		}
	}
	return(device_count);
}

static void print_hex(const uint8_t *pbtData, const size_t szBytes)
{
	size_t  szPos;

	for(szPos = 0; szPos < szBytes; szPos++) {
		printf("%02X", pbtData[szPos]);
	}
}

void failquit()
{
	if(words) free(words);
	if(aliaskeys) g_strfreev(aliaskeys);
	if(ini) g_key_file_free(ini);
	if(pnd) nfc_close(pnd);
	if(context) nfc_exit(context);
	exit(EXIT_SUCCESS);
}

void printhelp(char *binname)
{
	printf("NFCapdu v0.0.1\n");
	printf("Copyright (c) 2022 - Denis Bodor\n\n");
	printf("Usage : %s [OPTIONS]\n", binname);
	printf(" -l              list available readers\n");
	printf(" -d connstring   use this device (default: use the first available device)\n");
	printf(" -v              verbose mode\n");
	printf(" -h              show this help\n");
}

void showaliases()
{
	int i = 0;
	char *val;
	GError *err = NULL;

	if(!nbraliases || !haveconfig) {
		printf("No alias\n");
		return;
	}

	printf("Defined aliases:\n");
	while(aliaskeys[i]) {
		val = g_key_file_get_value(ini, "aliases", aliaskeys[i], &err);
		if(err) {
			g_clear_error(&err);
		} else {
			printf("  %s = %s%s\n", aliaskeys[i], val, strlen(val) == 0 ? "<empty!>" : "");
			g_free(val);
		}
		i++;
	}
}

int main(int argc, char**argv)
{
	char *in;
	char *fhistory;

	nfc_target nt;

	const nfc_modulation mod = {
		.nmt = NMT_ISO14443A,
		.nbr = NBR_106
	};

	uint8_t *resp;
	size_t respsz;

	int retopt;
	int optlistdev = 0;
	char *optconnstring = NULL;

	GError *err = NULL;
	char *aliasval;
	int nbr_commands = 0;

	// FIXME not pretty
	int wordsneedfree = 0;

	while((retopt = getopt(argc, argv, "hld:")) != -1) {
		switch (retopt) {
			case 'l':
				optlistdev = 1;
				break;
			case 'd':
				optconnstring = strdup(optarg);
				break;
			case 'h':
				printhelp(argv[0]);
				return(EXIT_FAILURE);
			default:
				printhelp(argv[0]);
				return(EXIT_FAILURE);
		}
	}

    if(signal(SIGINT, &sighandler) == SIG_ERR) {
        printf("Error: Can't catch SIGINT\n");
        return(EXIT_FAILURE);
    }

    if(signal(SIGTERM, &sighandler) == SIG_ERR) {
        printf("Error: Can't catch SIGTERM\n");
        return(EXIT_FAILURE);
    }

	// Initialize libnfc and set the nfc_context
	nfc_init(&context);
	if(context == NULL) {
		printf("Error: Unable to init libnfc (malloc)\n");
		exit(EXIT_FAILURE);
	}

	if(optlistdev) {
		listdevices();
		nfc_exit(context);
		return(EXIT_SUCCESS);
	}

	// load configuration
	haveconfig = apfu_initconfig();

	// get command history from config file (or use default)
	if(haveconfig) {
		conf_histsize = g_key_file_get_integer(ini, "general", "histsize", &err);
		if(err) {
			if(err->code == G_KEY_FILE_ERROR_INVALID_VALUE)
				fprintf(stderr, "Invalid value for 'histsize' in configuration file. Using default.\n");
			conf_histsize = HISTSIZE;
			g_clear_error(&err);
		}
	}

	// get color enable from config file (or use default)
	if(haveconfig) {
		conf_color = g_key_file_get_boolean(ini, "general", "color", &err);
		if(err) {
			if(err->code == G_KEY_FILE_ERROR_INVALID_VALUE)
				fprintf(stderr, "Invalid boolean for 'color' in configuration file. Using default.\n");
			conf_color = COLOR;
			g_clear_error(&err);
		}
	}

	// get max size of response APDU buffer from config file (or use default)
	if(haveconfig) {
		conf_rapdumaxsz = g_key_file_get_integer(ini, "general", "rapdumaxsz", &err);
		if(err) {
			if(err->code == G_KEY_FILE_ERROR_INVALID_VALUE)
				fprintf(stderr, "Invalid value for 'rapdumaxsz' in configuration file. Using default.\n");
			conf_rapdumaxsz = RAPDUMAXSZ;
			g_clear_error(&err);
		}
	}

	// allocate R-APDU buffer
	if((resp = malloc(sizeof(uint8_t) * conf_rapdumaxsz)) == NULL) {
		fprintf(stderr, "resp[] Malloc Error: %s\n", strerror(errno));
		failquit();
	}
	respsz = conf_rapdumaxsz;

	// get max size of command APDU buffer from config file (or use default)
	if(haveconfig) {
		conf_capdumaxsz = g_key_file_get_integer(ini, "general", "capdumaxsz", &err);
		if(err) {
			if(err->code == G_KEY_FILE_ERROR_INVALID_VALUE)
				fprintf(stderr, "Invalid value for 'capdumaxsz' in configuration file. Using default.\n");
			conf_capdumaxsz = CAPDUMAXSZ;
			g_clear_error(&err);
		}
	}

	// TODO modulation config from file

	if(optconnstring) {
		// Open, using specified NFC device
		pnd = nfc_open(context, optconnstring);
	} else {
		// Open, using the first available NFC device which can be in order of selection:
		//   - default device specified using environment variable or
		//   - first specified device in libnfc.conf (/etc/nfc) or
		//   - first specified device in device-configuration directory (/etc/nfc/devices.d) or
		//   - first auto-detected (if feature is not disabled in libnfc.conf) device
		pnd = nfc_open(context, NULL);
	}

	if(pnd == NULL) {
		fprintf(stderr, "Error: Unable to open NFC device!\n");
		exit(EXIT_FAILURE);
	}

	// Set opened NFC device to initiator mode
	if(nfc_initiator_init(pnd) < 0) {
		nfc_perror(pnd, "nfc_initiator_init");
		exit(EXIT_FAILURE);
	}

	printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

	if(nfc_initiator_select_passive_target(pnd, mod, NULL, 0, &nt) > 0) {
		printf("%s (%s) tag found. UID: %s",
				str_nfc_modulation_type(mod.nmt), str_nfc_baud_rate(mod.nbr), conf_color ? CYAN : "");
		print_hex(nt.nti.nai.abtUid, nt.nti.nai.szUidLen);
		printf("%s\n", conf_color ? RESET : "");
	} else {
		fprintf(stderr, "Error: No ISO14443A tag found!\n");
		failquit();
	}

	// show aliases & load readline completion
	if(haveconfig) {
		aliaskeys = g_key_file_get_keys(ini, "aliases", &nbraliases, &err);
		if(err) {
			fprintf(stderr, "%s\n", err->message);
			words = commands;
			g_clear_error(&err);
		} else {
			printf("%lu aliases loaded\n", nbraliases);
			// merge commands to aliases to completion wordslist
			while(commands[nbr_commands]) nbr_commands++;
			if((words = malloc(sizeof(char *) * (nbr_commands+nbraliases+1))) == NULL) {
				fprintf(stderr, "Words Malloc Error: %s\n", strerror(errno));
				failquit();
			}
			int i=0;
			while(commands[i]) {
				words[i] = commands[i];
				i++;
			}
			int j=0;
			while(aliaskeys[j]) {
				words[i] = aliaskeys[j];
				i++; j++;
			}
			words[i] = 0;
			wordsneedfree = 1; // enable free(words) when we quit
		}
	} else {
		words = commands;
	}

	// Load commands history
	apdu_inithistory(&fhistory);

	// Enable completion
	rl_attempted_completion_function = rl_commands_completion;

	while((in = readline("APDU> ")) != NULL) {
		if(strlen(in) && !isblankline(in)) {
			// strip whitespace
			g_strstrip(in);
			// add to commands history
			apdu_addhistory(in);
			if(strcmp(in, "alias") == 0) {
				showaliases();
				continue;
			}
			if(strcmp(in, "quit") == 0) {
				break;
			}
			if(!nbraliases) {
				// no alias in config file
				if(strcardtransmit(pnd, in, resp, &respsz) < 0) {
					fprintf(stderr, "cardtransmit error!\n");
				}
			} else {
				// look for alias
				aliasval = g_key_file_get_value(ini, "aliases", in, &err);
				if(err) {
					// alias not found
					if(strcardtransmit(pnd, in, resp, &respsz) < 0) {
						fprintf(stderr, "cardtransmit error!\n");
					}
					g_clear_error(&err);
				} else if(!strlen(aliasval)) {
					// alias resolv to ""
					printf("This alias resolv to an empty string. Fix your "CONFFILE" please.\n");
				} else {
					// alias found, use that
					if(strcardtransmit(pnd, aliasval, resp, &respsz) < 0) {
						fprintf(stderr, "cardtransmit error!\n");
					}
				}
				g_free(aliasval);
			}
		}
		if(in) free(in);
	}
	printf("\n");

	apdu_closehistory(fhistory);

	if(haveconfig) {
		if(aliaskeys) g_strfreev(aliaskeys);
		if(ini) g_key_file_free(ini);
	}

	if(words && wordsneedfree) free(words);

	// Close NFC device
	nfc_close(pnd);
	// Release the context
	nfc_exit(context);
	return(EXIT_SUCCESS);
}
