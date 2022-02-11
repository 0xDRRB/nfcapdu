#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>

#define HISTFILE    ".nfcapdu_history"
#define HISTSIZE    128

int blankline(char *line)
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

void apdu_inithistory(char **file) {
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

	stifle_history(HISTSIZE);

	*file = p;
}

void apdu_closehistory(char *file) {
	if(write_history(file) != 0) {
		fprintf(stderr, "write history error: %s\n", strerror(errno));
	}
	free(file);
}

void apdu_addhistory(char *line) {
	HIST_ENTRY *entry = history_get(history_length);
	if((!entry) || (strcmp(entry->line, line) != 0))
		add_history(line);
}

int main(int argc, char**argv)
{
	char *in;
	char *fhistory;

	apdu_inithistory(&fhistory);

	while((in = readline("APDU> ")) != NULL) {
		if(strlen(in) && !blankline(in)) {
			apdu_addhistory(in);
			// TODO
			printf("%s -> %zu\n", in, strlen(in));
		}
	}
	printf("\n");

	apdu_closehistory(fhistory);

	return 0;

}
