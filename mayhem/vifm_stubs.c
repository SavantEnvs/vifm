/* Stand-ins for the entry points that live in src/vifm.c (the program's main), as tests/test-support/stubs.c
 * does for upstream's own test binaries. */
#include <stdlib.h> /* abort() */

#include "../src/vifm.h"

struct view_t;

void vifm_reexec_startup_commands(void) { }
void vifm_try_leave(int write_info, int cquit, int force) { }
void vifm_choose_files(struct view_t *view, int nfiles, char *files[]) { abort(); }
void vifm_finish(const char message[]) { abort(); }
void vifm_exit(int exit_code) { abort(); }
int vifm_testing(void) { return 1; }
