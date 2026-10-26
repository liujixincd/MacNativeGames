#include "../games/totk/runtime/runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Noreturn void runtime_fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(2);
}
void runtime_game_data_path(const char *name, char *out, size_t cap) {
    int n = snprintf(out, cap, "%s/%s", getenv("TEST_GAME_DATA"), name);
    if (n < 0 || (size_t)n >= cap) runtime_fail("test game data path too long");
}
int main(void) {
    runtime_game_slot_acquire("boot");
    runtime_cheats_backup();
    puts("pass: profile protected before guest startup");
    return 0;
}
