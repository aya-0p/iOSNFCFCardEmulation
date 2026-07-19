#include "../Sources/Core/BoundedAppendLog.hpp"

#include <assert.h>
#include <string.h>
#include <sys/stat.h>

static const char kPath[] = "/tmp/fht_bounded_append_log_test.log";

int main() {
    NFCFBoundedAppendLog log =
        NFCF_BOUNDED_APPEND_LOG_INITIALIZER(kPath);
    NFCFResetBoundedAppendLog(&log);

    char line[2048];
    memset(line, 'A', sizeof(line));
    line[sizeof(line) - 1] = '\n';
    for (int index = 0; index < 700; ++index)
        NFCFWriteBoundedAppendLog(&log, line, sizeof(line));
    NFCFCloseBoundedAppendLog(&log);

    struct stat current = {};
    struct stat previous = {};
    char previous_path[1024];
    NFCFLogPreviousPath(kPath, previous_path);
    assert(stat(kPath, &current) == 0);
    assert(stat(previous_path, &previous) == 0);
    assert(current.st_size > 0 && current.st_size <= kNFCFLogLimit);
    assert(previous.st_size > 0 && previous.st_size <= kNFCFLogLimit);

    NFCFResetBoundedAppendLog(&log);
    assert(access(kPath, F_OK) != 0);
    assert(access(previous_path, F_OK) != 0);
    return 0;
}
