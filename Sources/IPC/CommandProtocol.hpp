#pragma once

#include <stdint.h>

namespace nfcf_backend {

enum class Command : uint32_t {
    kPrewarmOpen = 1,
    kPrewarmClose,
    kRoutingOff,
    kRoutingRestore,
    kT3TPatch,
    kT3TRestore,
    kSetCEStart,
    kSetCEStop,
    kSetCERecover,
    kSetCEStatus,
    kProfileApply,
    kProfileStatus,
    kProfileClear,
};

const char *CommandName(Command command);
const char *CommandNotification(Command command);
bool ParseCommandName(const char *name, Command *command);

bool WriteCommandRequestAtPath(const char *path, Command command,
                               const uint8_t nonce[16]);
bool ConsumeCommandRequestAtPath(const char *path, Command expected,
                                 uint64_t now);
bool WriteCommandRequest(Command command, const uint8_t nonce[16]);
bool ConsumeCommandRequest(Command expected);

}  // namespace nfcf_backend
