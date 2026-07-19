#pragma once

#include <stddef.h>
#include <stdint.h>

#include "NFCFProfileRecord.hpp"

namespace nfcf {

enum class DispatchStatus : uint8_t {
    kNoResponse = 0,
    kResponse = 1,
};

struct DispatchResult {
    DispatchStatus status;
    uint8_t request_command;
    size_t response_length;
};

// The active profile exists only for the current authorized emulation session.
// The implementation snapshots the complete profile under a mutex before
// replying.
bool SetActiveProfile(const Profile &profile);
bool CopyActiveProfile(Profile *profile);
void ClearActiveProfile(void);

// Implements Request Response and Read Without Encryption for the active
// read-only, single-service profile. Unsupported or malformed frames receive
// no response.
DispatchResult Dispatch(const uint8_t *frame, size_t frame_length,
                        uint8_t *response, size_t response_capacity);

}  // namespace nfcf
