#include "NFCFProtocol.hpp"

#include <pthread.h>
#include <string.h>

namespace nfcf {

static pthread_mutex_t gProfileMutex = PTHREAD_MUTEX_INITIALIZER;
static Profile gActiveProfile = {};
static bool gHasActiveProfile = false;

bool SetActiveProfile(const Profile &profile) {
    if (!IsValidProfile(profile)) return false;
    Profile normalized = profile;
    memset(normalized.blocks + normalized.block_count, 0,
           (kMaximumBlockCount - normalized.block_count) * kBlockSize);
    pthread_mutex_lock(&gProfileMutex);
    memcpy(&gActiveProfile, &normalized, sizeof(gActiveProfile));
    gHasActiveProfile = true;
    pthread_mutex_unlock(&gProfileMutex);
    return true;
}

bool CopyActiveProfile(Profile *profile) {
    if (profile == nullptr) return false;
    pthread_mutex_lock(&gProfileMutex);
    const bool available = gHasActiveProfile;
    if (available) memcpy(profile, &gActiveProfile, sizeof(*profile));
    pthread_mutex_unlock(&gProfileMutex);
    return available;
}

void ClearActiveProfile(void) {
    pthread_mutex_lock(&gProfileMutex);
    memset(&gActiveProfile, 0, sizeof(gActiveProfile));
    gHasActiveProfile = false;
    pthread_mutex_unlock(&gProfileMutex);
}

static DispatchResult NoResponse(uint8_t command) {
    return {DispatchStatus::kNoResponse, command, 0};
}

static DispatchResult HandleRequestResponse(const Profile &profile,
                                            uint8_t *response,
                                            size_t response_capacity) {
    constexpr size_t kLength = 11;
    if (response == nullptr || response_capacity < kLength)
        return NoResponse(0x04);
    response[0] = static_cast<uint8_t>(kLength);
    response[1] = 0x05;
    memcpy(response + 2, profile.idm, sizeof(profile.idm));
    response[10] = 0x00;
    return {DispatchStatus::kResponse, 0x04, kLength};
}

static DispatchResult HandleReadWithoutEncryption(
    const Profile &profile, const uint8_t *frame, size_t frame_length,
    uint8_t *response, size_t response_capacity) {
    // Length, command, IDm, service count, one service code, block count, and
    // at least one block-list element.
    if (frame_length < 16 || frame[10] != 0x01)
        return NoResponse(0x06);
    if (frame[11] != static_cast<uint8_t>(profile.service_code & 0xff) ||
        frame[12] != static_cast<uint8_t>(profile.service_code >> 8))
        return NoResponse(0x06);

    const uint8_t requested_blocks = frame[13];
    if (requested_blocks == 0 || requested_blocks > profile.block_count)
        return NoResponse(0x06);

    uint8_t block_numbers[kMaximumBlockCount] = {};
    size_t cursor = 14;
    for (uint8_t index = 0; index < requested_blocks; ++index) {
        if (cursor >= frame_length) return NoResponse(0x06);
        const uint8_t descriptor = frame[cursor++];
        const bool short_form = (descriptor & 0x80) != 0;
        // Only access mode 0 and service-code list order 0 are meaningful for
        // the single read-only service exposed by this engine.
        if ((descriptor & 0x70) != 0 || (descriptor & 0x0f) != 0)
            return NoResponse(0x06);
        uint16_t block_number = 0;
        if (short_form) {
            if (cursor >= frame_length) return NoResponse(0x06);
            block_number = frame[cursor++];
        } else {
            if (cursor + 1 >= frame_length) return NoResponse(0x06);
            block_number = static_cast<uint16_t>(frame[cursor]) |
                           static_cast<uint16_t>(frame[cursor + 1]) << 8;
            cursor += 2;
        }
        if (block_number >= profile.block_count) return NoResponse(0x06);
        block_numbers[index] = static_cast<uint8_t>(block_number);
    }
    if (cursor != frame_length) return NoResponse(0x06);

    const size_t response_length = 13 + 16 * requested_blocks;
    if (response == nullptr || response_capacity < response_length ||
        response_length > 0xff)
        return NoResponse(0x06);

    response[0] = static_cast<uint8_t>(response_length);
    response[1] = 0x07;
    memcpy(response + 2, profile.idm, sizeof(profile.idm));
    response[10] = 0x00;
    response[11] = 0x00;
    response[12] = requested_blocks;
    for (uint8_t index = 0; index < requested_blocks; ++index) {
        memcpy(response + 13 + index * 16,
               profile.blocks[block_numbers[index]], 16);
    }
    return {DispatchStatus::kResponse, 0x06, response_length};
}

DispatchResult Dispatch(const uint8_t *frame, size_t frame_length,
                        uint8_t *response, size_t response_capacity) {
    if (frame == nullptr || frame_length < 2 || frame_length > 0xff ||
        frame[0] != frame_length)
        return NoResponse(0xff);

    const uint8_t command = frame[1];
    Profile profile = {};
    if (!CopyActiveProfile(&profile) || frame_length < 10 ||
        memcmp(frame + 2, profile.idm, sizeof(profile.idm)) != 0)
        return NoResponse(command);

    switch (command) {
        case 0x04:
            if (frame_length != 10) return NoResponse(command);
            return HandleRequestResponse(profile, response, response_capacity);
        case 0x06:
            return HandleReadWithoutEncryption(
                profile, frame, frame_length, response, response_capacity);
        default:
            return NoResponse(command);
    }
}

}  // namespace nfcf
