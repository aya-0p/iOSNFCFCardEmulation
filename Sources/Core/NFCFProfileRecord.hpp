#pragma once

#include <stddef.h>
#include <stdint.h>

namespace nfcf {

inline constexpr size_t kBlockSize = 16;
inline constexpr size_t kMaximumBlockCount = 4;
inline constexpr uint32_t kProfileRecordVersion = 1;
inline constexpr size_t kProfileRecordEncodedSize = 99;

// The current engine exposes one read-only service with up to four blocks.
// System and service codes are values supplied by the profile producer.
struct Profile {
    uint16_t system_code;
    uint16_t service_code;
    uint8_t idm[8];
    // libNFC_Comet supplies the leading FE FE bytes for T3T PMm values. The
    // private controller accepts the remaining six timing bytes.
    uint8_t pmm_tail[6];
    uint8_t block_count;
    uint8_t blocks[kMaximumBlockCount][kBlockSize];
};

struct ProfileRecord {
    uint8_t magic[8];
    uint32_t version;
    uint16_t system_code;
    uint16_t service_code;
    uint8_t idm[8];
    uint8_t pmm_tail[6];
    uint8_t block_count;
    uint8_t blocks[kMaximumBlockCount][kBlockSize];
    uint32_t checksum;
};

bool IsValidProfile(const Profile &profile);
bool IsProfileRecordFormat(const ProfileRecord &record);
bool MakeProfileRecord(const Profile &profile, ProfileRecord *record);
bool EncodeProfileRecord(const ProfileRecord &record, uint8_t *bytes,
                         size_t length);
bool DecodeProfileRecordBytes(const uint8_t *bytes, size_t length,
                              ProfileRecord *record);
bool DecodeProfileRecord(const ProfileRecord &record, Profile *profile);

}  // namespace nfcf
