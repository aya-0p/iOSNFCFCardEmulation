#include "NFCFProfileRecord.hpp"

#include <string.h>

namespace nfcf {

static constexpr uint8_t kMagic[8] = {
    'N', 'F', 'C', 'F', 'P', 'R', 'O', 'F',
};
static constexpr size_t kChecksumOffset = kProfileRecordEncodedSize - 4;

static void PutUInt16LE(uint8_t *output, uint16_t value) {
    output[0] = static_cast<uint8_t>(value & 0xff);
    output[1] = static_cast<uint8_t>(value >> 8);
}

static void PutUInt32LE(uint8_t *output, uint32_t value) {
    output[0] = static_cast<uint8_t>(value & 0xff);
    output[1] = static_cast<uint8_t>((value >> 8) & 0xff);
    output[2] = static_cast<uint8_t>((value >> 16) & 0xff);
    output[3] = static_cast<uint8_t>(value >> 24);
}

static uint16_t GetUInt16LE(const uint8_t *input) {
    return static_cast<uint16_t>(input[0]) |
           static_cast<uint16_t>(input[1]) << 8;
}

static uint32_t GetUInt32LE(const uint8_t *input) {
    return static_cast<uint32_t>(input[0]) |
           static_cast<uint32_t>(input[1]) << 8 |
           static_cast<uint32_t>(input[2]) << 16 |
           static_cast<uint32_t>(input[3]) << 24;
}

static void EncodePayload(const ProfileRecord &record, uint8_t *bytes) {
    size_t offset = 0;
    memcpy(bytes + offset, record.magic, sizeof(record.magic));
    offset += sizeof(record.magic);
    PutUInt32LE(bytes + offset, record.version);
    offset += 4;
    PutUInt16LE(bytes + offset, record.system_code);
    offset += 2;
    PutUInt16LE(bytes + offset, record.service_code);
    offset += 2;
    memcpy(bytes + offset, record.idm, sizeof(record.idm));
    offset += sizeof(record.idm);
    memcpy(bytes + offset, record.pmm_tail, sizeof(record.pmm_tail));
    offset += sizeof(record.pmm_tail);
    bytes[offset++] = record.block_count;
    memcpy(bytes + offset, record.blocks, sizeof(record.blocks));
}

static uint32_t ChecksumBytes(const uint8_t *bytes, size_t length) {
    uint32_t value = 2166136261u;
    for (size_t index = 0; index < length; ++index) {
        value ^= bytes[index];
        value *= 16777619u;
    }
    return value;
}

static uint32_t Checksum(const ProfileRecord &record) {
    uint8_t encoded[kProfileRecordEncodedSize] = {};
    EncodePayload(record, encoded);
    return ChecksumBytes(encoded, kChecksumOffset);
}

bool IsValidProfile(const Profile &profile) {
    return profile.block_count > 0 &&
           profile.block_count <= kMaximumBlockCount;
}

bool IsProfileRecordFormat(const ProfileRecord &record) {
    Profile profile = {};
    profile.system_code = record.system_code;
    profile.service_code = record.service_code;
    memcpy(profile.idm, record.idm, sizeof(profile.idm));
    memcpy(profile.pmm_tail, record.pmm_tail, sizeof(profile.pmm_tail));
    profile.block_count = record.block_count;
    memcpy(profile.blocks, record.blocks, sizeof(profile.blocks));
    bool unused_blocks_are_zero = true;
    for (size_t block = record.block_count; block < kMaximumBlockCount;
         ++block) {
        for (size_t byte = 0; byte < kBlockSize; ++byte)
            unused_blocks_are_zero &= record.blocks[block][byte] == 0;
    }
    return memcmp(record.magic, kMagic, sizeof(kMagic)) == 0 &&
           record.version == kProfileRecordVersion &&
           record.checksum == Checksum(record) && IsValidProfile(profile) &&
           unused_blocks_are_zero;
}

bool MakeProfileRecord(const Profile &profile, ProfileRecord *record) {
    if (record == nullptr || !IsValidProfile(profile)) return false;
    memset(record, 0, sizeof(*record));
    memcpy(record->magic, kMagic, sizeof(kMagic));
    record->version = kProfileRecordVersion;
    record->system_code = profile.system_code;
    record->service_code = profile.service_code;
    memcpy(record->idm, profile.idm, sizeof(record->idm));
    memcpy(record->pmm_tail, profile.pmm_tail, sizeof(record->pmm_tail));
    record->block_count = profile.block_count;
    memcpy(record->blocks, profile.blocks,
           profile.block_count * kBlockSize);
    record->checksum = Checksum(*record);
    return true;
}

bool EncodeProfileRecord(const ProfileRecord &record, uint8_t *bytes,
                         size_t length) {
    if (bytes == nullptr || length != kProfileRecordEncodedSize ||
        !IsProfileRecordFormat(record))
        return false;
    memset(bytes, 0, length);
    EncodePayload(record, bytes);
    PutUInt32LE(bytes + kChecksumOffset, record.checksum);
    return true;
}

bool DecodeProfileRecordBytes(const uint8_t *bytes, size_t length,
                              ProfileRecord *record) {
    if (bytes == nullptr || record == nullptr ||
        length != kProfileRecordEncodedSize ||
        ChecksumBytes(bytes, kChecksumOffset) !=
            GetUInt32LE(bytes + kChecksumOffset))
        return false;

    ProfileRecord decoded = {};
    size_t offset = 0;
    memcpy(decoded.magic, bytes + offset, sizeof(decoded.magic));
    offset += sizeof(decoded.magic);
    decoded.version = GetUInt32LE(bytes + offset);
    offset += 4;
    decoded.system_code = GetUInt16LE(bytes + offset);
    offset += 2;
    decoded.service_code = GetUInt16LE(bytes + offset);
    offset += 2;
    memcpy(decoded.idm, bytes + offset, sizeof(decoded.idm));
    offset += sizeof(decoded.idm);
    memcpy(decoded.pmm_tail, bytes + offset, sizeof(decoded.pmm_tail));
    offset += sizeof(decoded.pmm_tail);
    decoded.block_count = bytes[offset++];
    memcpy(decoded.blocks, bytes + offset, sizeof(decoded.blocks));
    decoded.checksum = GetUInt32LE(bytes + kChecksumOffset);
    if (!IsProfileRecordFormat(decoded)) return false;
    *record = decoded;
    return true;
}

bool DecodeProfileRecord(const ProfileRecord &record, Profile *profile) {
    if (profile == nullptr || !IsProfileRecordFormat(record)) return false;
    memset(profile, 0, sizeof(*profile));
    profile->system_code = record.system_code;
    profile->service_code = record.service_code;
    memcpy(profile->idm, record.idm, sizeof(profile->idm));
    memcpy(profile->pmm_tail, record.pmm_tail, sizeof(profile->pmm_tail));
    profile->block_count = record.block_count;
    memcpy(profile->blocks, record.blocks, sizeof(profile->blocks));
    return true;
}

}  // namespace nfcf
