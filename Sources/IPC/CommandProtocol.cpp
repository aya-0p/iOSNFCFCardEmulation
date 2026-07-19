#include "CommandProtocol.hpp"

#include "../Core/BackendPaths.hpp"
#include "../Core/SecureFile.hpp"

#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

namespace nfcf_backend {

#pragma pack(push, 1)
struct CommandRequest {
    uint8_t magic[8];
    uint32_t version;
    uint32_t command;
    uint32_t process_id;
    uint32_t user_id;
    uint64_t issued_at;
    uint8_t nonce[16];
    uint32_t checksum;
};
#pragma pack(pop)

static constexpr uint8_t kMagic[8] = {'N', 'F', 'C', 'F', 'C', 'M', 'D', 0};
static constexpr uint32_t kVersion = 1;
static constexpr uint64_t kMaximumAgeSeconds = 30;

static uint32_t Checksum(const CommandRequest &request) {
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&request);
    uint32_t value = 2166136261u;
    for (size_t index = 0; index < offsetof(CommandRequest, checksum); ++index) {
        value ^= bytes[index];
        value *= 16777619u;
    }
    return value;
}

struct CommandDescriptor {
    Command command;
    const char *name;
    const char *notification;
};

static constexpr CommandDescriptor kCommands[] = {
    {Command::kPrewarmOpen, "prewarm-open", "org.hoshitsugi.iosnfcfcardemulation.command.prewarm.open"},
    {Command::kPrewarmClose, "prewarm-close", "org.hoshitsugi.iosnfcfcardemulation.command.prewarm.close"},
    {Command::kRoutingOff, "routing-off", "org.hoshitsugi.iosnfcfcardemulation.command.routing.off"},
    {Command::kRoutingRestore, "routing-restore", "org.hoshitsugi.iosnfcfcardemulation.command.routing.restore"},
    {Command::kT3TPatch, "t3t-patch", "org.hoshitsugi.iosnfcfcardemulation.command.t3t.patch"},
    {Command::kT3TRestore, "t3t-restore", "org.hoshitsugi.iosnfcfcardemulation.command.t3t.restore"},
    {Command::kSetCEStart, "setce-start", "org.hoshitsugi.iosnfcfcardemulation.command.setce.start"},
    {Command::kSetCEStop, "setce-stop", "org.hoshitsugi.iosnfcfcardemulation.command.setce.stop"},
    {Command::kSetCERecover, "setce-recover", "org.hoshitsugi.iosnfcfcardemulation.command.setce.recover"},
    {Command::kSetCEStatus, "setce-status", "org.hoshitsugi.iosnfcfcardemulation.command.setce.status"},
    {Command::kProfileApply, "profile-apply", "org.hoshitsugi.iosnfcfcardemulation.command.profile.apply"},
    {Command::kProfileStatus, "profile-status", "org.hoshitsugi.iosnfcfcardemulation.command.profile.status"},
    {Command::kProfileClear, "profile-clear", "org.hoshitsugi.iosnfcfcardemulation.command.profile.clear"},
};

const char *CommandName(Command command) {
    for (const auto &descriptor : kCommands)
        if (descriptor.command == command) return descriptor.name;
    return nullptr;
}

const char *CommandNotification(Command command) {
    for (const auto &descriptor : kCommands)
        if (descriptor.command == command) return descriptor.notification;
    return nullptr;
}

bool ParseCommandName(const char *name, Command *command) {
    if (name == nullptr || command == nullptr) return false;
    for (const auto &descriptor : kCommands) {
        if (strcmp(descriptor.name, name) == 0) {
            *command = descriptor.command;
            return true;
        }
    }
    return false;
}

bool WriteCommandRequestAtPath(const char *path, Command command,
                               const uint8_t nonce[16]) {
    if (path == nullptr || nonce == nullptr || CommandName(command) == nullptr)
        return false;
    CommandRequest request = {};
    memcpy(request.magic, kMagic, sizeof(kMagic));
    request.version = kVersion;
    request.command = static_cast<uint32_t>(command);
    request.process_id = static_cast<uint32_t>(getpid());
    request.user_id = static_cast<uint32_t>(getuid());
    request.issued_at = static_cast<uint64_t>(time(nullptr));
    memcpy(request.nonce, nonce, sizeof(request.nonce));
    request.checksum = Checksum(request);
    return WriteSecureFileAtomically(path, &request, sizeof(request));
}

bool ConsumeCommandRequestAtPath(const char *path, Command expected,
                                 uint64_t now) {
    CommandRequest request = {};
    bool read = ReadSecureFileExact(path, &request, sizeof(request), getuid());
    (void)unlink(path);
    if (!read || memcmp(request.magic, kMagic, sizeof(kMagic)) != 0 ||
        request.version != kVersion ||
        request.command != static_cast<uint32_t>(expected) ||
        request.user_id != static_cast<uint32_t>(getuid()) ||
        request.process_id == 0 || request.checksum != Checksum(request) ||
        request.issued_at > now || now - request.issued_at > kMaximumAgeSeconds) {
        return false;
    }
    return true;
}

bool WriteCommandRequest(Command command, const uint8_t nonce[16]) {
    return EnsurePrivateDirectory(kStateDirectory) &&
           WriteCommandRequestAtPath(kCommandRequestPath, command, nonce);
}

bool ConsumeCommandRequest(Command expected) {
    return ConsumeCommandRequestAtPath(
        kCommandRequestPath, expected, static_cast<uint64_t>(time(nullptr)));
}

}  // namespace nfcf_backend
