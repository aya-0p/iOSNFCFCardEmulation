#import <Foundation/Foundation.h>

#include <dispatch/dispatch.h>
#include <notify.h>
#include <string.h>
#include <unistd.h>

#include "NFCFProfileRecord.hpp"
#include "NFCFProtocol.hpp"
#include "Core/BackendPaths.hpp"
#include "Core/ResultWriter.hpp"
#include "Core/SecureFile.hpp"
#include "IPC/CommandProtocol.hpp"

static void write_profile_result(NSString *result) {
    NFCFWriteResult(nfcf_backend::kProfileResultPath, result);
}

static void apply_profile(void) {
    uint8_t encoded[nfcf::kProfileRecordEncodedSize] = {};
    nfcf::ProfileRecord record = {};
    nfcf::Profile profile = {};
    if (!nfcf_backend::ReadSecureFileExact(
            nfcf_backend::kProfileRecordPath, encoded, sizeof(encoded),
            getuid()) ||
        !nfcf::DecodeProfileRecordBytes(
            encoded, sizeof(encoded), &record) ||
        !nfcf::DecodeProfileRecord(record, &profile) ||
        !nfcf::SetActiveProfile(profile)) {
        nfcf::ClearActiveProfile();
        write_profile_result(
            @"result=refused profile=none active=0 reason=profile-validation");
        return;
    }
    write_profile_result([NSString stringWithFormat:
        @"result=0 profile=loaded active=1 blocks=%u systemCode=%04X serviceCode=%04X",
        profile.block_count, profile.system_code, profile.service_code]);
}

static void show_profile(void) {
    nfcf::Profile profile = {};
    if (!nfcf::CopyActiveProfile(&profile)) {
        write_profile_result(@"result=0 profile=none active=0");
        return;
    }
    write_profile_result([NSString stringWithFormat:
        @"result=0 profile=loaded active=1 blocks=%u systemCode=%04X serviceCode=%04X",
        profile.block_count, profile.system_code, profile.service_code]);
}

static void clear_profile(void) {
    nfcf::ClearActiveProfile();
    write_profile_result(@"result=0 profile=none active=0 cleared=1");
}

static void write_ready(void) {
    NSString *payload = [NSString stringWithFormat:@"ready=1 pid=%d\n", getpid()];
    (void)nfcf_backend::WriteSecureTextFile(
        nfcf_backend::kProfileReadyPath, payload.UTF8String);
}

extern "C" void NFCFInitializeProfileManager(void) {
    if (!nfcf_backend::EnsurePrivateDirectory(nfcf_backend::kStateDirectory))
        return;
    nfcf::ClearActiveProfile();

    static dispatch_queue_t queue = dispatch_queue_create(
        "org.hoshitsugi.iosnfcfcardemulation.profile.queue",
        DISPATCH_QUEUE_SERIAL);
    static int apply_token;
    static int status_token;
    static int clear_token;
    uint32_t apply_status = notify_register_dispatch(
        nfcf_backend::CommandNotification(nfcf_backend::Command::kProfileApply),
        &apply_token, queue, ^(int token) {
            (void)token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kProfileApply))
                apply_profile();
        });
    uint32_t status_status = notify_register_dispatch(
        nfcf_backend::CommandNotification(nfcf_backend::Command::kProfileStatus),
        &status_token, queue, ^(int token) {
            (void)token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kProfileStatus))
                show_profile();
        });
    uint32_t clear_status = notify_register_dispatch(
        nfcf_backend::CommandNotification(nfcf_backend::Command::kProfileClear),
        &clear_token, queue, ^(int token) {
            (void)token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kProfileClear))
                clear_profile();
        });
    if (apply_status != NOTIFY_STATUS_OK ||
        status_status != NOTIFY_STATUS_OK ||
        clear_status != NOTIFY_STATUS_OK) {
        if (apply_status == NOTIFY_STATUS_OK) notify_cancel(apply_token);
        if (status_status == NOTIFY_STATUS_OK) notify_cancel(status_token);
        if (clear_status == NOTIFY_STATUS_OK) notify_cancel(clear_token);
        write_profile_result(
            @"result=refused profile=none active=0 reason=notify-registration");
        return;
    }
    write_ready();
}
