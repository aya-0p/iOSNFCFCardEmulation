#pragma once

namespace nfcf_backend {

inline constexpr const char *kStateDirectory =
    "/var/jb/usr/libexec/iosnfcf/state";
inline constexpr const char *kCommandRequestPath =
    "/var/jb/usr/libexec/iosnfcf/state/command.request";
inline constexpr const char *kProfileRecordPath =
    "/var/jb/usr/libexec/iosnfcf/state/profile.record";

inline constexpr const char *kObserverResultPath =
    "/var/jb/usr/libexec/iosnfcf/state/nci-read.log";
inline constexpr const char *kObserverReadyPath =
    "/var/jb/usr/libexec/iosnfcf/state/nci-read.ready";
inline constexpr const char *kNCIObserverResultPath =
    "/var/jb/usr/libexec/iosnfcf/state/nci.log";
inline constexpr const char *kStackObserverResultPath =
    "/var/jb/usr/libexec/iosnfcf/state/stack.log";
inline constexpr const char *kProfileResultPath =
    "/var/jb/usr/libexec/iosnfcf/state/profile.result";
inline constexpr const char *kProfileReadyPath =
    "/var/jb/usr/libexec/iosnfcf/state/profile.ready";
inline constexpr const char *kPrewarmResultPath =
    "/var/jb/usr/libexec/iosnfcf/state/prewarm.result";
inline constexpr const char *kRoutingResultPath =
    "/var/jb/usr/libexec/iosnfcf/state/routing.result";
inline constexpr const char *kSetCEResultPath =
    "/var/jb/usr/libexec/iosnfcf/state/setce.result";
inline constexpr const char *kRoutePatchResultPath =
    "/var/jb/usr/libexec/iosnfcf/state/t3t-route.result";
}  // namespace nfcf_backend
