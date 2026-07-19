#include <dispatch/dispatch.h>

#include "Core/BackendPaths.hpp"
#include "Core/SecureFile.hpp"

extern "C" void NFCFInitializeProfileManager(void);
extern "C" void NFCFInitializePrewarm(void);
extern "C" void NFCFInitializeRouting(void);
extern "C" void NFCFInitializeSetCE(void);
extern "C" void NFCFInitializeT3TRoutePatch(void);
extern "C" void NFCFInitializeStackObserver(void);
extern "C" void NFCFInitializeNCIObserver(void);
extern "C" void NFCFInitializeNCIReadObserver(void);

static void InitializeBackend(void) {
    if (!nfcf_backend::EnsurePrivateDirectory(nfcf_backend::kStateDirectory))
        return;

    // Registration comes first so every state-changing command has a guarded
    // consumer before the low-level observers become active.
    NFCFInitializeProfileManager();
    NFCFInitializePrewarm();
    NFCFInitializeRouting();
    NFCFInitializeSetCE();
    NFCFInitializeT3TRoutePatch();

    // The observers validate exact image offsets and instruction bytes before
    // installing any hook. Their order is explicit to avoid constructor-order
    // dependencies between translation units.
    NFCFInitializeStackObserver();
    NFCFInitializeNCIObserver();
    NFCFInitializeNCIReadObserver();
}

__attribute__((constructor)) static void NFCFBackendRuntimeInitialize(void) {
    // opainject waits for constructors. Register and inspect images only after
    // the remote dlopen has returned to nfcd's normal execution context.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        InitializeBackend();
    });
}
