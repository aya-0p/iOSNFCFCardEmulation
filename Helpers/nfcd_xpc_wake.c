#include <dispatch/dispatch.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// The stripped-down Theos SDK used here omits xpc/xpc.h. These declarations
// match the libxpc C ABI used by this narrowly scoped launch probe.
typedef void *xpc_object_t;
typedef void *xpc_connection_t;
extern xpc_connection_t xpc_connection_create_mach_service(
    const char *name, dispatch_queue_t target_queue, uint64_t flags);
extern void xpc_connection_set_event_handler(
    xpc_connection_t connection, void (^handler)(xpc_object_t event));
extern void xpc_connection_resume(xpc_connection_t connection);
extern void xpc_connection_send_message(
    xpc_connection_t connection, xpc_object_t message);
extern void xpc_connection_cancel(xpc_connection_t connection);
extern xpc_object_t xpc_dictionary_create(
    const char *const *keys, const xpc_object_t *values, size_t count);
extern char *xpc_copy_description(xpc_object_t object);
extern void xpc_release(xpc_object_t object);

int main(void) {
    dispatch_queue_t queue = dispatch_queue_create(
        "org.hoshitsugi.iosnfcfcardemulation.xpcwake", NULL);
    xpc_connection_t connection = xpc_connection_create_mach_service(
        "com.apple.nfcd.hwmanager", queue, 0);
    if (connection == NULL) {
        fputs("xpc_connection_create_mach_service failed\n", stderr);
        return 1;
    }

    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        char *description = xpc_copy_description(event);
        fprintf(stderr, "xpc event: %s\n", description ? description : "unknown event");
        free(description);
    });
    xpc_connection_resume(connection);

    xpc_object_t empty = xpc_dictionary_create(NULL, NULL, 0);
    if (empty == NULL) {
        fputs("xpc_dictionary_create failed\n", stderr);
        xpc_connection_cancel(connection);
        return 2;
    }
    puts("sending one empty dictionary to com.apple.nfcd.hwmanager");
    fflush(stdout);
    xpc_connection_send_message(connection, empty);
    xpc_release(empty);

    sleep(3);
    xpc_connection_cancel(connection);
    sleep(1);
    return 0;
}
