#ifndef SNIFFER_MODULES_WEBSOCKET_C_INCLUDED
#define SNIFFER_MODULES_WEBSOCKET_C_INCLUDED

#include <libwebsockets.h>
#include <json-c/json.h>
#include <string.h>
#include <stdio.h>

static struct lws_context *context;
static struct lws *wsi;
static int interrupted = 0;

// ws callback
static int websocket_callback(struct lws *wsi, enum lws_callback_reasons reason,
                              void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            printf("WebSocket connection established.\n");
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE:
            printf("WebSocket ready to send data.\n");
            break;

        case LWS_CALLBACK_CLOSED:
            printf("WebSocket connection closed.\n");
            interrupted = 1;
            break;

        default:
            break;
    }
    return 0;
}

// ws protos
static struct lws_protocols protocols[] = {
    { "example-protocol", websocket_callback, 0, 1024, 0, NULL, 0 },
    { NULL, NULL, 0, 0, 0, NULL, 0 } // ending
};

// init ws client
void init_websocket() {
    printf("Connecting WebSocket...\n");
    struct lws_context_creation_info info;
    struct lws_client_connect_info ccinfo = { 0 };

    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;

    context = lws_create_context(&info);
    if (!context) {
        fprintf(stderr, "Failed to create WebSocket context.\n");
        exit(1);
    }

    ccinfo.context = context;
    ccinfo.address = "127.0.0.1";
    ccinfo.port = 9999;
    ccinfo.path = "/";
    ccinfo.protocol = protocols[0].name;

    wsi = lws_client_connect_via_info(&ccinfo);
    if (!wsi) {
        fprintf(stderr, "Failed to connect to WebSocket server.\n");
        lws_context_destroy(context);
        exit(1);
    }

    printf("WebSocket connected.\n");
}


void broadcast(char *buffer, size_t buffer_length) {
    printf("Bf size: %lu\n", buffer_length);
    
    if (wsi == NULL) {
        fprintf(stderr, "Error: WebSocket connection is not initialized.\n");
        return;
    }

    if (buffer_length > (BUFFER_SIZE - LWS_PRE)) {
        fprintf(stderr, "Error: buffer overflow.\n");
        return;
    }

    unsigned char buf[LWS_PRE + BUFFER_SIZE];
    unsigned char *p = &buf[LWS_PRE];

    memcpy(p, buffer, buffer_length);
    lws_callback_on_writable(wsi);

    // sending
    int n = lws_write(wsi, p, buffer_length, LWS_WRITE_TEXT);
    if (n < 0) {
        fprintf(stderr, "Errored while sending by WebSocket.\n");
    } else {
        printf("Sent by WebSocket: %s\n", buffer);
    }
}

#endif