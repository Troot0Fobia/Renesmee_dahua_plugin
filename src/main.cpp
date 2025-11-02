/*
 *
 * Copyright (c) 2025 Troot0Fobia. All Rights Reserved.
 */

#define PLUGIN_API_BUILD
#include "plugin_api.hpp"

static const char *PLUGIN_API_CALL getVersion() noexcept {
    return "0.0.1";
}

static int PLUGIN_API_CALL validateAddr(const __Addr *addr,
                                        void *const ctx,
                                        LogCallback log) {
  return 0;
}

static int PLUGIN_API_CALL sendRequest(const __Addr *const addr,
                                       const __Proxy *proxy, __Creds creds,
                                       void *const ctx, LogCallback log,
                                       PrintProcessedCallback print_processed) {
    return 0;
}
