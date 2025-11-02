/*
 * This file is readonly! And used only for your help.
 * You can use it like interface for implementing
 * functions which used in main application.
 *
 * Implement all functions that included in PluginAPI structure.
 */

#pragma once

#ifndef PLUGIN_API_H
#define PLUGIN_API_H

#include "api_DTOs.hpp"

#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
    #ifdef PLUGIN_API_BUILD
        #define PLUGIN_API_EXPORT __declspec(dllexport)
    #else
        #define PLUGIN_API_EXPORT
    #endif
    #define PLUGIN_API_CALL __cdecl
#else
    #define PLUGIN_API_EXPORT __attribute__((visibility("default")))
    #define PLUGIN_API_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum VerboseLogLevel { VERBOSE = 0, DEBUG };
using LogCallback = void (*)(void* ctx, VerboseLogLevel level, const char* msg);
using PrintProcessedCallback = void (*)(void* ctx, const __Addr* addr, const char* status);
using GetPluginVersion = const char* (PLUGIN_API_CALL *)() noexcept;
using ValidateAddr = int (PLUGIN_API_CALL *)(const __Addr* addr,
                                             void* const ctx,
                                             LogCallback log);
using SendRequest = int (PLUGIN_API_CALL *)(const __Addr* const addr,
                                            const __Proxy* proxy,
                                            __Creds creds,
                                            void* const ctx,
                                            LogCallback log,
                                            PrintProcessedCallback print_processed);

struct PLUGIN_API_EXPORT PluginAPI {
    GetPluginVersion  getVersion;
    ValidateAddr validateAddr;
    SendRequest sendRequest;
};

PLUGIN_API_EXPORT struct PluginAPI* PLUGIN_API_CALL get_plugin_api();

#ifdef __cplusplus
}
#endif

#endif // PLUGIN_API_H
