/*
 * This file is readonly! And used only for your help.
 * You can use it like interface for implementing
 * functions which used in main application.
 *
 * Implement all functions that included in PluginAPI structure.
 *
 * Copyright (c) 2025 Troot0Fobia. All Rights Reserved.
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

enum PluginLogLevel { VERBOSE = 0, DEBUG, ERROR };
using LogCallback = void (*)(void* ctx, PluginLogLevel level, const char* msg);
using PrintProcessedCallback = void (*)(void* ctx,
                                        const __Addr* addr,
                                        const char* status);

using InitPlugin = int (PLUGIN_API_CALL *)();
using ShutdownPlugin = void (PLUGIN_API_CALL *)();
using CreateSession =
    const void *const (PLUGIN_API_CALL *)(const __Proxy *proxy);
using CloseSession = void (PLUGIN_API_CALL *) (const void *const session_p);
using GetPluginVersion = const char* (PLUGIN_API_CALL *)() noexcept;
using ValidateAddr = int (PLUGIN_API_CALL *)(const void *const session_p,
                                             const __Addr* addr,
                                             void* const ctx,
                                             LogCallback log);
using CheckCreds = int (PLUGIN_API_CALL *)(const void *const session,
                                           __Creds creds,
                                           void* const ctx,
                                           LogCallback log,
                                           PrintProcessedCallback print_processed);

struct PLUGIN_API_EXPORT PluginAPI {
    InitPlugin initPlugin;
    CreateSession createSession;
    GetPluginVersion getVersion;
    ValidateAddr validateAddr;
    CheckCreds checkCreds;
    CloseSession closeSession;
    ShutdownPlugin shutdownPlugin;
};

PLUGIN_API_EXPORT struct PluginAPI* PLUGIN_API_CALL get_plugin_api();

#ifdef __cplusplus
}
#endif

#endif  // PLUGIN_API_H

