/*
 *
 * Copyright (c) 2025 Troot0Fobia. All Rights Reserved.
 */

#define PLUGIN_API_BUILD
#include "api_DTOs.hpp"
#include "hasher/hasher.hpp"
#include "plugin_api.hpp"
#include "requester/requester.hpp"
#include <cstdint>
#include <curl/curl.h>
#include <optional>
#include <string_view>
#include <sys/poll.h>
#include <vector>

#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <system_error>
static void WriteResponse(const std::string &filepath,
                          const std::vector<uint8_t> &data) {
    std::error_code err_code;
    std::filesystem::path path(filepath);
    std::filesystem::create_directories(path.parent_path(), err_code);
    std::ofstream outputFile(path, std::ios::binary);

    if (outputFile) {
        outputFile.write(reinterpret_cast<const char *>(data.data()),
                         static_cast<std::streamsize>(data.size()));
    }
}

static int PLUGIN_API_CALL initPlugin() {
    CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
    if (res != CURLE_OK) {
        return -1;
    }

    return 0;
}

static const void *const PLUGIN_API_CALL createSession(const __Proxy *proxy) {
    Session *session = new Session();
    if (!session) {
        return nullptr;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        return nullptr;
    }

    session->curl = curl;
    session->proxy = proxy;

    return reinterpret_cast<const void *const>(session);
}

static const char *PLUGIN_API_CALL getVersion() noexcept {
    return "0.0.1";
}

static int PLUGIN_API_CALL validateAddr(const void *const session_p,
                                        const __Addr* addr,
                                        void* const ctx,
                                        LogCallback log) {
    Session *const session =
        reinterpret_cast<Session *>(const_cast<void *>(session_p));

    session->addr = addr;
    if (!establishConnection(session)) {
        log(ctx, PluginLogLevel::ERROR,
            std::format(
                "{}:{} | Failed establish connection with proxy {} "
                "while validate address",
                addr->ip,
                addr->port,
                session->proxy->addr.ip).c_str());
        return 0;
    }

    auto request = createRequestBody(RequestType::pollRequest);
    WriteResponse(std::format("responses/{}_{}/poll_request.bin",
                              addr->ip, addr->port),
                  request);
    if (!sendRequest(session, request)) {
        log(ctx, PluginLogLevel::ERROR,
            std::format("{}:{} | Failed send poll request",
                        addr->ip,
                        addr->port).c_str());
        return 0;
    }

    std::optional<std::vector<uint8_t>> response = receiveResponse(session);
    if (!response) {
        log(ctx, PluginLogLevel::DEBUG,
            std::format("{}:{} | No response received from poll request",
                        addr->ip,
                        addr->port).c_str());
        return 0;
    }

    WriteResponse(std::format("responses/{}_{}/poll_response.bin",
                              addr->ip, addr->port),
                  *response);
    if (!isValidResponse(*response, RequestType::pollRequest)) {
        log(ctx, PluginLogLevel::DEBUG,
            std::format(
                "{}:{} | Received response from poll request is not valid",
                addr->ip,
                addr->port).c_str());
        return 0;
    }

    std::string_view poll_response_payload(
        reinterpret_cast<const char *>(response->data() + 32),
        response->size() - 32);

    if (!parsePollResponse(poll_response_payload)) {
        log(ctx, PluginLogLevel::ERROR,
            std::format("{}:{} | Failed parse data from poll response",
                        addr->ip,
                        addr->port).c_str());
        return 0;
    }

    return 1;
}

static int PLUGIN_API_CALL checkCreds(const void *const session_p,
                                      __Creds creds,
                                      void *const ctx,
                                      LogCallback log,
                                      PrintProcessedCallback print_processed) {
    Session *const session =
        reinterpret_cast<Session *>(const_cast<void *>(session_p));

    if (!establishConnection(session)) {
        log(ctx, PluginLogLevel::ERROR,
            std::format("{}:{} | Failed establish connection with proxy {} "
                        "while check creds",
                        session->addr->ip,
                        session->addr->port,
                        session->proxy->addr.ip).c_str());
        return 0;
    }

    if (!sendRequest(session, createRequestBody(RequestType::pollRequest))) {
        log(ctx, PluginLogLevel::ERROR,
            std::format("{}:{} | Failed send poll request in check creds",
                        session->addr->ip,
                        session->addr->port).c_str());
        return 0;
    }

    std::optional<std::vector<uint8_t>> response = receiveResponse(session);
    if (!response) {
        log(ctx, PluginLogLevel::DEBUG,
            std::format(
                "{}:{} | No response received from poll request in check creds",
                session->addr->ip,
                session->addr->port).c_str());
        return 0;
    }

    WriteResponse(std::format("responses/{}_{}/creds_poll_response_{}_{}.bin",
                              session->addr->ip,
                              session->addr->port,
                              creds.login,
                              creds.password),
                  *response);
    if (!isValidResponse(*response, RequestType::pollRequest)) {
        log(ctx, PluginLogLevel::DEBUG,
            std::format(
                "{}:{} | Received response from poll request in check "
                "creds is not valid",
                session->addr->ip,
                session->addr->port).c_str());
        return 0;
    }

    std::string_view poll_response_payload(
        reinterpret_cast<const char *>(response->data() + 32),
        response->size() - 32);

    auto device_data = parsePollResponse(poll_response_payload);
    if (!device_data) {
        log(ctx, PluginLogLevel::ERROR,
            std::format(
                "{}:{} | Failed parse data from poll response in check creds",
                session->addr->ip,
                session->addr->port).c_str());
        return 0;
    }

    std::vector<uint8_t> requestBody =
        createRequestBody(RequestType::authRequest);

    std::vector<uint8_t> payload =
        createPayload(std::string_view(device_data->first),
                      std::string_view(device_data->second),
                      std::string_view(creds.login),
                      std::string_view(creds.password));
    uint32_t payloadSize = payload.size();

    for (int i = 0; i < 4; ++i) {
        requestBody[i + 4] =
            static_cast<uint8_t>(payloadSize >> (i * 8)) & 0xFF;
    }

    requestBody.insert(requestBody.end(), payload.begin(), payload.end());

    if (!sendRequest(session, requestBody)) {
        log(ctx, PluginLogLevel::ERROR,
            std::format("{}:{} {}:{} | Failed send creds request",
                        session->addr->ip,
                        session->addr->port,
                        creds.login,
                        creds.password).c_str());
        return 0;
    }

    response = receiveResponse(session);
    if (!response) {
        log(ctx, PluginLogLevel::DEBUG,
            std::format(
                "{}:{} {}:{} | No response received from checking creds",
                session->addr->ip,
                session->addr->port,
                creds.login,
                creds.password).c_str());
        return 0;
    }

    WriteResponse(std::format("responses/{}_{}/creds_response_{}_{}.bin",
                              session->addr->ip,
                              session->addr->port,
                              creds.login,
                              creds.password),
                  *response);
    if (!isValidResponse(*response, RequestType::authRequest)) {
        log(ctx, PluginLogLevel::DEBUG,
            std::format(
                "{}:{} {}:{} | Received response from checking creds "
                "is not valid",
                session->addr->ip,
                session->addr->port,
                creds.login,
                creds.password).c_str());
        return 0;
    }

    if ((*response)[8] == 0x01 && (*response)[9] == 0x04) {
        log(ctx, PluginLogLevel::VERBOSE,
            std::format("{}:{} | Camera is blocked",
                        session->addr->ip,
                        session->addr->port).c_str());
        print_processed(ctx, session->addr, "blocked");
        return -1;  // Camera is blocked
    } else if ((*response)[8] == 0x00) {
        log(ctx, PluginLogLevel::VERBOSE,
            std::format("Found valid creds for camera | {}:{} {}:{}",
                        session->addr->ip,
                        session->addr->port,
                        creds.login,
                        creds.password).c_str());
        print_processed(ctx, session->addr, "valid");
        return 1;  // Creds are valid
    }

    return 0;  // Unknow state. Maybe creds are invalid
}

static void PLUGIN_API_CALL closeSession(const void *const session_p) {
    if (!session_p) {
        return;
    }

    Session *session =
        reinterpret_cast<Session *>(const_cast<void *>(session_p));

    if (session) {
        if (session->curl) {
            curl_easy_cleanup(session->curl);
            session->curl = nullptr;
        }
        delete session;
        session = nullptr;
    }
}

static void PLUGIN_API_CALL shutdownPlugin() {
    curl_global_cleanup();
}

static PluginAPI api = {
    &initPlugin,
    &createSession,
    &getVersion,
    &validateAddr,
    &checkCreds,
    &closeSession,
    &shutdownPlugin,
};

PLUGIN_API_EXPORT PluginAPI* PLUGIN_API_CALL get_plugin_api() {
    return &api;
}

