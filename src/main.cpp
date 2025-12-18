/*
 *
 * Copyright (c) 2025 Troot0Fobia. All Rights Reserved.
 */

#include <sstream>
#define PLUGIN_API_BUILD
#include "api_DTOs.hpp"
#include "plugin_api.hpp"
#include "requester/requester.hpp"
#include <cstdint>
#include <curl/curl.h>
#include <format>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/poll.h>
#endif


#include <filesystem>
#include <fstream>
#include <string>
static void WriteResponse(const std::string &filepath,
                          const std::vector<uint8_t> &data,
                          int interface_type) {
    std::string newFilePath =
        std::format("{}{}",
                    filepath,
                    interface_type == INTERFACE_TYPE_BINARY ? "bin" : "json");
    std::error_code err_code;
    std::filesystem::path path(newFilePath);
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
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

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

static void PLUGIN_API_CALL changeSessionState(const void *const session_p,
                                               const char *state_name,
                                               int value) {
    Session *const session =
        reinterpret_cast<Session *>(const_cast<void *>(session_p));

    if (!std::string(state_name).compare("interface_type")) {
        session->interface_type = value;
    }
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
    std::string_view interface_type = "";

    for (int i = 1; i < 3; i++) {
        if (i == 1) {
            session->interface_type = INTERFACE_TYPE_BINARY;
            interface_type = "bin";
        } else if (i == 2) {
            session->interface_type = INTERFACE_TYPE_WEB;
            interface_type = "web";
        }

        if (!establishConnection(session, log, ctx)) {
            log(ctx, PluginLogLevel::ERROR,
                std::format(
                    "{}:{} | Failed establish {} connection with proxy {} "
                    "while validate address",
                    addr->ip,
                    addr->port,
                    interface_type,
                    session->proxy->addr.ip).c_str());
            return -2;
        }

        auto request = createRequestBody(session->interface_type,
                                           RequestType::pollRequest);
        WriteResponse(std::format("responses/{}_{}/poll_request.",
                                  session->addr->ip,
                                  session->addr->port),
                      request,
                      session->interface_type);
        if (!sendRequest(session, request, log, ctx)) {
            log(ctx, PluginLogLevel::ERROR,
                std::format("{}:{} | Failed send {} poll request",
                            addr->ip, addr->port, interface_type).c_str());
            continue;
        }

        std::optional<std::vector<uint8_t>> response = receiveResponse(session);
        if (!response) {
            log(ctx, PluginLogLevel::DEBUG,
                std::format("{}:{} | No response received from {} poll request",
                            addr->ip, addr->port, interface_type).c_str());
            continue;
        }

        WriteResponse(std::format("responses/{}_{}/poll_response.",
                                  addr->ip,
                                  addr->port),
                      *response,
                      session->interface_type);
        if (!isValidResponse(*response,
                             session->interface_type,
                             RequestType::pollRequest)) {
            log(ctx, PluginLogLevel::DEBUG,
                std::format(
                    "{}:{} | Received response from {} "
                    "poll request is not valid",
                    addr->ip, addr->port, interface_type).c_str());
            continue;
        }

        if (!parsePollResponse(session->interface_type, *response)) {
            log(ctx, PluginLogLevel::ERROR,
                std::format("{}:{} | Failed parse data from {} poll response",
                            addr->ip, addr->port, interface_type).c_str());
            continue;
        }

        log(ctx,
            PluginLogLevel::VERBOSE,
            std::format("Determined iterface type for {}:{} - {}",
                        addr->ip, addr->port, interface_type).c_str());
        return session->interface_type;
    }

    return 0;
}

static int PLUGIN_API_CALL checkCreds(const void *const session_p,
                                      __Creds creds,
                                      void *const ctx,
                                      LogCallback log,
                                      PrintProcessedCallback print_processed) {
    Session *const session =
        reinterpret_cast<Session *>(const_cast<void *>(session_p));
    std::string_view interface_type =
        session->interface_type == INTERFACE_TYPE_WEB ? "web" : "bin";

    if (!establishConnection(session, log, ctx)) {
        log(ctx, PluginLogLevel::ERROR,
            std::format("{}:{} - {} | Failed establish connection "
                        "with proxy {} while check creds",
                        session->addr->ip,
                        session->addr->port,
                        interface_type,
                        session->proxy->addr.ip).c_str());
        return -2;
    }

    if (!sendRequest(session,
                     createRequestBody(session->interface_type,
                                       RequestType::pollRequest),
                     log,
                     ctx)) {
        log(ctx, PluginLogLevel::ERROR,
            std::format("{}:{} | Failed send {} poll request in check creds",
                        session->addr->ip,
                        session->addr->port,
                        interface_type).c_str());
        return 0;
    }

    std::optional<std::vector<uint8_t>> response = receiveResponse(session);
    if (!response) {
        log(ctx, PluginLogLevel::DEBUG,
            std::format(
                "{}:{} | No response received from {} poll request "
                "in check creds",
                session->addr->ip,
                session->addr->port,
                interface_type).c_str());
        return 0;
    }

    WriteResponse(std::format("responses/{}_{}/creds_poll_response_{}_{}.",
                              session->addr->ip,
                              session->addr->port,
                              creds.login,
                              creds.password),
                  *response,
                  session->interface_type);
    if (!isValidResponse(*response,
                         session->interface_type,
                         RequestType::pollRequest)) {
        log(ctx, PluginLogLevel::DEBUG,
            std::format(
                "{}:{} | Received response from {} poll request in check "
                "creds is not valid",
                session->addr->ip,
                session->addr->port,
                interface_type).c_str());
        return 0;
    }

    auto device_data = parsePollResponse(session->interface_type, *response);
    if (!device_data) {
        log(ctx, PluginLogLevel::ERROR,
            std::format(
                "{}:{} | Failed parse data from {} poll response "
                "in check creds",
                session->addr->ip,
                session->addr->port,
                interface_type).c_str());
        return 0;
    }

    std::vector<uint8_t> requestBody;
    std::string_view username = creds.login;
    std::string_view password = creds.password;
    std::vector<uint8_t> payload = createPayload(*device_data,
                                                 username,
                                                 password);
    if (payload.empty()) {
        log(ctx, PluginLogLevel::DEBUG, "Payload data is empty");
        return -2;
    }

    if (session->interface_type == INTERFACE_TYPE_BINARY) {
        requestBody = createRequestBody(INTERFACE_TYPE_BINARY,
                                        RequestType::authRequest);
        uint32_t payloadSize = payload.size();

        for (int i = 0; i < 4; ++i) {
            requestBody[i + 4] =
                static_cast<uint8_t>(payloadSize >> (i * 8)) & 0xFF;
        }
        requestBody.insert(requestBody.end(),
                           payload.begin(),
                           payload.end());
    } else if (session->interface_type == INTERFACE_TYPE_WEB) {
        requestBody = std::move(payload);
    }

    if (!sendRequest(session, requestBody, log, ctx)) {
        log(ctx, PluginLogLevel::ERROR,
            std::format("{}:{} {}:{} | Failed send {} creds request",
                        session->addr->ip,
                        session->addr->port,
                        creds.login,
                        creds.password,
                        interface_type).c_str());
        return 0;
    }

    response = receiveResponse(session);
    if (!response) {
        log(ctx, PluginLogLevel::DEBUG,
            std::format(
                "{}:{} {}:{} | No {} response received from checking creds",
                session->addr->ip,
                session->addr->port,
                creds.login,
                creds.password,
                interface_type).c_str());
        return 0;
    }

    WriteResponse(std::format("responses/{}_{}/creds_response_{}_{}.",
                              session->addr->ip,
                              session->addr->port,
                              creds.login,
                              creds.password),
                  *response,
                  session->interface_type);
    if (!isValidResponse(*response,
                         session->interface_type,
                         RequestType::authRequest)) {
        log(ctx, PluginLogLevel::DEBUG,
            std::format(
                "{}:{} {}:{} | Received {} response from checking creds "
                "is not valid",
                session->addr->ip,
                session->addr->port,
                creds.login,
                creds.password,
                interface_type).c_str());
        return 0;
    }

    if (session->interface_type == INTERFACE_TYPE_BINARY) {
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
    } else if (session->interface_type == INTERFACE_TYPE_WEB) {
        int validation_res = validateResponse(*response);
        if (validation_res == -1) {
            log(ctx, PluginLogLevel::VERBOSE,
                std::format("{}:{} | Camera is blocked",
                            session->addr->ip,
                            session->addr->port).c_str());
            print_processed(ctx, session->addr, "blocked");
            return -1;
        } else if (validation_res == 1) {
            log(ctx, PluginLogLevel::VERBOSE,
                std::format("Found valid creds for camera | {}:{} {}:{}",
                            session->addr->ip,
                            session->addr->port,
                            creds.login,
                            creds.password).c_str());
            print_processed(ctx, session->addr, "valid");
            return 1;
        } else if (validation_res == -2) {
            log(ctx, PluginLogLevel::VERBOSE,
                std::format("{}:{} | Something strange with plugins",
                            session->addr->ip,
                            session->addr->port).c_str());
            print_processed(ctx, session->addr, "required_plugin");
            return -1;
        } else if (validation_res == -3) {
            log(ctx, PluginLogLevel::VERBOSE,
                std::format("{}:{} {}:{} | Invalid username was provided",
                            session->addr->ip,
                            session->addr->port,
                            creds.login,
                            creds.password).c_str());
            return -3;
        }
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
        if (session->headers_list) {
            curl_slist_free_all(session->headers_list);
            session->headers_list = nullptr;
        }
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
#ifdef _WIN32
    WSACleanup();
#endif
}

static PluginAPI api = {
    &initPlugin,
    &createSession,
    &changeSessionState,
    &getVersion,
    &validateAddr,
    &checkCreds,
    &closeSession,
    &shutdownPlugin,
};

PLUGIN_API_EXPORT PluginAPI* PLUGIN_API_CALL get_plugin_api() {
    return &api;
}

