/*
 *
 * Copyright (c) 2025 Troot0Fobia. All Rights Reserved.
 */

#include "requester.hpp"
#include "api_DTOs.hpp"
#include "binary_interface/binary_interface.hpp"
#include "plugin_api.hpp"
#include "web_interface/web_interface.hpp"
#include <cstdint>
#include <curl/curl.h>
#include <format>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>


bool establishConnection(Session *const session, LogCallback log, void *ctx) {
    if (!session || !session->proxy || !session->curl || !session->addr) {
        log(ctx,
            PluginLogLevel::ERROR,
            "Not session or proxy or curl handler or addr does not provided");

        if (!session) {
            log(ctx, PluginLogLevel::DEBUG, "Session does not provided");
        } else if (!session->proxy) {
            log(ctx, PluginLogLevel::DEBUG, "Proxy does not provided");
        } else if (!session->curl) {
            log(ctx, PluginLogLevel::DEBUG, "Curl does not provided");
        } else if (!session->addr) {
            log(ctx, PluginLogLevel::DEBUG, "Addr does not provided");
        }

        return false;
    }

    int attempts = 5;
    std::string_view interface_type =
        session->interface_type == INTERFACE_TYPE_WEB ? "web" : "bin";
    while (attempts--) {
        log(ctx,
            PluginLogLevel::DEBUG,
            std::format("Attempt #{} to establish {} connection",
                        5 - attempts, interface_type).c_str());

        curl_easy_cleanup(session->curl);
        session->curl = curl_easy_init();

        curl_easy_setopt(session->curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
        curl_easy_setopt(session->curl, CURLOPT_PROXY, session->proxy->addr.ip);
        curl_easy_setopt(session->curl, CURLOPT_PROXYPORT,
                         session->proxy->addr.port);
        curl_easy_setopt(session->curl, CURLOPT_PROXYUSERNAME,
                         session->proxy->creds.login);
        curl_easy_setopt(session->curl, CURLOPT_PROXYPASSWORD,
                         session->proxy->creds.password);
        curl_easy_setopt(session->curl, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(session->curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(session->curl, CURLOPT_SERVER_RESPONSE_TIMEOUT, 25L);

        if (session->interface_type == INTERFACE_TYPE_BINARY) {
            if (!binary_interface::configureCurl(session, log, ctx)) {
                continue;
            }
        } else if (session->interface_type == INTERFACE_TYPE_WEB) {
            web_interface::configureCurl(session);
        } else {
            return false;
        }

        return true;
    }

    return false;
}

std::vector<uint8_t> createRequestBody(int interface_type,
                                       uint8_t requestType) {
    if (interface_type == INTERFACE_TYPE_BINARY) {
        return binary_interface::createRequestBody(requestType);
    } else if (interface_type == INTERFACE_TYPE_WEB) {
        return web_interface::createRequestBody();
    }

    return {};
}

bool sendRequest(Session *const session,
                 const std::vector<uint8_t> &data,
                 LogCallback log,
                 void *ctx) {
    if (data.empty()) {
        log(ctx, PluginLogLevel::DEBUG, "While send request body is empty");
        return false;
    }

    if (session->interface_type == INTERFACE_TYPE_BINARY) {
        return binary_interface::sendRequest(session, data, log, ctx);
    } else if (session->interface_type == INTERFACE_TYPE_WEB) {
        return web_interface::sendRequest(session, data, log, ctx);
    }

    return false;
}

std::optional<std::vector<uint8_t>> receiveResponse(Session *const session) {
    if (session->interface_type == INTERFACE_TYPE_BINARY) {
        return binary_interface::receiveResponse(session);
    } else if (session->interface_type == INTERFACE_TYPE_WEB) {
        return web_interface::receiveResponse(session);
    }

    return std::nullopt;
}

bool isValidResponse(const std::vector<uint8_t> &response,
                     int interface_type,
                     RequestType type) {
    if (interface_type == INTERFACE_TYPE_BINARY) {
        return binary_interface::isValidResponse(response, type);
    } else if (interface_type == INTERFACE_TYPE_WEB) {
        return web_interface::isValidResponse(response, type);
    }

    return false;
}

std::optional<std::variant<std::pair<std::string_view, std::string_view>,
                           std::string_view>>
parsePollResponse(int interface_type, const std::vector<uint8_t> &response) {
    if (interface_type == INTERFACE_TYPE_BINARY) {
        return binary_interface::parsePollResponse(std::string_view(
            reinterpret_cast<const char *>(response.data() + 32),
            response.size() - 32));
    } else if (interface_type == INTERFACE_TYPE_WEB) {
        return std::string_view(
            reinterpret_cast<const char *>(response.data()), response.size());
    }

    return std::nullopt;
}

std::vector<uint8_t>
createPayload(const std::variant<std::pair<std::string_view, std::string_view>,
                                 std::string_view> &device_data,
              std::string_view username,
              std::string_view password) {
    if (auto binary_data =
            std::get_if<std::pair<std::string_view,
                                  std::string_view>>(&device_data)) {
        return binary_interface::createPayload(
            binary_data->first, binary_data->second, username, password);
    } else if (auto web_data =
                   std::get_if<std::string_view>(&device_data)) {
        return web_interface::createPayload(*web_data, username, password);
    }

    return {};
}

int validateResponse(const std::vector<uint8_t> &response) {
    return web_interface::validateResponse(response);
}

