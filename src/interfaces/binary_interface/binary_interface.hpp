#pragma once

#include "plugin_api.hpp"
#include "requester/requester.hpp"
#include <cstdint>
#include <string_view>
#include <vector>

namespace binary_interface {

const std::string_view REALM_TAG = "Realm:";
const std::string_view RANDOM_TAG = "Random:";
const std::string_view EOL_TAG = "\r\n";

bool configureCurl(Session *const session, LogCallback log, void *ctx);
std::vector<uint8_t> createRequestBody(uint8_t requestType);
bool sendRequest(const Session *const session,
                 const std::vector<uint8_t> &data,
                 LogCallback log,
                 void *ctx);
std::optional<std::vector<uint8_t>> receiveResponse(Session *const session);
bool isValidResponse(const std::vector<uint8_t> &response, RequestType type);
std::optional<std::pair<std::string_view, std::string_view>>
parsePollResponse(std::string_view response);
std::vector<uint8_t> createPayload(std::string_view realm,
                                   std::string_view random,
                                   std::string_view username,
                                   std::string_view password);

}  // namespace binary_interface
