/*
 *
 *
 * Copyright (c) 2025 Me. All Rights Reserved.
 */

#pragma once

#include <cstdint>
#include <openssl/evp.h>
#include <string>
#include <string_view>
#include <vector>


constexpr const char *format_str = "{}:{}:{}";

std::vector<uint8_t> to_byte_vector(std::string_view text);
std::vector<uint8_t> md5(const std::vector<uint8_t> &data);
std::string to_hex_string(const std::vector<uint8_t> &data);
std::string collapse_data(const std::vector<uint8_t> &data);
std::vector<uint8_t> createPasswordHash(std::string_view username,
                                        std::string_view realm,
                                        std::string_view random,
                                        std::string_view password);
std::vector<uint8_t> createPayload(std::string_view realm,
                                   std::string_view random,
                                   std::string_view username,
                                   std::string_view password);

