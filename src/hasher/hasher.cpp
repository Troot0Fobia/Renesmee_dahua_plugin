/*
 *
 *
 * Copyright (c) 2025 Me. All Rights Reserved.
 */

#include "hasher.hpp"
#include <algorithm>
#include <cstdint>
#include <format>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>


std::vector<uint8_t> to_byte_vector(std::string_view text) {
    std::vector<uint8_t> bytes;
    bytes.reserve(text.size());
    std::transform(text.begin(), text.end(), std::back_inserter(bytes),
                   [](char ch) { return static_cast<uint8_t>(ch); });
    return bytes;
}

std::vector<uint8_t> md5(const std::vector<uint8_t> &data) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint8_t hash[EVP_MAX_MD_SIZE];
    uint32_t len = 0;

    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);

    std::vector<uint8_t> result(hash, hash + len);

    return result;
}

std::string to_hex_string(const std::vector<uint8_t> &data) {
    std::ostringstream oss;
    for (auto t : data) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(t);
    }

    return oss.str();
}

std::string collapse_data(const std::vector<uint8_t> &data) {
    std::ostringstream result;

    for (uint8_t i = 0; i < 8; ++i) {
        uint8_t collapsed_data =
            static_cast<char>((data[i * 2] + data[i * 2 + 1]) % 62);

        if (static_cast<uint8_t>(collapsed_data) > 9u) {
            if (collapsed_data < 10 || collapsed_data > 35) {
                collapsed_data += 61;
            } else {
                collapsed_data += 55;
            }
        } else {
            collapsed_data += 48;
        }
        result << collapsed_data;
    }

    return result.str();
}

std::string createFirstStep(std::string_view username,
                            std::string_view realm,
                            std::string_view random,
                            std::string_view password) {
    std::string first_step = std::format(format_str, username, realm, password);

    std::string first_step_hash =
        to_hex_string(md5(to_byte_vector(first_step)));

    for (size_t i = 0; i < first_step_hash.length(); ++i) {
        first_step_hash[i] = std::toupper(first_step_hash[i]);
    }

    std::string second_step =
        std::format(format_str, username, random, first_step_hash);

    std::string second_hashed_step =
        to_hex_string(md5(to_byte_vector(second_step)));

    for (size_t i = 0; i < second_hashed_step.length(); ++i) {
        second_hashed_step[i] = std::toupper(second_hashed_step[i]);
    }

    return second_hashed_step;
}

std::vector<uint8_t> createPasswordHash(std::string_view username,
                                        std::string_view realm,
                                        std::string_view random,
                                        std::string_view password) {
    std::string first_hashed_step =
        createFirstStep(username, realm, random, password);

    std::vector<uint8_t> password_hash = md5(to_byte_vector(password));
    std::string collapsed_pass = collapse_data(password_hash);

    std::string second_step_pass =
        std::format(format_str, username, random, collapsed_pass);

    std::string second_hashed_step =
        to_hex_string(md5(to_byte_vector(second_step_pass)));

    for (size_t i = 0; i < second_hashed_step.length(); ++i) {
        second_hashed_step[i] = std::toupper(second_hashed_step[i]);
    }

    return to_byte_vector(first_hashed_step + second_hashed_step);
}

std::vector<uint8_t> createBinPayload(std::string_view realm,
                                   std::string_view random,
                                   std::string_view username,
                                   std::string_view password) {
    std::vector<uint8_t> payload;
    std::vector<uint8_t> username_bytes = to_byte_vector(username);

    payload.insert(payload.end(), username_bytes.begin(), username_bytes.end());
    payload.emplace_back(0x26);
    payload.emplace_back(0x26);

    std::vector<uint8_t> password_hash =
        createPasswordHash(username,
                           realm,
                           random,
                           password);
    payload.insert(payload.end(), password_hash.begin(), password_hash.end());

    return payload;
}

