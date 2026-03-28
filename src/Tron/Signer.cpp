// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#include "Signer.h"

#include "Protobuf/TronInternal.pb.h"

#include "Serialization.h"
#include "../Base58.h"
#include "../BinaryCoding.h"
#include "../HexCoding.h"

#include <nlohmann/json.hpp>
#include <cassert>
#include <chrono>
#include <stdexcept>

namespace TW::Tron {

const std::string TRANSFER_TOKEN_FUNCTION = "0xa9059cbb";
using json = nlohmann::json;

namespace {

constexpr size_t kTransactionHashSize = 32;

std::string stripHexPrefix(std::string value) {
    if (value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0) {
        return value.substr(2);
    }
    return value;
}

bool parseHexString(const std::string& value, const char* fieldName, Data& bytes, std::string& errorMessage, size_t expectedSize = 0) {
    const auto normalized = stripHexPrefix(value);
    if (normalized.empty() || !is_hex_encoded(value)) {
        errorMessage = std::string("Invalid hex for field: ") + fieldName;
        return false;
    }

    bytes = parse_hex(normalized);
    if (bytes.empty()) {
        errorMessage = std::string("Invalid hex for field: ") + fieldName;
        return false;
    }

    if (expectedSize != 0 && bytes.size() != expectedSize) {
        errorMessage = std::string("Invalid length for field: ") + fieldName;
        return false;
    }

    return true;
}

const json& requireField(const json& object, const char* key) {
    if (!object.contains(key)) {
        throw std::invalid_argument(std::string("Missing required field: ") + key);
    }
    return object.at(key);
}

std::string requireString(const json& object, const char* key) {
    const auto& value = requireField(object, key);
    if (!value.is_string()) {
        throw std::invalid_argument(std::string("Expected string for field: ") + key);
    }
    return value.get<std::string>();
}

int64_t requireInt64(const json& object, const char* key) {
    const auto& value = requireField(object, key);
    if (value.is_number_integer()) {
        return value.get<int64_t>();
    }
    if (value.is_number_unsigned()) {
        return static_cast<int64_t>(value.get<uint64_t>());
    }
    if (value.is_string()) {
        return std::stoll(value.get<std::string>());
    }
    throw std::invalid_argument(std::string("Expected integer for field: ") + key);
}

bool optionalBool(const json& object, const char* key, bool defaultValue = false) {
    if (!object.contains(key)) {
        return defaultValue;
    }
    const auto& value = object.at(key);
    if (!value.is_boolean()) {
        throw std::invalid_argument(std::string("Expected bool for field: ") + key);
    }
    return value.get<bool>();
}

Data parseHexField(const json& object, const char* key) {
    return parse_hex(stripHexPrefix(requireString(object, key)));
}

Data parseAddressField(const json& object, const char* key) {
    const auto value = requireString(object, key);
    if (!value.empty() && value.front() == 'T') {
        return Base58::decodeCheck(value);
    }
    return parse_hex(stripHexPrefix(value));
}

protocol::ResourceCode parseResourceCodeField(const json& object, const char* key) {
    const auto resourceName = requireString(object, key);
    protocol::ResourceCode resource;
    if (!protocol::ResourceCode_Parse(resourceName, &resource)) {
        throw std::invalid_argument(std::string("Invalid resource code: ") + resourceName);
    }
    return resource;
}

protocol::Transaction::Contract parseContract(const json& contractJSON) {
    const auto contractTypeName = requireString(contractJSON, "type");
    protocol::Transaction::Contract::ContractType contractType;
    if (!protocol::Transaction::Contract::ContractType_Parse(contractTypeName, &contractType)) {
        throw std::invalid_argument(std::string("Unsupported contract type: ") + contractTypeName);
    }

    const auto& parameter = requireField(contractJSON, "parameter");
    const auto& value = requireField(parameter, "value");
    if (!value.is_object()) {
        throw std::invalid_argument("Expected parameter.value object");
    }

    protocol::Transaction::Contract contract;
    contract.set_type(contractType);
    google::protobuf::Any any;

    switch (contractType) {
    case protocol::Transaction::Contract::TransferContract: {
        protocol::TransferContract transfer;
        const auto owner = parseAddressField(value, "owner_address");
        const auto to = parseAddressField(value, "to_address");
        transfer.set_owner_address(owner.data(), owner.size());
        transfer.set_to_address(to.data(), to.size());
        transfer.set_amount(requireInt64(value, "amount"));
        any.PackFrom(transfer);
        break;
    }
    case protocol::Transaction::Contract::TransferAssetContract: {
        protocol::TransferAssetContract transfer;
        const auto assetName = parseHexField(value, "asset_name");
        const auto owner = parseAddressField(value, "owner_address");
        const auto to = parseAddressField(value, "to_address");
        transfer.set_asset_name(assetName.data(), assetName.size());
        transfer.set_owner_address(owner.data(), owner.size());
        transfer.set_to_address(to.data(), to.size());
        transfer.set_amount(requireInt64(value, "amount"));
        any.PackFrom(transfer);
        break;
    }
    case protocol::Transaction::Contract::FreezeBalanceContract: {
        protocol::FreezeBalanceContract freeze;
        const auto owner = parseAddressField(value, "owner_address");
        const auto receiver = parseAddressField(value, "receiver_address");
        freeze.set_owner_address(owner.data(), owner.size());
        freeze.set_receiver_address(receiver.data(), receiver.size());
        freeze.set_frozen_balance(requireInt64(value, "frozen_balance"));
        freeze.set_frozen_duration(requireInt64(value, "frozen_duration"));
        freeze.set_resource(parseResourceCodeField(value, "resource"));
        any.PackFrom(freeze);
        break;
    }
    case protocol::Transaction::Contract::FreezeBalanceV2Contract: {
        protocol::FreezeBalanceV2Contract freeze;
        const auto owner = parseAddressField(value, "owner_address");
        freeze.set_owner_address(owner.data(), owner.size());
        freeze.set_frozen_balance(requireInt64(value, "frozen_balance"));
        freeze.set_resource(parseResourceCodeField(value, "resource"));
        any.PackFrom(freeze);
        break;
    }
    case protocol::Transaction::Contract::UnfreezeBalanceContract: {
        protocol::UnfreezeBalanceContract unfreeze;
        const auto owner = parseAddressField(value, "owner_address");
        const auto receiver = parseAddressField(value, "receiver_address");
        unfreeze.set_owner_address(owner.data(), owner.size());
        unfreeze.set_receiver_address(receiver.data(), receiver.size());
        unfreeze.set_resource(parseResourceCodeField(value, "resource"));
        any.PackFrom(unfreeze);
        break;
    }
    case protocol::Transaction::Contract::UnfreezeBalanceV2Contract: {
        protocol::UnfreezeBalanceV2Contract unfreeze;
        const auto owner = parseAddressField(value, "owner_address");
        unfreeze.set_owner_address(owner.data(), owner.size());
        unfreeze.set_unfreeze_balance(requireInt64(value, "unfreeze_balance"));
        unfreeze.set_resource(parseResourceCodeField(value, "resource"));
        any.PackFrom(unfreeze);
        break;
    }
    case protocol::Transaction::Contract::WithdrawExpireUnfreezeContract: {
        protocol::WithdrawExpireUnfreezeContract withdraw;
        const auto owner = parseAddressField(value, "owner_address");
        withdraw.set_owner_address(owner.data(), owner.size());
        any.PackFrom(withdraw);
        break;
    }
    case protocol::Transaction::Contract::DelegateResourceContract: {
        protocol::DelegateResourceContract delegate;
        const auto owner = parseAddressField(value, "owner_address");
        const auto receiver = parseAddressField(value, "receiver_address");
        delegate.set_owner_address(owner.data(), owner.size());
        delegate.set_receiver_address(receiver.data(), receiver.size());
        delegate.set_resource(parseResourceCodeField(value, "resource"));
        delegate.set_balance(requireInt64(value, "balance"));
        delegate.set_lock(optionalBool(value, "lock"));
        any.PackFrom(delegate);
        break;
    }
    case protocol::Transaction::Contract::UnDelegateResourceContract: {
        protocol::UnDelegateResourceContract undelegate;
        const auto owner = parseAddressField(value, "owner_address");
        const auto receiver = parseAddressField(value, "receiver_address");
        undelegate.set_owner_address(owner.data(), owner.size());
        undelegate.set_receiver_address(receiver.data(), receiver.size());
        undelegate.set_resource(parseResourceCodeField(value, "resource"));
        undelegate.set_balance(requireInt64(value, "balance"));
        any.PackFrom(undelegate);
        break;
    }
    case protocol::Transaction::Contract::VoteAssetContract: {
        protocol::VoteAssetContract vote;
        const auto owner = parseAddressField(value, "owner_address");
        vote.set_owner_address(owner.data(), owner.size());
        vote.set_support(optionalBool(value, "support"));
        vote.set_count(static_cast<int32_t>(requireInt64(value, "count")));
        const auto& addresses = requireField(value, "vote_address");
        if (!addresses.is_array()) {
            throw std::invalid_argument("Expected vote_address array");
        }
        for (const auto& addressJSON : addresses) {
            if (!addressJSON.is_string()) {
                throw std::invalid_argument("Expected vote_address string");
            }
            const auto address = addressJSON.get<std::string>();
            const auto decoded = (!address.empty() && address.front() == 'T')
                ? Base58::decodeCheck(address)
                : parse_hex(stripHexPrefix(address));
            vote.add_vote_address(decoded.data(), decoded.size());
        }
        any.PackFrom(vote);
        break;
    }
    case protocol::Transaction::Contract::VoteWitnessContract: {
        protocol::VoteWitnessContract vote;
        const auto owner = parseAddressField(value, "owner_address");
        vote.set_owner_address(owner.data(), owner.size());
        vote.set_support(optionalBool(value, "support"));
        const auto& votesJSON = requireField(value, "votes");
        if (!votesJSON.is_array()) {
            throw std::invalid_argument("Expected votes array");
        }
        for (const auto& voteJSON : votesJSON) {
            auto* nextVote = vote.add_votes();
            const auto voteAddress = parseAddressField(voteJSON, "vote_address");
            nextVote->set_vote_address(voteAddress.data(), voteAddress.size());
            nextVote->set_vote_count(requireInt64(voteJSON, "vote_count"));
        }
        any.PackFrom(vote);
        break;
    }
    case protocol::Transaction::Contract::WithdrawBalanceContract: {
        protocol::WithdrawBalanceContract withdraw;
        const auto owner = parseAddressField(value, "owner_address");
        withdraw.set_owner_address(owner.data(), owner.size());
        any.PackFrom(withdraw);
        break;
    }
    case protocol::Transaction::Contract::UnfreezeAssetContract: {
        protocol::UnfreezeAssetContract unfreeze;
        const auto owner = parseAddressField(value, "owner_address");
        unfreeze.set_owner_address(owner.data(), owner.size());
        any.PackFrom(unfreeze);
        break;
    }
    case protocol::Transaction::Contract::TriggerSmartContract: {
        protocol::TriggerSmartContract trigger;
        const auto owner = parseAddressField(value, "owner_address");
        const auto contractAddress = parseAddressField(value, "contract_address");
        trigger.set_owner_address(owner.data(), owner.size());
        trigger.set_contract_address(contractAddress.data(), contractAddress.size());
        if (value.contains("call_value")) {
            trigger.set_call_value(requireInt64(value, "call_value"));
        }
        if (value.contains("data")) {
            const auto data = parseHexField(value, "data");
            trigger.set_data(data.data(), data.size());
        }
        if (value.contains("call_token_value")) {
            trigger.set_call_token_value(requireInt64(value, "call_token_value"));
        }
        if (value.contains("token_id")) {
            trigger.set_token_id(requireInt64(value, "token_id"));
        }
        any.PackFrom(trigger);
        break;
    }
    case protocol::Transaction::Contract::AccountCreateContract:
    default:
        throw std::invalid_argument(std::string("Unsupported contract type: ") + contractTypeName);
    }

    *contract.mutable_parameter() = any;
    return contract;
}

Data serializeRawDataJSON(const json& rawDataJSON) {
    if (!rawDataJSON.is_object()) {
        throw std::invalid_argument("Expected raw_data object");
    }

    protocol::Transaction::raw raw;
    const auto refBlockBytes = parseHexField(rawDataJSON, "ref_block_bytes");
    const auto refBlockHash = parseHexField(rawDataJSON, "ref_block_hash");
    raw.set_ref_block_bytes(refBlockBytes.data(), refBlockBytes.size());
    raw.set_ref_block_hash(refBlockHash.data(), refBlockHash.size());
    raw.set_expiration(requireInt64(rawDataJSON, "expiration"));
    raw.set_timestamp(requireInt64(rawDataJSON, "timestamp"));

    if (rawDataJSON.contains("ref_block_num")) {
        raw.set_ref_block_num(requireInt64(rawDataJSON, "ref_block_num"));
    }
    if (rawDataJSON.contains("fee_limit")) {
        raw.set_fee_limit(requireInt64(rawDataJSON, "fee_limit"));
    }
    if (rawDataJSON.contains("data")) {
        const auto memo = parseHexField(rawDataJSON, "data");
        raw.set_data(memo.data(), memo.size());
    }

    const auto& contracts = requireField(rawDataJSON, "contract");
    if (!contracts.is_array() || contracts.empty()) {
        throw std::invalid_argument("Expected non-empty raw_data.contract array");
    }
    for (const auto& contractJSON : contracts) {
        *raw.add_contract() = parseContract(contractJSON);
    }

    const auto serialized = raw.SerializeAsString();
    return Data(serialized.begin(), serialized.end());
}

/// Returns a reference to the actual transaction object within the JSON.
/// Some dApps (e.g. SUN.io) wrap transactions in one or more {"transaction": {...}} layers.
/// Recursively unwraps until we find the object with raw_data/raw_data_hex/txID.
json& findTransactionObject(json& parsed) {
    if (parsed.contains("raw_data") || parsed.contains("raw_data_hex") || parsed.contains("txID")) {
        return parsed;
    }
    if (parsed.contains("transaction") && parsed["transaction"].is_object()) {
        return findTransactionObject(parsed["transaction"]);
    }
    return parsed;
}

bool ensureTransactionHashes(json& parsed, std::string& errorMessage) {
    Data rawDataFromHex;
    Data rawDataFromJSON;
    bool hasRawDataHex = false;
    bool hasRawDataJSON = false;

    if (parsed.contains("raw_data_hex")) {
        if (!parsed["raw_data_hex"].is_string()) {
            errorMessage = "Expected string for field: raw_data_hex";
            return false;
        }
        if (!parseHexString(parsed["raw_data_hex"].get<std::string>(), "raw_data_hex", rawDataFromHex, errorMessage)) {
            return false;
        }
        hasRawDataHex = true;
    }

    if (parsed.contains("raw_data")) {
        if (!parsed["raw_data"].is_object()) {
            errorMessage = "Expected object for field: raw_data";
            return false;
        }
        rawDataFromJSON = serializeRawDataJSON(parsed["raw_data"]);
        hasRawDataJSON = true;
    }

    if (!hasRawDataHex && !hasRawDataJSON) {
        if (parsed.contains("txID") && parsed["txID"].is_string()) {
            errorMessage = "raw_json signing requires raw_data_hex or raw_data; use txid for explicit digest signing";
        } else {
            errorMessage = "No txID, raw_data_hex, or raw_data found in raw JSON";
        }
        return false;
    }

    if (hasRawDataHex && hasRawDataJSON && rawDataFromHex != rawDataFromJSON) {
        errorMessage = "raw_data_hex does not match canonical raw_data serialization";
        return false;
    }

    const auto& rawData = hasRawDataHex ? rawDataFromHex : rawDataFromJSON;
    const auto computedTxID = Hash::sha256(rawData);

    if (parsed.contains("txID")) {
        if (!parsed["txID"].is_string()) {
            errorMessage = "Expected string for field: txID";
            return false;
        }

        Data providedTxID;
        if (!parseHexString(parsed["txID"].get<std::string>(), "txID", providedTxID, errorMessage, kTransactionHashSize)) {
            return false;
        }

        if (providedTxID != computedTxID) {
            errorMessage = "Provided txID does not match recomputed transaction hash";
            return false;
        }
    }

    parsed["raw_data_hex"] = hex(rawData);
    parsed["txID"] = hex(computedTxID);
    return true;
}

} // namespace

/// Converts an external TransferContract to an internal one used for signing.
protocol::TransferContract to_internal(const Proto::TransferContract& transfer) {
    auto internal = protocol::TransferContract();

    const auto ownerAddress = Base58::decodeCheck(transfer.owner_address());
    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());

    const auto toAddress = Base58::decodeCheck(transfer.to_address());
    internal.set_to_address(toAddress.data(), toAddress.size());

    internal.set_amount(transfer.amount());

    return internal;
}

/// Converts an external TransferAssetContract to an internal one used for
/// signing.
protocol::TransferAssetContract to_internal(const Proto::TransferAssetContract& transfer) {
    auto internal = protocol::TransferAssetContract();

    internal.set_asset_name(transfer.asset_name());

    const auto ownerAddress = Base58::decodeCheck(transfer.owner_address());
    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());

    const auto toAddress = Base58::decodeCheck(transfer.to_address());
    internal.set_to_address(toAddress.data(), toAddress.size());

    internal.set_amount(transfer.amount());

    return internal;
}

protocol::FreezeBalanceContract to_internal(const Proto::FreezeBalanceContract& freezeContract) {
    auto internal = protocol::FreezeBalanceContract();
    auto resource = protocol::ResourceCode();
    const auto ownerAddress = Base58::decodeCheck(freezeContract.owner_address());
    const auto receiverAddress = Base58::decodeCheck(freezeContract.receiver_address());

    protocol::ResourceCode_Parse(freezeContract.resource(), &resource);

    internal.set_resource(resource);
    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());
    internal.set_receiver_address(receiverAddress.data(), receiverAddress.size());
    internal.set_frozen_balance(freezeContract.frozen_balance());
    internal.set_frozen_duration(freezeContract.frozen_duration());

    return internal;
}

protocol::FreezeBalanceV2Contract to_internal(const Proto::FreezeBalanceV2Contract& freezeContract) {
    auto internal = protocol::FreezeBalanceV2Contract();
    auto resource = protocol::ResourceCode();
    const auto ownerAddress = Base58::decodeCheck(freezeContract.owner_address());

    protocol::ResourceCode_Parse(freezeContract.resource(), &resource);

    internal.set_resource(resource);
    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());
    internal.set_frozen_balance(freezeContract.frozen_balance());

    return internal;
}

protocol::UnfreezeBalanceContract to_internal(const Proto::UnfreezeBalanceContract& unfreezeContract) {
    auto internal = protocol::UnfreezeBalanceContract();
    auto resource = protocol::ResourceCode();
    const auto ownerAddress = Base58::decodeCheck(unfreezeContract.owner_address());
    const auto receiverAddress = Base58::decodeCheck(unfreezeContract.receiver_address());

    protocol::ResourceCode_Parse(unfreezeContract.resource(), &resource);

    internal.set_resource(resource);
    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());
    internal.set_receiver_address(receiverAddress.data(), receiverAddress.size());

    return internal;
}

protocol::UnfreezeBalanceV2Contract to_internal(const Proto::UnfreezeBalanceV2Contract& unfreezeContract) {
    auto internal = protocol::UnfreezeBalanceV2Contract();
    auto resource = protocol::ResourceCode();
    const auto ownerAddress = Base58::decodeCheck(unfreezeContract.owner_address());

    protocol::ResourceCode_Parse(unfreezeContract.resource(), &resource);

    internal.set_resource(resource);
    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());
    internal.set_unfreeze_balance(unfreezeContract.unfreeze_balance());

    return internal;
}

protocol::DelegateResourceContract to_internal(const Proto::DelegateResourceContract& delegateContract) {
    auto internal = protocol::DelegateResourceContract();
    auto resource = protocol::ResourceCode();
    const auto ownerAddress = Base58::decodeCheck(delegateContract.owner_address());
    const auto receiverAddress = Base58::decodeCheck(delegateContract.receiver_address());

    protocol::ResourceCode_Parse(delegateContract.resource(), &resource);

    internal.set_resource(resource);
    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());
    internal.set_receiver_address(receiverAddress.data(), receiverAddress.size());
    internal.set_balance(delegateContract.balance());
    internal.set_lock(delegateContract.lock());

    return internal;
}

protocol::UnDelegateResourceContract to_internal(const Proto::UnDelegateResourceContract& undelegateContract) {
    auto internal = protocol::UnDelegateResourceContract();
    auto resource = protocol::ResourceCode();
    const auto ownerAddress = Base58::decodeCheck(undelegateContract.owner_address());
    const auto receiverAddress = Base58::decodeCheck(undelegateContract.receiver_address());

    protocol::ResourceCode_Parse(undelegateContract.resource(), &resource);

    internal.set_resource(resource);
    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());
    internal.set_receiver_address(receiverAddress.data(), receiverAddress.size());
    internal.set_balance(undelegateContract.balance());

    return internal;
}

protocol::WithdrawExpireUnfreezeContract to_internal(const Proto::WithdrawExpireUnfreezeContract& withdrawExpireUnfreezeContract) {
    auto internal = protocol::WithdrawExpireUnfreezeContract();
    const auto ownerAddress = Base58::decodeCheck(withdrawExpireUnfreezeContract.owner_address());
    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());
    return internal;
}

protocol::UnfreezeAssetContract to_internal(const Proto::UnfreezeAssetContract& unfreezeContract) {
    auto internal = protocol::UnfreezeAssetContract();
    const auto ownerAddress = Base58::decodeCheck(unfreezeContract.owner_address());

    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());

    return internal;
}

protocol::VoteAssetContract to_internal(const Proto::VoteAssetContract& voteContract) {
    auto internal = protocol::VoteAssetContract();
    const auto ownerAddress = Base58::decodeCheck(voteContract.owner_address());

    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());
    internal.set_support(voteContract.support());
    internal.set_count(voteContract.count());
    for (int i = 0; i < voteContract.vote_address_size(); i++) {
        auto voteAddress = Base58::decodeCheck(voteContract.vote_address(i));
        internal.add_vote_address(voteAddress.data(), voteAddress.size());
    }

    return internal;
}

protocol::VoteWitnessContract to_internal(const Proto::VoteWitnessContract& voteContract) {
    auto internal = protocol::VoteWitnessContract();
    const auto ownerAddress = Base58::decodeCheck(voteContract.owner_address());

    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());
    internal.set_support(voteContract.support());
    for (int i = 0; i < voteContract.votes_size(); i++) {
        auto voteAddress = Base58::decodeCheck(voteContract.votes(i).vote_address());
        auto* vote = internal.add_votes();

        vote->set_vote_address(voteAddress.data(), voteAddress.size());
        vote->set_vote_count(voteContract.votes(i).vote_count());
    }

    return internal;
}

protocol::WithdrawBalanceContract to_internal(const Proto::WithdrawBalanceContract& withdrawContract) {
    auto internal = protocol::WithdrawBalanceContract();
    const auto ownerAddress = Base58::decodeCheck(withdrawContract.owner_address());

    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());

    return internal;
}

protocol::TriggerSmartContract to_internal(const Proto::TriggerSmartContract& triggerSmartContract) {
    auto internal = protocol::TriggerSmartContract();
    const auto ownerAddress = Base58::decodeCheck(triggerSmartContract.owner_address());
    const auto contractAddress = Base58::decodeCheck(triggerSmartContract.contract_address());

    internal.set_owner_address(ownerAddress.data(), ownerAddress.size());
    internal.set_contract_address(contractAddress.data(), contractAddress.size());
    internal.set_call_value(triggerSmartContract.call_value());
    internal.set_data(triggerSmartContract.data().data(), triggerSmartContract.data().size());
    internal.set_call_token_value(triggerSmartContract.call_token_value());
    internal.set_token_id(triggerSmartContract.token_id());

    return internal;
}

protocol::TriggerSmartContract to_internal(const Proto::TransferTRC20Contract& transferTrc20Contract) {
    auto toAddress = Base58::decodeCheck(transferTrc20Contract.to_address());
    // amount is 256 bits, big endian
    Data amount = data(transferTrc20Contract.amount());

    // Encode smart contract call parameters
    auto contract_params = parse_hex(TRANSFER_TOKEN_FUNCTION);

    // TRON addresses in ABI parameters must be 20 bytes (strip 0x41 prefix) and padded to 32 bytes
    if (toAddress.size() == 21 && toAddress[0] == 0x41) {
        toAddress.erase(toAddress.begin());
    }
    pad_left(toAddress, 32);
    pad_left(amount, 32);
    append(contract_params, toAddress);
    append(contract_params, amount);

    auto triggerSmartContract = Proto::TriggerSmartContract();
    triggerSmartContract.set_owner_address(transferTrc20Contract.owner_address());
    triggerSmartContract.set_contract_address(transferTrc20Contract.contract_address());
    triggerSmartContract.set_data(contract_params.data(), contract_params.size());

    return to_internal(triggerSmartContract);
}

/// Converts an external BlockHeader to an internal one used for signing.
protocol::BlockHeader to_internal(const Proto::BlockHeader& header) {
    auto internal = protocol::BlockHeader();

    internal.mutable_raw_data()->set_timestamp(header.timestamp());
    internal.mutable_raw_data()->set_tx_trie_root(header.tx_trie_root());
    internal.mutable_raw_data()->set_parent_hash(header.parent_hash());
    internal.mutable_raw_data()->set_number(header.number());
    internal.mutable_raw_data()->set_witness_address(header.witness_address());
    internal.mutable_raw_data()->set_version(header.version());

    return internal;
}

Data getBlockHash(const protocol::BlockHeader& header) {
    const auto data = header.raw_data().SerializeAsString();
    return Hash::sha256(data);
}

void setBlockReference(const Proto::Transaction& transaction, protocol::Transaction& internal) {
    const auto blockHash = getBlockHash(to_internal(transaction.block_header()));
    assert(blockHash.size() > 15);
    internal.mutable_raw_data()->set_ref_block_hash(blockHash.data() + 8, 8);

    const auto blockHeight = transaction.block_header().number();
    auto heightData = Data();
    encode64LE(blockHeight, heightData);
    std::reverse(heightData.begin(), heightData.end());
    internal.mutable_raw_data()->set_ref_block_bytes(heightData.data() + heightData.size() - 2, 2);
}

protocol::Transaction buildTransaction(const Proto::SigningInput& input) noexcept {
    auto tx = protocol::Transaction();

    if (input.transaction().has_transfer()) {
        auto contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_TransferContract);

        auto transfer = to_internal(input.transaction().transfer());
        google::protobuf::Any any;
        any.PackFrom(transfer);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_transfer_asset()) {
        auto contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_TransferAssetContract);

        auto transfer = to_internal(input.transaction().transfer_asset());
        google::protobuf::Any any;
        any.PackFrom(transfer);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_freeze_balance()) {
        auto contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_FreezeBalanceContract);

        auto freeze_balance = to_internal(input.transaction().freeze_balance());
        google::protobuf::Any any;
        any.PackFrom(freeze_balance);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_freeze_balance_v2()) {
        auto* contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_FreezeBalanceV2Contract);
        auto freeze_balance = to_internal(input.transaction().freeze_balance_v2());
        google::protobuf::Any any;
        any.PackFrom(freeze_balance);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_unfreeze_balance()) {
        auto contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_UnfreezeBalanceContract);
        auto unfreeze_balance = to_internal(input.transaction().unfreeze_balance());
        google::protobuf::Any any;
        any.PackFrom(unfreeze_balance);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_unfreeze_balance_v2()) {
        auto* contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_UnfreezeBalanceV2Contract);
        auto unfreeze_balance = to_internal(input.transaction().unfreeze_balance_v2());
        google::protobuf::Any any;
        any.PackFrom(unfreeze_balance);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_withdraw_expire_unfreeze()) {
        auto* contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_WithdrawExpireUnfreezeContract);
        auto withdraw_expire_unfreeze = to_internal(input.transaction().withdraw_expire_unfreeze());
        google::protobuf::Any any;
        any.PackFrom(withdraw_expire_unfreeze);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_delegate_resource()) {
        auto* contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_DelegateResourceContract);
        auto delegate_resource = to_internal(input.transaction().delegate_resource());
        google::protobuf::Any any;
        any.PackFrom(delegate_resource);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_undelegate_resource()) {
        auto* contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_UnDelegateResourceContract);
        auto undelegate_resource = to_internal(input.transaction().undelegate_resource());
        google::protobuf::Any any;
        any.PackFrom(undelegate_resource);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_unfreeze_asset()) {
        auto contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_UnfreezeAssetContract);

        auto unfreeze_asset = to_internal(input.transaction().unfreeze_asset());
        google::protobuf::Any any;
        any.PackFrom(unfreeze_asset);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_vote_asset()) {
        auto contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_VoteAssetContract);

        auto vote_asset = to_internal(input.transaction().vote_asset());
        google::protobuf::Any any;
        any.PackFrom(vote_asset);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_vote_witness()) {
        auto contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_VoteWitnessContract);

        auto vote_witness = to_internal(input.transaction().vote_witness());
        google::protobuf::Any any;
        any.PackFrom(vote_witness);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_withdraw_balance()) {
        auto contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_WithdrawBalanceContract);

        auto withdraw = to_internal(input.transaction().withdraw_balance());
        google::protobuf::Any any;
        any.PackFrom(withdraw);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_trigger_smart_contract()) {
        auto contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_TriggerSmartContract);

        auto trigger_smart_contract = to_internal(input.transaction().trigger_smart_contract());
        google::protobuf::Any any;
        any.PackFrom(trigger_smart_contract);
        *contract->mutable_parameter() = any;
    } else if (input.transaction().has_transfer_trc20_contract()) {
        auto contract = tx.mutable_raw_data()->add_contract();
        contract->set_type(protocol::Transaction_Contract_ContractType_TriggerSmartContract);

        auto trigger_smart_contract = to_internal(input.transaction().transfer_trc20_contract());
        google::protobuf::Any any;
        any.PackFrom(trigger_smart_contract);
        *contract->mutable_parameter() = any;
    }

    if (!input.transaction().memo().empty()) {
        tx.mutable_raw_data()->set_data(input.transaction().memo());
    }

    tx.mutable_raw_data()->set_timestamp(input.transaction().timestamp());
    tx.mutable_raw_data()->set_expiration(input.transaction().expiration());
    tx.mutable_raw_data()->set_fee_limit(input.transaction().fee_limit());
    setBlockReference(input.transaction(), tx);

    return tx;
}

Data serialize(const protocol::Transaction& tx) noexcept {
    const auto serialized = tx.raw_data().SerializeAsString();
    return Data(serialized.begin(), serialized.end());
}

Proto::SigningOutput signDirect(const Proto::SigningInput& input) {
    const auto key = PrivateKey(input.private_key(), TWCurveSECP256k1);
    auto output = Proto::SigningOutput();

    Data hash;
    if (!input.txid().empty()) {
        std::string errorMessage;
        if (!parseHexString(input.txid(), "txid", hash, errorMessage, kTransactionHashSize)) {
            output.set_error(Common::Proto::Error_invalid_params);
            output.set_error_message(errorMessage);
            return output;
        }
    } else if (!input.raw_json().empty()) {
        try {
            auto parsed = json::parse(input.raw_json());
            auto& txObj = findTransactionObject(parsed);
            std::string errorMessage;
            if (!ensureTransactionHashes(txObj, errorMessage)) {
                output.set_error(Common::Proto::Error_invalid_params);
                output.set_error_message(errorMessage);
                return output;
            }
            hash = parse_hex(stripHexPrefix(txObj["txID"].get<std::string>()));
        } catch (const std::exception& e) {
            output.set_error(Common::Proto::Error_invalid_params);
            output.set_error_message(e.what());
            return output;
        }
    }

    const auto signature = key.sign(hash);
    output.set_signature(signature.data(), signature.size());
    output.set_id(hash.data(), hash.size());

    // Produce signed JSON: inject signature into the transaction object,
    // preserving the original wrapper structure (e.g. {"transaction": {...}})
    if (!input.raw_json().empty()) {
        try {
            auto parsed = json::parse(input.raw_json());
            auto& txObj = findTransactionObject(parsed);
            std::string errorMessage;
            if (ensureTransactionHashes(txObj, errorMessage)) {
                txObj["signature"] = json::array({hex(signature)});
                txObj["txID"] = hex(hash);
                auto jsonString = parsed.dump();
                output.set_json(jsonString.data(), jsonString.size());
            }
        } catch (...) {
            // Best effort — signature is still in the output
        }
    }

    return output;
}

Proto::SigningOutput Signer::sign(const Proto::SigningInput& input) {
    if (!input.txid().empty() || !input.raw_json().empty()) {
        return signDirect(input);
    }

    auto output = Proto::SigningOutput();
    auto tx = buildTransaction(input);

    // Get default timestamp and expiration
    const uint64_t now = duration_cast<std::chrono::milliseconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
    const uint64_t timestamp = input.transaction().timestamp() == 0
                                   ? now
                                   : input.transaction().timestamp();
    const uint64_t expiration = input.transaction().expiration() == 0
                                    ? timestamp + 10 * 60 * 60 * 1000 // 10 hours
                                    : input.transaction().expiration();

    tx.mutable_raw_data()->set_timestamp(timestamp);
    tx.mutable_raw_data()->set_expiration(expiration);

    output.set_ref_block_bytes(tx.raw_data().ref_block_bytes());
    output.set_ref_block_hash(tx.raw_data().ref_block_hash());

    const auto hash = Hash::sha256(serialize(tx));

    const auto key = PrivateKey(input.private_key(), TWCurveSECP256k1);
    const auto signature = key.sign(hash);

    const auto json = transactionJSON(tx, hash, signature).dump();

    output.set_id(hash.data(), hash.size());
    output.set_signature(signature.data(), signature.size());
    output.set_json(json.data(), json.size());

    return output;
}

Proto::SigningOutput Signer::compile(const Data& signature) const {
    Proto::SigningOutput output;
    if (!input.raw_json().empty()) {
        try {
            auto parsed = json::parse(input.raw_json());
            auto& txObj = findTransactionObject(parsed);
            std::string errorMessage;
            if (!ensureTransactionHashes(txObj, errorMessage)) {
                output.set_error(Common::Proto::Error_invalid_params);
                output.set_error_message(errorMessage);
                return output;
            }
            txObj["signature"] = json::array({hex(signature)});
            output.set_json(parsed.dump());
            output.set_signature(signature.data(), signature.size());
            auto txID = parse_hex(stripHexPrefix(txObj["txID"].get<std::string>()));
            output.set_id(txID.data(), txID.size());
            return output;
        } catch (const std::exception& e) {
            output.set_error(Common::Proto::Error_invalid_params);
            output.set_error_message(e.what());
            return output;
        }
    }
    auto preImage = signaturePreimage();
    auto hash = Hash::sha256(preImage);
    auto transaction = buildTransaction(input);
    const auto json = transactionJSON(transaction, hash, signature).dump();
    output.set_json(json.data(), json.size());
    output.set_ref_block_bytes(transaction.raw_data().ref_block_bytes());
    output.set_ref_block_hash(transaction.raw_data().ref_block_hash());
    output.set_id(hash.data(), hash.size());
    output.set_signature(signature.data(), signature.size());
    return output;
}

Data Signer::signaturePreimage() const {
    if (!input.raw_json().empty()) {
        try {
            auto parsed = json::parse(input.raw_json());
            auto& txObj = findTransactionObject(parsed);
            std::string errorMessage;
            if (ensureTransactionHashes(txObj, errorMessage) &&
                txObj.contains("raw_data_hex") && txObj["raw_data_hex"].is_string()) {
                return parse_hex(stripHexPrefix(txObj["raw_data_hex"].get<std::string>()));
            }
            return {};
        } catch (...) {
            return {};
        }
    }
    return serialize(buildTransaction(input));
}

Data Signer::signaturePreimageHash() const {
    if (!input.raw_json().empty()) {
        try {
            auto parsed = json::parse(input.raw_json());
            auto& txObj = findTransactionObject(parsed);
            std::string errorMessage;
            if (ensureTransactionHashes(txObj, errorMessage) &&
                txObj.contains("txID") && txObj["txID"].is_string()) {
                return parse_hex(stripHexPrefix(txObj["txID"].get<std::string>()));
            }
            return {};
        } catch (...) {
            return {};
        }
    }
    auto preImage = signaturePreimage();
    return Hash::sha256(preImage);
}

} // namespace TW::Tron
