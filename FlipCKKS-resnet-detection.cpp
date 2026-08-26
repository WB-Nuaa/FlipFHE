// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "cnpy.h"
#include <bitset>
#include <iomanip>
#include <algorithm>

#include <filesystem>
#include <sstream>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <limits>
#include <random>
#include <stdexcept>

using namespace std;
using namespace seal;
namespace fs = std::filesystem;

namespace
{
    constexpr size_t check_slot_count = 8;
    constexpr double check_threshold = 1e-3;
    constexpr double server_check_multiplier = 5.0;

    const vector<double> check_slot_values{
        0.125, -0.375, 0.625, -0.875, 1.125, -1.375, 1.625, -1.875};

    struct CheckSlotResult
    {
        bool passed = true;
        double max_abs_error = 0.0;
        size_t worst_slot = 0;
        double expected = 0.0;
        double observed = 0.0;
    };

    void append_check_slots(
        vector<double> &input, size_t slot_count, size_t &check_slot_start)
    {
        if (check_slot_values.size() != check_slot_count)
        {
            throw logic_error("check slot configuration mismatch");
        }
        if (input.size() + check_slot_count > slot_count)
        {
            throw invalid_argument("not enough CKKS slots for data and check slots");
        }

        check_slot_start = input.size();
        input.resize(slot_count, 0.0);
        copy(check_slot_values.begin(), check_slot_values.end(),
             input.begin() + check_slot_start);
    }

    vector<double> expected_check_slots()
    {
        vector<double> expected(check_slot_count);
        for (size_t i = 0; i < check_slot_count; ++i)
        {
            expected[i] = server_check_multiplier * check_slot_values[i];
        }
        return expected;
    }

    CheckSlotResult verify_check_slots(
        const vector<double> &decoded, size_t check_slot_start,
        const vector<double> &expected, double threshold)
    {
        if (check_slot_start + expected.size() > decoded.size())
        {
            throw invalid_argument("decoded vector does not contain all check slots");
        }

        CheckSlotResult result;
        double total_error = 0.0;
        for (size_t i = 0; i < expected.size(); ++i)
        {
            const double observed = decoded[check_slot_start + i];
            const double error = abs(observed - expected[i]);
            total_error += error;
            if (error > result.max_abs_error)
            {
                result.max_abs_error = error;
                result.worst_slot = check_slot_start + i;
                result.expected = expected[i];
                result.observed = observed;
            }
        }

        result.max_abs_error = total_error / static_cast<double>(expected.size());
        result.passed = isfinite(result.max_abs_error) && result.max_abs_error <= threshold;
        return result;
    }

    void print_check_slot_result(
        const string &label, const CheckSlotResult &result, double threshold)
    {
        cout << label << ": " << (result.passed ? "PASS" : "BIT-FLIP DETECTED")
             << ", max_abs_error=" << result.max_abs_error
             << ", threshold=" << threshold;
        if (!result.passed)
        {
            cout << ", worst_slot=" << result.worst_slot
                 << ", expected=" << result.expected
                 << ", observed=" << result.observed;
        }
        cout << endl;
    }
}

// void print_hex_binary(uint64_t value);

void print_hex_binary(uint64_t value) {
    cout << "0x" << hex << setw(16) << setfill('0') << value 
         << " (" << dec << value << ")  Binary: "
         << std::bitset<64>(value) << endl;
    cout << dec << setfill(' ');
}


inline uint64_t flip_bit(uint64_t x, size_t bit_pos) {
    return x ^ (uint64_t(1) << bit_pos); 

    
}



double softmax_probability(const vector<double> &logits, size_t count, size_t class_idx)
{
    if (count == 0 || logits.size() < count || class_idx >= count)
    {
        throw invalid_argument("Invalid logits size for softmax probability.");
    }

    double max_logit = -numeric_limits<double>::infinity();
    for (size_t i = 0; i < count; ++i)
    {
        if (isfinite(logits[i]))
        {
            max_logit = max(max_logit, logits[i]);
        }
    }

    if (!isfinite(max_logit) || !isfinite(logits[class_idx]))
    {
        return 0.0;
    }

    double denominator = 0.0;
    for (size_t i = 0; i < count; ++i)
    {
        if (isfinite(logits[i]))
        {
            denominator += exp(logits[i] - max_logit);
        }
    }

    if (denominator <= 0.0 || !isfinite(denominator))
    {
        return 0.0;
    }

    return exp(logits[class_idx] - max_logit) / denominator;
}

size_t argmax_class(const vector<double> &logits, size_t count)
{
    if (logits.size() < count)
    {
        throw invalid_argument("Invalid logits size for argmax.");
    }
    return static_cast<size_t>(
        distance(logits.begin(), max_element(logits.begin(), logits.begin() + count)));
}

void example_ckks_basics()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    int scale_size = 40;
    double scale = pow(2.0, scale_size); //

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    // exit(1);

    const fs::path model_dir("/home/qemu/SEAL/SEAL/native/CKKS/Resnet18/");
    const fs::path data_path = model_dir / "data.npy";
    const fs::path labels_path = model_dir / "labels.npy";
    const fs::path weights_path = model_dir / "linear_weights.npy";
    const fs::path bias_path = model_dir / "linear_bias.npy";

    cnpy::NpyArray arr = cnpy::npy_load(data_path.string());
    if (arr.word_size != sizeof(double) || (arr.shape.size() != 1 && arr.shape.size() != 2))
    {
        throw invalid_argument("data.npy must be a float64 array with shape [512] or [num_samples, 512].");
    }
    double* data = arr.data<double>();
    size_t sample_count = 1;
    size_t feature_count_from_file = arr.shape[0];
    if (arr.shape.size() == 2)
    {
        sample_count = arr.shape[0];
        feature_count_from_file = arr.shape[1];
    }
    size_t total = sample_count * feature_count_from_file;
    vector<double> all_features(data, data + total);

    if (!fs::exists(labels_path))
    {
        throw invalid_argument("Missing labels.npy for batch accuracy evaluation.");
    }
    cnpy::NpyArray labels_array = cnpy::npy_load(labels_path.string());
    if (labels_array.shape.size() != 1 || labels_array.shape[0] != sample_count ||
        labels_array.word_size != sizeof(long long))
    {
        throw invalid_argument("labels.npy must be an int64 array with shape [num_samples].");
    }
    long long *label_data = labels_array.data<long long>();
    vector<int> labels(sample_count);
    for (size_t sample_idx = 0; sample_idx < sample_count; ++sample_idx)
    {
        labels[sample_idx] = static_cast<int>(label_data[sample_idx]);
    }

    vector<double> input(
        all_features.begin(),
        all_features.begin() + feature_count_from_file);
    size_t check_slot_start = 0;
    append_check_slots(input, slot_count, check_slot_start);
    const vector<double> expected_checks = expected_check_slots();

    cout << "Input vector: " << feature_count_from_file << " data slots + "
         << check_slot_count << " check slots" << endl;
    cout << "Check slots: start=" << check_slot_start
         << ", count=" << check_slot_count
         << ", threshold=" << check_threshold << endl;
    print_vector(input, 3, 7);
    

    Plaintext x_plain;
    // print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);


    cout << "Starting encrypted ResNet18 classification head..." << endl;

    constexpr size_t num_classes = 10;
    constexpr size_t resnet_feature_count = 512;
    const size_t feature_count = feature_count_from_file;
    if (feature_count == 0 || feature_count > slot_count)
    {
        throw invalid_argument("The input feature vector must fit in one CKKS ciphertext.");
    }
    if (feature_count != resnet_feature_count)
    {
        throw invalid_argument("data.npy must contain a 512-D pretrained ResNet18 feature vector.");
    }

    vector<double> weights(num_classes * feature_count);
    vector<double> bias(num_classes);

    if (!fs::exists(weights_path) || !fs::exists(bias_path))
    {
        throw invalid_argument(
            "Missing pretrained ResNet18 head files: linear_weights.npy and linear_bias.npy.");
    }

    if (fs::exists(weights_path) && fs::exists(bias_path))
    {
        cnpy::NpyArray weights_array = cnpy::npy_load(weights_path.string());
        cnpy::NpyArray bias_array = cnpy::npy_load(bias_path.string());

        if (weights_array.word_size != sizeof(double) ||
            weights_array.shape.size() != 2 ||
            weights_array.shape[0] != num_classes ||
            weights_array.shape[1] != feature_count)
        {
            throw invalid_argument(
                "linear_weights.npy must be a float64 array with shape [10, feature_count].");
        }
        if (bias_array.word_size != sizeof(double) ||
            bias_array.shape.size() != 1 ||
            bias_array.shape[0] != num_classes)
        {
            throw invalid_argument("linear_bias.npy must be a float64 array with shape [10].");
        }

        const double *weights_data = weights_array.data<double>();
        const double *bias_data = bias_array.data<double>();
        copy(weights_data, weights_data + weights.size(), weights.begin());
        copy(bias_data, bias_data + bias.size(), bias.begin());
        cout << "Loaded pretrained ResNet18 classification head from " << model_dir << endl;
    }
    else
    {

        cerr << "Warning: trained linear model files were not found; "
             << "using deterministic fallback parameters." << endl;
        for (size_t class_idx = 0; class_idx < num_classes; ++class_idx)
        {
            bias[class_idx] = 0.01 * (static_cast<double>(class_idx) - 4.5);
            for (size_t feature_idx = 0; feature_idx < feature_count; ++feature_idx)
            {
                const double phase = static_cast<double>((class_idx + 1) * (feature_idx + 1));
                weights[class_idx * feature_count + feature_idx] =
                    0.01 * sin(phase * 0.013) + 0.005 * cos(phase * 0.007);
            }
        }
    }

    {
        auto compute_expected_logits = [&](const vector<double> &sample) {
            vector<double> logits(num_classes, 0.0);
            for (size_t class_idx = 0; class_idx < num_classes; ++class_idx)
            {
                logits[class_idx] = bias[class_idx];
                for (size_t feature_idx = 0; feature_idx < feature_count; ++feature_idx)
                {
                    logits[class_idx] +=
                        weights[class_idx * feature_count + feature_idx] * sample[feature_idx];
                }
            }
            return logits;
        };

        auto evaluate_ckks_head = [&](const vector<double> &sample) {
            vector<double> checked_sample(sample.begin(), sample.begin() + feature_count);
            size_t sample_check_slot_start = 0;
            append_check_slots(checked_sample, slot_count, sample_check_slot_start);
            if (sample_check_slot_start != check_slot_start)
            {
                throw logic_error("inconsistent check slot position");
            }
            Plaintext sample_plain;
            encoder.encode(checked_sample, scale, sample_plain);
            Ciphertext sample_encrypted;
            encryptor.encrypt(sample_plain, sample_encrypted);

            Ciphertext result;
            bool initialized = false;
            for (size_t class_idx = 0; class_idx < num_classes; ++class_idx)
            {
                vector<double> packed_weights(slot_count, 0.0);
                copy_n(
                    weights.begin() + class_idx * feature_count,
                    feature_count,
                    packed_weights.begin());

                Plaintext weights_plain;
                encoder.encode(packed_weights, scale, weights_plain);

                Ciphertext class_score;
                evaluator.multiply_plain(sample_encrypted, weights_plain, class_score);
                evaluator.rescale_to_next_inplace(class_score);

                for (size_t step = 1; step < slot_count; step <<= 1)
                {
                    Ciphertext rotated;
                    evaluator.rotate_vector(class_score, static_cast<int>(step), gal_keys, rotated);
                    evaluator.add_inplace(class_score, rotated);
                }

                vector<double> class_mask(slot_count, 0.0);
                class_mask[class_idx] = 1.0;
                Plaintext class_mask_plain;
                encoder.encode(class_mask, class_score.parms_id(), scale, class_mask_plain);
                evaluator.multiply_plain_inplace(class_score, class_mask_plain);
                evaluator.rescale_to_next_inplace(class_score);

                if (!initialized)
                {
                    result = class_score;
                    initialized = true;
                }
                else
                {
                    evaluator.add_inplace(result, class_score);
                }
            }

            vector<double> check_multiplier(slot_count, 0.0);
            fill_n(check_multiplier.begin() + check_slot_start,
                   check_slot_count, server_check_multiplier);
            Plaintext check_multiplier_plain;
            encoder.encode(check_multiplier, scale, check_multiplier_plain);
            Ciphertext encrypted_checks;
            evaluator.multiply_plain(
                sample_encrypted, check_multiplier_plain, encrypted_checks);
            evaluator.rescale_to_next_inplace(encrypted_checks);

            vector<double> check_mask(slot_count, 0.0);
            fill_n(check_mask.begin() + check_slot_start, check_slot_count, 1.0);
            Plaintext check_mask_plain;
            encoder.encode(
                check_mask, encrypted_checks.parms_id(), scale, check_mask_plain);
            evaluator.multiply_plain_inplace(encrypted_checks, check_mask_plain);
            evaluator.rescale_to_next_inplace(encrypted_checks);
            evaluator.add_inplace(result, encrypted_checks);

            vector<double> packed_bias(slot_count, 0.0);
            copy(bias.begin(), bias.end(), packed_bias.begin());
            Plaintext bias_plain;
            encoder.encode(packed_bias, result.parms_id(), result.scale(), bias_plain);
            evaluator.add_plain_inplace(result, bias_plain);
            return result;
        };

        auto switch_to_last_level = [&](Ciphertext &ct) {
            size_t coeff_modulus_size = context.get_context_data(ct.parms_id())
                                            ->parms()
                                            .coeff_modulus()
                                            .size();
            while (coeff_modulus_size > 1)
            {
                auto data_context = context.get_context_data(ct.parms_id());
                if (!data_context->next_context_data())
                {
                    break;
                }
                evaluator.mod_switch_to_inplace(ct, data_context->next_context_data()->parms_id());
                coeff_modulus_size = context.get_context_data(ct.parms_id())
                                         ->parms()
                                         .coeff_modulus()
                                         .size();
            }
        };

        constexpr size_t target_poly_idx = 0;
        constexpr size_t target_mod_idx = 0;
        constexpr size_t target_coeff_idx = 1;
        constexpr size_t bit_count = 64;
        size_t plaintext_correct = 0;
        size_t ckks_correct = 0;
        vector<size_t> faulty_correct(bit_count, 0);
        vector<size_t> faulty_valid(bit_count, 0);
        vector<size_t> decrypt_errors(bit_count, 0);
        vector<size_t> decode_errors(bit_count, 0);

        cout << "\n========== Batch accuracy over " << sample_count
             << " images ==========\n" << endl;

        for (size_t sample_idx = 0; sample_idx < sample_count; ++sample_idx)
        {
            if (labels[sample_idx] < 0 || labels[sample_idx] >= static_cast<int>(num_classes))
            {
                throw invalid_argument("labels.npy contains an invalid class label.");
            }

            vector<double> sample(
                all_features.begin() + sample_idx * feature_count,
                all_features.begin() + (sample_idx + 1) * feature_count);

            vector<double> expected = compute_expected_logits(sample);
            const size_t expected_class = argmax_class(expected, num_classes);
            plaintext_correct +=
                (expected_class == static_cast<size_t>(labels[sample_idx])) ? 1 : 0;

            Ciphertext encrypted_result = evaluate_ckks_head(sample);
            switch_to_last_level(encrypted_result);

            auto data_context = context.get_context_data(encrypted_result.parms_id());
            const auto &batch_parms = data_context->parms();
            const size_t N = batch_parms.poly_modulus_degree();
            const size_t L = batch_parms.coeff_modulus().size();
            const size_t num_poly = encrypted_result.size();
            if (target_poly_idx >= num_poly || target_mod_idx >= L || target_coeff_idx >= N)
            {
                throw logic_error("Fault injection target is outside the ciphertext layout.");
            }

            Plaintext golden_plain;
            decryptor.decrypt(encrypted_result, golden_plain);
            vector<double> golden_logits;
            encoder.decode(golden_plain, golden_logits);
            const size_t encrypted_class = argmax_class(golden_logits, num_classes);
            ckks_correct +=
                (encrypted_class == static_cast<size_t>(labels[sample_idx])) ? 1 : 0;

            for (size_t bit_idx = 0; bit_idx < bit_count; ++bit_idx)
            {
                Ciphertext faulty_ct = encrypted_result;
                if (faulty_ct.is_ntt_form())
                {
                    evaluator.transform_from_ntt_inplace(faulty_ct);
                }

                uint64_t *poly_ptr = faulty_ct.data(target_poly_idx);
                uint64_t *coeff_ptr = poly_ptr + target_mod_idx * N + target_coeff_idx;
                *coeff_ptr = flip_bit(*coeff_ptr, bit_idx);
                evaluator.transform_to_ntt_inplace(faulty_ct);

                Plaintext faulty_plain;
                try
                {
                    decryptor.decrypt(faulty_ct, faulty_plain);
                }
                catch (...)
                {
                    decrypt_errors[bit_idx]++;
                    continue;
                }

                vector<double> decoded;
                try
                {
                    encoder.decode(faulty_plain, decoded);
                }
                catch (...)
                {
                    decode_errors[bit_idx]++;
                    continue;
                }

                if (decoded.size() < num_classes)
                {
                    decode_errors[bit_idx]++;
                    continue;
                }

                const size_t faulty_class = argmax_class(decoded, num_classes);
                faulty_valid[bit_idx]++;
                faulty_correct[bit_idx] +=
                    (faulty_class == static_cast<size_t>(labels[sample_idx])) ? 1 : 0;
            }

            cout << "Sample " << sample_idx << ": label=" << labels[sample_idx]
                 << ", plaintext=" << expected_class
                 << ", CKKS=" << encrypted_class << endl;
        }

        const double plaintext_accuracy =
            static_cast<double>(plaintext_correct) / static_cast<double>(sample_count);
        const double ckks_accuracy =
            static_cast<double>(ckks_correct) / static_cast<double>(sample_count);

        cout << "\nPlain ResNet18 accuracy: " << plaintext_correct << "/"
             << sample_count << " = " << plaintext_accuracy << endl;
        cout << "CKKS ResNet18 accuracy: " << ckks_correct << "/"
             << sample_count << " = " << ckks_accuracy << endl;
        cout << "Fault injection target: p" << target_poly_idx << "_m"
             << target_mod_idx << "_c" << target_coeff_idx << endl;
        cout << "Faulty CKKS accuracy per bit:" << endl;
        for (size_t bit_idx = 0; bit_idx < bit_count; ++bit_idx)
        {
            const double valid_accuracy =
                faulty_valid[bit_idx] == 0
                    ? 0.0
                    : static_cast<double>(faulty_correct[bit_idx]) /
                          static_cast<double>(faulty_valid[bit_idx]);
            const double total_accuracy =
                static_cast<double>(faulty_correct[bit_idx]) /
                static_cast<double>(sample_count);
            cout << "  bit " << bit_idx << ": correct/total="
                 << faulty_correct[bit_idx] << "/" << sample_count
                 << " = " << total_accuracy
                 << ", correct/valid=" << faulty_correct[bit_idx] << "/"
                 << faulty_valid[bit_idx] << " = " << valid_accuracy
                 << ", decrypt_errors=" << decrypt_errors[bit_idx]
                  << ", decode_errors=" << decode_errors[bit_idx] << endl;
        }

        Ciphertext experiment_ciphertext = evaluate_ckks_head(input);
        switch_to_last_level(experiment_ciphertext);
        const auto experiment_context =
            context.get_context_data(experiment_ciphertext.parms_id());
        const auto &experiment_parms = experiment_context->parms();
        const size_t experiment_coefficient_count = experiment_parms.poly_modulus_degree();
        const size_t experiment_modulus_count = experiment_parms.coeff_modulus().size();
        const size_t experiment_poly_count = experiment_ciphertext.size();

        Plaintext experiment_golden_plain;
        decryptor.decrypt(experiment_ciphertext, experiment_golden_plain);
        vector<double> experiment_golden;
        encoder.decode(experiment_golden_plain, experiment_golden);
        print_check_slot_result(
            "Clean ciphertext check slots",
            verify_check_slots(
                experiment_golden, check_slot_start, expected_checks, check_threshold),
            check_threshold);

        constexpr size_t experiment_count = 5000;
        const uint32_t random_seed = random_device{}();
        mt19937 rng(random_seed);
        uniform_int_distribution<size_t> poly_distribution(0, experiment_poly_count - 1);
        uniform_int_distribution<size_t> modulus_distribution(0, experiment_modulus_count - 1);
        uniform_int_distribution<size_t> coefficient_distribution(
            0, experiment_coefficient_count - 1);

        const fs::path output_dir =
            fs::current_path() / "result" / "random_bit_flips_1000";
        fs::create_directories(output_dir);
        ofstream summary(output_dir / "summary.csv");
        if (!summary)
        {
            throw runtime_error("failed to create bit-flip experiment summary");
        }
        summary << "experiment,poly,modulus,coefficient,bit,before,after,"
                   "output_corrupted,check_slot_detected,check_mean_abs_error,status,result_file\n";

        size_t check_slot_detected_count = 0;
        size_t processing_error_count = 0;
        size_t true_positive = 0;
        size_t false_positive = 0;
        size_t true_negative = 0;
        size_t false_negative = 0;

        for (size_t experiment_id = 0; experiment_id < experiment_count; ++experiment_id)
        {
            const size_t poly_idx = poly_distribution(rng);
            const size_t mod_idx = modulus_distribution(rng);
            const size_t coeff_idx = coefficient_distribution(rng);
            const size_t modulus_bit_count =
                experiment_parms.coeff_modulus()[mod_idx].bit_count();
            uniform_int_distribution<size_t> bit_distribution(0, modulus_bit_count - 1);
            const size_t bit_idx = bit_distribution(rng);

            Ciphertext faulty_ct = experiment_ciphertext;
            if (faulty_ct.is_ntt_form())
            {
                evaluator.transform_from_ntt_inplace(faulty_ct);
            }
            uint64_t *coeff_ptr = faulty_ct.data(poly_idx) +
                                  mod_idx * experiment_coefficient_count + coeff_idx;
            const uint64_t before = *coeff_ptr;
            *coeff_ptr = flip_bit(before, bit_idx);
            const uint64_t after = *coeff_ptr;
            evaluator.transform_to_ntt_inplace(faulty_ct);

            bool output_corrupted = false;
            bool check_slot_detected = false;
            bool processing_error = false;
            double check_mean_abs_error = numeric_limits<double>::infinity();
            string status;
            fs::path result_file =
                output_dir / ("experiment_" + to_string(experiment_id) + ".npy");

            try
            {
                Plaintext faulty_plain;
                decryptor.decrypt(faulty_ct, faulty_plain);
                vector<double> decoded;
                encoder.decode(faulty_plain, decoded);

                const CheckSlotResult check_result = verify_check_slots(
                    decoded, check_slot_start, expected_checks, check_threshold);
                check_slot_detected = !check_result.passed;
                check_mean_abs_error = check_result.max_abs_error;

                double logits_mse = 0.0;
                for (size_t class_idx = 0; class_idx < num_classes; ++class_idx)
                {
                    const double delta =
                        decoded[class_idx] - experiment_golden[class_idx];
                    logits_mse += delta * delta;
                }
                logits_mse /= static_cast<double>(num_classes);
                output_corrupted = !isfinite(logits_mse) || logits_mse > check_threshold;

                if (check_slot_detected && output_corrupted)
                {
                    ++true_positive;
                }
                else if (check_slot_detected)
                {
                    ++false_positive;
                }
                else if (output_corrupted)
                {
                    ++false_negative;
                }
                else
                {
                    ++true_negative;
                }

                status = check_slot_detected ? "detected" : "missed";
                const vector<size_t> shape{ decoded.size() };
                cnpy::npy_save(result_file.string(), decoded.data(), shape, "w");
            }
            catch (const exception &error)
            {
                processing_error = true;
                status = "decrypt_or_decode_error";
                result_file.replace_extension(".txt");
                ofstream error_file(result_file);
                error_file << error.what() << '\n';
            }
            catch (...)
            {
                processing_error = true;
                status = "decrypt_or_decode_error";
                result_file.replace_extension(".txt");
                ofstream error_file(result_file);
                error_file << "unknown decrypt/decode error\n";
            }

            check_slot_detected_count += check_slot_detected ? 1 : 0;
            processing_error_count += processing_error ? 1 : 0;
            summary << experiment_id << ',' << poly_idx << ',' << mod_idx << ','
                    << coeff_idx << ',' << bit_idx << ',' << before << ',' << after << ','
                    << (output_corrupted ? 1 : 0) << ','
                    << (check_slot_detected ? 1 : 0) << ',' << check_mean_abs_error << ','
                    << status << ',' << result_file.filename().string() << '\n';

            cout << "Experiment " << (experiment_id + 1) << '/' << experiment_count
                 << ": p=" << poly_idx << ", m=" << mod_idx << ", c=" << coeff_idx
                 << ", bit=" << bit_idx << ", " << status << endl;
        }

        const double check_slot_detection_rate =
            100.0 * static_cast<double>(check_slot_detected_count) / experiment_count;
        const double system_detection_rate =
            100.0 * static_cast<double>(
                        check_slot_detected_count + processing_error_count) /
            experiment_count;
        summary << "# seed," << random_seed << '\n'
                << "# check_slot_detected," << check_slot_detected_count << '\n'
                << "# processing_errors," << processing_error_count << '\n'
                << "# check_slot_detection_rate_percent," << check_slot_detection_rate << '\n'
                << "# system_detection_rate_percent," << system_detection_rate << '\n'
                << "# true_positive," << true_positive << '\n'
                << "# false_positive," << false_positive << '\n'
                << "# true_negative," << true_negative << '\n'
                << "# false_negative," << false_negative << '\n';

        cout << "Check slots detected " << check_slot_detected_count << '/'
             << experiment_count << " random bit flips (" << check_slot_detection_rate
             << "%). Processing errors: " << processing_error_count
             << ". System detection rate: " << system_detection_rate
             << "%. Results: " << output_dir << endl;
        cout << "Confusion matrix (TP FP TN FN): " << true_positive << ' '
             << false_positive << ' ' << true_negative << ' ' << false_negative << endl;

        return;
    }

    vector<double> expected_logits(num_classes, 0.0);
    for (size_t class_idx = 0; class_idx < num_classes; ++class_idx)
    {
        expected_logits[class_idx] = bias[class_idx];
        for (size_t feature_idx = 0; feature_idx < feature_count; ++feature_idx)
        {
            expected_logits[class_idx] +=
                weights[class_idx * feature_count + feature_idx] * input[feature_idx];
        }
    }

    // cout<<"11111"<<endl;
    Ciphertext linear_result;
    bool result_initialized = false;

    for (size_t class_idx = 0; class_idx < num_classes; ++class_idx)
    {
        
        vector<double> packed_weights(slot_count, 0.0);
        copy_n(
            weights.begin() + class_idx * feature_count,
            feature_count,
            packed_weights.begin());

        Plaintext weights_plain;
        encoder.encode(packed_weights, scale, weights_plain);

        Ciphertext class_score;
        evaluator.multiply_plain(x1_encrypted, weights_plain, class_score);
        evaluator.rescale_to_next_inplace(class_score);



        for (size_t step = 1; step < slot_count; step <<= 1)
        {
            Ciphertext rotated;
            evaluator.rotate_vector(class_score, static_cast<int>(step), gal_keys, rotated);
            evaluator.add_inplace(class_score, rotated);
        }


        vector<double> class_mask(slot_count, 0.0);
        class_mask[class_idx] = 1.0;
        Plaintext class_mask_plain;
        encoder.encode(class_mask, class_score.parms_id(), scale, class_mask_plain);
        evaluator.multiply_plain_inplace(class_score, class_mask_plain);
        evaluator.rescale_to_next_inplace(class_score);


        if (!result_initialized)
        {
            linear_result = class_score;
            result_initialized = true;
        }
        else
        {
            evaluator.add_inplace(linear_result, class_score);
        }
    }

    vector<double> check_multiplier(slot_count, 0.0);
    fill_n(check_multiplier.begin() + check_slot_start,
           check_slot_count, server_check_multiplier);
    Plaintext check_multiplier_plain;
    encoder.encode(check_multiplier, scale, check_multiplier_plain);
    Ciphertext encrypted_checks;
    evaluator.multiply_plain(x1_encrypted, check_multiplier_plain, encrypted_checks);
    evaluator.rescale_to_next_inplace(encrypted_checks);

    vector<double> check_mask(slot_count, 0.0);
    fill_n(check_mask.begin() + check_slot_start, check_slot_count, 1.0);
    Plaintext check_mask_plain;
    encoder.encode(check_mask, encrypted_checks.parms_id(), scale, check_mask_plain);
    evaluator.multiply_plain_inplace(encrypted_checks, check_mask_plain);
    evaluator.rescale_to_next_inplace(encrypted_checks);
    evaluator.add_inplace(linear_result, encrypted_checks);

    vector<double> packed_bias(slot_count, 0.0);
    copy(bias.begin(), bias.end(), packed_bias.begin());
    Plaintext bias_plain;
    encoder.encode(
        packed_bias, linear_result.parms_id(), linear_result.scale(), bias_plain);
    evaluator.add_plain_inplace(linear_result, bias_plain);

    cout << "Encrypted ResNet18 classification head completed. The first " << num_classes
         << " slots contain the class logits." << endl;
    
    // 获取上下文参数

    auto context_data = context.get_context_data(linear_result.parms_id());
    auto &parms_info = context_data->parms();
    size_t poly_modulus_degree_val = parms_info.poly_modulus_degree();
    size_t coeff_modulus_size_val = parms_info.coeff_modulus().size();


    x1_encrypted = linear_result;

    while (coeff_modulus_size_val > 1)
    {
        auto context_data = context.get_context_data(x1_encrypted.parms_id());

        if (!context_data->next_context_data())
            break;

        auto next_parms_id = context_data->next_context_data()->parms_id();
        
        evaluator.mod_switch_to_inplace(x1_encrypted, next_parms_id);
        coeff_modulus_size_val = context.get_context_data(x1_encrypted.parms_id())
                                      ->parms()
                                      .coeff_modulus()
                                      .size();

    }

    context_data = context.get_context_data(x1_encrypted.parms_id());
    auto &parms_info1 = context_data->parms();
    poly_modulus_degree_val = parms_info1.poly_modulus_degree();
    coeff_modulus_size_val = parms_info1.coeff_modulus().size();

    if (coeff_modulus_size_val != 1)
    {
        throw logic_error("Fault injection requires a last-level, single-modulus ciphertext.");
    }

    Plaintext golden_plain;
    decryptor.decrypt(x1_encrypted, golden_plain);
    vector<double> golden_logits;
    encoder.decode(golden_plain, golden_logits);

    double logits_mse = 0.0;
    double max_abs_error = 0.0;
    cout << "Golden logits (expected, CKKS):" << endl;
    for (size_t class_idx = 0; class_idx < num_classes; ++class_idx)
    {
        const double error = golden_logits[class_idx] - expected_logits[class_idx];
        logits_mse += error * error;
        max_abs_error = max(max_abs_error, abs(error));
        cout << "  class " << class_idx << ": " << expected_logits[class_idx]
             << ", " << golden_logits[class_idx] << endl;
    }
    logits_mse /= static_cast<double>(num_classes);
    const size_t expected_class = static_cast<size_t>(
        distance(expected_logits.begin(), max_element(expected_logits.begin(), expected_logits.end())));
    const size_t encrypted_class = static_cast<size_t>(
        distance(golden_logits.begin(),
                 max_element(golden_logits.begin(), golden_logits.begin() + num_classes)));
    const double expected_probability =
        softmax_probability(expected_logits, num_classes, expected_class);
    const double encrypted_probability =
        softmax_probability(golden_logits, num_classes, encrypted_class);
    cout << "ResNet18-head MSE: " << logits_mse
         << ", max absolute error: " << max_abs_error << endl;
    cout << "Predicted class/probability (plaintext, CKKS): "
         << expected_class << " (" << expected_probability << "), "
         << encrypted_class << " (" << encrypted_probability << ")" << endl;


    size_t N = poly_modulus_degree_val;
    size_t L = coeff_modulus_size_val;
    size_t num_poly = x1_encrypted.size();

    size_t experiment_id = 0;

    for (size_t poly_idx = 0; poly_idx < num_poly; poly_idx++) {
        for (size_t mod_idx = 0; mod_idx < L; mod_idx++) {
            for (size_t coeff_idx = 1; coeff_idx < N; coeff_idx++) {

                std::ostringstream dir_oss;
                    dir_oss <<"p" << poly_idx
                        << "_m" << mod_idx
                        << "_c" << coeff_idx;

                for (size_t bit_idx = 0; bit_idx < 64; bit_idx++) {

                // 
                    seal::Ciphertext faulty_ct = x1_encrypted;

                    uint64_t *poly_ptr_1 = faulty_ct.data(poly_idx);
                    uint64_t value = *poly_ptr_1;

                    std::cout << "NTT: "  << endl;
                    print_hex_binary(value);



                    if (faulty_ct.is_ntt_form()) {
                        evaluator.transform_from_ntt_inplace(faulty_ct);
                        // std::cout<< "1111" << endl;
                    }

                    uint64_t *poly_ptr = faulty_ct.data(poly_idx);
                    
                    uint64_t *coeff_ptr =
                        poly_ptr + mod_idx * N + coeff_idx;
                    // uint64_t *neighbor_1 = coeff_ptr + 1;
                    // uint64_t *neighbor_2 = coeff_ptr + 2;

                    std::cout << *poly_ptr << " " << *coeff_ptr  << endl;
                    // 3.

                    *coeff_ptr = flip_bit(*coeff_ptr, bit_idx);
  

                    std::cout << "Bit: " << bit_idx << " " << *coeff_ptr << endl;

                    evaluator.transform_to_ntt_inplace(faulty_ct);


                // 4.
                    seal::Plaintext faulty_plain;
                    try {
                        decryptor.decrypt(faulty_ct, faulty_plain);
                    } catch (...) {
                        
                        cout<< "decrypt_ERROR!" << endl;
                        //exit(1);
                        continue;
                    }

                // 5. 解码
                    std::vector<double> decoded;
                    try {
                        encoder.decode(faulty_plain, decoded);
                    } catch (...) {
                        cout<< "decode_ERROR!" << endl;
                        //exit(1);
                        continue;
                    }

                    cout << "    + Computed result ...... Correct." << endl;
                    print_vector(decoded, 3, 7);
                    if (decoded.size() >= num_classes)
                    {
                        double faulty_expected_mse = 0.0;
                        double faulty_golden_mse = 0.0;
                        double faulty_max_abs_delta = 0.0;

                        cout << "Faulty logits (expected, CKKS, faulty CKKS):" << endl;
                        for (size_t class_idx = 0; class_idx < num_classes; ++class_idx)
                        {
                            const double expected_error =
                                decoded[class_idx] - expected_logits[class_idx];
                            const double golden_delta =
                                decoded[class_idx] - golden_logits[class_idx];
                            faulty_expected_mse += expected_error * expected_error;
                            faulty_golden_mse += golden_delta * golden_delta;
                            faulty_max_abs_delta =
                                max(faulty_max_abs_delta, abs(golden_delta));
                            cout << "  class " << class_idx << ": "
                                 << expected_logits[class_idx] << ", "
                                 << golden_logits[class_idx] << ", "
                                 << decoded[class_idx] << endl;
                        }
                        faulty_expected_mse /= static_cast<double>(num_classes);
                        faulty_golden_mse /= static_cast<double>(num_classes);

                        const size_t faulty_class = static_cast<size_t>(
                            distance(decoded.begin(),
                                     max_element(decoded.begin(), decoded.begin() + num_classes)));
                        const double faulty_probability =
                            softmax_probability(decoded, num_classes, faulty_class);
                        cout << "Faulty logits MSE (vs expected, vs CKKS): "
                             << faulty_expected_mse << ", " << faulty_golden_mse
                             << ", max absolute CKKS delta: "
                             << faulty_max_abs_delta << endl;
                        cout << "Predicted class/probability (plaintext, CKKS, faulty CKKS): "
                             << expected_class << " (" << expected_probability << "), "
                             << encrypted_class << " (" << encrypted_probability << "), "
                             << faulty_class << " (" << faulty_probability << ")" << endl;
                    }
                    else
                    {
                        cout << "Predicted class/probability (faulty CKKS): unavailable; decoded slots = "
                             << decoded.size() << endl;
                    }
                    // 6. 保存为 .npy
                    fs::current_path("/home/qemu/SEAL/SEAL/native/CKKS/result");
                    std::cout << "CWD = " << fs::current_path() << std::endl;
                    std::ostringstream file_oss;
                    file_oss << bit_idx << ".npy";

                    fs::create_directories(dir_oss.str());
                    fs::path file_path = fs::path(dir_oss.str()) / file_oss.str();

                    std::vector<size_t> shape = { decoded.size() };
                    cnpy::npy_save(
                        file_path.string(),
                        decoded.data(),   
                        shape,
                        "w"               
                        );

                    // save_npy(oss.str(), decoded);

                    experiment_id++;
                    //exit(0);
            }
           exit(0);
        }
    }
}
    

}
