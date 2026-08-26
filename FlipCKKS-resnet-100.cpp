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
#include <limits>
#include <stdexcept>

using namespace std;
using namespace seal;
namespace fs = std::filesystem;

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

    cout << "Input vector: " << input.size() << endl;
    print_vector(input, 3, 7);
    

    Plaintext x_plain;

    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    cout << "Starting encrypted ResNet18 classification head..." << endl;

    constexpr size_t num_classes = 10;
    constexpr size_t resnet_feature_count = 512;
    const size_t feature_count = input.size();
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
            Plaintext sample_plain;
            encoder.encode(sample, scale, sample_plain);
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

    cout<<"2222"<<endl;

    vector<double> packed_bias(slot_count, 0.0);
    copy(bias.begin(), bias.end(), packed_bias.begin());
    Plaintext bias_plain;
    encoder.encode(
        packed_bias, linear_result.parms_id(), linear_result.scale(), bias_plain);
    evaluator.add_plain_inplace(linear_result, bias_plain);

    cout << "Encrypted ResNet18 classification head completed. The first " << num_classes
         << " slots contain the class logits." << endl;
    

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

                // 1.
                    seal::Ciphertext faulty_ct = x1_encrypted;

                    uint64_t *poly_ptr_1 = faulty_ct.data(poly_idx);
                    uint64_t value = *poly_ptr_1;

                    std::cout << "NTT: "  << endl;
                    print_hex_binary(value);



                    if (faulty_ct.is_ntt_form()) {
                        evaluator.transform_from_ntt_inplace(faulty_ct);
                        // std::cout<< "1111" << endl;
                    }

                // 2. 
                    uint64_t *poly_ptr = faulty_ct.data(poly_idx);
                    
                    uint64_t *coeff_ptr =
                        poly_ptr + mod_idx * N + coeff_idx;

                    std::cout << *poly_ptr << " " << *coeff_ptr  << endl;

                    *coeff_ptr = flip_bit(*coeff_ptr, bit_idx);
                    // *neighbor_1 = flip_bit(*neighbor_1, bit_idx);
                    // *neighbor_2 = flip_bit(*neighbor_2, bit_idx);
                    // for(int k = 1; k < 5000; k++)
                    // {
                    //     uint64_t *neighbor_1 = coeff_ptr + k;
                    //     *neighbor_1 = flip_bit(*neighbor_1, bit_idx);
                    // }
                    // for (int k = 1; k < 30; k++)
                    // {
                    //    *coeff_ptr = flip_bit(*coeff_ptr, bit_idx+k); 
                    // }

                    std::cout << "Bit: " << bit_idx << " " << *coeff_ptr << endl;

                    evaluator.transform_to_ntt_inplace(faulty_ct);


                // 4. 
                    seal::Plaintext faulty_plain;
                    try {
                        decryptor.decrypt(faulty_ct, faulty_plain);
                    } catch (...) {
                        cout<< "decrypt_ERROR!" << endl;
                        continue;
                    }

                // 5. 
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

                    experiment_id++;
            }
           exit(0);
        }
    }
}
    
}
