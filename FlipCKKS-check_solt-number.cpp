// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "cnpy.h"
#include <bitset>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <limits>
#include <random>
#include <stdexcept>

#include <filesystem>
#include <sstream>

using namespace std;
using namespace seal;
namespace fs = std::filesystem;

namespace
{
    constexpr double check_threshold = 1e-3;
    constexpr double server_check_multiplier = 5.0;

    // Random check values are generated once per program run from a configurable seed.
    // A fixed seed makes experiments reproducible; replace it with std::random_device{}()
    // when a different random sequence is desired for every run.
    vector<double> generate_check_slot_values(size_t count, uint32_t seed)
    {
        if (count == 0)
        {
            throw invalid_argument("check_slot_count must be greater than zero");
        }

        constexpr double min_abs_value = 0.125;
        constexpr double max_abs_value = 2.0;

        mt19937 rng(seed);
        uniform_real_distribution<double> magnitude_distribution(min_abs_value, max_abs_value);
        bernoulli_distribution negative_distribution(0.5);

        vector<double> values;
        values.reserve(count);
        for (size_t i = 0; i < count; ++i)
        {
            double value = magnitude_distribution(rng);
            if (negative_distribution(rng))
            {
                value = -value;
            }
            values.push_back(value);
        }
        return values;
    }

    struct CheckSlotResult
    {
        bool passed = true;
        double max_abs_error = 0.0;
        size_t worst_slot = 0;
        double expected = 0.0;
        double observed = 0.0;
    };

    void append_check_slots(
        vector<double> &input,
        size_t slot_count,
        const vector<double> &check_slot_values,
        size_t &check_slot_start)
    {
        if (check_slot_values.empty())
        {
            throw invalid_argument("check_slot_values must not be empty");
        }

        if (input.size() + check_slot_values.size() > slot_count)
        {
            throw invalid_argument("not enough CKKS slots for data and check slots");
        }

        check_slot_start = input.size();
        input.resize(slot_count, 0.0);
        for (size_t i = 0; i < check_slot_values.size(); ++i)
        {
            input[check_slot_start + i] = check_slot_values[i];
        }
    }

    vector<double> expected_check_slots(const vector<double> &check_slot_values)
    {
        vector<double> expected(check_slot_values.size());
        for (size_t i = 0; i < check_slot_values.size(); ++i)
        {
            expected[i] = server_check_multiplier * check_slot_values[i];
        }
        return expected;
    }

    CheckSlotResult verify_check_slots(
        const vector<double> &decoded, size_t check_slot_start, const vector<double> &expected, double threshold)
    {
        if (expected.empty())
        {
            throw invalid_argument("expected check slots must not be empty");
        }
        if (check_slot_start + expected.size() > decoded.size())
        {
            throw invalid_argument("decoded vector does not contain all check slots");
        }
        // cout << "" << expected.size() << endl;
        // exit(1);
        CheckSlotResult result;
        double total = 0;
        for (size_t i = 0; i < expected.size(); ++i)
        {
            double observed = decoded[check_slot_start + i];
            double error = std::abs(observed - expected[i]);
            total += error;
            if (error > result.max_abs_error)
            {
                result.max_abs_error = error;
                result.worst_slot = check_slot_start + i;
                result.expected = expected[i];
                result.observed = observed;
            }
            // if (error > threshold)
            // {
            //     result.passed = false;
            // }
        }
        total = total / expected.size();
        result.max_abs_error = total;
        if (total > threshold)
            {
                result.passed = false;
            }
        return result;
    }

    void print_check_slot_result(const string &label, const CheckSlotResult &result, double threshold)
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


double calculate_mse(const vector<double> true_result, const vector<double> decoded, size_t check_slots_long){
    if (true_result.size() != decoded.size() || true_result.empty()) {
        throw std::invalid_argument("Vectors must have the same non-zero size.");
    }

    double sumSquaredError = 0.0;
    size_t sumlong = true_result.size() - check_slots_long;
    for (std::size_t i = 0; i < sumlong; ++i) {
        const double error = true_result[i] - decoded[i];
        sumSquaredError += error * error;
    }

    return sumSquaredError / static_cast<double>(sumlong);
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

    cnpy::NpyArray arr = cnpy::npy_load("/home/qemu/SEAL/SEAL/native/CKKS/data.npy");
    //std::cout<< "11111" <<endl;
    double* data = arr.data<double>();
    size_t total = 1;
    for (auto d : arr.shape) total *= d; 
    vector<double> input (data, data + total);

    // Configure the number of check slots here. The value vector is generated
    // automatically with exactly check_slot_count elements.
    const size_t check_slot_count = 64;
    const uint32_t check_slot_seed = 20260806U;
    const vector<double> check_slot_values =
        generate_check_slot_values(check_slot_count, check_slot_seed);

    size_t check_slot_start = 0;
    append_check_slots(input, slot_count, check_slot_values, check_slot_start);
    vector<double> expected_checks = expected_check_slots(check_slot_values);

    cout << "Input vector: " << total << " data slots + "
         << check_slot_count << " check slots" << endl;
    cout << "Check slots: start=" << check_slot_start
         << ", count=" << check_slot_count
         << ", threshold=" << check_threshold
         << ", seed=" << check_slot_seed << endl;
    cout << "Generated check-slot values: ";
    for (size_t i = 0; i < check_slot_values.size(); ++i)
    {
        cout << setprecision(8) << check_slot_values[i]
             << (i + 1 == check_slot_values.size() ? '\n' : ' ');
    }
    print_vector(input, 3, 7);
    

    Plaintext x_plain;
    // print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    cout << "Scale-1: " << x1_encrypted.scale() << endl;


   
    cout << "Starting Sharpening Process..." << endl;

    int width = 32;
    int height = 32;
    int channel_pixels = width * height; // 1024

    Ciphertext rot_left, rot_right, rot_up, rot_down;
    evaluator.rotate_vector(x1_encrypted, 1, gal_keys, rot_left);
    evaluator.rotate_vector(x1_encrypted, -1, gal_keys, rot_right);
    evaluator.rotate_vector(x1_encrypted, width, gal_keys, rot_up);
    evaluator.rotate_vector(x1_encrypted, -width, gal_keys, rot_down);

    Ciphertext neighbor_sum;
    evaluator.add(rot_up, rot_down, neighbor_sum);
    evaluator.add_inplace(neighbor_sum, rot_left);
    evaluator.add_inplace(neighbor_sum, rot_right);

    vector<double> mask_vec(slot_count, 0.0);
    for (int c = 0; c < 3; ++c) {
        for (int y = 1; y < height - 1; ++y) {
            for (int x = 1; x < width - 1; ++x) {
                mask_vec[c * channel_pixels + y * width + x] = 1.0;
            }
        }
    }
    Plaintext mask_plain;
    encoder.encode(mask_vec, scale, mask_plain);
    
    evaluator.multiply_plain_inplace(neighbor_sum, mask_plain);
    evaluator.rescale_to_next_inplace(neighbor_sum);

    Ciphertext center_weighted;
    Plaintext p_five;
    encoder.encode(5.0, scale, p_five);
    evaluator.multiply_plain(x1_encrypted, p_five, center_weighted);
    evaluator.rescale_to_next_inplace(center_weighted);

    if (neighbor_sum.parms_id() != center_weighted.parms_id()) {
        evaluator.mod_switch_to_inplace(neighbor_sum, center_weighted.parms_id());
    }

    Ciphertext sharpened_result;
    evaluator.sub(center_weighted, neighbor_sum, sharpened_result);

    cout << "Sharpening Completed." << endl;
    

    auto context_data = context.get_context_data(sharpened_result.parms_id());
    auto &parms_info = context_data->parms();
    size_t poly_modulus_degree_val = parms_info.poly_modulus_degree();
    size_t coeff_modulus_size_val = parms_info.coeff_modulus().size();

    x1_encrypted = sharpened_result;

  
    while (poly_modulus_degree_val > 1)
    {
        auto context_data = context.get_context_data(x1_encrypted.parms_id());

        if (!context_data->next_context_data())
            break;

        auto next_parms_id = context_data->next_context_data()->parms_id();
        
        evaluator.mod_switch_to_inplace(x1_encrypted, next_parms_id);
        poly_modulus_degree_val--;
    }


    context_data = context.get_context_data(x1_encrypted.parms_id());
    auto &parms_info1 = context_data->parms();
    poly_modulus_degree_val = parms_info1.poly_modulus_degree();
    coeff_modulus_size_val = parms_info1.coeff_modulus().size();

    Plaintext plain_result;
    decryptor.decrypt(x1_encrypted, plain_result);
    vector<double> true_result;
    encoder.decode(plain_result, true_result);
    print_check_slot_result(
        "Clean ciphertext check slots",
        verify_check_slots(true_result, check_slot_start, expected_checks, check_threshold),
        check_threshold);

    constexpr size_t experiment_count = 1000;
    const size_t coefficient_count = poly_modulus_degree_val;
    const size_t modulus_count = coeff_modulus_size_val;
    const size_t ciphertext_poly_count = x1_encrypted.size();
    const uint32_t random_seed = std::random_device{}();
    std::mt19937 rng(random_seed);
    std::uniform_int_distribution<size_t> poly_distribution(0, ciphertext_poly_count - 1);
    std::uniform_int_distribution<size_t> modulus_distribution(0, modulus_count - 1);
    std::uniform_int_distribution<size_t> coefficient_distribution(0, coefficient_count - 1);

    const fs::path output_dir = fs::current_path() / "result" / "random_bit_flips_500";
    fs::create_directories(output_dir);
    std::ofstream summary(output_dir / "summary.csv");
    if (!summary)
    {
        throw runtime_error("failed to create bit-flip experiment summary");
    }
    summary << "experiment,poly,modulus,coefficient,bit,before,after,"
               "check_slot_detected,max_abs_error,status,result_file\n";

    size_t check_slot_detected_count = 0;
    size_t processing_error_count = 0;
    size_t total_number_TP = 0;
    size_t total_number_FP = 0;
    size_t total_number_TN = 0;
    size_t total_number_FN = 0;
    for (size_t experiment_id = 0; experiment_id < experiment_count; ++experiment_id)
    {
        bool passed_flag = true;
        const size_t poly_idx = poly_distribution(rng);
        const size_t mod_idx = modulus_distribution(rng);
        const size_t coeff_idx = coefficient_distribution(rng);
        const size_t modulus_bit_count = parms_info1.coeff_modulus()[mod_idx].bit_count();
        std::uniform_int_distribution<size_t> bit_distribution(0, modulus_bit_count - 1);
        const size_t bit_idx = bit_distribution(rng);

        Ciphertext faulty_ct = x1_encrypted;

        if (faulty_ct.is_ntt_form()) {
            evaluator.transform_from_ntt_inplace(faulty_ct);
            // std::cout<< "1111" << endl;
        }
        uint64_t *coeff_ptr =
            faulty_ct.data(poly_idx) + mod_idx * coefficient_count + coeff_idx;
        const uint64_t before = *coeff_ptr;
        *coeff_ptr = flip_bit(before, bit_idx);
        const uint64_t after = *coeff_ptr;
        evaluator.transform_to_ntt_inplace(faulty_ct);

        bool check_slot_detected = false;
        bool processing_error = false;
        double max_abs_error = std::numeric_limits<double>::infinity();
        string status;
        string true_string;
        fs::path result_file = output_dir / ("experiment_" + to_string(experiment_id) + ".npy");

        try
        {
            Plaintext faulty_plain;
            decryptor.decrypt(faulty_ct, faulty_plain);

            vector<double> decoded;
            encoder.decode(faulty_plain, decoded);
            const CheckSlotResult check_result =
                verify_check_slots(decoded, check_slot_start, expected_checks, check_threshold);
            check_slot_detected = !check_result.passed;

            double result_mse = calculate_mse(true_result, decoded, check_slot_count);
            if (result_mse > check_threshold){
                passed_flag = false;
            }
            true_string = passed_flag ? "True" : "Error";
            if (!passed_flag == check_slot_detected && true_string == "True")
            {
                total_number_TP++;
            }
            else if (!passed_flag == check_slot_detected && true_string == "Error"){
                total_number_TN++;
            }
            else if (passed_flag == check_slot_detected && true_string == "True"){
                total_number_FN++;
            }
            else{
                total_number_FP++;
            }

            max_abs_error = check_result.max_abs_error;
            status = check_slot_detected ? "detected" : "missed";

            const vector<size_t> shape{ decoded.size() };
            cnpy::npy_save(result_file.string(), decoded.data(), shape, "w");
        }
        catch (const std::exception &exception)
        {
            processing_error = true;
            status = "decrypt_or_decode_error";
            result_file.replace_extension(".txt");
            std::ofstream error_file(result_file);
            error_file << exception.what() << '\n';
        }
        catch (...)
        {
            processing_error = true;
            status = "decrypt_or_decode_error";
            result_file.replace_extension(".txt");
            std::ofstream error_file(result_file);
            error_file << "unknown decrypt/decode error\n";
        }

        if (check_slot_detected)
        {
            ++check_slot_detected_count;
        }
        if (processing_error)
        {
            ++processing_error_count;
        }

        summary << experiment_id << ',' << poly_idx << ',' << mod_idx << ',' << coeff_idx << ','
                << bit_idx << ',' << before << ',' << after << ','
                << (check_slot_detected ? 1 : 0) << ',' << max_abs_error << ',' << status << ','
                << result_file.filename().string() << '\n';

        cout << "Experiment " << (experiment_id + 1) << '/' << experiment_count
             << ": p=" << poly_idx << ", m=" << mod_idx << ", c=" << coeff_idx
             << ", bit=" << bit_idx << ", " << status << endl;
    }

    const double check_slot_detection_rate =
        100.0 * static_cast<double>(check_slot_detected_count) / experiment_count;
    const double system_detection_rate =
        100.0 * static_cast<double>(check_slot_detected_count + processing_error_count) / experiment_count;
    summary << "# seed," << random_seed << '\n';
    summary << "# check_slot_detected," << check_slot_detected_count << '\n';
    summary << "# processing_errors," << processing_error_count << '\n';
    summary << "# check_slot_detection_rate_percent," << check_slot_detection_rate << '\n';
    summary << "# system_detection_rate_percent," << system_detection_rate << '\n';

    cout << "Check slots detected " << check_slot_detected_count << '/' << experiment_count
         << " random bit flips (" << check_slot_detection_rate << "%). Processing errors: "
         << processing_error_count << ". System detection rate: " << system_detection_rate
         << "%. Results: " << output_dir << endl;
    cout << "Result: " << total_number_TP << " " << total_number_FP << " " << total_number_TN << " " << total_number_FN <<  " " << experiment_count << endl;
    return;

}
