// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "cnpy.h"
#include <bitset>
#include <iomanip>
#include <algorithm>
#include <random>
#include <chrono>
#include <filesystem>
#include <sstream>

using namespace std;
using namespace seal;
namespace fs = std::filesystem;


unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
std::mt19937 rng(seed);

// void print_hex_binary(uint64_t value);

void print_hex_binary(uint64_t value) {
    cout << "0x" << hex << setw(16) << setfill('0') << value 
         << " (" << dec << value << ")  Binary: "
         << std::bitset<64>(value) << endl;
    cout << dec << setfill(' ');
}


inline uint64_t flip_bit(uint64_t x, size_t bit_pos) {
    return x ^ (uint64_t(1) << bit_pos); //bit flips
}



void example_ckks_basics()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    int scale_size = 40;
    double scale = pow(2.0, scale_size); 

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

    cnpy::NpyArray arr = cnpy::npy_load("/home/qemu/SEAL/SEAL/native/CKKS/data.npy");
    //std::cout<< "11111" <<endl;
    double* data = arr.data<double>();
    size_t total = 1;
    for (auto d : arr.shape) total *= d; 
    vector<double> input (data, data + total);

    cout << "Input vector: " << input.size() << endl;
    print_vector(input, 3, 7);
    

    Plaintext x_plain;
    // print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);




    //Image Sharpening
// ---Start
    cout << "Starting Sharpening Process..." << endl;

    // Image parameters
    int width = 32;
    int height = 32;
    int channel_pixels = width * height; // 1024

    Ciphertext rot_left, rot_right, rot_up, rot_down;
    evaluator.rotate_vector(x1_encrypted, 1, gal_keys, rot_left);
    evaluator.rotate_vector(x1_encrypted, -1, gal_keys, rot_right);
    evaluator.rotate_vector(x1_encrypted, width, gal_keys, rot_up);
    evaluator.rotate_vector(x1_encrypted, -width, gal_keys, rot_down);

    // 2. (Up + Down + Left + Right)
    Ciphertext neighbor_sum;
    evaluator.add(rot_up, rot_down, neighbor_sum);
    evaluator.add_inplace(neighbor_sum, rot_left);
    evaluator.add_inplace(neighbor_sum, rot_right);

    // 3.  Masking
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
    
    // multiplication
    evaluator.multiply_plain_inplace(neighbor_sum, mask_plain);
    evaluator.rescale_to_next_inplace(neighbor_sum);

    // 4. 5 * Input
    Ciphertext center_weighted;
    Plaintext p_five;
    encoder.encode(5.0, scale, p_five);
    evaluator.multiply_plain(x1_encrypted, p_five, center_weighted);
    evaluator.rescale_to_next_inplace(center_weighted);

    // neighbor_sum.scale() = scale; 
    // center_weighted.scale() = scale;

    if (neighbor_sum.parms_id() != center_weighted.parms_id()) {
        evaluator.mod_switch_to_inplace(neighbor_sum, center_weighted.parms_id());
    }

    // 6. Sharpened = 5 * Input - Sum(Neighbors)
    Ciphertext sharpened_result;
    evaluator.sub(center_weighted, neighbor_sum, sharpened_result);

    cout << "Sharpening Completed." << endl;
    

    auto context_data = context.get_context_data(sharpened_result.parms_id());
    auto &parms_info = context_data->parms();
    size_t poly_modulus_degree_val = parms_info.poly_modulus_degree();
    size_t coeff_modulus_size_val = parms_info.coeff_modulus().size();

    cout << "Degree (N): " << poly_modulus_degree_val << endl;
    cout << "Modulus: " << coeff_modulus_size_val << endl;
    cout << "Polynomials: " << x1_encrypted.size() << endl;

    x1_encrypted = sharpened_result;

    // exit(1);

    while (poly_modulus_degree_val > 1)
    {
        auto context_data = context.get_context_data(x1_encrypted.parms_id());

        if (!context_data->next_context_data())
            break;

        auto next_parms_id = context_data->next_context_data()->parms_id();
        
        evaluator.mod_switch_to_inplace(x1_encrypted, next_parms_id);
        poly_modulus_degree_val--;
    }


    cout << "\n========== Information ==========\n" << endl;

    
    // Context

    context_data = context.get_context_data(x1_encrypted.parms_id());
    auto &parms_info1 = context_data->parms();
    poly_modulus_degree_val = parms_info1.poly_modulus_degree();
    coeff_modulus_size_val = parms_info1.coeff_modulus().size();

    cout << "Degree (N): " << poly_modulus_degree_val << endl;
    cout << "Modulus: " << coeff_modulus_size_val << endl;
    cout << "Polynomials: " << x1_encrypted.size() << endl;


    //Generate 100 sets of random multiple-bit flips
    // 
    std::uniform_int_distribution<int> dist_large(0, 8191); //poly_modulus_degree_val
    std::uniform_int_distribution<int> dist_small(0, 59); //last Modulus
    std::uniform_int_distribution<int> dist_count(3, 7); //multiple bits

    std::vector<std::vector<int>> groups100;

    for (int i = 0; i < 100; ++i) {
        std::vector<int> group;
        group.push_back(dist_large(rng));
        int n = dist_count(rng);
        for (int j = 0; j < n; ++j) {
            group.push_back(dist_small(rng));
        }
        groups100.push_back(group);
    }

    // Bit flips
    for(size_t i = 0; i < 100; i++)
    {
        std::ostringstream dir_oss;
        dir_oss << "G" << i;
        std::vector<int> temp = groups100[i];
        int max = 0;

        seal::Ciphertext faulty_ct = x1_encrypted;
        if (faulty_ct.is_ntt_form()) {
            evaluator.transform_from_ntt_inplace(faulty_ct);
        }
        uint64_t *poly_ptr = faulty_ct.data(0);
        uint64_t *coeff_ptr = poly_ptr + temp[0];

        cout << temp[0] <<endl;
        for (size_t j = 1; j < temp.size(); j++){
            *coeff_ptr = flip_bit(*coeff_ptr, temp[j]);
            if (temp[j] > max)
            {
                max = temp[j];
            }
            cout << temp[j] << " ";
        }
        cout<<endl;
        evaluator.transform_to_ntt_inplace(faulty_ct);
        seal::Plaintext faulty_plain;
        try {
            decryptor.decrypt(faulty_ct, faulty_plain);
        } catch (...) {
            cout<< "decrypt_ERROR!" << endl;
            //exit(1);
            continue;
        }
        std::vector<double> decoded;
        try {
            encoder.decode(faulty_plain, decoded);
        } catch (...) {
            cout<< "decode_ERROR!" << endl;
                        //exit(1);
            continue;
        }
        cout << "  Multi Flip." << endl;
        print_vector(decoded, 3, 7);
        // 6. store .npy
        fs::current_path("/home/qemu/SEAL/SEAL/native/CKKS/result");
        std::cout << "CWD = " << fs::current_path() << std::endl;
        std::ostringstream file_oss;
        file_oss << 'M' << i << ".npy";

        fs::create_directories(dir_oss.str());
        fs::path file_path = fs::path(dir_oss.str()) / file_oss.str();

        std::vector<size_t> shape = { decoded.size() };
        cnpy::npy_save(
            file_path.string(),
            decoded.data(),   
            shape,
            "w"               
            );

        //Highest bit flip
        seal::Ciphertext faulty_ct_max = x1_encrypted;
        if (faulty_ct_max.is_ntt_form()) {
            evaluator.transform_from_ntt_inplace(faulty_ct_max);
        }
        uint64_t *poly_ptr_max = faulty_ct_max.data(0);
        uint64_t *coeff_ptr_max = poly_ptr_max + temp[0];
        *coeff_ptr_max = flip_bit(*coeff_ptr_max, max);

        evaluator.transform_to_ntt_inplace(faulty_ct_max);
        seal::Plaintext faulty_plain_max;
        try {
            decryptor.decrypt(faulty_ct_max, faulty_plain_max);
        } catch (...) {
            cout<< "decrypt_ERROR!" << endl;
            //exit(1);
            continue;
        }
  
        std::vector<double> decoded_max;
        try {
            encoder.decode(faulty_plain_max, decoded_max);
        } catch (...) {
            cout<< "decode_ERROR!" << endl;
                        //exit(1);
            continue;
        }
        cout << "  MAX Bit Flip." << endl;
        print_vector(decoded_max, 3, 7);

        fs::current_path("/home/qemu/SEAL/SEAL/native/CKKS/result");
        std::cout << "CWD = " << fs::current_path() << std::endl;
        std::ostringstream file_oss_max;
        file_oss_max << 'M' << i << 'M' << ".npy";

        fs::create_directories(dir_oss.str());
        fs::path file_path_max = fs::path(dir_oss.str()) / file_oss_max.str();

        std::vector<size_t> shape_max = { decoded_max.size() };
        cnpy::npy_save(
            file_path_max.string(),
            decoded_max.data(),   
            shape_max,
            "w"               
            );        
    }
 
}