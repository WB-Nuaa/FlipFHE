// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "cnpy.h"
#include <bitset>
#include <iomanip>
#include <algorithm>

#include <filesystem>
#include <sstream>
#include <fstream>

using namespace std;
using namespace seal;
namespace fs = std::filesystem;



//Store .txt
void SAVETXT(std::vector<uint64_t> value, const std::string& filename)
{
    std::ofstream out(filename);
    if (!out.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    for (auto val : value) {
        out << val << '\n';
    }
    out.close();

    std::cout << "Saved highbit values to " << filename << std::endl;

}

//Only store the ciphertext
void saveHighBitsToTxt(const uint64_t* poly_ptr, std::size_t coeff_count, std::size_t number, const std::string& filename) {
    if (!poly_ptr) {
        throw std::runtime_error("Invalid polynomial pointer");
    }

    std::vector<uint64_t> high_bits(coeff_count * 2);
    for (std::size_t i = 0; i < 0 + coeff_count; ++i) {
        high_bits[i] = poly_ptr[i] >> number;
    }
    for (std::size_t i = coeff_count; i < 2 * coeff_count; ++i) {
        high_bits[i] = poly_ptr[i] >> (number/2);
    }
    SAVETXT(high_bits, filename);
}


void print_hex_binary(uint64_t value) {
    cout << "0x" << hex << setw(16) << setfill('0') << value 
         << " (" << dec << value << ")  Binary: "
         << std::bitset<64>(value) << endl;
    cout << dec << setfill(' ');
}


inline uint64_t flip_bit(uint64_t x, size_t bit_pos) {
    return x & ~(uint64_t(1) << bit_pos); //To 0
    
}

//Store the complete ciphertext, which can be used for transmission.
void save_ciphertext(const Ciphertext &encrypted, const std::string &filename) {
    std::ofstream ct_stream(filename, std::ios::binary);
    if (!ct_stream) {
        throw std::runtime_error("Can not open file: " + filename);
    }
    // Call save 
    encrypted.save(ct_stream);
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
    cout << "Starting Sharpening Process..." << endl;

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

    // 3.  (Masking)

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

    // 4. (5 * Input)
    Ciphertext center_weighted;
    Plaintext p_five;
    encoder.encode(5.0, scale, p_five);
    evaluator.multiply_plain(x1_encrypted, p_five, center_weighted);
    evaluator.rescale_to_next_inplace(center_weighted);

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
    cout << "Poly: " << sharpened_result.size() << endl;

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

    context_data = context.get_context_data(x1_encrypted.parms_id());
    auto &parms_info1 = context_data->parms();
    poly_modulus_degree_val = parms_info1.poly_modulus_degree();
    coeff_modulus_size_val = parms_info1.coeff_modulus().size();

    cout << "Degree (N): " << poly_modulus_degree_val << endl;
    cout << "Modulus: " << coeff_modulus_size_val << endl;
    cout << "Poly: " << x1_encrypted.size() << endl;


   
    evaluator.transform_from_ntt_inplace(x1_encrypted);
    // Storing ciphertext in non-NTT domain. It can also be stored directly in the form of NTT. There is no impact of either of them on decryption.
    save_ciphertext(x1_encrypted, "/home/qemu/SEAL/SEAL/native/CKKS/result.seal");
    evaluator.transform_to_ntt_inplace(x1_encrypted);
    // exit(1);

    //Read
    std::ifstream ct_stream("/home/qemu/SEAL/SEAL/native/CKKS/result.seal", std::ios::binary);
    if (!ct_stream) {
        throw std::runtime_error("Can not open file: ");
    }
    Ciphertext x2_encrypted;
    x2_encrypted.load(context, ct_stream);

    if (!x2_encrypted.is_ntt_form()) {
        evaluator.transform_to_ntt_inplace(x2_encrypted);
    }

    Plaintext plain_result;
    decryptor.decrypt(x2_encrypted, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result, 3, 7);



    size_t N = poly_modulus_degree_val;
    size_t L = coeff_modulus_size_val;
    size_t num_poly = x1_encrypted.size();

    size_t experiment_id = 0;
    size_t number = 0;

    //Only store the ciphertext
    evaluator.transform_from_ntt_inplace(x1_encrypted);
    for (size_t poly_idx = 0; poly_idx < num_poly; poly_idx++) {
        
        uint64_t *poly_ptr = x1_encrypted.data(poly_idx);
        std::vector<uint64_t> value(N*2);
        for (std::size_t i = 0; i < N*2; ++i) {
            value[i] = poly_ptr[i];
        }
        SAVETXT(value, "/home/qemu/SEAL/SEAL/native/CKKS/origin.txt");   
        break;   
    }
    //Only store the high bits of the ciphertext
    for (size_t poly_idx = 0; poly_idx < num_poly; poly_idx++) {
        
        uint64_t *poly_ptr = x1_encrypted.data(poly_idx);
        saveHighBitsToTxt(poly_ptr, N, 30, "/home/qemu/SEAL/SEAL/native/CKKS/flip.txt");
        break;   
    }
    evaluator.transform_to_ntt_inplace(x1_encrypted);

    //To 0
    for (size_t poly_idx = 0; poly_idx < num_poly; poly_idx++) {
        for (size_t mod_idx = 0; mod_idx < L; mod_idx++) {
            for (size_t coeff_idx = 0; coeff_idx < N; coeff_idx++) {

                for (size_t bit_idx = 0; bit_idx < 1; bit_idx++) {

                    if (x1_encrypted.is_ntt_form()) {
                        evaluator.transform_from_ntt_inplace(x1_encrypted);
                    }

                    uint64_t *poly_ptr = x1_encrypted.data(poly_idx);
 
                    uint64_t *coeff_ptr =
                        poly_ptr + mod_idx * N + coeff_idx;
  
                    *coeff_ptr = flip_bit(*coeff_ptr, bit_idx);
 
                    if (poly_idx == 1){
                        number = 15;
                    }
                    else
                    {
                        number = 30;
                    }
                    for (int k = 1; k <number; k++)
                    {
                       *coeff_ptr = flip_bit(*coeff_ptr, bit_idx+k); 
                    }

                    evaluator.transform_to_ntt_inplace(x1_encrypted);

            }
        }
    }
}

    evaluator.transform_from_ntt_inplace(x1_encrypted);
    //Storing the ciphertext where all the lower bits become 0 
    save_ciphertext(x1_encrypted, "/home/qemu/SEAL/SEAL/native/CKKS/result1.seal");

    std::ifstream ct_stream_1("/home/qemu/SEAL/SEAL/native/CKKS/result1.seal", std::ios::binary);
    if (!ct_stream_1) {
        throw std::runtime_error("Can not open file: ");
    }
    Ciphertext x3_encrypted;
    x3_encrypted.load(context, ct_stream_1);

    if (!x3_encrypted.is_ntt_form()) {
        evaluator.transform_to_ntt_inplace(x3_encrypted);
    }

    Plaintext plain_result_1;
    decryptor.decrypt(x3_encrypted, plain_result_1);
    vector<double> result_1;
    encoder.decode(plain_result_1, result_1);
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result_1, 3, 7);


    evaluator.transform_to_ntt_inplace(x1_encrypted);
    std::ostringstream dir_oss;
    dir_oss <<"overhead";

    seal::Plaintext faulty_plain;
    try {
        decryptor.decrypt(x1_encrypted, faulty_plain);
    } catch (...) {
        cout<< "decrypt_ERROR!" << endl;

    }
    std::vector<double> decoded;
    try {
        encoder.decode(faulty_plain, decoded);
    } catch (...) {
        cout<< "decode_ERROR!" << endl;

    }

    cout << "    + Computed result ...... Correct." << endl;
    print_vector(decoded, 3, 7);
    fs::current_path("/home/qemu/SEAL/SEAL/native/CKKS/result");
    std::cout << "CWD = " << fs::current_path() << std::endl;
    std::ostringstream file_oss;
    file_oss << "result_45.npy";

    fs::create_directories(dir_oss.str());
    fs::path file_path = fs::path(dir_oss.str()) / file_oss.str();

    std::vector<size_t> shape = { decoded.size() };
    cnpy::npy_save(
        file_path.string(),
        decoded.data(),   
        shape,
        "w"               
        );

}