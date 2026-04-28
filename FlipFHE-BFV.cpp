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


void print_hex_binary(uint64_t value) {
    cout << "0x" << hex << setw(16) << setfill('0') << value 
         << " (" << dec << value << ")  Binary: "
         << std::bitset<64>(value) << endl;

    cout << dec << setfill(' ');
}


inline uint64_t flip_bit(uint64_t x, size_t bit_pos) {
    return x ^ (uint64_t(1) << bit_pos); //Flip

    
}



void example_ckks_basics()
{
    print_example_banner("Example: BFV Basics");
    
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    size_t final_module = 50;
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { final_module, 30, 30, 50, final_module}));

    /*
    To enable batching, we need to set the plain_modulus to be a prime number
    congruent to 1 modulo 2*poly_modulus_degree. Microsoft SEAL provides a helper
    method for finding such a prime. In this example we create a 20-bit prime
    that supports batching.
    */
    size_t plain_size = 20;
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, plain_size));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    /*
    We can verify that batching is indeed enabled by looking at the encryption
    parameter qualifiers created by SEALContext.
    */
    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    /*
    Batching is done through an instance of the BatchEncoder class.
    */
    BatchEncoder batch_encoder(context);

    /*
    The total number of batching `slots' equals the poly_modulus_degree, N, and
    these slots are organized into 2-by-(N/2) matrices that can be encrypted and
    computed on. Each slot contains an integer modulo plain_modulus.
    */
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    /*
    The matrix plaintext is simply given to BatchEncoder as a flattened vector
    of numbers. The first `row_size' many numbers form the first row, and the
    rest form the second row. Here we create the following matrix:

        [ 0,  1,  2,  3,  0,  0, ...,  0 ]
        [ 4,  5,  6,  7,  0,  0, ...,  0 ]
    */
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    /*
    We can instantly decode to verify correctness of the encoding. Note that no
    encryption or decryption has yet taken place.
    */
    vector<uint64_t> pod_result;
    cout << "    + Decode plaintext matrix ...... Correct." << endl;
    batch_encoder.decode(plain_matrix, pod_result);
    print_matrix(pod_result, row_size);

    /*
    Next we encrypt the encoded plaintext.
    */
    Ciphertext encrypted_matrix;
    print_line(__LINE__);
    cout << "Encrypt plain_matrix to encrypted_matrix." << endl;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "    + Noise budget in encrypted_matrix: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;

    /*
    Operating on the ciphertext results in homomorphic operations being performed
    simultaneously in all 8192 slots (matrix elements). To illustrate this, we
    form another plaintext matrix

        [ 1,  2,  1,  2,  1,  2, ..., 2 ]
        [ 1,  2,  1,  2,  1,  2, ..., 2 ]

    and encode it into a plaintext.
    */
    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_matrix2.push_back((i & size_t(0x1)) + 1);
    }
    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << endl;
    cout << "Second input plaintext matrix:" << endl;
    print_matrix(pod_matrix2, row_size);

    /*
    We now add the second (plaintext) matrix to the encrypted matrix, and square
    the sum.
    */
    print_line(__LINE__);
    cout << "Sum, square, and relinearize." << endl;
    evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
    evaluator.square_inplace(encrypted_matrix);
    evaluator.relinearize_inplace(encrypted_matrix, relin_keys);

    /*
    How much noise budget do we have left?
    */
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    We decrypt and decompose the plaintext to recover the result as a matrix.
    */
    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);
    // exit(0);



    auto context_data = context.first_context_data(); 
    auto &parms_info = context_data->parms();
    size_t poly_modulus_degree_val = parms_info.poly_modulus_degree();
    size_t coeff_modulus_size_val = parms_info.coeff_modulus().size();
    
    std::cout << "Degree (N): " << poly_modulus_degree_val << std::endl;
    std::cout << "Modulus: " << coeff_modulus_size_val << std::endl;
    std::cout << "Poly: " << encrypted_matrix.size() << std::endl;

    Ciphertext x1_encrypted = encrypted_matrix;

    while (poly_modulus_degree_val > 1)
    {
        auto context_data = context.get_context_data(x1_encrypted.parms_id());

        if (!context_data->next_context_data())
            break;

        auto next_parms_id = context_data->next_context_data()->parms_id();
        
        evaluator.mod_switch_to_inplace(x1_encrypted, next_parms_id);
        poly_modulus_degree_val--;

    }


    cout << "\n========== Info ==========\n" << endl;


    context_data = context.get_context_data(x1_encrypted.parms_id());
    auto &parms_info1 = context_data->parms();
    poly_modulus_degree_val = parms_info1.poly_modulus_degree();
    coeff_modulus_size_val = parms_info1.coeff_modulus().size();

    cout << "Degree (N): " << poly_modulus_degree_val << endl;
    cout << "Modulus: " << coeff_modulus_size_val << endl;
    cout << "Poly: " << x1_encrypted.size() << endl;

    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(x1_encrypted) << " bits" << endl;


    
    size_t N = poly_modulus_degree_val;
    size_t L = coeff_modulus_size_val;
    size_t num_poly = x1_encrypted.size();

    size_t experiment_id = 0;

    //Flip
    for (size_t poly_idx = 0; poly_idx < num_poly; poly_idx++) {
        for (size_t mod_idx = 0; mod_idx < L; mod_idx++) {
            for (size_t coeff_idx = 0; coeff_idx < N; coeff_idx++) {

                std::ostringstream dir_oss;
                    dir_oss << plain_size << "_" << final_module <<"_p" << poly_idx
                        << "_m" << mod_idx
                        << "_c" << coeff_idx;

                for (size_t bit_idx = 0; bit_idx < 64; bit_idx++) {

                    seal::Ciphertext faulty_ct = x1_encrypted;

                    uint64_t *poly_ptr_1 = faulty_ct.data(poly_idx);
                    uint64_t value = *poly_ptr_1;

                    uint64_t *poly_ptr = faulty_ct.data(poly_idx);
                    
                    uint64_t *coeff_ptr =
                        poly_ptr + mod_idx * N + coeff_idx;


                    std::cout << *poly_ptr << " " << *coeff_ptr  << endl;
                    // 3. Flipping

                    *coeff_ptr = flip_bit(*coeff_ptr, bit_idx);


                    std::cout << "Bit: " << bit_idx << " " << *coeff_ptr << endl;


                    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(faulty_ct) << " bits" << endl;
                // 4.
                    seal::Plaintext faulty_plain;
                    try {
                        decryptor.decrypt(faulty_ct, faulty_plain);
                    } catch (...) {

                        cout<< "decrypt_ERROR!" << endl;

                        continue;
                    }

                    vector<uint64_t> result;
                    batch_encoder.decode(faulty_plain, result);
                    print_matrix(result, row_size);

                    fs::current_path("/home/qemu/SEAL/SEAL/native/CKKS/result");
                    std::cout << "CWD = " << fs::current_path() << std::endl;
                    std::ostringstream file_oss;
                    file_oss << bit_idx << ".npy";

                    fs::create_directories(dir_oss.str());
                    fs::path file_path = fs::path(dir_oss.str()) / file_oss.str();

                    std::vector<size_t> shape = { result.size() };
                    cnpy::npy_save(
                        file_path.string(),
                        result.data(),   
                        shape,
                        "w"               
                        );
                    //exit(0);
            }
           exit(0);
        }
    }
}


}