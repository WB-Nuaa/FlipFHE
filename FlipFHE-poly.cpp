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
    return x ^ (uint64_t(1) << bit_pos); //Flip
    
}


void save_ciphertext(const Ciphertext &encrypted, const std::string &filename) {
    std::ofstream ct_stream(filename, std::ios::binary);
    if (!ct_stream) {
        throw std::runtime_error("Can not open file: " + filename);
    }

    encrypted.save(ct_stream);

}



void example_ckks_basics()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
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

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl;

    /*
    We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode
    that encodes the given floating-point value to every slot in the vector.
    */
    Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
    encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    /*
    To compute x^3 we first compute x^2 and relinearize. However, the scale has
    now grown to 2^80.
    */
    Ciphertext x3_encrypted;
    print_line(__LINE__);
    cout << "Compute x^2 and relinearize:" << endl;
    evaluator.square(x1_encrypted, x3_encrypted);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Scale of x^2 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    /*
    Now rescale; in addition to a modulus switch, the scale is reduced down by
    a factor equal to the prime that was switched away (40-bit prime). Hence, the
    new scale should be close to 2^40. Note, however, that the scale is not equal
    to 2^40: this is because the 40-bit prime is only close to 2^40.
    */
    print_line(__LINE__);
    cout << "Rescale x^2." << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Scale of x^2 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    print_line(__LINE__);
    cout << "Compute and rescale PI*x." << endl;
    Ciphertext x1_encrypted_coeff3;
    evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3);
    cout << "    + Scale of PI*x before rescale: " << log2(x1_encrypted_coeff3.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted_coeff3);
    cout << "    + Scale of PI*x after rescale: " << log2(x1_encrypted_coeff3.scale()) << " bits" << endl;

    /*
    Since x3_encrypted and x1_encrypted_coeff3 have the same exact scale and use
    the same encryption parameters, we can multiply them together. We write the
    result to x3_encrypted, relinearize, and rescale. Note that again the scale
    is something close to 2^40, but not exactly 2^40 due to yet another scaling
    by a prime. We are down to the last level in the modulus switching chain.
    */
    print_line(__LINE__);
    cout << "Compute, relinearize, and rescale (PI*x)*x^2." << endl;
    evaluator.multiply_inplace(x3_encrypted, x1_encrypted_coeff3);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Scale of PI*x^3 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Scale of PI*x^3 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    /*
    Next we compute the degree one term. All this requires is one multiply_plain
    with plain_coeff1. We overwrite x1_encrypted with the result.
    */
    print_line(__LINE__);
    cout << "Compute and rescale 0.4*x." << endl;
    evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1);
    cout << "    + Scale of 0.4*x before rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted);
    cout << "    + Scale of 0.4*x after rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;

    cout << endl;
    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl;
    cout << "    + Modulus chain index for x3_encrypted: "
         << context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for x1_encrypted: "
         << context.get_context_data(x1_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for plain_coeff0: "
         << context.get_context_data(plain_coeff0.parms_id())->chain_index() << endl;
    cout << endl;

    print_line(__LINE__);
    cout << "The exact scales of all three terms are different:" << endl;
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "    + Exact scale in PI*x^3: " << x3_encrypted.scale() << endl;
    cout << "    + Exact scale in  0.4*x: " << x1_encrypted.scale() << endl;
    cout << "    + Exact scale in      1: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt);

    print_line(__LINE__);
    cout << "Normalize scales to 2^40." << endl;
    x3_encrypted.scale() = pow(2.0, scale_size);
    x1_encrypted.scale() = pow(2.0, scale_size);

    /*
    We still have a problem with mismatching encryption parameters. This is easy
    to fix by using traditional modulus switching (no rescaling). CKKS supports
    modulus switching just like the BFV scheme, allowing us to switch away parts
    of the coefficient modulus when it is simply not needed.
    */
    print_line(__LINE__);
    cout << "Normalize encryption parameters to the lowest level." << endl;
    parms_id_type last_parms_id = x3_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);

    /*
    All three ciphertexts are now compatible and can be added.
    */
    print_line(__LINE__);
    cout << "Compute PI*x^3 + 0.4*x + 1." << endl;
    Ciphertext encrypted_result;
    evaluator.add(x3_encrypted, x1_encrypted, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0);

    /*
    First print the true result.
    */
    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode PI*x^3 + 0.4x + 1." << endl;
    cout << "    + Expected result:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back((3.14159265 * x * x + 0.4) * x + 1);
    }
    print_vector(true_result, 3, 7);

    fs::current_path("/home/qemu/SEAL/SEAL/native/CKKS/");
    std::cout << "CWD = " << fs::current_path() << std::endl;
    std::ostringstream file_oss;
    file_oss << "true_result.npy";

    fs::path file_path = fs::path() / file_oss.str();

    std::vector<size_t> shape = { true_result.size() };
    cnpy::npy_save(
        file_path.string(),
        true_result.data(),   
        shape,
        "w"               
        );

    // exit(1);

    /*
    Decrypt, decode, and print the result.
    */
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result, 3, 7);


    auto context_data = context.get_context_data(encrypted_result.parms_id());
    auto &parms_info = context_data->parms();
    size_t poly_modulus_degree_val = parms_info.poly_modulus_degree();
    size_t coeff_modulus_size_val = parms_info.coeff_modulus().size();

    cout << "Degree (N): " << poly_modulus_degree_val << endl;
    cout << "Modulus: " << coeff_modulus_size_val << endl;
    cout << "Poly: " << encrypted_result.size() << endl;

    x1_encrypted = encrypted_result;

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

    size_t N = poly_modulus_degree_val;
    size_t L = coeff_modulus_size_val;
    size_t num_poly = x1_encrypted.size();

    size_t experiment_id = 0;
    size_t number = 0;

    for (size_t poly_idx = 0; poly_idx < num_poly; poly_idx++) {
        for (size_t mod_idx = 0; mod_idx < L; mod_idx++) {
            for (size_t coeff_idx = 0; coeff_idx < N; coeff_idx++) {

                std::ostringstream dir_oss;
                    dir_oss <<"p" << poly_idx
                        << "_m" << mod_idx
                        << "_c" << coeff_idx;

                for (size_t bit_idx = 0; bit_idx < 64; bit_idx++) {

                    seal::Ciphertext faulty_ct = x1_encrypted;
                    if (faulty_ct.is_ntt_form()) {
                        evaluator.transform_from_ntt_inplace(faulty_ct);
                        // std::cout<< "1111" << endl;
                    }

                    uint64_t *poly_ptr = faulty_ct.data(poly_idx);
                    
                    uint64_t *coeff_ptr =
                        poly_ptr + mod_idx * N + coeff_idx;
                    *coeff_ptr = flip_bit(*coeff_ptr, bit_idx);

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
                        continue;
                    }

                    cout << "    + Computed result ...... Correct." << endl;
                    print_vector(decoded, 3, 7);
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

            }
        }
    }
}

}