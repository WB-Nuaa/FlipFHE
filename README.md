# One Bit Is Enough: Catastrophic Decryption Precision Loss in Fully Homomorphic Encryption

It allows controlled fault injection (i.e., bit flips) during FHE evaluation operations, aiming to minimize the mean squared error (MSE) of the decrypted ciphertext relative to that obtained without fault injection.
In this repository, we provide the source code, configuration files, requirements, and partial data.
 
## Setup
FlipFHE is developed upon the C++ Microsoft SEAL library (version 4.1.2). Therefore, you need to install a matching version of SEAL first, then compile FlipFHE.

### Build and Install Microsoft SEAL
In the Ubuntu system, open the terminal and execute the following commands:
```bash
git clone  https://github.com/microsoft/SEAL.git
cd SEAL

# Configure the build
cmake -S . -B build
cmake --build build

# Install in the system
sudo cmake --install build
```

### Install FlipFHE
After creating the `CKKS` folder inside the SEAL `native` directory and copying all files into it. Then, open the terminal and execute the following commands:
```bash
sudo cmake -S . -B build
sudo cmake --build build
```
This way, an executable file named CKKS can be obtained:
```bash
 cd build/bin
 ./CKKS
```

## Important Programs
The important programs in FlipFHE are as follows:
- FlipFHE-image.cpp: In the image sharpening task using the CKKS scheme, each coefficient of each polynomial of the ciphertext is flipped bit by bit to obtain the complete ciphertext error information. In addition, experiments with different scaling factors are also included in this program. Just need to modify the corresponding scaling factor, i.e., `scale_size`. And the `/home/qemu/SEAL/SEAL/native/CKKS/data.npy` is the numerical file of the image, which needs to be modified to your corresponding address. The `/home/qemu/SEAL/SEAL/native/CKKS/result` is the storage address of the decrypted data and also needs to be modified.
- FlipFHE-image-overhead.cpp: In the image sharpening task using the CKKS scheme, obtaining the size of the ciphertext and storing it in `/home/qemu/SEAL/SEAL/native/CKKS/origin.txt` and `/home/qemu/SEAL/SEAL/native/CKKS/flip.txt`. Next, we iterate over each coefficient and change its low bits to 0, storing the changed data in `/home/qemu/SEAL/SEAL/native/CKKS/result1.seal`.
- FlipFHE-image-Multiple-bitflips.cpp: In the image sharpening task using the CKKS scheme, generating 100 sets of random multiple-bit flips, performing multiple-bit flips, and the highest bit flip, respectively.
- FlipFHE-poly.cpp: In the polynomial evaluation ($3.14x^3 + 0.4x + 1$) task using the CKKS scheme, each coefficient of each polynomial of the ciphertext is flipped bit by bit to obtain the complete ciphertext error information.
- FlipFHE-poly-overhead.cpp: In the polynomial evaluation task using the CKKS scheme, obtain the size of the ciphertext and store it.
- FlipFHE-BFV.cpp: In the polynomial evaluation ($4(x^2+1)(x+1)^2$) task using the BFV scheme, 





