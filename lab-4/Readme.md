# Programming Symmetric & Asymmetric Crypto

Let's create a Python program to implement the following functions:

1. AES encryption/decryption with two key lengths, 128 and 256 bits, and two modes ECB and CFB (5 marks).

## Instruction to run the code

1. Run the following command to install the requirements

```bash
pip install -r requirements.txt
```

2. Now run the following commands:

### Usage:

Below are the commands to test all the functions in the task.py file, including any necessary commands to create additional files if required. Ensure you replace placeholders like <encrypted_data> with the actual encrypted data obtained from the previous commands.

1. **Generate AES Key:**

   ```sh
   python task.py generate_key 16 keys.key
   ```

2. **Encrypt Data Using AES (ECB Mode):**

   ```sh
   python task.py aes_encrypt "Hello Shawon" keys.key ECB
   ```

3. **Decrypt Data Using AES (ECB Mode):**

   ```sh
   # Replace <encrypted_data> with the output from the previous command
   python task.py aes_decrypt <encrypted_data> keys.key ECB
   ```

4. **Encrypt Data Using AES (CFB Mode):**

   ```sh
   python task.py aes_encrypt "Hello Shawon" keys.key CFB
   ```

5. **Decrypt Data Using AES (CFB Mode):**

   ```sh
   # Replace <encrypted_data> with the output from the previous command
   python task.py aes_decrypt <encrypted_data> keys.key CFB
   ```

6. **Generate RSA Key Pair:**

   ```sh
   python task.py generate_rsa_key_pair
   ```

7. **Encrypt Data Using RSA:**

   ```sh
   python task.py rsa_encrypt "Starting Date of WW3" public_key.pem
   ```

8. **Decrypt Data Using RSA:**

   ```sh
   # Replace <encrypted_data> with the output from the previous command
   python task.py rsa_decrypt <encrypted_data> private_key.pem
   ```

9. **Create a File for RSA Sign/Verify and SHA256 Hash:**

   ```sh
   echo "This is a test file." > testfile.txt
   ```

10. **Sign a File Using RSA:**

    ```sh
    python task.py rsa_sign testfile.txt private_key.pem
    ```

11. **Verify the Signature of a File Using RSA:**

    ```sh
    python task.py rsa_verify testfile.txt public_key.pem
    ```

12. **Generate SHA256 Hash of a File:**
    ```sh
    python task.py sha256_hash testfile.txt
    ```

Ensure you replace placeholders like <encrypted_data> with the actual encrypted data obtained from the previous commands. This sequence of commands will thoroughly test all the functions implemented in your task.py file.

## Time measurements & Observations in Graph

I experimented with RSA and AES encryption and decryption using five different key sizes: 16, 32, 64, 128, and 256 bytes. For each key size, I measured the time taken for both encryption and decryption. The following graph illustrates the time measurements for each key size.

To get the graph run the following command:

```bash
python time_measurement.py
```
