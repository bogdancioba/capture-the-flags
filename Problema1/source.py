import base64

def extract_encrypted_content(filepath):
    with open(filepath, 'rb') as enc_file:
        return enc_file.read().split(b'\n')

def decode_lines(enc_lines):
    return [base64.b64decode(line) for line in enc_lines if line]

def perform_xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def retrieve_decrypted_lines(encoded_lines, ref_message):
    ref_encrypted = encoded_lines[0][:len(ref_message)]
    return [perform_xor(perform_xor(line, ref_encrypted), ref_message) for line in encoded_lines]

def save_and_display_flag_content(decrypted_content, flag_filename):
    with open(flag_filename, 'wb') as flag_file:
        for entry in decrypted_content:
            flag_file.write(entry + b'\n')
            if entry.startswith(b"ATM{") and entry.endswith(b"}"):
                print(entry.decode())

encrypted_content_path = 'secret.enc'
reference_message = b"Secret Message for our President.After you read this, please burn this message!"

encrypted_lines = extract_encrypted_content(encrypted_content_path)
decoded_content = decode_lines(encrypted_lines)
decrypted_lines = retrieve_decrypted_lines(decoded_content, reference_message)

save_and_display_flag_content(decrypted_lines, 'flag.txt')