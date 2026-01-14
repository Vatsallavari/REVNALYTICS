/*
 * Combined Vulnerability: Buffer Overflow + Weak Cryptography
 * CVE Patterns: CWE-121 + CWE-327 + CWE-320 + CWE-325
 * Similar to: CVE-2014-0160 (Heartbleed), CVE-2008-0166 (Debian OpenSSL)
 * 
 * Combines:
 * - Buffer overflow in crypto operations
 * - Key leakage via overflow
 * - Weak key generation
 * - Crypto oracle attacks
 * - Padding oracle vulnerability
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// ============================================
// Simulated crypto structures (vulnerable)
// ============================================

typedef struct {
    unsigned char key[32];        // AES-256 key
    unsigned char iv[16];         // Initialization vector
    unsigned char internal_state[64];
    int key_size;
    int block_size;
} CryptoContext;

typedef struct {
    char username[32];
    char encrypted_password[64];
    unsigned char session_key[32];
    int privilege_level;
    CryptoContext *crypto_ctx;
} SecureSession;

// Global crypto context (simulates key in memory)
CryptoContext global_crypto = {
    .key = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    .iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    .key_size = 32,
    .block_size = 16
};

// ============================================
// VULNERABILITY 1: Buffer overflow leaks crypto key
// Similar to Heartbleed - reads beyond buffer
// ============================================

void process_encrypted_message(const char *input, int claimed_length) {
    char receive_buffer[64];
    char response_buffer[256];
    
    // VULN: Trust client-supplied length
    // If claimed_length > actual input, reads adjacent memory (keys!)
    printf("[*] Processing message of claimed length: %d\n", claimed_length);
    
    // Copy input (might be small)
    int actual_len = strlen(input);
    if (actual_len < 64) {
        strcpy(receive_buffer, input);
    }
    
    // VULN: Heartbleed-style - copy claimed_length bytes to response
    // This can leak memory beyond receive_buffer including keys
    printf("[*] Building response with %d bytes...\n", claimed_length);
    memcpy(response_buffer, receive_buffer, claimed_length);  // VULN!
    
    printf("[*] Response (hex): ");
    for (int i = 0; i < claimed_length && i < 256; i++) {
        printf("%02x", (unsigned char)response_buffer[i]);
    }
    printf("\n");
    
    // The adjacent memory might contain:
    printf("\n[DEBUG] Memory layout:\n");
    printf("  receive_buffer: %p\n", (void*)receive_buffer);
    printf("  global_crypto:  %p\n", (void*)&global_crypto);
}

// ============================================
// VULNERABILITY 2: Buffer overflow overwrites crypto key
// ============================================

void set_encryption_key(const char *user_key) {
    char key_buffer[32];
    
    // Key validation (appears safe)
    printf("[*] Setting encryption key...\n");
    
    // VULN: strcpy overflow can overwrite adjacent crypto context
    strcpy(key_buffer, user_key);  // OVERFLOW if user_key > 32 bytes
    
    // Copy to global context
    memcpy(global_crypto.key, key_buffer, 32);
    
    printf("[*] Key set successfully\n");
}

// Adjacent structure that can be corrupted
static struct {
    char padding[32];
    int crypto_enabled;
    int use_strong_crypto;
    void (*encrypt_func)(void*, void*, int);
} crypto_config = {
    .crypto_enabled = 1,
    .use_strong_crypto = 1,
    .encrypt_func = NULL
};

void configure_crypto_vulnerable(const char *config_data) {
    char config_buffer[32];
    
    // VULN: Overflow corrupts crypto_config
    strcpy(config_buffer, config_data);
    
    printf("[*] Crypto enabled: %d\n", crypto_config.crypto_enabled);
    printf("[*] Strong crypto: %d\n", crypto_config.use_strong_crypto);
    
    // If overflow set use_strong_crypto to 0, weak crypto used
    if (!crypto_config.use_strong_crypto) {
        printf("[!] WARNING: Falling back to weak encryption!\n");
    }
}

// ============================================
// VULNERABILITY 3: Weak key derivation + overflow
// ============================================

void derive_key_vulnerable(const char *password, unsigned char *derived_key) {
    char password_buffer[32];
    unsigned char temp_key[32];
    
    // VULN 1: Buffer overflow in password handling
    strcpy(password_buffer, password);
    
    // VULN 2: Weak key derivation (simple XOR, no salt, no iterations)
    for (int i = 0; i < 32; i++) {
        temp_key[i] = password_buffer[i % strlen(password_buffer)] ^ 0x5A;
    }
    
    // VULN 3: Predictable IV generation
    srand(time(NULL));  // Weak seed
    for (int i = 0; i < 16; i++) {
        global_crypto.iv[i] = rand() % 256;  // Weak PRNG
    }
    
    memcpy(derived_key, temp_key, 32);
    printf("[*] Key derived from password\n");
}

// ============================================
// VULNERABILITY 4: Crypto padding oracle + overflow
// ============================================

typedef struct {
    unsigned char data[64];
    unsigned char padding[16];
    int padding_length;
} PaddedBlock;

int check_padding_vulnerable(PaddedBlock *block) {
    int pad_len = block->padding_length;
    
    // VULN 1: Integer can be controlled to read out of bounds
    if (pad_len > 16 || pad_len < 1) {
        return -1;  // Invalid padding
    }
    
    // VULN 2: Timing side-channel in padding check
    // Different execution time reveals padding validity
    for (int i = 0; i < pad_len; i++) {
        if (block->padding[16 - pad_len + i] != pad_len) {
            // VULN: Early return reveals position of bad byte
            return -1;
        }
    }
    
    return 0;  // Valid padding
}

int decrypt_with_padding_oracle(const char *ciphertext, int ct_len) {
    PaddedBlock block;
    char plaintext[128];
    
    // VULN: Overflow in ciphertext copy
    memcpy(block.data, ciphertext, ct_len);  // No bounds check!
    
    // Simulated decryption (XOR for demo)
    for (int i = 0; i < ct_len && i < 64; i++) {
        plaintext[i] = block.data[i] ^ global_crypto.key[i % 32];
    }
    
    // VULN: Padding oracle - returns different errors
    block.padding_length = plaintext[ct_len - 1];
    int result = check_padding_vulnerable(&block);
    
    if (result == 0) {
        printf("[+] Decryption successful, valid padding\n");
    } else {
        printf("[-] Decryption failed, invalid padding\n");  // Oracle!
    }
    
    return result;
}

// ============================================
// VULNERABILITY 5: Session key extraction via overflow
// ============================================

SecureSession* create_session(const char *username, const char *password) {
    SecureSession *session = (SecureSession *)malloc(sizeof(SecureSession));
    
    // VULN: Overflow in username overwrites session_key
    strcpy(session->username, username);
    
    // Generate session key
    for (int i = 0; i < 32; i++) {
        session->session_key[i] = rand() % 256;
    }
    
    session->privilege_level = 0;
    session->crypto_ctx = &global_crypto;
    
    printf("[*] Session created for: %s\n", session->username);
    printf("[*] Session key (first 8 bytes): ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", session->session_key[i]);
    }
    printf("...\n");
    
    return session;
}

void print_session_debug(SecureSession *session) {
    // VULN: Debug function leaks sensitive info
    printf("\n[DEBUG] Session dump:\n");
    printf("  Username: %s\n", session->username);
    printf("  Privilege: %d\n", session->privilege_level);
    printf("  Session key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", session->session_key[i]);
    }
    printf("\n");
    
    if (session->crypto_ctx) {
        printf("  Crypto key: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", session->crypto_ctx->key[i]);
        }
        printf("\n");
    }
}

// ============================================
// VULNERABILITY 6: IV reuse + overflow
// ============================================

static int encryption_counter = 0;

void encrypt_message_vulnerable(const char *message, char *output) {
    char msg_buffer[64];
    
    // VULN 1: Buffer overflow
    strcpy(msg_buffer, message);
    
    // VULN 2: IV reuse - same IV used for multiple messages
    // This breaks semantic security of encryption
    printf("[*] Encrypting with IV: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", global_crypto.iv[i]);
    }
    printf(" (used %d times)\n", ++encryption_counter);
    
    // Simulated encryption (XOR - also a vuln!)
    for (int i = 0; msg_buffer[i] && i < 64; i++) {
        output[i] = msg_buffer[i] ^ global_crypto.key[i % 32] ^ global_crypto.iv[i % 16];
    }
}

// ============================================
// COMBINED ATTACK DEMONSTRATION
// ============================================

void vulnerable_crypto_handshake(const char *client_hello, int hello_len) {
    char server_hello[32];
    char shared_secret[64];
    
    printf("\n=== Vulnerable Crypto Handshake ===\n");
    
    // VULN 1: Heartbleed-style read
    printf("[1] Processing client hello (%d claimed bytes)...\n", hello_len);
    process_encrypted_message(client_hello, hello_len);
    
    // VULN 2: Weak random for server hello
    srand(time(NULL));
    for (int i = 0; i < 32; i++) {
        server_hello[i] = rand() % 256;
    }
    
    // VULN 3: Overflow in key derivation
    printf("[2] Deriving shared secret...\n");
    derive_key_vulnerable(client_hello, (unsigned char*)shared_secret);
    
    // VULN 4: Key material in debug output
    printf("[3] Handshake complete\n");
    printf("    Server hello: ");
    for (int i = 0; i < 8; i++) printf("%02x", (unsigned char)server_hello[i]);
    printf("...\n");
}

int main(int argc, char *argv[]) {
    printf("=== Buffer Overflow + Crypto Vulnerabilities Demo ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <demo> [args...]\n", argv[0]);
        printf("\nDemos:\n");
        printf("  heartbleed <data> <claimed_len>  - Heartbleed-style memory leak\n");
        printf("  keyoverwrite <long_key>          - Overflow overwrites crypto config\n");
        printf("  weakkey <password>               - Weak key derivation + overflow\n");
        printf("  padding <ciphertext>             - Padding oracle attack\n");
        printf("  session <long_username>          - Session key leak via overflow\n");
        printf("  handshake <client_data> <len>    - Combined crypto handshake vulns\n");
        return 1;
    }
    
    if (strcmp(argv[1], "heartbleed") == 0 && argc >= 4) {
        process_encrypted_message(argv[2], atoi(argv[3]));
        
    } else if (strcmp(argv[1], "keyoverwrite") == 0 && argc >= 3) {
        printf("Before overflow:\n");
        printf("  crypto_enabled: %d, strong_crypto: %d\n", 
               crypto_config.crypto_enabled, crypto_config.use_strong_crypto);
        configure_crypto_vulnerable(argv[2]);
        printf("After overflow:\n");
        printf("  crypto_enabled: %d, strong_crypto: %d\n",
               crypto_config.crypto_enabled, crypto_config.use_strong_crypto);
        
    } else if (strcmp(argv[1], "weakkey") == 0 && argc >= 3) {
        unsigned char derived[32];
        derive_key_vulnerable(argv[2], derived);
        printf("Derived key: ");
        for (int i = 0; i < 32; i++) printf("%02x", derived[i]);
        printf("\n");
        
    } else if (strcmp(argv[1], "padding") == 0 && argc >= 3) {
        decrypt_with_padding_oracle(argv[2], strlen(argv[2]));
        
    } else if (strcmp(argv[1], "session") == 0 && argc >= 3) {
        SecureSession *s = create_session(argv[2], "password");
        print_session_debug(s);
        free(s);
        
    } else if (strcmp(argv[1], "handshake") == 0 && argc >= 4) {
        vulnerable_crypto_handshake(argv[2], atoi(argv[3]));
    }
    
    return 0;
}

