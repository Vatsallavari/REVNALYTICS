/*
 * Multi-Vulnerability: Weak Cryptography + Information Disclosure
 * CVE Patterns: CWE-327 + CWE-328 + CWE-330 + CWE-200 + CWE-312
 * 
 * Combines:
 * - Weak/broken cryptographic algorithms
 * - Insufficient entropy
 * - Hardcoded keys
 * - Sensitive data exposure
 * - Insecure random number generation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

// ===== VULNERABILITY: Hardcoded cryptographic keys (CWE-321) =====
const char *HARDCODED_KEY = "MySecretKey12345";
const char *HARDCODED_IV = "InitVector12345!";
const unsigned char AES_KEY[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// ===== VULNERABILITY: Weak PRNG seed (CWE-330) =====
void init_weak_random() {
    // VULN: Predictable seed - time is guessable
    srand(time(NULL));
}

void init_very_weak_random() {
    // VULN: Constant seed - always same sequence
    srand(12345);
}

// ===== VULNERABILITY: Weak random number generation =====
char* generate_session_token() {
    // VULN: Using weak PRNG for security-sensitive token
    char *token = (char *)malloc(33);
    static const char charset[] = "0123456789ABCDEF";
    
    // VULN: rand() is not cryptographically secure
    for (int i = 0; i < 32; i++) {
        token[i] = charset[rand() % 16];
    }
    token[32] = '\0';
    
    return token;
}

int generate_otp() {
    // VULN: Predictable OTP using time-based seed
    srand(time(NULL));
    // VULN: OTP based on weak PRNG
    return rand() % 1000000;
}

// ===== VULNERABILITY: Broken hash function (CWE-328) =====
uint32_t weak_hash(const char *data) {
    // VULN: Custom weak hash - easily reversible/collides
    uint32_t hash = 0;
    while (*data) {
        hash = hash * 31 + *data++;
    }
    return hash;
}

// Simulated MD5-like (broken) hashing
void md5_hash_password(const char *password, char *output) {
    // VULN: MD5 is cryptographically broken
    // Simulating MD5 output format
    uint32_t h = weak_hash(password);
    sprintf(output, "%08x%08x%08x%08x", h, h ^ 0xdeadbeef, h ^ 0xcafebabe, h ^ 0x12345678);
}

// ===== VULNERABILITY: XOR "encryption" (CWE-327) =====
void xor_encrypt(const char *plaintext, const char *key, char *ciphertext) {
    // VULN: XOR is not encryption - trivially breakable
    size_t key_len = strlen(key);
    size_t text_len = strlen(plaintext);
    
    for (size_t i = 0; i < text_len; i++) {
        ciphertext[i] = plaintext[i] ^ key[i % key_len];
    }
    ciphertext[text_len] = '\0';
}

void xor_decrypt(const char *ciphertext, const char *key, char *plaintext, size_t len) {
    // Same as encrypt (XOR is symmetric)
    size_t key_len = strlen(key);
    
    for (size_t i = 0; i < len; i++) {
        plaintext[i] = ciphertext[i] ^ key[i % key_len];
    }
    plaintext[len] = '\0';
}

// ===== VULNERABILITY: Caesar cipher (CWE-327) =====
void caesar_encrypt(const char *plaintext, int shift, char *ciphertext) {
    // VULN: Caesar cipher is trivially breakable
    while (*plaintext) {
        if (*plaintext >= 'a' && *plaintext <= 'z') {
            *ciphertext = ((*plaintext - 'a' + shift) % 26) + 'a';
        } else if (*plaintext >= 'A' && *plaintext <= 'Z') {
            *ciphertext = ((*plaintext - 'A' + shift) % 26) + 'A';
        } else {
            *ciphertext = *plaintext;
        }
        plaintext++;
        ciphertext++;
    }
    *ciphertext = '\0';
}

// ===== VULNERABILITY: Base64 as "encryption" (CWE-311) =====
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const unsigned char *data, size_t len, char *output) {
    // VULN: Base64 is encoding, not encryption!
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        uint32_t n = data[i] << 16;
        if (i + 1 < len) n |= data[i + 1] << 8;
        if (i + 2 < len) n |= data[i + 2];
        
        output[j] = b64_table[(n >> 18) & 0x3F];
        output[j + 1] = b64_table[(n >> 12) & 0x3F];
        output[j + 2] = (i + 1 < len) ? b64_table[(n >> 6) & 0x3F] : '=';
        output[j + 3] = (i + 2 < len) ? b64_table[n & 0x3F] : '=';
    }
    output[j] = '\0';
}

// ===== VULNERABILITY: Password stored in memory (CWE-316) =====
typedef struct {
    char username[64];
    char password[64];  // VULN: Plaintext password in memory
    char session_key[33];
    int privilege_level;
} UserCredentials;

UserCredentials* create_user(const char *username, const char *password) {
    UserCredentials *user = (UserCredentials *)malloc(sizeof(UserCredentials));
    
    strcpy(user->username, username);
    // VULN: Storing plaintext password
    strcpy(user->password, password);
    
    init_weak_random();
    strcpy(user->session_key, generate_session_token());
    user->privilege_level = 0;
    
    return user;
}

// ===== VULNERABILITY: Information disclosure in errors (CWE-209) =====
void authenticate_verbose(const char *username, const char *password) {
    // VULN: Verbose error messages leak information
    UserCredentials *stored = create_user("admin", "SuperSecretPass123!");
    
    if (strcmp(username, stored->username) != 0) {
        // VULN: Reveals that username doesn't exist
        printf("ERROR: User '%s' not found in database\n", username);
        printf("DEBUG: Expected username: %s\n", stored->username);
        free(stored);
        return;
    }
    
    if (strcmp(password, stored->password) != 0) {
        // VULN: Reveals that password is wrong (confirms username exists)
        printf("ERROR: Invalid password for user '%s'\n", username);
        printf("DEBUG: Password hash mismatch\n");
        printf("DEBUG: Stored password length: %zu\n", strlen(stored->password));
        free(stored);
        return;
    }
    
    printf("SUCCESS: User authenticated\n");
    printf("Session: %s\n", stored->session_key);
    free(stored);
}

// ===== VULNERABILITY: Timing side-channel (CWE-208) =====
int insecure_compare(const char *a, const char *b) {
    // VULN: Early exit reveals length through timing
    if (strlen(a) != strlen(b)) {
        return 0;  // VULN: Length revealed through timing
    }
    
    // VULN: Character-by-character comparison with early exit
    for (size_t i = 0; a[i] && b[i]; i++) {
        if (a[i] != b[i]) {
            return 0;  // VULN: Position of mismatch revealed
        }
    }
    return 1;
}

int main(int argc, char *argv[]) {
    printf("=== Weak Cryptography Demo ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <demo> [args...]\n", argv[0]);
        printf("\nDemos:\n");
        printf("  token             - Generate weak session token\n");
        printf("  otp               - Generate predictable OTP\n");
        printf("  hash <password>   - Hash with weak algorithm\n");
        printf("  xor <plaintext>   - XOR 'encryption'\n");
        printf("  caesar <text>     - Caesar cipher\n");
        printf("  auth <user> <pwd> - Verbose authentication\n");
        return 1;
    }
    
    if (strcmp(argv[1], "token") == 0) {
        init_weak_random();
        for (int i = 0; i < 3; i++) {
            char *token = generate_session_token();
            printf("Token %d: %s\n", i + 1, token);
            free(token);
        }
        printf("\nNote: These tokens are predictable!\n");
        
    } else if (strcmp(argv[1], "otp") == 0) {
        printf("Generated OTPs (predictable):\n");
        for (int i = 0; i < 3; i++) {
            printf("  OTP: %06d\n", generate_otp());
        }
        
    } else if (strcmp(argv[1], "hash") == 0 && argc >= 3) {
        char hash[33];
        md5_hash_password(argv[2], hash);
        printf("Password: %s\n", argv[2]);
        printf("Hash: %s\n", hash);
        printf("\nWarning: MD5 is broken!\n");
        
    } else if (strcmp(argv[1], "xor") == 0 && argc >= 3) {
        char ciphertext[256];
        char recovered[256];
        
        xor_encrypt(argv[2], HARDCODED_KEY, ciphertext);
        printf("Plaintext: %s\n", argv[2]);
        printf("Key: %s\n", HARDCODED_KEY);
        printf("Ciphertext (hex): ");
        for (size_t i = 0; i < strlen(argv[2]); i++) {
            printf("%02x", (unsigned char)ciphertext[i]);
        }
        printf("\n\nXOR is not encryption!\n");
        
    } else if (strcmp(argv[1], "caesar") == 0 && argc >= 3) {
        char encrypted[256];
        caesar_encrypt(argv[2], 13, encrypted);
        printf("Plaintext: %s\n", argv[2]);
        printf("Encrypted (ROT13): %s\n", encrypted);
        printf("\nCaesar cipher has only 26 possible keys!\n");
        
    } else if (strcmp(argv[1], "auth") == 0 && argc >= 4) {
        authenticate_verbose(argv[2], argv[3]);
    }
    
    return 0;
}

