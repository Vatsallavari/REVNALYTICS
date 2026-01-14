/*
 * Vulnerable Program: Integer Overflow/Underflow
 * CVE Pattern: CWE-190 (Integer Overflow), CWE-191 (Integer Underflow)
 * Similar to: CVE-2021-41773 (Apache path traversal), CVE-2014-0160 (Heartbleed)
 * 
 * Vulnerability: Integer calculations overflow/underflow, leading to
 * buffer overflows, memory corruption, or logic bypasses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

// VULNERABLE: Integer overflow in size calculation
void allocate_buffer_vulnerable(unsigned int num_elements, unsigned int element_size) {
    // VULNERABLE: Multiplication can overflow
    // If num_elements = 0x40000001 and element_size = 4
    // Result overflows to small value, but loop writes much more
    unsigned int total_size = num_elements * element_size;
    
    printf("[*] Allocating: %u elements * %u bytes = %u total\n", 
           num_elements, element_size, total_size);
    
    char *buffer = (char *)malloc(total_size);
    if (!buffer) {
        printf("Allocation failed\n");
        return;
    }
    
    // This loop will write way more than allocated
    printf("[*] Buffer allocated at %p, writing data...\n", (void*)buffer);
    for (unsigned int i = 0; i < num_elements; i++) {
        // This writes beyond allocated buffer if overflow occurred
        memset(buffer + (i * element_size), 'A', element_size);
    }
    
    free(buffer);
}

// VULNERABLE: Signed integer overflow
int vulnerable_add(int a, int b) {
    // VULNERABLE: No overflow check
    // INT_MAX + 1 wraps to INT_MIN
    int result = a + b;
    printf("[*] %d + %d = %d\n", a, b, result);
    return result;
}

// VULNERABLE: Length calculation underflow
void copy_with_length_vulnerable(char *dest, const char *src, int max_len, int offset) {
    // VULNERABLE: If offset > max_len, result underflows
    int copy_len = max_len - offset;  // Can become negative (huge positive when cast)
    
    printf("[*] max_len=%d, offset=%d, copy_len=%d\n", max_len, offset, copy_len);
    
    if (copy_len > 0) {  // This check passes for small positive values
        // VULNERABLE: copy_len might have underflowed
        memcpy(dest, src + offset, (size_t)copy_len);
    }
}

// VULNERABLE: Array index calculation overflow
void access_array_vulnerable(int *array, unsigned int base, unsigned int index) {
    // VULNERABLE: base + index can overflow
    unsigned int final_index = base + index;
    
    printf("[*] Accessing array[%u + %u = %u]\n", base, index, final_index);
    
    // If overflow happened, might access unintended memory
    printf("[*] Value: %d\n", array[final_index]);
}

// VULNERABLE: Type conversion truncation
void process_size_vulnerable(size_t large_size) {
    // VULNERABLE: Truncation when converting size_t to int
    int small_size = (int)large_size;  // Truncates on 64-bit systems
    
    printf("[*] Original size: %zu\n", large_size);
    printf("[*] Truncated size: %d\n", small_size);
    
    if (small_size < 1024) {
        printf("[*] Size seems safe, proceeding...\n");
        // But actual allocation might be huge
        char *buf = malloc(large_size);
        if (buf) {
            printf("[*] Allocated %zu bytes\n", large_size);
            free(buf);
        }
    }
}

// VULNERABLE: Wrap-around in loop counter
void vulnerable_loop() {
    unsigned short counter = 65530;  // Near USHRT_MAX (65535)
    
    printf("[*] Starting counter at %u\n", counter);
    
    // VULNERABLE: Counter will wrap around
    while (counter < 65540) {  // This condition becomes infinite loop
        printf("counter = %u\n", counter);
        counter++;
        
        // Safety break for demonstration
        static int iterations = 0;
        if (++iterations > 20) {
            printf("[!] Breaking infinite loop for safety\n");
            break;
        }
    }
}

int main(int argc, char *argv[]) {
    printf("=== Integer Overflow Demo ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <demo_type>\n", argv[0]);
        printf("\nDemo types:\n");
        printf("  mult     - Multiplication overflow\n");
        printf("  add      - Addition overflow  \n");
        printf("  under    - Underflow demo\n");
        printf("  trunc    - Type truncation\n");
        printf("  loop     - Counter wraparound\n");
        return 1;
    }
    
    if (strcmp(argv[1], "mult") == 0) {
        // Demonstrate multiplication overflow
        // 0x40000000 * 4 = 0x100000000, which truncates to 0
        allocate_buffer_vulnerable(0x40000001, 4);
        
    } else if (strcmp(argv[1], "add") == 0) {
        // Demonstrate signed overflow
        printf("INT_MAX = %d\n", INT_MAX);
        vulnerable_add(INT_MAX, 1);  // Overflows to INT_MIN
        vulnerable_add(INT_MAX, INT_MAX);  // Large overflow
        
    } else if (strcmp(argv[1], "under") == 0) {
        // Demonstrate underflow
        char dest[256] = {0};
        char src[256];
        memset(src, 'X', 256);
        
        // offset > max_len causes underflow
        copy_with_length_vulnerable(dest, src, 100, 150);
        
    } else if (strcmp(argv[1], "trunc") == 0) {
        // Demonstrate truncation on 64-bit systems
        size_t huge_size = 0x100000400;  // ~4GB + 1024
        process_size_vulnerable(huge_size);
        
    } else if (strcmp(argv[1], "loop") == 0) {
        // Demonstrate counter wraparound
        vulnerable_loop();
    }
    
    return 0;
}

