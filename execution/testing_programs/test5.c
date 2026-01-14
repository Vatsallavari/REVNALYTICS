#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Mathematical operations
int add_numbers(int a, int b) {
    return a + b;
}

int multiply_values(int x, int y) {
    return x * y;
}

int compute_factorial(int n) {
    if (n <= 1) return 1;
    return n * compute_factorial(n - 1);
}

int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// String operations
int string_length(const char* str) {
    int len = 0;
    while (str[len] != '\0') len++;
    return len;
}

void reverse_string(char* str) {
    int len = string_length(str);
    for (int i = 0; i < len / 2; i++) {
        char temp = str[i];
        str[i] = str[len - i - 1];
        str[len - i - 1] = temp;
    }
}

int count_vowels(const char* str) {
    int count = 0;
    for (int i = 0; str[i] != '\0'; i++) {
        char c = str[i] | 32; // Convert to lowercase
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
            count++;
        }
    }
    return count;
}

// Array operations
int find_max(int* arr, int size) {
    int max = arr[0];
    for (int i = 1; i < size; i++) {
        if (arr[i] > max) max = arr[i];
    }
    return max;
}

int find_min(int* arr, int size) {
    int min = arr[0];
    for (int i = 1; i < size; i++) {
        if (arr[i] < min) min = arr[i];
    }
    return min;
}

int sum_array(int* arr, int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return sum;
}

void bubble_sort(int* arr, int size) {
    for (int i = 0; i < size - 1; i++) {
        for (int j = 0; j < size - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

// Utility functions
int is_prime(int n) {
    if (n <= 1) return 0;
    for (int i = 2; i * i <= n; i++) {
        if (n % i == 0) return 0;
    }
    return 1;
}

int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

int power(int base, int exp) {
    int result = 1;
    for (int i = 0; i < exp; i++) {
        result *= base;
    }
    return result;
}

// Validation functions
int validate_range(int value, int min, int max) {
    return (value >= min && value <= max);
}

int check_even(int n) {
    return (n % 2 == 0);
}

// Main computation orchestrator
int perform_computation(int x, int y) {
    int sum = add_numbers(x, y);
    int product = multiply_values(x, y);
    int fact = compute_factorial(5);
    int fib = fibonacci(7);
    
    return sum + product + fact + fib;
}

int main(int argc, char* argv[]) {
    printf("Testing reverse engineering tool...\n");
    
    int result = perform_computation(10, 20);
    printf("Computation result: %d\n", result);
    
    int arr[] = {64, 34, 25, 12, 22, 11, 90};
    int size = sizeof(arr) / sizeof(arr[0]);
    
    printf("Max: %d, Min: %d, Sum: %d\n", 
           find_max(arr, size), 
           find_min(arr, size), 
           sum_array(arr, size));
    
    char test_str[] = "Hello World";
    printf("String length: %d, Vowels: %d\n", 
           string_length(test_str), 
           count_vowels(test_str));
    
    printf("Is 17 prime? %d\n", is_prime(17));
    printf("GCD(48, 18) = %d\n", gcd(48, 18));
    printf("2^10 = %d\n", power(2, 10));
    
    return 0;
}
