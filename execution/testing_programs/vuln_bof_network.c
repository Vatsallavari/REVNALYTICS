/*
 * Combined Vulnerability: Buffer Overflow + Network Protocol Handling
 * CVE Patterns: CWE-121 + CWE-129 + CWE-131 + CWE-805
 * Similar to: CVE-2014-6271 (Shellshock), CVE-2017-0144 (EternalBlue)
 * 
 * Combines:
 * - Buffer overflow in packet parsing
 * - Length field manipulation
 * - Type confusion in protocol handling
 * - Off-by-one in header parsing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

// ============================================
// Protocol structures
// ============================================

#pragma pack(push, 1)

typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t length;  // Total packet length
    uint32_t sequence;
} PacketHeader;

typedef struct {
    PacketHeader header;
    char payload[256];
} NetworkPacket;

typedef struct {
    uint8_t command;
    uint8_t num_args;
    uint16_t arg_length;
    char args[128];
} CommandPacket;

typedef struct {
    uint16_t name_length;
    uint16_t value_length;
    char data[252];  // name + value
} KeyValuePacket;

typedef struct {
    uint32_t chunk_count;
    uint32_t chunk_size;
    char data[248];
} ChunkedPacket;

#pragma pack(pop)

// ============================================
// VULNERABILITY 1: Length field overflow
// Similar to Heartbleed
// ============================================

void process_packet_heartbleed_style(const char *packet_data, size_t actual_size) {
    NetworkPacket *pkt = (NetworkPacket *)packet_data;
    char response[512];
    
    // Parse header
    uint16_t claimed_length = ntohs(pkt->header.length);
    
    printf("[*] Packet received:\n");
    printf("    Actual size: %zu\n", actual_size);
    printf("    Claimed length: %u\n", claimed_length);
    printf("    Type: %u\n", pkt->header.type);
    
    // VULN: Trust client-supplied length, not actual size
    // If claimed_length > actual_size, reads beyond buffer
    if (claimed_length > sizeof(response)) {
        claimed_length = sizeof(response);
    }
    
    printf("[*] Copying %u bytes to response...\n", claimed_length);
    
    // VULN: Reads memory beyond actual packet data
    memcpy(response, pkt->payload, claimed_length);
    
    // Echo back - leaks adjacent memory
    printf("[*] Response (hex): ");
    for (int i = 0; i < claimed_length && i < 64; i++) {
        printf("%02x", (unsigned char)response[i]);
    }
    printf("...\n");
}

// ============================================
// VULNERABILITY 2: Integer overflow in chunk processing
// Similar to EternalBlue
// ============================================

void process_chunked_data(const char *packet_data) {
    ChunkedPacket *pkt = (ChunkedPacket *)packet_data;
    
    uint32_t chunk_count = ntohl(pkt->chunk_count);
    uint32_t chunk_size = ntohl(pkt->chunk_size);
    
    printf("[*] Chunked packet:\n");
    printf("    Chunk count: %u\n", chunk_count);
    printf("    Chunk size: %u\n", chunk_size);
    
    // VULN: Integer overflow in total size calculation
    uint32_t total_size = chunk_count * chunk_size;  // Can overflow!
    
    printf("    Total size: %u (0x%08x)\n", total_size, total_size);
    
    // VULN: Allocate small buffer due to overflow
    char *buffer = (char *)malloc(total_size + 1);
    if (!buffer) {
        printf("[-] Allocation failed\n");
        return;
    }
    
    printf("[*] Allocated %u bytes at %p\n", total_size + 1, (void*)buffer);
    
    // VULN: Write more data than allocated
    // If overflow occurred, this writes way beyond buffer
    printf("[*] Processing chunks...\n");
    for (uint32_t i = 0; i < chunk_count && i < 10; i++) {  // Limit for demo
        size_t offset = i * chunk_size;
        printf("    Chunk %u at offset %zu\n", i, offset);
        
        // In real scenario, this would overflow
        if (offset < 248) {
            memcpy(buffer + offset, pkt->data, chunk_size < 248 ? chunk_size : 248);
        }
    }
    
    free(buffer);
}

// ============================================
// VULNERABILITY 3: Off-by-one in header parsing
// ============================================

typedef struct {
    char headers[10][64];
    int header_count;
    char body[256];
    int authenticated;
} HTTPRequest;

void parse_http_headers(const char *raw_request) {
    HTTPRequest req;
    char *line;
    char *request_copy;
    int i = 0;
    
    memset(&req, 0, sizeof(req));
    request_copy = strdup(raw_request);
    
    printf("[*] Parsing HTTP headers...\n");
    
    // VULN: Off-by-one in header count check
    line = strtok(request_copy, "\r\n");
    while (line && i <= 10) {  // BUG: Should be < 10, not <= 10
        printf("    Header %d: %.40s...\n", i, line);
        
        // VULN: Writes header[10] which is out of bounds
        // Overwrites header_count and potentially body/authenticated
        strcpy(req.headers[i], line);
        
        i++;
        line = strtok(NULL, "\r\n");
    }
    
    req.header_count = i;
    
    printf("[*] Parsed %d headers\n", req.header_count);
    printf("[*] authenticated flag: %d\n", req.authenticated);
    
    free(request_copy);
}

// ============================================
// VULNERABILITY 4: Type confusion in protocol
// ============================================

#define PKT_TYPE_DATA    1
#define PKT_TYPE_COMMAND 2
#define PKT_TYPE_KEYVAL  3

void process_protocol_packet(const char *packet_data, size_t size) {
    PacketHeader *header = (PacketHeader *)packet_data;
    
    printf("[*] Protocol packet type: %u\n", header->type);
    
    switch (header->type) {
        case PKT_TYPE_DATA: {
            NetworkPacket *data_pkt = (NetworkPacket *)packet_data;
            printf("[*] Data packet, payload: %.32s\n", data_pkt->payload);
            break;
        }
        
        case PKT_TYPE_COMMAND: {
            // VULN: Type confusion - packet might not actually be CommandPacket
            CommandPacket *cmd_pkt = (CommandPacket *)packet_data;
            
            printf("[*] Command packet:\n");
            printf("    Command: %u\n", cmd_pkt->command);
            printf("    Num args: %u\n", cmd_pkt->num_args);
            printf("    Arg length: %u\n", ntohs(cmd_pkt->arg_length));
            
            // VULN: Trust num_args without validation
            // Can cause buffer overread/overwrite
            char arg_buffer[256];
            uint16_t arg_len = ntohs(cmd_pkt->arg_length);
            
            // VULN: No bounds check on arg_length
            memcpy(arg_buffer, cmd_pkt->args, arg_len);
            printf("    Args: %s\n", arg_buffer);
            break;
        }
        
        case PKT_TYPE_KEYVAL: {
            KeyValuePacket *kv_pkt = (KeyValuePacket *)packet_data;
            uint16_t name_len = ntohs(kv_pkt->name_length);
            uint16_t val_len = ntohs(kv_pkt->value_length);
            
            printf("[*] Key-Value packet:\n");
            printf("    Name length: %u\n", name_len);
            printf("    Value length: %u\n", val_len);
            
            // VULN: name_len + val_len can exceed data buffer
            char name[128], value[128];
            
            // VULN: Reads beyond packet if lengths are malicious
            memcpy(name, kv_pkt->data, name_len);
            name[name_len < 127 ? name_len : 127] = '\0';
            
            memcpy(value, kv_pkt->data + name_len, val_len);
            value[val_len < 127 ? val_len : 127] = '\0';
            
            printf("    Name: %s\n", name);
            printf("    Value: %s\n", value);
            break;
        }
        
        default:
            printf("[-] Unknown packet type\n");
    }
}

// ============================================
// VULNERABILITY 5: DNS-style label parsing
// Similar to DNSpooq vulnerabilities
// ============================================

typedef struct {
    char name[256];
    uint16_t type;
    uint16_t class;
} DNSQuestion;

int parse_dns_name(const unsigned char *data, size_t data_len, char *output, size_t out_size) {
    size_t pos = 0;
    size_t out_pos = 0;
    int jumps = 0;
    
    printf("[*] Parsing DNS-style name...\n");
    
    while (pos < data_len && data[pos] != 0) {
        uint8_t label_len = data[pos];
        
        // Check for compression pointer (starts with 11xxxxxx)
        if ((label_len & 0xC0) == 0xC0) {
            // VULN: Pointer can point anywhere, including back (infinite loop)
            // or forward beyond buffer
            uint16_t pointer = ((label_len & 0x3F) << 8) | data[pos + 1];
            printf("    Compression pointer to offset: %u\n", pointer);
            
            // VULN: No validation of pointer target
            if (pointer < data_len) {
                pos = pointer;  // Follow pointer (can loop forever!)
            }
            
            jumps++;
            if (jumps > 10) {
                printf("[-] Too many compression jumps!\n");
                break;
            }
            continue;
        }
        
        printf("    Label length: %u\n", label_len);
        
        // VULN: No check if label_len exceeds remaining data
        pos++;
        
        // VULN: Buffer overflow if output too small
        for (int i = 0; i < label_len && pos < data_len; i++, pos++) {
            if (out_pos < out_size - 1) {
                output[out_pos++] = data[pos];
            }
        }
        
        if (data[pos] != 0) {
            output[out_pos++] = '.';
        }
    }
    
    output[out_pos] = '\0';
    printf("[*] Parsed name: %s\n", output);
    
    return pos + 1;  // Return bytes consumed
}

// ============================================
// VULNERABILITY 6: TLV (Type-Length-Value) parsing
// ============================================

typedef struct {
    uint8_t type;
    uint16_t length;
    uint8_t value[];
} TLVField;

void parse_tlv_fields(const char *data, size_t data_len) {
    size_t offset = 0;
    char extracted_data[256];
    int field_count = 0;
    
    printf("[*] Parsing TLV fields from %zu bytes...\n", data_len);
    
    while (offset < data_len) {
        TLVField *field = (TLVField *)(data + offset);
        uint16_t length = ntohs(field->length);
        
        printf("    Field %d: type=%u, length=%u\n", field_count++, field->type, length);
        
        // VULN: Length field can exceed remaining data
        // VULN: Length can cause integer overflow in offset calculation
        
        if (field->type == 1) {  // String field
            // VULN: No bounds check - copies based on untrusted length
            memcpy(extracted_data, field->value, length);
            extracted_data[length < 255 ? length : 255] = '\0';
            printf("    String value: %s\n", extracted_data);
        }
        
        // VULN: offset + 3 + length can overflow
        offset += 3 + length;  // 3 bytes for type + length fields
        
        // Infinite loop prevention
        if (field_count > 20) break;
    }
}

int main(int argc, char *argv[]) {
    printf("=== Buffer Overflow + Network Protocol Demo ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <demo> [args...]\n", argv[0]);
        printf("\nDemos:\n");
        printf("  heartbleed <data> <claimed_len>  - Heartbleed-style length overflow\n");
        printf("  chunked <count> <size>           - Integer overflow in chunked data\n");
        printf("  http <headers>                   - Off-by-one in HTTP parsing\n");
        printf("  proto <hex_packet>               - Protocol type confusion\n");
        printf("  dns <hex_data>                   - DNS name compression overflow\n");
        printf("  tlv <hex_data>                   - TLV parsing overflow\n");
        return 1;
    }
    
    if (strcmp(argv[1], "heartbleed") == 0 && argc >= 4) {
        // Build a fake packet
        NetworkPacket pkt;
        pkt.header.version = 1;
        pkt.header.type = 1;
        pkt.header.length = htons(atoi(argv[3]));  // Claimed length
        strncpy(pkt.payload, argv[2], 255);
        
        process_packet_heartbleed_style((char*)&pkt, strlen(argv[2]) + sizeof(PacketHeader));
        
    } else if (strcmp(argv[1], "chunked") == 0 && argc >= 4) {
        ChunkedPacket pkt;
        pkt.chunk_count = htonl(atoi(argv[2]));
        pkt.chunk_size = htonl(atoi(argv[3]));
        memset(pkt.data, 'A', 248);
        
        process_chunked_data((char*)&pkt);
        
    } else if (strcmp(argv[1], "http") == 0 && argc >= 3) {
        parse_http_headers(argv[2]);
        
    } else if (strcmp(argv[1], "dns") == 0 && argc >= 3) {
        // Convert hex string to bytes
        char data[256];
        size_t len = strlen(argv[2]) / 2;
        for (size_t i = 0; i < len && i < 256; i++) {
            sscanf(argv[2] + i*2, "%2hhx", &data[i]);
        }
        
        char output[256];
        parse_dns_name((unsigned char*)data, len, output, sizeof(output));
        
    } else if (strcmp(argv[1], "tlv") == 0 && argc >= 3) {
        char data[256];
        size_t len = strlen(argv[2]) / 2;
        for (size_t i = 0; i < len && i < 256; i++) {
            sscanf(argv[2] + i*2, "%2hhx", &data[i]);
        }
        
        parse_tlv_fields(data, len);
    }
    
    return 0;
}

