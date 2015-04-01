// Template headers.p4 file for __PROJECT_NAME__
// Edit this file as needed for your P4 program

// Here's an ethernet header to get started.

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header ethernet_t ethernet;
