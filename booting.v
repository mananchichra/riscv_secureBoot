module boot_rom (
    input wire clk,
    input wire rst_n,
    input wire [31:0] addr,
    output reg [31:0] data_out,
    input wire cs,
    input wire read_en,
    output reg hash_valid,    // Hash verification status
    output reg boot_ready     // Boot completion signal
);

    // ROM storage
    reg [31:0] rom_memory [0:255];  // 256 words of 32-bit ROM
    
    // Secure boot constants
    localparam BOOT_SIGNATURE = 32'hCAFEBABE;
    localparam SECURE_KEY = 32'h1234_5678;
    
    // SHA-256 constants
    localparam [31:0] SHA_H0 = 32'h6a09e667;
    localparam [31:0] SHA_H1 = 32'hbb67ae85;
    localparam [31:0] SHA_H2 = 32'h3c6ef372;
    localparam [31:0] SHA_H3 = 32'ha54ff53a;
    localparam [31:0] SHA_H4 = 32'h510e527f;
    localparam [31:0] SHA_H5 = 32'h9b05688c;
    localparam [31:0] SHA_H6 = 32'h1f83d9ab;
    localparam [31:0] SHA_H7 = 32'h5be0cd19;
    
    // Expected hash value of the firmware (would be computed offline)
    localparam [255:0] EXPECTED_HASH = {
        32'h1234_5678, 32'h9abc_def0, 32'h2468_ace0, 32'h1357_9bdf,
        32'hfedc_ba98, 32'h7654_3210, 32'haaaa_5555, 32'h0123_4567
    };
    
    // Hash computation registers
    reg [31:0] hash_regs [0:7];
    reg [5:0] hash_block_counter;
    reg hash_computing;
    
    // SHA-256 processing functions
    function [31:0] ch;
        input [31:0] x, y, z;
        begin
            ch = (x & y) ^ (~x & z);
        end
    endfunction
    
    function [31:0] maj;
        input [31:0] x, y, z;
        begin
            maj = (x & y) ^ (x & z) ^ (y & z);
        end
    endfunction
    
    function [31:0] ep0;
        input [31:0] x;
        begin
            ep0 = {x[1:0], x[31:2]} ^ {x[12:0], x[31:13]} ^ {x[21:0], x[31:22]};
        end
    endfunction
    
    function [31:0] ep1;
        input [31:0] x;
        begin
            ep1 = {x[5:0], x[31:6]} ^ {x[10:0], x[31:11]} ^ {x[24:0], x[31:25]};
        end
    endfunction
    
    // Initialize ROM with secure boot sequence
    initial begin
        // Boot header with signature
        rom_memory[0] = BOOT_SIGNATURE;
        
        // Security initialization sequence
        rom_memory[1] = 32'h00100013;  // addi x0, x0, 1    // Enable secure mode
        rom_memory[2] = 32'h00200073;  // csrw mstatus, 0   // Clear status
        rom_memory[3] = SECURE_KEY;    // Load security key
        
        // Hash verification sequence
        rom_memory[4] = 32'h0ff0000f;  // fence.i           // Ensure instruction consistency
        rom_memory[5] = 32'h30200073;  // csrw medeleg, 0   // Disable delegation
        rom_memory[6] = 32'h30300073;  // csrw mideleg, 0   // Disable interrupts delegation
        
        // Initialize hash computation
        for (int i = 0; i < 8; i = i + 1) begin
            hash_regs[i] = 32'h0;
        end
        
        hash_block_counter = 6'h0;
        hash_computing = 1'b0;
        hash_valid = 1'b0;
        boot_ready = 1'b0;
    end
    
    // Hash computation state machine
    reg [2:0] hash_state;
    localparam HASH_IDLE = 3'b000;
    localparam HASH_INIT = 3'b001;
    localparam HASH_PROCESS = 3'b010;
    localparam HASH_VERIFY = 3'b011;
    localparam HASH_COMPLETE = 3'b100;
    
    // Hash computation process
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            hash_state <= HASH_IDLE;
            hash_computing <= 1'b0;
            hash_valid <= 1'b0;
            boot_ready <= 1'b0;
        end else begin
            case (hash_state)
                HASH_IDLE: begin
                    if (cs && read_en && addr == 32'h0) begin
                        hash_state <= HASH_INIT;
                        hash_computing <= 1'b1;
                    end
                end
                
                HASH_INIT: begin
                    // Initialize hash registers with SHA-256 constants
                    hash_regs[0] <= SHA_H0;
                    hash_regs[1] <= SHA_H1;
                    hash_regs[2] <= SHA_H2;
                    hash_regs[3] <= SHA_H3;
                    hash_regs[4] <= SHA_H4;
                    hash_regs[5] <= SHA_H5;
                    hash_regs[6] <= SHA_H6;
                    hash_regs[7] <= SHA_H7;
                    hash_state <= HASH_PROCESS;
                end
                
                HASH_PROCESS: begin
                    // Process ROM contents in blocks
                    if (hash_block_counter < 64) begin
                        // Simplified SHA-256 processing for demonstration
                        hash_regs[0] <= hash_regs[0] + ep0(rom_memory[hash_block_counter]);
                        hash_regs[1] <= hash_regs[1] + ep1(hash_regs[0]);
                        hash_regs[2] <= hash_regs[2] + maj(hash_regs[0], hash_regs[1], hash_regs[2]);
                        hash_regs[3] <= hash_regs[3] + ch(hash_regs[0], hash_regs[1], hash_regs[2]);
                        hash_block_counter <= hash_block_counter + 1;
                    end else begin
                        hash_state <= HASH_VERIFY;
                    end
                end
                
                HASH_VERIFY: begin
                    // Compare computed hash with expected hash
                    if ({hash_regs[7], hash_regs[6], hash_regs[5], hash_regs[4],
                         hash_regs[3], hash_regs[2], hash_regs[1], hash_regs[0]} == EXPECTED_HASH) begin
                        hash_valid <= 1'b1;
                        boot_ready <= 1'b1;
                    end else begin
                        hash_valid <= 1'b0;
                        boot_ready <= 1'b0;
                    end
                    hash_state <= HASH_COMPLETE;
                end
                
                HASH_COMPLETE: begin
                    hash_computing <= 1'b0;
                    // Stay in this state until reset
                end
            endcase
        end
    end
    
    // Synchronous read operation
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            data_out <= 32'h0;
        end else if (cs && read_en && hash_valid) begin
            data_out <= rom_memory[addr[9:2]];
        end else begin
            data_out <= 32'h0;
        end
    end

endmodule

// Testbench
module boot_rom_tb;
    reg clk;
    reg rst_n;
    reg [31:0] addr;
    wire [31:0] data_out;
    reg cs;
    reg read_en;
    wire hash_valid;
    wire boot_ready;
    
    // Instantiate boot ROM
    boot_rom uut (
        .clk(clk),
        .rst_n(rst_n),
        .addr(addr),
        .data_out(data_out),
        .cs(cs),
        .read_en(read_en),
        .hash_valid(hash_valid),
        .boot_ready(boot_ready)
    );
    
    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end
    
    // Test stimulus
    initial begin
        // Initialize inputs
        rst_n = 0;
        addr = 0;
        cs = 0;
        read_en = 0;
        
        // Release reset
        #20 rst_n = 1;
        
        // Start boot process
        #10 cs = 1;
        read_en = 1;
        addr = 0;
        
        // Wait for hash verification
        wait(hash_valid);
        
        // Test memory access
        #10 addr = 4;
        #10 addr = 8;
        #10 addr = 12;
        
        // End simulation
        #100 $finish;
    end
    
    // Monitor changes
    initial begin
        $monitor("Time=%0t rst_n=%b addr=%h data=%h hash_valid=%b boot_ready=%b",
                 $time, rst_n, addr, data_out, hash_valid, boot_ready);
    end
endmodule