module secure_boot_system (
    input wire clk,
    input wire rst_n,
    input wire [31:0] addr,
    output reg [31:0] data_out,
    input wire cs,
    input wire read_en,
    output reg hash_valid,
    output reg boot_ready,
    output reg bootloader_verified,
    // External flash interface
    input wire [31:0] flash_data,
    output reg [31:0] flash_addr,
    output reg flash_read_en,
    // Security status outputs
    output reg [2:0] boot_stage,
    output reg security_violation
);

    // ROM storage
    reg [31:0] rom_memory [0:255];  // 256 words of 32-bit ROM
    
    // Bootloader parameters
    localparam BOOTLOADER_START = 32'h1000_0000;
    localparam BOOTLOADER_SIZE = 32'h0000_1000;  // 4KB bootloader
    
    // Security constants
    localparam BOOT_SIGNATURE = 32'hCAFEBABE;
    localparam SECURE_KEY = 32'h1234_5678;
    localparam BOOTLOADER_SIGNATURE = 32'hB007_0001;
    
    // Expected hash values
    localparam [255:0] EXPECTED_ROM_HASH = {
        32'h1234_5678, 32'h9abc_def0, 32'h2468_ace0, 32'h1357_9bdf,
        32'hfedc_ba98, 32'h7654_3210, 32'haaaa_5555, 32'h0123_4567
    };
    
    localparam [255:0] EXPECTED_BOOTLOADER_HASH = {
        32'habcd_ef01, 32'h2468_ace0, 32'h1357_9bdf, 32'hfedc_ba98,
        32'h7654_3210, 32'haaaa_5555, 32'h0123_4567, 32'h89ab_cdef
    };
    
    // Boot stages
    localparam STAGE_RESET = 3'b000;
    localparam STAGE_ROM_VERIFY = 3'b001;
    localparam STAGE_BOOTLOADER_LOAD = 3'b010;
    localparam STAGE_BOOTLOADER_VERIFY = 3'b011;
    localparam STAGE_SECURE_BOOT = 3'b100;
    localparam STAGE_ERROR = 3'b111;
    
    // Hash computation registers
    reg [31:0] hash_regs [0:7];
    reg [31:0] bootloader_hash_regs [0:7];
    reg [31:0] bootloader_buffer [0:255];  // Buffer for bootloader verification
    
    // State control
    reg [7:0] verify_counter;
    reg [7:0] bootloader_counter;
    reg hash_computing;
    reg bootloader_loading;
    
    // Security timestamps
    reg [31:0] boot_timestamp;
    reg [31:0] last_verify_time;
    
    // Anti-rollback protection
    reg [31:0] minimum_version;
    reg [31:0] current_version;
    
    // Initialize secure boot system
    initial begin
        boot_stage = STAGE_RESET;
        security_violation = 0;
        bootloader_verified = 0;
        hash_valid = 0;
        boot_ready = 0;
        minimum_version = 32'h0000_0001;  // Initial minimum version
        
        // Initialize ROM with secure sequence
        rom_memory[0] = BOOT_SIGNATURE;
        rom_memory[1] = 32'h00100013;  // Enable secure mode
        rom_memory[2] = SECURE_KEY;
        rom_memory[3] = BOOTLOADER_SIGNATURE;
    end
    
    // Security violation checker
    always @(posedge clk) begin
        if (current_version < minimum_version) begin
            security_violation <= 1;
            boot_stage <= STAGE_ERROR;
        end
    end

    reg init_rom, next_rom, mode_rom;
    reg init_bl, next_bl, mode_bl;
    reg [511:0] block_rom, block_bl;
    wire ready_rom, digest_valid_rom, ready_bl, digest_valid_bl;
    wire [255:0] digest_rom, digest_bl;

    sha256_core sha256_rom (
        .clk(clk),
        .reset_n(rst_n),
        .init(init_rom),
        .next(next_rom),
        .mode(mode_rom),
        .block(block_rom),
        .ready(ready_rom),
        .digest(digest_rom),
        .digest_valid(digest_valid_rom)
    );

    sha256_core sha256_bl (
        .clk(clk),
        .reset_n(rst_n),
        .init(init_bl),
        .next(next_bl),
        .mode(mode_bl),
        .block(block_bl),
        .ready(ready_bl),
        .digest(digest_bl),
        .digest_valid(digest_valid_bl)
    );
    
    // Main boot state machine
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            boot_stage <= STAGE_RESET;
            hash_computing <= 0;
            init_rom <= 0;
            init_bl <= 0;
            next_rom <= 0;
            next_bl <= 0;
            mode_rom <= 0;
            mode_bl <= 0;
            security_violation <= 0;
            verify_counter <= 0;
            bootloader_counter <= 0;
        end else begin
            case (boot_stage)
                STAGE_RESET: begin
                    boot_timestamp <= $time;
                    boot_stage <= STAGE_ROM_VERIFY;
                    hash_computing <= 1;
                end
                
                // STAGE_ROM_VERIFY: begin
                //     if (hash_computing) begin
                //         if (verify_counter < 255) begin
                //             // Compute ROM hash
                //             hash_regs[verify_counter[2:0]] <= hash_regs[verify_counter[2:0]] + 
                //                                             rom_memory[verify_counter];
                //             verify_counter <= verify_counter + 1;
                //         end else begin
                //             // Verify ROM hash
                //             if ({hash_regs[7], hash_regs[6], hash_regs[5], hash_regs[4],
                //                  hash_regs[3], hash_regs[2], hash_regs[1], hash_regs[0]} == EXPECTED_ROM_HASH) begin
                //                 hash_valid <= 1;
                //                 boot_stage <= STAGE_BOOTLOADER_LOAD;
                //                 last_verify_time <= $time;
                //             end else begin
                //                 security_violation <= 1;
                //                 boot_stage <= STAGE_ERROR;
                //             end
                //             hash_computing <= 0;
                //         end
                //     end
                // end

                STAGE_ROM_VERIFY: begin
                    if (!hash_computing) begin
                        // Start ROM hash computation
                        init_rom <= 1;
                        mode_rom <= 0;  // Set mode for ROM
                        block_rom <= {rom_memory[0], rom_memory[1], rom_memory[2], rom_memory[3], rom_memory[4], rom_memory[5], rom_memory[6], rom_memory[7]};
                        hash_computing <= 1;
                    end else if (digest_valid_rom) begin
                        // Check if the ROM hash matches the expected value
                        if (digest_rom == EXPECTED_ROM_HASH) begin
                            hash_valid <= 1;
                            boot_stage <= STAGE_BOOTLOADER_LOAD;
                            last_verify_time <= $time;
                        end else begin
                            security_violation <= 1;
                            boot_stage <= STAGE_ERROR;
                        end
                        hash_computing <= 0;
                        init_rom <= 0;
                    end else if (ready_rom) begin
                        // Process the next block of ROM data
                        next_rom <= 1;
                    end
                end
                
                STAGE_BOOTLOADER_LOAD: begin
                    if (!bootloader_loading) begin
                        flash_addr <= BOOTLOADER_START;
                        flash_read_en <= 1;
                        bootloader_loading <= 1;
                    end else if (bootloader_counter < BOOTLOADER_SIZE[7:0]) begin
                        bootloader_buffer[bootloader_counter] <= flash_data;
                        flash_addr <= flash_addr + 4;
                        bootloader_counter <= bootloader_counter + 1;
                    end else begin
                        bootloader_loading <= 0;
                        flash_read_en <= 0;
                        boot_stage <= STAGE_BOOTLOADER_VERIFY;
                    end
                end
                
                // STAGE_BOOTLOADER_VERIFY: begin
                //     if (!hash_computing) begin
                //         hash_computing <= 1;
                //         verify_counter <= 0;
                //     end else if (verify_counter < 255) begin
                //         // Compute bootloader hash
                //         bootloader_hash_regs[verify_counter[2:0]] <= 
                //             bootloader_hash_regs[verify_counter[2:0]] + 
                //             bootloader_buffer[verify_counter];
                //         verify_counter <= verify_counter + 1;
                //     end else begin
                //         // Verify bootloader hash
                //         if ({bootloader_hash_regs[7], bootloader_hash_regs[6], bootloader_hash_regs[5], bootloader_hash_regs[4],
                //              bootloader_hash_regs[3], bootloader_hash_regs[2], bootloader_hash_regs[1], bootloader_hash_regs[0]} == EXPECTED_BOOTLOADER_HASH) begin
                //             bootloader_verified <= 1;
                //             boot_stage <= STAGE_SECURE_BOOT;
                //         end else begin
                //             security_violation <= 1;
                //             boot_stage <= STAGE_ERROR;
                //         end
                //         hash_computing <= 0;
                //     end
                // end

                STAGE_BOOTLOADER_VERIFY: begin
                    if (!hash_computing) begin
                        // Start bootloader hash computation
                        init_bl <= 1;
                        mode_bl <= 1;  // Set mode for bootloader
                        block_bl <= {bootloader_buffer[0], bootloader_buffer[1], bootloader_buffer[2], bootloader_buffer[3], bootloader_buffer[4], bootloader_buffer[5], bootloader_buffer[6], bootloader_buffer[7]};
                        hash_computing <= 1;
                    end else if (digest_valid_bl) begin
                        // Check if the bootloader hash matches the expected value
                        if (digest_bl == EXPECTED_BOOTLOADER_HASH) begin
                            bootloader_verified <= 1;
                            boot_stage <= STAGE_SECURE_BOOT;
                        end else begin
                            security_violation <= 1;
                            boot_stage <= STAGE_ERROR;
                        end
                        hash_computing <= 0;
                        init_bl <= 0;
                    end else if (ready_bl) begin
                        // Process the next block of bootloader data
                        next_bl <= 1;
                    end
                end
                
                STAGE_SECURE_BOOT: begin
                    if (!boot_ready) begin
                        // Final security checks
                        if (bootloader_verified && hash_valid &&
                            !security_violation && 
                            (current_version >= minimum_version)) begin
                            boot_ready <= 1;
                        end else begin
                            security_violation <= 1;
                            boot_stage <= STAGE_ERROR;
                        end
                    end
                end
                
                STAGE_ERROR: begin
                    // Lock system in error state
                    boot_ready <= 0;
                    hash_valid <= 0;
                    bootloader_verified <= 0;
                    security_violation <= 1;
                end
            endcase
        end
    end
    
    // Secure read operation
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            data_out <= 32'h0;
        end else if (cs && read_en && boot_ready) begin
            if (addr < 32'h1000) begin
                data_out <= rom_memory[addr[9:2]];
            end else if (addr >= BOOTLOADER_START && 
                        addr < (BOOTLOADER_START + BOOTLOADER_SIZE)) begin
                data_out <= bootloader_buffer[(addr - BOOTLOADER_START) >> 2];
            end else begin
                data_out <= 32'h0;
            end
        end else begin
            data_out <= 32'h0;
        end
    end
endmodule

// Testbench
module secure_boot_system_tb;
    reg clk;
    reg rst_n;
    reg [31:0] addr;
    wire [31:0] data_out;
    reg cs;
    reg read_en;
    wire hash_valid;
    wire boot_ready;
    wire bootloader_verified;
    reg [31:0] flash_data;
    wire [31:0] flash_addr;
    wire flash_read_en;
    wire [2:0] boot_stage;
    wire security_violation;
    
    // Instantiate secure boot system
    secure_boot_system uut (
        .clk(clk),
        .rst_n(rst_n),
        .addr(addr),
        .data_out(data_out),
        .cs(cs),
        .read_en(read_en),
        .hash_valid(hash_valid),
        .boot_ready(boot_ready),
        .bootloader_verified(bootloader_verified),
        .flash_data(flash_data),
        .flash_addr(flash_addr),
        .flash_read_en(flash_read_en),
        .boot_stage(boot_stage),
        .security_violation(security_violation)
    );
        // Bootloader parameters
    localparam BOOTLOADER_START = 32'h1000_0000;
   
    localparam BOOTLOADER_SIGNATURE = 32'hB007_0001;

    
    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end
    
    // Flash memory simulation
    always @(posedge clk) begin
        if (flash_read_en) begin
            // Simulate flash data
            flash_data <= flash_addr ^ BOOTLOADER_SIGNATURE;
        end
    end
    
    // Test stimulus
    initial begin
        // Initialize
        rst_n = 0;
        addr = 0;
        cs = 0;
        read_en = 0;
        flash_data = 0;
        
        // Release reset
        #20 rst_n = 1;
        
        // Wait for boot stages
        wait(boot_stage == 3'b001);  // ROM verification
        #100;
        
        wait(boot_stage == 3'b010);  // Bootloader load
        #200;
        
        wait(boot_stage == 3'b011);  // Bootloader verification
        #100;
        
        wait(boot_stage == 3'b100);  // Secure boot
        #100;
        
        // Test memory access
        if (boot_ready) begin
            cs = 1;
            read_en = 1;
            
            // Test ROM access
            addr = 0;
            #20;
            addr = 4;
            #20;
            
            // Test bootloader access
            addr = BOOTLOADER_START;
            #20;
            addr = BOOTLOADER_START + 4;
            #20;
        end
        
        // End simulation
        #100 $finish;
    end
    
    // Monitor
    initial begin
        $monitor("Time=%0t Stage=%h Valid=%b Ready=%b BL_Ver=%b Violation=%b",
                 $time, boot_stage, hash_valid, boot_ready,
                 bootloader_verified, security_violation);
    end
endmodule