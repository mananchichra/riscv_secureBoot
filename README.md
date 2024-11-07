# Secure Boot Implementation for a RISC V Processor

Team members:
    Manan Chichra ()
    Archit Narwadkar (2022111032)

Here, we present a working solution for implementing secure boot for a RISC V processor and demonstrate it on a simple RISC V processor core called the PICORV32 implementation.

## How to Run the Code

Using icarus verilog, the code can be run with the commands:

    iverilog -o my_sim .\booting_with_bootloaderVer.v .\sha256_core.v .\sha256_k_constants.v .\sha256_w_mem.v
    vvp .\my_sim

## 1. Multi-Stage Boot Process

- STAGE_RESET: Initial system reset
- STAGE_ROM_VERIFY: Verify ROM contents
- STAGE_BOOTLOADER_LOAD: Load bootloader from flash
- STAGE_BOOTLOADER_VERIFY: Verify bootloader integrity
- STAGE_SECURE_BOOT: Final secure boot stage
- STAGE_ERROR: Handle security violations

## 2. Security Features

- Bootloader signature verification
- Separate hash verification for ROM and bootloader
- Anti-rollback protection with version checking
- Security violation detection and handling
- Boot timing measurements
- Memory access controls

## 3. Flash Interface

- Controlled bootloader loading from flash
- Address generation for flash reads
- Data buffering for verification

## 4. Verification Process

- Two-stage hash verification (ROM and bootloader)
- Signature checking
- Version validation
- Timing checks

## 5. Security Outputs

- Boot stage tracking
- Security violation flags
- Verification status signals
- Boot readiness indication


## To implement this in your system

- Connect the flash interface to your actual flash memory
- Update the hash constants with your actual values
- Adjust the bootloader size and address range as needed
- Implement any additional security measures specific to your system
