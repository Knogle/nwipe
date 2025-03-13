.intel_syntax noprefix
.text

###############################################################################
# xorshift128plus_init
#
# This function initializes the internal state (two 64-bit words) for the
# xorshift128+ PRNG. We will refer to these state words as s0 and s1. The
# function also sets a 32-bit counter to zero (stored at [rdi + 16], though
# it is unused in this snippet).
#
# Parameters:
#   rdi -> pointer to the PRNG state in memory (where s0, s1, and a 32-bit
#          counter are stored)
#   rsi -> pointer to an array of potential seed values (two 64-bit integers)
#   rdx -> number of valid seed values actually present in that array
#
# Behavior:
#   1) If rdx >= 1, s0 is taken from rsi[0]. Otherwise s0 is set to a default.
#   2) If rdx >= 2, s1 is taken from rsi[1]. Otherwise s1 is set to s0 XOR a
#      fixed constant (0x9E3779B97F4A7C15).
#   3) The 32-bit integer at [rdi + 16] is set to 0.
#   4) The function returns.
###############################################################################
.global xorshift128plus_init
xorshift128plus_init:
    cmp rdx, 0                  # Compare rdx with 0 to see if we have at least one seed value
    jle .Ldefault_s0            # Jump if rdx <= 0: we must use the default seed for s0

    mov rax, qword ptr [rsi]    # Otherwise, load s0 from the first 64-bit value at rsi
    jmp .Lstore_s0              # Skip the default path

.Ldefault_s0:
    movabs rax, 0x12345678ABCDEF01  # Default seed value if no seed is provided

.Lstore_s0:
    mov qword ptr [rdi], rax    # Store the chosen s0 into the PRNG state at [rdi]

    cmp rdx, 1                  # Now check if rdx >= 2, i.e., if we can use the second seed value
    jle .Lxor_s1                # If rdx <= 1, we do not have a second seed -> jump to use XOR-based s1

    mov rax, qword ptr [rsi+8]  # If rdx >= 2, load the second 64-bit value from rsi
    jmp .Lstore_s1              # Jump to store s1

.Lxor_s1:
    mov rax, qword ptr [rdi]    # Load s0 from the PRNG state
    mov r8, 0x9E3779B97F4A7C15  # Fixed constant (related to the "golden ratio")
    xor rax, r8                 # s1 = s0 XOR that fixed constant

.Lstore_s1:
    mov qword ptr [rdi+8], rax  # Store s1
    mov dword ptr [rdi+16], 0   # Optionally store an unused 32-bit counter at [rdi+16]
    ret                         # Return from xorshift128plus_init


###############################################################################
# xorshift128plus_genrand_uint128_to_buf
#
# This function generates two 64-bit pseudorandom values (thus, a total of
# 128 bits) using the xorshift128+ algorithm and stores them sequentially
# into a user-supplied buffer at [rsi] and [rsi + 8].
#
# Parameters:
#   rdi -> pointer to the PRNG state (which includes s0 and s1)
#   rsi -> pointer to a buffer (at least 16 bytes) where generated
#          128 bits (two 64-bit values) will be stored
#
# Behavior:
#   1) Load s0 and s1 from the PRNG state.
#   2) Perform the xorshift128+ algorithm steps once, storing the result
#      (s0 + s1) at [rsi].
#   3) Update the state.
#   4) Perform another xorshift128+ to get the second 64-bit output and
#      store that at [rsi + 8].
#   5) Update the state again.
#   6) Return.
#
# NOTE: The repeated operations are part of generating the two 64-bit outputs
# for a total of 128 bits. Each time, xorshift128+ is:
#       t = s0 ^ (s0 << 23);
#       t ^= (t >> 17);
#       t ^= s1 ^ (s1 >> 26);
#       s0 = s1;
#       s1 = t;
#       output = s0 + s1;  # final 64-bit result
###############################################################################
.global xorshift128plus_genrand_uint128_to_buf
xorshift128plus_genrand_uint128_to_buf:
    # -------------------------------
    # First 64-bit xorshift128+ output
    # -------------------------------

    mov rax, qword ptr [rdi]     # Load s0 from PRNG state
    mov rcx, qword ptr [rdi+8]   # Load s1 from PRNG state

    mov qword ptr [rdi], rcx     # s0 <- s1 (the old s1 becomes new s0)

    # t = old_s0 ^ (old_s0 << 23)
    mov r8, rax
    shl r8, 23
    xor rax, r8

    # t ^= (t >> 17)
    mov r8, rax
    shr r8, 17
    xor rax, r8

    # t ^= old_s1 ^ (old_s1 >> 26)
    mov r8, rcx
    mov r9, rcx
    shr r9, 26
    xor r8, r9
    xor rax, r8

    # We now have t in rax
    mov rdx, rax
    mov qword ptr [rdi+8], rdx   # s1 <- t

    # output_0 = s0 + s1 = new_s0 + new_s1
    mov rax, rdx
    add rax, rcx
    mov qword ptr [rsi], rax     # Store the first 64-bit result into [rsi]

    # -------------------------------
    # Second 64-bit xorshift128+ output
    # -------------------------------
    mov rax, rcx                 # This line reuses rcx as 's0' again
    mov qword ptr [rdi], rdx     # s0 <- (the first t we generated)

    # t = old_s0 ^ (old_s0 << 23)
    mov r8, rax
    shl r8, 23
    xor rax, r8

    # t ^= (t >> 17)
    mov r8, rax
    shr r8, 17
    xor rax, r8

    # t ^= s1 ^ (s1 >> 26), where s1 is rdx
    mov r8, rdx
    mov r9, rdx
    shr r9, 26
    xor r8, r9
    xor rax, r8

    # s1 <- t
    mov qword ptr [rdi+8], rax

    # output_1 = new_s0 + new_s1 = rdx + rax
    add rax, rdx
    mov qword ptr [rsi+8], rax   # Store the second 64-bit result at [rsi + 8]

    ret                           # Return to the caller

