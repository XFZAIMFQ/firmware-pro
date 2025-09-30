# GDB script for debugging UsageFault on STM32H747
# Usage: arm-none-eabi-gdb -x debug_usagefault.gdb build/firmware/firmware.elf

# Connect to OpenOCD
target remote 127.0.0.1:3333
monitor reset halt

# STM32H747 specific - select Cortex-M7 core
monitor targets stm32h7x.cpu0

# Enable UsageFault and BusFault (if not in production mode)
set *(unsigned int*)0xE000ED24 |= 0x00070000

# Set breakpoints for fault handlers
break ShowUsageFault
break ShowHardFault  
break ShowBusFault
break ShowMemManage_MM
break ShowMemManage_SO

# Define helper functions
define print_fault_regs
    printf "=== FAULT REGISTERS ===\n"
    printf "CFSR  = 0x%08x\n", *(unsigned int*)0xE000ED28
    printf "HFSR  = 0x%08x\n", *(unsigned int*)0xE000ED2C  
    printf "BFAR  = 0x%08x\n", *(unsigned int*)0xE000ED34
    printf "MMFAR = 0x%08x\n", *(unsigned int*)0xE000ED38
    printf "======================\n"
end

define print_fault_pc
    printf "=== FAULT CONTEXT ===\n"
    printf "LR = 0x%08x\n", $lr
    if ($lr & 4)
        printf "Using PSP, fault PC = 0x%08x\n", *(unsigned int*)($psp + 24)
        printf "Stack frame at PSP = 0x%08x:\n", $psp
        x/8xw $psp
    else
        printf "Using MSP, fault PC = 0x%08x\n", *(unsigned int*)($msp + 24)  
        printf "Stack frame at MSP = 0x%08x:\n", $msp
        x/8xw $msp
    end
    printf "====================\n"
end

define decode_usagefault
    set $ufsr = (*(unsigned int*)0xE000ED28) >> 16
    printf "=== USAGEFAULT DECODE ===\n"
    if ($ufsr & 1)
        printf "UNDEFINSTR: Undefined instruction\n"
    end
    if ($ufsr & 2)
        printf "INVSTATE: Invalid state\n"  
    end
    if ($ufsr & 4)
        printf "INVPC: Invalid PC\n"
    end
    if ($ufsr & 8)
        printf "NOCP: Coprocessor not available\n"
    end
    if ($ufsr & 0x100)
        printf "UNALIGNED: Unaligned memory access\n"
    end
    if ($ufsr & 0x200)
        printf "DIVBYZERO: Division by zero\n"
    end
    printf "========================\n"
end

# Auto-run when fault breakpoint hits
commands 1
    print_fault_regs
    decode_usagefault
    print_fault_pc
    bt
end

echo "=== UsageFault Debug Setup Complete ===\n"
echo "Type 'continue' to start execution\n"
echo "When fault occurs, registers and context will be printed automatically\n"
echo "Manual commands: print_fault_regs, decode_usagefault, print_fault_pc\n"