// Mythic JIT Script for StikDebug
// Handles BRK #0xf00d (universal protocol) with x16-based command dispatch
// Advances PC past ALL BRK instructions to prevent infinite loops

function littleEndianHexStringToNumber(hexStr) {
    const bytes = [];
    for (let i = 0; i < hexStr.length; i += 2) {
        bytes.push(parseInt(hexStr.substr(i, 2), 16));
    }
    let num = 0n;
    for (let i = 7; i >= 0; i--) {
        num = (num << 8n) | BigInt(bytes[i] || 0);
    }
    return num;
}

function numberToLittleEndianHexString(num) {
    const bytes = [];
    for (let i = 0; i < 8; i++) {
        bytes.push(Number(num & 0xFFn));
        num >>= 8n;
    }
    return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

function littleEndianHexToU32(hexStr) {
    return parseInt(hexStr.match(/../g).reverse().join(''), 16);
}

function extractBrkImmediate(u32) {
    return (u32 >> 5) & 0xFFFF;
}

let pid = get_pid();
log(`Mythic JIT: pid = ${pid}`);
let attachResponse = send_command(`vAttach;${pid.toString(16)}`);
log(`Mythic JIT: attached = ${attachResponse}`);

let detached = false;

while (!detached) {
    let brkResponse = send_command(`c`);

    let tidMatch = /T[0-9a-f]+thread:(?<tid>[0-9a-f]+);/.exec(brkResponse);
    let tid = tidMatch ? tidMatch.groups['tid'] : null;
    let pcMatch = /20:(?<reg>[0-9a-f]{16});/.exec(brkResponse);
    let pc = pcMatch ? pcMatch.groups['reg'] : null;
    let x16Match = /10:(?<reg>[0-9a-f]{16});/.exec(brkResponse);
    let x16 = x16Match ? x16Match.groups['reg'] : null;

    if (!tid || !pc || !x16) {
        log(`Mythic JIT: failed to parse, continuing`);
        continue;
    }

    let pcNum = littleEndianHexStringToNumber(pc);

    let instrHex = send_command(`m${pcNum.toString(16)},4`);
    let instrU32 = littleEndianHexToU32(instrHex);
    let brkImm = extractBrkImmediate(instrU32);

    // ALWAYS advance PC past BRK to prevent infinite loop
    let pcPlus4 = numberToLittleEndianHexString(pcNum + 4n);
    send_command(`P20=${pcPlus4};thread:${tid};`);

    // Skip unknown BRK immediates (PC already advanced)
    if (brkImm !== 0xf00d && brkImm !== 0x69) {
        // Set x0=0 (failure/skip indicator) so app's SIGTRAP fallback works
        send_command(`P0=${numberToLittleEndianHexString(0n)};thread:${tid};`);
        continue;
    }

    log(`Mythic JIT: BRK #0x${brkImm.toString(16)}`);

    // Parse x0 and x1
    let x0Match = /00:(?<reg>[0-9a-f]{16});/.exec(brkResponse);
    let x1Match = /01:(?<reg>[0-9a-f]{16});/.exec(brkResponse);
    let x0 = x0Match ? littleEndianHexStringToNumber(x0Match.groups['reg']) : 0n;
    let x1 = x1Match ? littleEndianHexStringToNumber(x1Match.groups['reg']) : 0n;
    let x16Num = littleEndianHexStringToNumber(x16);

    if (brkImm === 0xf00d) {
        log(`Mythic JIT: x16 = ${x16Num}`);

        if (x16Num === 0n) {
            // CMD_DETACH
            log(`Mythic JIT: detach`);
            send_command(`D`);
            detached = true;

        } else if (x16Num === 1n) {
            // CMD_PREPARE_REGION
            log(`Mythic JIT: prepare addr=0x${x0.toString(16)} size=0x${x1.toString(16)}`);

            let addr = x0;
            if (x0 === 0n && x1 !== 0n) {
                let allocResp = send_command(`_M${x1.toString(16)},rx`);
                if (allocResp && allocResp.length > 0) {
                    addr = BigInt(`0x${allocResp}`);
                    log(`Mythic JIT: allocated at 0x${addr.toString(16)}`);
                }
            }

            if (addr !== 0n && x1 !== 0n) {
                let prepResp = prepare_memory_region(addr, x1);
                log(`Mythic JIT: prepared = ${prepResp}`);
            }

            send_command(`P0=${numberToLittleEndianHexString(addr)};thread:${tid};`);

        } else if (x16Num === 3n) {
            // CMD_MAP_PAGE_ZERO: Map a page at address 0 with TEB data.
            // x0 = TEB address, x1 = size (0x4000 = 16KB iOS page)
            // The app can't map page 0 itself (kernel refuses). The debugger
            // may have different privileges to create this mapping.
            log(`Mythic JIT: map page zero, TEB=0x${x0.toString(16)} size=0x${x1.toString(16)}`);

            let success = 0n;

            // Try allocating RW memory at address 0 via _M with fixed address
            // StikDebug's _M command: _M<size>,<perms> — but doesn't support fixed addr
            // Try GDB memory allocation: mmap via the debugger's task port
            // Use vCont or direct Mach calls if available

            // Approach 1: Try writing TEB data to address 0 directly.
            // If the hardware zero page is writable via the debugger, this works.
            if (x0 !== 0n && x1 !== 0n) {
                // Read TEB data from the app's memory
                let tebPage = x0 & ~0x3FFFn;  // align to 16KB page
                let tebOff = x0 - tebPage;

                // Try to write TEB data at address 0 via GDB M command
                // Read 256 bytes from TEB (enough for PEB pointer at offset 0x60)
                let tebData = send_command(`m${x0.toString(16)},100`);
                if (tebData && tebData.length > 0) {
                    // Write it to address 0+tebOff
                    let writeResp = send_command(`M${tebOff.toString(16)},${(tebData.length/2).toString(16)}:${tebData}`);
                    log(`Mythic JIT: write TEB to page0 offset 0x${tebOff.toString(16)}: ${writeResp}`);
                    if (writeResp === 'OK') {
                        success = 1n;
                    }
                }
            }

            send_command(`P0=${numberToLittleEndianHexString(success)};thread:${tid};`);
        }

    } else if (brkImm === 0x69) {
        // Legacy protocol
        log(`Mythic JIT: legacy BRK 0x69, x0=0x${x0.toString(16)}`);
        if (x0 !== 0n) {
            prepare_memory_region(x0, x0);
        }
        send_command(`P0=${numberToLittleEndianHexString(x0)};thread:${tid};`);
    }
}
