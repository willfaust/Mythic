// Mythic JIT Script for StikDebug
// Handles BRK #0xf00d (universal protocol) with x16-based command dispatch
// Compatible with StikDebug 2.3.5+

function littleEndianHexStringToNumber(hexStr) {
    const bytes = [];
    for (let i = 0; i < hexStr.length; i += 2) {
        bytes.push(parseInt(hexStr.substr(i, 2), 16));
    }
    let num = 0n;
    for (let i = 4; i >= 0; i--) {
        num = (num << 8n) | BigInt(bytes[i]);
    }
    return num;
}

function numberToLittleEndianHexString(num) {
    const bytes = [];
    for (let i = 0; i < 5; i++) {
        bytes.push(Number(num & 0xFFn));
        num >>= 8n;
    }
    while (bytes.length < 8) {
        bytes.push(0);
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
let lastFaultPC = 0n;
let faultRepeatCount = 0;
const MAX_FAULT_REPEATS = 3;

while (!detached) {
    let brkResponse = send_command(`c`);

    // Extract registers
    let tidMatch = /T[0-9a-f]+thread:(?<tid>[0-9a-f]+);/.exec(brkResponse);
    let tid = tidMatch ? tidMatch.groups['tid'] : null;
    let pcMatch = /20:(?<reg>[0-9a-f]{16});/.exec(brkResponse);
    let pc = pcMatch ? pcMatch.groups['reg'] : null;
    let x16Match = /10:(?<reg>[0-9a-f]{16});/.exec(brkResponse);
    let x16 = x16Match ? x16Match.groups['reg'] : null;

    if (!tid || !pc) {
        log(`Mythic JIT: failed to parse response`);
        continue;
    }

    let pcNum = littleEndianHexStringToNumber(pc);

    // Read instruction at PC
    let instrHex = send_command(`m${pcNum.toString(16)},4`);
    let instrU32 = littleEndianHexToU32(instrHex);

    // Check if BRK instruction
    if ((instrU32 & 0xFFE0001F) >>> 0 !== 0xD4200000) {
        // Not a BRK - check for fault loop
        if (pcNum === lastFaultPC) {
            faultRepeatCount++;
            if (faultRepeatCount >= MAX_FAULT_REPEATS) {
                log(`Mythic JIT: FAULT LOOP detected at PC=0x${pcNum.toString(16)} (${faultRepeatCount} repeats) — returning to caller with error`);
                // Read LR (x30) to return to caller
                let lrMatch = /1e:(?<reg>[0-9a-f]{16});/.exec(brkResponse);
                if (lrMatch) {
                    let lr = lrMatch.groups['reg'];
                    log(`Mythic JIT: Setting PC=LR (0x${littleEndianHexStringToNumber(lr).toString(16)}), x0=-3`);
                    send_command(`P20=${lr};thread:${tid};`);
                } else {
                    // Fallback: skip 4 bytes
                    let pcPlus4 = numberToLittleEndianHexString(pcNum + 4n);
                    send_command(`P20=${pcPlus4};thread:${tid};`);
                }
                // Set x0 to -3 to indicate fault loop
                send_command(`P0=${numberToLittleEndianHexString(BigInt("0xFFFFFFFFFFFFFFFD"))};thread:${tid};`);
                lastFaultPC = 0n;
                faultRepeatCount = 0;
                continue;
            }
        } else {
            lastFaultPC = pcNum;
            faultRepeatCount = 1;
        }

        let sigMatch = /^T(?<sig>[a-z0-9]{2})/.exec(brkResponse);
        if (sigMatch) {
            log(`Mythic JIT: non-BRK signal ${sigMatch.groups['sig']} at PC=0x${pcNum.toString(16)}, instr=0x${instrU32.toString(16)} — forwarding (repeat ${faultRepeatCount}/${MAX_FAULT_REPEATS})`);
            send_command(`vCont;S${sigMatch.groups['sig']}:${tid}`);
        }
        continue;
    }

    // Reset fault tracking on successful BRK handling
    lastFaultPC = 0n;
    faultRepeatCount = 0;

    let brkImm = extractBrkImmediate(instrU32);
    log(`Mythic JIT: BRK #0x${brkImm.toString(16)}`);

    // Advance PC past BRK
    let pcPlus4 = numberToLittleEndianHexString(pcNum + 4n);
    send_command(`P20=${pcPlus4};thread:${tid};`);

    if (brkImm === 0xf00d) {
        // Universal protocol: dispatch on x16
        let x16Num = x16 ? littleEndianHexStringToNumber(x16) : 0n;
        log(`Mythic JIT: x16 = ${x16Num}`);

        if (x16Num === 0n) {
            // CMD_DETACH
            log(`Mythic JIT: detach requested`);
            let detachResp = send_command(`D`);
            log(`Mythic JIT: detached = ${detachResp}`);
            detached = true;

        } else if (x16Num === 1n) {
            // CMD_PREPARE_REGION
            let x0Match = /00:(?<reg>[0-9a-f]{16});/.exec(brkResponse);
            let x1Match = /01:(?<reg>[0-9a-f]{16});/.exec(brkResponse);
            let x0 = x0Match ? littleEndianHexStringToNumber(x0Match.groups['reg']) : 0n;
            let x1 = x1Match ? littleEndianHexStringToNumber(x1Match.groups['reg']) : 0n;

            log(`Mythic JIT: prepare_region addr=0x${x0.toString(16)} size=0x${x1.toString(16)}`);

            let addr = x0;
            if (x0 === 0n && x1 !== 0n) {
                // Allocate new RX region
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

            // Write address back to x0
            send_command(`P0=${numberToLittleEndianHexString(addr)};thread:${tid};`);
        }

    } else if (brkImm === 0x69) {
        // Legacy MeloNX protocol (BRK 0x69)
        let x0Match = /00:(?<reg>[0-9a-f]{16});/.exec(brkResponse);
        let x0 = x0Match ? littleEndianHexStringToNumber(x0Match.groups['reg']) : 0n;

        log(`Mythic JIT: legacy BRK 0x69, x0=0x${x0.toString(16)}`);

        if (x0 !== 0n) {
            let prepResp = prepare_memory_region(x0, x0);
            log(`Mythic JIT: prepared = ${prepResp}`);
        }

        send_command(`P0=${numberToLittleEndianHexString(x0)};thread:${tid};`);

    } else {
        log(`Mythic JIT: unhandled BRK #0x${brkImm.toString(16)}, skipping`);
    }
}
