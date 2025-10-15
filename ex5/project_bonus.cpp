/*########################################################################################################*/
// cd <pin-3.30-path>/source/tools/SimpleExamples
// make btranslate-mt2.test
//  ../../../pin -t obj-intel64/btranslate-mt2.so -- ~/workdir/tst
/*########################################################################################################*/
/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2011 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/* ===================================================================== */

/* ===================================================================== */
/*! @file
 * This probe pintool generates translated code of all the routines, places them
 * in an allocated  TC along with instrumentation instructions that collect
 * profiling for each BBL.
 * It then patches the orginal code to jump to the translated code in the TC.
 * When running the pintool with the flag "-create_tc2", it also starts
 * a separate thread that creates another translation cache called TC2
 * and patches TC with jumps from TC to TC2.
 *
 */

#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <values.h>
#include <map>
#include "xed-interface.h"

using namespace std;

/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE,    "pintool",
                         "verbose", "0", "Verbose run");

KNOB<BOOL>   KnobDumpOrigCode(KNOB_MODE_WRITEONCE,    "pintool",
                              "dump_orig_code", "0", "Dump Original non-translated Code");

KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
                                    "dump_tc", "0", "Dump Translated Code");

KNOB<BOOL>   KnobDumpTranslatedCode2(KNOB_MODE_WRITEONCE,    "pintool",
                                     "dump_tc2", "0", "Dump 2nd Translated Code");

KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
                                           "no_tc_commit", "0", "Do not commit translated code");

KNOB<BOOL>   KnobApplyThreadedCommit(KNOB_MODE_WRITEONCE,    "pintool",
                                     "create_tc2", "0", "Create a 2nd TC based on collected BBL counters so far");

KNOB<UINT> KnobNumSecsDuringProfile(KNOB_MODE_WRITEONCE,    "pintool",
                                    "prof_time", "2", "Number of seconds for collecting BBL counters");

KNOB<BOOL> KnobProbeBackwardJumps(KNOB_MODE_WRITEONCE,    "pintool",
                                  "probe_back_jumps", "0", "Number of seconds for collecting BBL counters");

KNOB<UINT> KnobProfileThreshold(KNOB_MODE_WRITEONCE,    "pintool",
                                     "prof_threshold", "95", "Profile percentage threshold level");



/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
std::ofstream* out = 0;

// For XED:
#if defined(TARGET_IA32E)
xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

//For XED: Pass in the proper length: 15 is the max. But if you do not want to
//cross pages, you can pass less than 15 bytes, of course, the
//instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

// tc containing the new code:
char *tc;
unsigned tc_size = 0;

// 2nd tc containing the new code:
char *tc2;
unsigned tc2_size = 0;

// Array of original target addresses that cannot
// be relocated in the TC.
ADDRINT *jump_to_orig_addr_map = nullptr;
unsigned jump_to_orig_addr_num = 0;

typedef enum {
    RegularIns = 0,
    RtnHeadIns,
    ProfilingIns,
} ins_enum_t;

// instruction map with an entry for each new instruction:
typedef struct {
    ADDRINT orig_ins_addr;
    ADDRINT new_ins_addr;
    ADDRINT orig_targ_addr;
    ins_enum_t ins_type;
    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
    unsigned int size;
    int targ_map_entry;
    unsigned bbl_num;
    xed_category_enum_t xed_category;
} instr_map_t;


// Instrs map:
instr_map_t *instr_map = NULL;
unsigned num_of_instr_map_entries = 0;
unsigned max_ins_count = 0;

//instr_map_t *ordered_instr_map = NULL;
instr_map_t *reordered_instr_map = NULL;


// Bbl map of all the bbl exec counters to be collected at runtime:
typedef struct {
    UINT64 counter;
    unsigned starting_ins_entry;
    unsigned terminating_ins_entry;
    unsigned heat_level;
    ADDRINT fallthrough_addr;
    bool visited;
} bb_map_t;

bb_map_t *bbl_map;
unsigned bbl_num = 0;

// BBL map of vectors for BBLs for each heat level.
std::map<unsigned, std::vector<unsigned>> bbl_heat_map;

unsigned getFirstElementOfLargestKey(const std::map<unsigned, std::vector<unsigned>>& myMap) {
    // Check if the map is empty
    if (myMap.empty()) {
       cerr<< "The map is empty." << endl;
    }

    // Access the last element in the map (largest key)
    auto largestKeyIter = std::prev(myMap.end());
    return largestKeyIter->second.front();
}



bool decode_instruction_at_address(ADDRINT address, xed_decoded_inst_t* xedd) {
    xed_state_t dstate;
    xed_state_zero(&dstate);  // Initialize to zero
    xed_state_init(&dstate, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b, XED_ADDRESS_WIDTH_64b);

    // Initialize the XED instruction
    xed_decoded_inst_zero_set_mode(xedd, &dstate);

    // Read instruction bytes from the memory at the given address
    unsigned char* instruction_bytes = reinterpret_cast<unsigned char*>(address);

    // Decode the instruction
    xed_error_enum_t xed_error = xed_decode(xedd, instruction_bytes, XED_MAX_INSTRUCTION_BYTES);

    if (xed_error != XED_ERROR_NONE) {
        std::cerr << "Failed to decode instruction at address 0x" << std::hex << address << std::endl;
        return false;
    }

    return true;
}

bool valueExists(const std::map<ADDRINT, ADDRINT>& myMap, const ADDRINT& value) {
    for (const auto& pair : myMap) {
        if (pair.second == value) {
			cerr << "pair.first" << pair.first << endl;
			cerr << "pair.second" << pair.second << endl;
            return true; // Value found
        }
    }
    return false; // Value not found
}
/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

// Function to decode and extract target address from an instruction at a given address
// Function to decode and extract target address from an instruction at a given address
ADDRINT ExtractTargetAddressFromMem(ADDRINT instruction_addr) {
    xed_decoded_inst_t xedd;
    xed_error_enum_t xed_error;
    unsigned int max_inst_len = 15; // Maximum length of an x86 instruction is 15 bytes
    xed_decoded_inst_zero_set_mode(&xedd, &dstate); // Initialize the XED decoder state

    // Decode the instruction at the given address
    xed_error = xed_decode(&xedd, reinterpret_cast<const UINT8*>(instruction_addr), max_inst_len);

    if (xed_error != XED_ERROR_NONE) {
        std::cerr << "Error: Failed to decode instruction at address " << std::hex << instruction_addr << std::endl;
        return 0;
    }

    // Check if the instruction is a direct branch/jump or a call
    if (xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_UNCOND_BR ||
        xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_COND_BR ||
        xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_CALL) {

        // Handle direct branches
        if (xed_decoded_inst_get_branch_displacement_width(&xedd) > 0) {
            // Get the branch displacement
            INT32 displacement = xed_decoded_inst_get_branch_displacement(&xedd);
            ADDRINT target_addr = instruction_addr + xed_decoded_inst_get_length(&xedd) + displacement;
            return target_addr;
        }

        // Handle indirect branches/jumps (e.g., jmp rax)
        xed_reg_enum_t reg = xed_decoded_inst_get_reg(&xedd, XED_OPERAND_REG0); // Get the register operand
        if (reg != XED_REG_INVALID) {
            //std::cerr << "Indirect jump using register: " << xed_reg_enum_t2str(reg) << std::endl;
            // Return 0 or some special value indicating that the target is in a register (e.g., rax)
            return 0; // Or some other indicator for indirect jumps
        }
        }

    std::cerr << "Error: Instruction at address " << std::hex << instruction_addr << " is not a direct branch/jump" << std::endl;
    return 0; // Return 0 if it's not a direct branch/jump
}
//ADDRINT ExtractTargetAddressFromMem(ADDRINT instruction_addr) {
//    xed_decoded_inst_t xedd;
//    xed_error_enum_t xed_error;
//    unsigned int max_inst_len = 15; // Maximum length of an x86 instruction is 15 bytes
//    xed_decoded_inst_zero_set_mode(&xedd, &dstate); // Initialize the XED decoder state
//
//    // Decode the instruction at the given address
//    xed_error = xed_decode(&xedd, reinterpret_cast<const UINT8*>(instruction_addr), max_inst_len);
//
//    if (xed_error != XED_ERROR_NONE) {
//        std::cerr << "Error: Failed to decode instruction at address " << std::hex << instruction_addr
//                  << ". XED Error: " << xed_error_enum_t2str(xed_error) << std::endl;
//        return 0;
//    }
//
//    unsigned int instruction_length = xed_decoded_inst_get_length(&xedd);
//    std::cerr << "Decoded instruction length: " << instruction_length << std::endl;
//
//    // Check if the instruction is a direct branch/jump or a call
//    if (xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_UNCOND_BR ||
//        xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_COND_BR ||
//        xed_decoded_inst_get_category(&xedd) == XED_CATEGORY_CALL) {
//
//        // Handle direct branches
//        if (xed_decoded_inst_get_branch_displacement_width(&xedd) > 0) {
//            // Get the branch displacement
//            INT32 displacement = xed_decoded_inst_get_branch_displacement(&xedd);
//            ADDRINT target_addr = instruction_addr + instruction_length + displacement;
//            return target_addr;
//        }
//
//        // Handle indirect branches/jumps (e.g., jmp rax)
//        xed_reg_enum_t reg = xed_decoded_inst_get_reg(&xedd, XED_OPERAND_REG0); // Get the register operand
//        if (reg != XED_REG_INVALID) {
//            std::cerr << "Indirect jump using register: " << xed_reg_enum_t2str(reg) << std::endl;
//            return 0; // Indicating the target is in a register
//        }
//    }
//
//    std::cerr << "Error: Instruction at address " << std::hex << instruction_addr << " is not a direct branch/jump" << std::endl;
//    return 0; // Return 0 if it's not a direct branch/jump
//}


/*************************/
/* dump_all_image_instrs */
/*************************/
void dump_image_instrs(IMG img)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {

            // Open the RTN.
            RTN_Open( rtn );

            cerr << RTN_Name(rtn) << ":" << endl;

            for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
            {
                cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
            }

            // Close the RTN.
            RTN_Close( rtn );

            cerr << endl;
        }
    }
}


/*************************/
/* dump_instr_from_xedd */
/*************************/
void dump_instr_from_xedd (xed_decoded_inst_t* xedd, ADDRINT address)
{
    // debug print decoded instr:
    char disasm_buf[2048];

    xed_uint64_t runtime_address = static_cast<UINT64>(address);  // set the runtime adddress for disassembly

    xed_format_context(XED_SYNTAX_INTEL, xedd, disasm_buf, sizeof(disasm_buf), static_cast<UINT64>(runtime_address), 0, 0);

    cerr << hex << address << ": " << disasm_buf <<  endl;
}


/************************/
/* dump_instr_from_mem */
/************************/
void dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr)
{
    char disasm_buf[2048];
    xed_decoded_inst_t new_xedd;

    xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);
    xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);

    BOOL xed_ok = (xed_code == XED_ERROR_NONE);
    if (!xed_ok){
        cerr << "invalid opcode" << endl;
    }

    xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(new_addr), 0, 0);

    cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;
}


/****************************/
/*  dump_entire_instr_map() */
/****************************/
void dump_entire_instr_map()
{
    for (unsigned i=0; i < num_of_instr_map_entries; i++) {
        //Print a new line after each BBL.
        if (i+1 < num_of_instr_map_entries && instr_map[i+1].bbl_num != instr_map[i].bbl_num)
            cerr << endl;

        // Print the routine name if known.
        if (instr_map[i].ins_type == RtnHeadIns) {
            PIN_LockClient();
            RTN rtn = RTN_FindByAddress(instr_map[i].orig_ins_addr);
            if (rtn == RTN_Invalid()) {
                cerr << "Unknown"  << ":" << endl;
            } else {
                cerr << RTN_Name(rtn) << ":" << endl;
            }
            PIN_UnlockClient();
        }
        dump_instr_from_mem ((ADDRINT *)instr_map[i].encoded_ins, instr_map[i].new_ins_addr);
    }
}


/**************************/
/* dump_instr_map_entry() */
/**************************/
void dump_instr_map_entry(unsigned instr_map_entry)
{
    cerr << dec << instr_map_entry << ": ";
    cerr << " orig_ins_addr: " << hex << instr_map[instr_map_entry].orig_ins_addr;
    cerr << " new_ins_addr: " << hex << instr_map[instr_map_entry].new_ins_addr;
    cerr << " orig_targ_addr: " << hex << instr_map[instr_map_entry].orig_targ_addr;

    ADDRINT new_targ_addr;
    if (instr_map[instr_map_entry].targ_map_entry >= 0)
        new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;
    else
        new_targ_addr = instr_map[instr_map_entry].orig_targ_addr;

    cerr << " new_targ_addr: " << hex << new_targ_addr;
    cerr << "    new instr:";
    dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins,
                        instr_map[instr_map_entry].new_ins_addr);
}


/*************/
/* dump_tc() */
/*************/
void dump_tc(char *tc, unsigned size_tc)
{
    char disasm_buf[2048];
    xed_decoded_inst_t new_xedd;
    ADDRINT address = (ADDRINT)&tc[0];

    while (address < (ADDRINT)&tc[size_tc]) {

        xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);
        xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);

        BOOL xed_ok = (xed_code == XED_ERROR_NONE);
        if (!xed_ok){
            cerr << "invalid opcode" << endl;
            return;
        }

        xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(address), 0, 0);

        cerr << "0x" << hex << address << ": " << disasm_buf <<  endl;

        address += xed_decoded_inst_get_length (&new_xedd);
    }
}


/* ============================================================= */
/* Service translation routines                                  */
/* ============================================================= */


bool isJumpOrRet(INS ins)
{
    if (!INS_IsCall(ins) &&
        (INS_IsIndirectControlFlow(ins) ||
         INS_IsDirectControlFlow(ins) ||
         INS_IsRet(ins)))
        return true;

    return false;
}

bool isBackwardJump(INS ins)
{
    return (!INS_IsCall(ins) && INS_IsDirectControlFlow(ins) &&
            INS_DirectControlFlowTargetAddress(ins) < INS_Address(ins));
}

bool isRipBaseInstr(xed_decoded_inst_t *xedd)
{
    bool isRipBase = false;
    unsigned int memops = xed_decoded_inst_number_of_memory_operands(xedd);
    xed_reg_enum_t base_reg = XED_REG_INVALID;
    for(unsigned int i=0; i < memops ; i++)   {
        base_reg = xed_decoded_inst_get_base_reg(xedd,i);
        if (base_reg == XED_REG_RIP) {
            isRipBase = true;
            break;
        }
    }
    return isRipBase;
}

REG getKilledRegByIns(INS ins)
{
    REG killed_reg = REG_INVALID();

    if (!INS_IsMov(ins) && !INS_IsLea(ins))
        return REG_INVALID();

    for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); i++) {
        REG regw = INS_RegW(ins, i); // Get the i-th written register
        if (REG_Width(regw) != REGWIDTH_64) // && REG_Width(regw) != REGWIDTH_32)
            continue;
        if (INS_RegRContain(ins, regw))
            continue;
        return REG_FullRegName(regw);
    }
    return killed_reg;
}


int encode_jump_instr(ADDRINT pc, ADDRINT target_addr, char *encoded_jmp_ins)
{
    xed_encoder_instruction_t enc_instr;
    xed_encoder_request_t enc_req;
    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
    unsigned int olen = 0;

    xed_int64_t disp = target_addr - pc - olen;
    xed_inst1(&enc_instr, dstate,  XED_ICLASS_JMP, 64, xed_relbr(disp, 32)); // FIXME: use 8 bits for short jumps

    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }
    xed_error_enum_t xed_error = xed_encode(&enc_req,
                                            reinterpret_cast<UINT8*>(encoded_jmp_ins), ilen, &olen);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }

    disp = target_addr - pc - olen;
    xed_inst1(&enc_instr, dstate,  XED_ICLASS_JMP, 64, xed_relbr(disp, 32)); // FIXME: use 8 bits for short jumps

    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }
    xed_error = xed_encode(&enc_req,
                           reinterpret_cast<UINT8*>(encoded_jmp_ins), ilen, &olen);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }
    return olen;
}


/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */


/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, ins_enum_t ins_type)
{
    // copy orig instr to instr map:
    ADDRINT orig_targ_addr = 0x0;

    // Check if the instruction has a branch displacement:
    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);
    xed_int32_t disp;
    if (disp_byts > 0) { // there is a branch offset.
        disp = xed_decoded_inst_get_branch_displacement(xedd);
        orig_targ_addr = pc + xed_decoded_inst_get_length (xedd) + disp;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode (xedd);

    unsigned int new_size = 0;

    xed_error_enum_t xed_error =
            xed_encode (xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins),
                        max_inst_len , &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }

    // Add a new entry to instr_map:
    //
    instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
    instr_map[num_of_instr_map_entries].new_ins_addr = 0x0;
    instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr;
    instr_map[num_of_instr_map_entries].targ_map_entry = -1;
    instr_map[num_of_instr_map_entries].size = new_size;
    instr_map[num_of_instr_map_entries].ins_type = ins_type;
    instr_map[num_of_instr_map_entries].bbl_num = bbl_num;
    instr_map[num_of_instr_map_entries].xed_category = xed_decoded_inst_get_category(xedd);

    num_of_instr_map_entries++;

    if (num_of_instr_map_entries >= max_ins_count) {
        cerr << "out of memory for map_instr" << endl;
        return -1;
    }

    // debug print new encoded instr:
    if (KnobVerbose) {
        cerr << "    new instr:";
        dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries-1].encoded_ins,
                            instr_map[num_of_instr_map_entries-1].new_ins_addr);
    }

    return new_size;
}



/*************************************************/
/* chain_all_direct_br_and_call_target_entries() */
/*************************************************/
void chain_all_direct_br_and_call_target_entries(unsigned from_entry,
                                                 unsigned until_entry)
{
    std::map<ADDRINT, unsigned> entry_map;
    entry_map.clear();

    for (unsigned i = from_entry; i < until_entry; i++) {
        ADDRINT orig_ins_addr = instr_map[i].orig_ins_addr;
        if (!orig_ins_addr)
            continue;
        // For instrs with same orig_addr, give precedence to the first one.
        entry_map.emplace(orig_ins_addr, i);
    }

    for (unsigned i = from_entry; i < until_entry; i++) {
        ADDRINT orig_targ_addr = instr_map[i].orig_targ_addr;
        if (orig_targ_addr == 0)
            continue;
        if (instr_map[i].targ_map_entry > 0)
            continue;
        if (!entry_map.count(orig_targ_addr))
            continue;
        instr_map[i].targ_map_entry = entry_map[orig_targ_addr];
    }
}


/***************************************/
/* set_new_estimated_ins_addrs_in_tc() */
/***************************************/
void set_initial_estimated_new_ins_addrs_in_tc(char *tc) {
    unsigned tc_cursor = 0;
    // Set initial estimated new addrs for each instruction in the tc.
    for (unsigned i=0; i < num_of_instr_map_entries; i++) {
        instr_map[i].new_ins_addr = (ADDRINT)&tc[tc_cursor];
        // update expected size of tc.
        tc_cursor += instr_map[i].size;
    }
}


/**************************/
/* fix_rip_displacement() */
/**************************/
int fix_rip_displacement(int instr_map_entry)
{
    //debug print:
    //dump_instr_map_entry(instr_map_entry);

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

    if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
        return 0;

    //cerr << "Memory Operands" << endl;
    bool isRipBase = false;
    xed_reg_enum_t base_reg = XED_REG_INVALID;
    xed_int64_t disp = 0;
    for(unsigned int i=0; i < memops ; i++)   {
        base_reg = xed_decoded_inst_get_base_reg(&xedd,i);
        disp = xed_decoded_inst_get_memory_displacement(&xedd,i);
        if (base_reg == XED_REG_RIP) {
            isRipBase = true;
            break;
        }
    }

    if (!isRipBase)
        return 0;

    //xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
    xed_int64_t new_disp = 0;
    xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

    unsigned int orig_size = xed_decoded_inst_get_length (&xedd);

    // modify rip displacement. use direct addressing mode:
    new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size; // xed_decoded_inst_get_length (&xedd_orig);
    xed_encoder_request_set_base0 (&xedd, XED_REG_INVALID);

    //Set the memory displacement using a bit length
    xed_encoder_request_set_memory_displacement (&xedd, new_disp, new_disp_byts);

    unsigned int size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode (&xedd);

    xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins),
                                             size , &new_size); // &instr_map[i].size
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return new_size;
}


/************************************/
/* fix_direct_br_call_to_orig_addr */
/************************************/
int fix_direct_br_call_to_orig_addr(int instr_map_entry)
{

    // check for cases of direct jumps/calls back to the orginal target address:
    if (instr_map[instr_map_entry].targ_map_entry >= 0) {
        cerr << "ERROR: Invalid jump or call instruction" << endl;
        return -1;
    }

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    xed_error_enum_t xed_code =
            xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x"
             << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

    if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {
        cerr << "ERROR: Invalid direct jump from translated code to original code in routine: "
             << RTN_Name(RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr)) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
    unsigned int olen = 0;

    xed_encoder_instruction_t  enc_instr;

    // Use the heap variable instr_map[instr_map_entry].orig_targ_addr as the
    // memory container that holds the target address for the jmp/call
    // and indirectly jmp/call via that memory location.

    // search for orig_targ_addr in jump_to_orig_addr_map.
    int jump_to_orig_addr_map_entry = -1;
    for (unsigned i = 0; i < jump_to_orig_addr_num; i++) {
        if (instr_map[instr_map_entry].orig_targ_addr == jump_to_orig_addr_map[i]) {
            jump_to_orig_addr_map_entry = i;
            break;
        }
    }
    if (jump_to_orig_addr_map_entry < 0) {
        jump_to_orig_addr_num++;
        jump_to_orig_addr_map_entry = jump_to_orig_addr_num;
        jump_to_orig_addr_map[jump_to_orig_addr_map_entry] = instr_map[instr_map_entry].orig_targ_addr;
    }

    ADDRINT new_disp = (ADDRINT)&jump_to_orig_addr_map[jump_to_orig_addr_map_entry] -
                                 instr_map[instr_map_entry].new_ins_addr -
                                 xed_decoded_inst_get_length (&xedd);

    if (category_enum == XED_CATEGORY_CALL)
        xed_inst1(&enc_instr, dstate,
                  XED_ICLASS_CALL_NEAR, 64,
                  xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

    if (category_enum == XED_CATEGORY_UNCOND_BR)
        xed_inst1(&enc_instr, dstate,
                  XED_ICLASS_JMP, 64,
                  xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

    xed_encoder_request_t enc_req;

    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }

    xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    // debug prints:
    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return olen;
}


/**************************************/
/* fix_direct_br_or_call_displacement */
/**************************************/
int fix_direct_br_or_call_displacement(int instr_map_entry)
{
    // Check if it is indeed a direct branch or a direct call instr:
    if (instr_map[instr_map_entry].orig_targ_addr == 0)
        return 0;

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: "
             << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    xed_int64_t  new_disp = 0;
    unsigned int size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;


    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

    if (category_enum != XED_CATEGORY_CALL &&
        category_enum != XED_CATEGORY_COND_BR &&
        category_enum != XED_CATEGORY_UNCOND_BR) {
        cerr << "ERROR: unrecognized branch displacement" << endl;
        return -1;
    }

    // fix branches/calls to original targ addresses:
    if (instr_map[instr_map_entry].targ_map_entry < 0) {
        int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
        return rc;
    }

    ADDRINT new_targ_addr;
    new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;

    new_disp = (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size; // orig_size;

    xed_uint_t   new_disp_byts = 4; // num_of_bytes(new_disp);  ???

    // the max displacement size of loop instructions is 1 byte:
    xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
    if (iclass_enum == XED_ICLASS_LOOP ||  iclass_enum == XED_ICLASS_LOOPE || iclass_enum == XED_ICLASS_LOOPNE) {
        new_disp_byts = 1;
    }

    // the max displacement size of jecxz instructions is ???:
    xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum (&xedd);
    if (iform_enum == XED_IFORM_JRCXZ_RELBRb){
        new_disp_byts = 1;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode (&xedd);

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

    xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
    unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;

    xed_error_enum_t xed_error = xed_encode (&xedd, enc_buf, max_size , &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
        char buf[2048];
        xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, static_cast<UINT64>(instr_map[instr_map_entry].orig_ins_addr), 0, 0);
        cerr << " instr: " << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
        return -1;
    }

    new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;

    new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

    xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    //debug print of new instruction in tc:
    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return new_size;
}


/************************************/
/* fix_instructions_displacements() */
/************************************/
int fix_instructions_displacements()
{
    // fix displacemnets of direct branch or call instructions:

    int size_diff = 0;

    do {

        size_diff = 0;

        if (KnobVerbose) {
            cerr << "starting a pass of fixing instructions displacements: " << endl;
        }

        for (unsigned i=0; i < num_of_instr_map_entries; i++) {

            instr_map[i].new_ins_addr += size_diff;

            // fix rip displacement:
            int new_size = fix_rip_displacement(i);
            if (new_size < 0)
                return -1;

            if (new_size > 0) { // this was a rip-based instruction which was fixed.
                if (instr_map[i].size != (unsigned int)new_size) {
                    size_diff += (new_size - instr_map[i].size);
                }
                instr_map[i].size = (unsigned int)new_size;
            }

            // fix instr displacement for direct jump or call:
            new_size = fix_direct_br_or_call_displacement(i);
            if (new_size < 0)
                return -1;

            if (new_size > 0) {
                if (instr_map[i].size != (unsigned int)new_size) {
                    size_diff += (new_size - instr_map[i].size);
                }
                instr_map[i].size = (unsigned int)new_size;
            }

        }  // end int i=0; i ..

    } while (size_diff != 0);

    return 0;
}


/*****************************************/
/* find_candidate_rtns_for_translation() */
/*****************************************/
int find_candidate_rtns_for_translation(IMG img)
{
    int rc = 0;

    // go over routines and check if they are candidates for translation and mark them for translation:

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
            continue;

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            // Keep the entry num of the rtn head in case we need to
            // revert the insertin of the instruction in rtn into the instructions
            // map due to an invalid decoding.
            //unsigned rtn_entry = num_of_instr_map_entries;

            bool isBBLAlreadyProfiled = false;
            bool isAlreadyCheckedForKilledRAXinBBL = false;
            bool isRaxKilledInBBL = false;

            // Open the RTN.
            RTN_Open( rtn );

            // Check if RTN contains an indirect jump and if so, avoid translating it.
            //bool isBreak = false;
            //for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
            //  if (INS_IsIndirectControlFlow(ins) && !INS_IsCall(ins) &&
            //      !INS_IsRet(ins) && !INS_RegRContain (ins, REG_RIP)) {
            //    //cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << "\n"
            //    //     << " skipping rtn: " << RTN_Name(rtn) << "\n";
            //    isBreak = true;
            //    break;
            //  }
            //}
            //if (isBreak) {
            //  RTN_Close( rtn );
            //  continue;
            //}

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {

                //debug print of orig instruction:
                if (KnobVerbose) {
                    cerr << "old instr: ";
                    cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) <<  endl;
                    //xed_print_hex_line(reinterpret_cast<UINT8*>(INS_Address (ins)), INS_Size(ins));
                }

                ADDRINT ins_addr = INS_Address(ins);

                xed_decoded_inst_t xedd;
                xed_error_enum_t xed_code;

                // Add instr into instr map:
                bool isRtnHeadIns = (RTN_Address(rtn) == ins_addr);
                ins_enum_t ins_type = (isRtnHeadIns ? RtnHeadIns : RegularIns);
                bool isInsBackwardJump = KnobProbeBackwardJumps && isBackwardJump(ins);

                // Insert a NOP7 instr at Rtn Head (to be overwritten
                // later by a probing jump via mem from TC to TC2).
                //
                if (KnobApplyThreadedCommit && (isRtnHeadIns || isInsBackwardJump)) {
                    xed_encoder_instruction_t enc_instr;
                    xed_encoder_request_t enc_req;
                    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
                    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
                    unsigned int olen = 0;

                    xed_inst0(&enc_instr, dstate, XED_ICLASS_NOP7, 64); //unsigned char nop7[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };

                    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
                    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
                    if (!convert_ok) {
                        cerr << "conversion to encode request failed" << endl;
                        return -1;
                    }
                    xed_error_enum_t xed_error = xed_encode(&enc_req,
                                                            reinterpret_cast<UINT8*>(encoded_ins), ilen, &olen);
                    if (xed_error != XED_ERROR_NONE) {
                        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
                        return -1;
                    }
                    xed_decoded_inst_zero_set_mode(&xedd,&dstate);
                    xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(&encoded_ins), max_inst_len); // xed_decode(&xedd, nop7, max_inst_len);
                    if (xed_code != XED_ERROR_NONE) {
                        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << ins_addr << endl;
                        return -1;;
                    }
                    rc = add_new_instr_entry(&xedd, ins_addr, ins_type);
                    if (rc < 0) {
                        cerr << "ERROR: failed during instructon translation." << endl;
                        return -1;
                    }
                    ins_type = RegularIns;
                }

                // Check forward untill end of BBL if there is an instr that kills RAX.
                if (!isAlreadyCheckedForKilledRAXinBBL) {
                    isRaxKilledInBBL = false;
                    for (INS next_ins = ins; INS_Valid(next_ins); next_ins = INS_Next(next_ins)) {
                        if (isJumpOrRet(next_ins))
                            break;
                        if (RTN_FindByAddress(INS_Address(next_ins)) != rtn)
                            break;
                        if (getKilledRegByIns(next_ins) == REG_RAX) {
                            isRaxKilledInBBL = true;
                            break;
                        }
                    }
                    isAlreadyCheckedForKilledRAXinBBL = true;
                }

                // Check if ins is a control transfer instr that terminates a BBL:
                bool isInsTerminatesBBL = isJumpOrRet(ins);

                REG killed_reg = getKilledRegByIns(ins);

                // Add profiling instructions to count each BBL exec at runtime:
                //
                if (KnobApplyThreadedCommit && !isBBLAlreadyProfiled) {
                    // Do not insert the profiling now if there is a later instr
                    // in the BBL that kills RAX.
                    if (isInsTerminatesBBL ||
                        (isRaxKilledInBBL && killed_reg == REG_RAX) ||
                        (!isRaxKilledInBBL && killed_reg != REG_INVALID())) {
                        xed_encoder_instruction_t enc_instr;
                        static uint64_t rax_mem;

                        isBBLAlreadyProfiled = true;

                        // debug print.
                        //if (killed_reg != REG_INVALID())
                        //  cerr << "killed reg: " << REG_StringShort(killed_reg).c_str()
                        //       << " at instruction at address: 0x"
                        //       << std::hex << INS_Address(ins)
                        //       << ": " << INS_Disassemble(ins)
                        //       << std::endl;

                        for (unsigned i = 0; i < 6; i++) {
                            if (i == 0)
                                // NOP instr to be overwritten later on by a jmp that skips
                                // the profiling, once profiling is done.
                                xed_inst0(&enc_instr, dstate, XED_ICLASS_NOP, 64);
                            if (i == 1)  {
                                if (killed_reg == REG_RAX)
                                    continue;
                                else if (killed_reg != REG_INVALID())
                                    // MOV RAX into killed_reg
                                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                                              xed_reg(INS_XedExactMapFromPinReg(killed_reg)),
                                              xed_reg(XED_REG_RAX));
                                else
                                    // MOV RAX into rax_mem
                                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                                              xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64),
                                              xed_reg(XED_REG_RAX));
                            } else if (i == 2)
                                // MOV from bb_map into RAX
                                xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                                          xed_reg(XED_REG_RAX),
                                          xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&bbl_map[bbl_num].counter, 64), 64));
                            else if (i == 3)
                                // lea rax, [rax+1]
                                xed_inst2(&enc_instr, dstate, XED_ICLASS_LEA,  64,  // operand width
                                          xed_reg(XED_REG_RAX),
                                          xed_mem_bd(XED_REG_RAX, xed_disp(1, 8), 64));
                            else if (i == 4)
                                // MOV from RAX into bb_map
                                xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                                          xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&bbl_map[bbl_num].counter, 64), 64),
                                          xed_reg(XED_REG_RAX));
                            else if (i == 5) {
                                if (killed_reg == REG_RAX)
                                    continue;
                                else if (killed_reg != REG_INVALID())
                                    // MOV killed_reg into RAX
                                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                                              xed_reg(XED_REG_RAX),
                                              xed_reg(INS_XedExactMapFromPinReg(killed_reg)));
                                else
                                    // MOV from rax_mem into RAX
                                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                                              xed_reg(XED_REG_RAX),
                                              xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64));
                            }

                            xed_encoder_request_t enc_req;

                            xed_encoder_request_zero_set_mode(&enc_req, &dstate);
                            xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
                            if (!convert_ok) {
                                cerr << "conversion to encode request failed" << endl;
                                return -1;
                            }

                            char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
                            unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
                            unsigned int olen = 0;

                            xed_error_enum_t xed_error = xed_encode(&enc_req,
                                                                    reinterpret_cast<UINT8*>(encoded_ins), ilen, &olen);
                            if (xed_error != XED_ERROR_NONE) {
                                cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
                                return -1;
                            }

                            xed_decoded_inst_zero_set_mode(&xedd,&dstate);
                            xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(&encoded_ins), max_inst_len);
                            if (xed_code != XED_ERROR_NONE) {
                                cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << ins_addr << endl;
                                return -1;;
                            }
                            rc = add_new_instr_entry(&xedd, ins_addr, ProfilingIns);
                            if (rc < 0) {
                                cerr << "ERROR: failed during instructon translation." << endl;
                                return -1;
                            }
                        } // end for (...
                    } // end if (..
                } // end if (!isBBLAlreadyProfiled ...

                // Add ins to instr_map:
                //
                xed_decoded_inst_zero_set_mode(&xedd,&dstate);
                xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(ins_addr), max_inst_len);
                if (xed_code != XED_ERROR_NONE) {
                    cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << ins_addr << endl;
                    return -1;
                }

                rc = add_new_instr_entry(&xedd, INS_Address(ins), ins_type);
                if (rc < 0) {
                    cerr << "ERROR: failed during instructon translation." << endl;
                    return -1;
                }

                if (isInsTerminatesBBL) {
                    bbl_map[bbl_num].terminating_ins_entry = num_of_instr_map_entries - 1;
                    if(INS_Valid(INS_Next(ins))) {
                        bbl_map[bbl_num].fallthrough_addr = INS_Address(INS_Next(ins));
                    }
                    else{
                        bbl_map[bbl_num].fallthrough_addr = 0;
                    }
                    bbl_map[bbl_num].visited = false;
                    bbl_num++;
                    bbl_map[bbl_num].starting_ins_entry = num_of_instr_map_entries;
                    isBBLAlreadyProfiled = false;
                    isAlreadyCheckedForKilledRAXinBBL = false;
                }

            } // end for INS...

            // debug print of routine name:
            if (KnobVerbose) {
                cerr <<   "rtn name: " << RTN_Name(rtn) << endl;
            }

            // Close the RTN.
            RTN_Close( rtn );

            // Apply local chaining of direct calls and branches for this routine.
            //chain_all_direct_br_and_call_target_entries(rtn_entry, num_of_instr_map_entries);

        } // end for RTN..
    } // end for SEC...

    return 0;
}


/***************************/
/* int copy_instrs_to_tc() */
/***************************/
int copy_instrs_to_tc(char *tc)
{
    int cursor = 0;

    for (unsigned i=0; i < num_of_instr_map_entries; i++) {

        if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
            cerr << "ERROR: Non-matching instruction addresses: "
                 << hex << (ADDRINT)&tc[cursor]
                    << " vs. " << instr_map[i].new_ins_addr << endl;
            return -1;
        }

        memcpy(&tc[cursor], (char *)instr_map[i].encoded_ins, instr_map[i].size);

        cursor += instr_map[i].size;
    }

    return cursor;
}


/***************************************/
/* void commit_translated_rtns_to_tc() */
/***************************************/
inline void commit_translated_rtns_to_tc()
{
    // Commit the translated functions:
    // Go over the candidate functions and replace the original ones
    // by their new successfully translated ones:

    for (unsigned i=0; i < num_of_instr_map_entries; i++) {

        //replace function by new function in tc

        if (instr_map[i].ins_type != RtnHeadIns)
            continue;

        RTN rtn = RTN_FindByAddress(instr_map[i].orig_ins_addr);

        //debug print:
        //if (rtn == RTN_Invalid()) {
        //    cerr << "committing rtN: Unknown";
        //} else {
        //    cerr << "committing rtN: " << RTN_Name(rtn);
        //}
        //cerr << " from: 0x" << hex << RTN_Address(rtn)
        //     << " to: 0x" << hex << instr_map[i].new_ins_addr << endl;

        if (RTN_Valid(rtn) && RTN_IsSafeForProbedReplacement(rtn)) {

            AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[i].new_ins_addr);

            if (origFptr == NULL) {
                cerr << "RTN_ReplaceProbed failed.";
                cerr << " orig routine addr: 0x" << hex << RTN_Address(rtn)
                     << " replacement routine addr: 0x" << hex
                     << instr_map[i].new_ins_addr << endl;
                dump_instr_from_mem ((ADDRINT *)RTN_Address(rtn), RTN_Address(rtn));
            }

            // debug print.
            //if (origFptr != NULL) {
            //  cerr << "RTN_ReplaceProbed succeeded. ";
            //  cerr << " orig routine addr: 0x" << hex << RTN_Address(rtn)
            //       << " replacement routine addr: 0x" << hex
            //       << instr_map[i].new_ins_addr << endl;
            //  dump_instr_from_mem ((ADDRINT *)RTN_Address(rtn), RTN_Address(rtn));
            //}
        }
    }
}

/****************************************/
/* void commit_translated_rtns_to_tc2() */
/****************************************/
int commit_translated_rtns_to_tc2()
{

    for (unsigned i=0; i < num_of_instr_map_entries; i++) {

        // Insert a probing jump from at routine header in TC to its corresponding
        // header in TC2, provided it is a wide NOP instr.
        if ((!KnobProbeBackwardJumps && instr_map[i].ins_type != RtnHeadIns) ||
            instr_map[i].xed_category != XED_CATEGORY_WIDENOP)
            continue;

        // Form a probing jump instruction:
        //

        // Option 1: Use a direct jump for probing:
        unsigned int olen = encode_jump_instr(instr_map[i].orig_ins_addr,
                                              instr_map[i].new_ins_addr,
                                              instr_map[i].encoded_ins);
        if (olen < 0)
            return -1;

        // Option 2: Use an indirect jump for probing:
        //ADDRINT new_disp = (ADDRINT)&instr_map[i].new_ins_addr - instr_map[i].orig_ins_addr - olen;
        //xed_inst1(&enc_instr, dstate,
        //    XED_ICLASS_JMP, 64,
        //    xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

        //memcpy((ADDRINT *)instr_map[i].orig_ins_addr, instr_map[i].encoded_ins, olen);

        // Set the probing jump instruction atomically in 2 stages:
        //

        // 1st stage: set the last 4 bytes of the probe jmp instr.
        if (olen > 4)
            memcpy((char *)(instr_map[i].orig_ins_addr + 4),
                   (char *)((ADDRINT)instr_map[i].encoded_ins + 4), olen - 4);

        // 2nd stage: set the first 4 bytes of the probe jmp instr.
        memcpy((char *)instr_map[i].orig_ins_addr, instr_map[i].encoded_ins, 4);

        //debug print:
        /*cerr << " committing rtN from: 0x" << hex << instr_map[i].orig_ins_addr
             << " to: 0x" << hex << instr_map[i].new_ins_addr
             << " size: " << olen
             << endl;
              */
        dump_instr_from_mem ((ADDRINT *)instr_map[i].orig_ins_addr, instr_map[i].orig_ins_addr);
    }

    return 0;
}


/****************************/
/* create_tc2_thread_func() */
/****************************/
void create_tc2_thread_func(void *v)
{
    // Wait prof_time seconds for the profiling to count
    // execution frequency for each BBL.
    sleep(KnobNumSecsDuringProfile);

    // Step 1: disable profiling.
    //         Add a jump to bypass the profiling counters in TC.
    //
    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
        // Check for the case of a NOP instr at the head of a
        // pofiling code stub and replace it by a jump instr that skips it.
        if (instr_map[i].ins_type == ProfilingIns &&
            instr_map[i].xed_category == XED_CATEGORY_NOP) {
            // Calculate the jump displacement.
            unsigned j = 1;
            xed_int64_t disp = 0;
            while (instr_map[i+j].ins_type == ProfilingIns) {
                disp += instr_map[i+j].size;
                j++;
            }

            xed_encoder_instruction_t enc_instr;
            xed_encoder_request_t enc_req;
            unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
            char encoded_jmp_ins[XED_MAX_INSTRUCTION_BYTES];
            unsigned int olen = 2; // skip jump instr is exactly 2 bytes long.

            disp += (instr_map[i].size - olen);
            xed_inst1(&enc_instr, dstate,  XED_ICLASS_JMP, 64, xed_relbr(disp, 8));

            xed_encoder_request_zero_set_mode(&enc_req, &dstate);
            xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
            if (!convert_ok) {
                cerr << "conversion to encode request failed" << endl;
                return;
            }
            xed_error_enum_t xed_error = xed_encode(&enc_req,
                                                    reinterpret_cast<UINT8*>(encoded_jmp_ins), ilen, &olen);
            if (xed_error != XED_ERROR_NONE) {
                cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
                return;
            }
            if (olen > instr_map[i].size) {
                cerr << " unable to set a relative jump to skip the profiling code stub at: "
                     << hex << "0x" << instr_map[i].new_ins_addr << "\n";
                return;
            }

            // Write the bypassing jump instr on the NOP instr.
            memcpy((ADDRINT *)instr_map[i].new_ins_addr, encoded_jmp_ins, olen);
            i += (j - 1);
        }
    }

    if (!bbl_num) {
        cerr << "Invalid number of BBLs\n";
        return;
    }

    // Set the heat level for each BBL according to collected profile and
    // percentage of thershold level.
    UINT64 total_bbl_heat_sum = 0;
    for (unsigned i = 0; i < bbl_num; i++)
        total_bbl_heat_sum += bbl_map[i].counter;

    if (!total_bbl_heat_sum)
        cerr << "Note: Profiling is empty\n";

    UINT64 average_bbl_heat = total_bbl_heat_sum / bbl_num;
    if (total_bbl_heat_sum) {
        for (unsigned i = 0; i < bbl_num; i++)
            if (average_bbl_heat)
                bbl_map[i].heat_level =
                        (!bbl_map[i].counter ? 0 : bbl_map[i].counter / average_bbl_heat + 1);
    }


    // debug print of all bbl counters.
    //cerr << "dumping bbl counters: " << endl;
    //for (unsigned i = 0; i < bbl_num; i++) {
    //  if (bbl_map[i].counter) {
    //    unsigned starting_ins_entry = bbl_map[i].starting_ins_entry;
    //    unsigned terminating_ins_entry = bbl_map[i].terminating_ins_entry;
    //    cerr << "   " << hex << "0x" << instr_map[starting_ins_entry].orig_ins_addr
    //         << " , " << hex << "0x" << instr_map[terminating_ins_entry].orig_ins_addr
    //         << " , " << dec << bbl_map[i].counter
    //         << " , " << dec << bbl_map[i].heat_level
    //         << "\n";
    //    //xed_category_enum_t xed_category = instr_map[terminating_ins_entry].xed_category;
    //    //cerr << " " << xed_category_enum_t2str(xed_category) << "\n";
    //  }
    //}
    //cerr << "\n";

    // debug print instr_map along with the heat level for each instr.
    //cerr << "instr_map:\n";
    //for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
    //   unsigned bbl_num = instr_map[i].bbl_num;
    //   cerr << " heat: " << dec << bbl_map[bbl_num].heat_level << " : ";
    //   dump_instr_from_mem((ADDRINT *)instr_map[i].encoded_ins,
    //                       instr_map[i].orig_ins_addr);
    //}
    //cerr << "\n";

//    cerr << "after calculating total bbl heat sum and average bbl heat\n";
//    cerr << " total_bbl_heat_sum: " << dec << total_bbl_heat_sum << "\n";
//    cerr << " average_bbl_heat: " << dec << average_bbl_heat << "\n";
    // Step 2.1: Modify instr_map.
    //
    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
        // Skip the profiling instructions added in TC for each BBL.
        if (instr_map[i].ins_type == ProfilingIns)
          //TODO: FIXME?
          //instr_map[i].size = 0;

        // Skip the wide NOP instr at the Rtn head which was reserved
        // for the probing jump from TC to TC2.
        if (instr_map[i].ins_type == RtnHeadIns &&
            instr_map[i].xed_category == XED_CATEGORY_WIDENOP)
            //TODO: FIXME?
            //instr_map[i].size = 0;

        // Fix orig_targ_addr by new_ins_addr and targ_map_entry.
        if (instr_map[i].targ_map_entry >= 0) {
            ADDRINT new_targ_addr = instr_map[instr_map[i].targ_map_entry].new_ins_addr;
            instr_map[i].orig_targ_addr = new_targ_addr;
        }
    }

    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
        instr_map[i].orig_ins_addr = instr_map[i].new_ins_addr;
        instr_map[i].new_ins_addr = 0x0;
        instr_map[i].targ_map_entry = -1;
    }

    // Step 2.2: Create ordered_instr_map.
    //

    // Populate bbl_heat_map with all BBs.
    for (unsigned i = 0; i < bbl_num; i++) {
        unsigned heat_level = bbl_map[i].heat_level;
        bbl_heat_map[heat_level].push_back(i);
    }

    //debug print:
    //cerr << "*******after fallthrough management" <<endl;
    // Debug print of ordered_instr_map.

    //Debug Print
//    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
//        unsigned bbl_num = instr_map[i].bbl_num;
//        cerr << " heat: " << dec << bbl_map[bbl_num].heat_level << " BBL NUMBER: "<< bbl_num<<  " : ";
//        dump_instr_from_mem((ADDRINT *)instr_map[i].encoded_ins,
//                            instr_map[i].orig_ins_addr);
//    }


    //Debug Print
//    unsigned filled_entries = 0;
//    cerr << "Filled entries: " <<dec <<  filled_entries << ", num_of_instr_map_entries: "<< dec << num_of_instr_map_entries << endl;
//
//    for (unsigned i = 0; i < max_ins_count; ++i) {
//        if (instr_map[i].orig_ins_addr != 0) { // or any other field that indicates a valid entry
//            filled_entries++;
//        }
//    }
//    cerr << "Filled entries: " << dec << filled_entries << ", num_of_instr_map_entries: " << dec << num_of_instr_map_entries << endl;



    unsigned ordered_ind = 0;
    std::map<ADDRINT, ADDRINT> addr_map; // To map old addresses to new ones
    ADDRINT new_address_cursor = (ADDRINT)&tc2[0];
    unsigned i =0;
    unsigned hottest_bbl =  getFirstElementOfLargestKey(bbl_heat_map);
    unsigned current_bbl_index = hottest_bbl;
    unsigned last_bbl_index = hottest_bbl;
    unsigned bbl_index_module;
    int total_size=0;

    i= 0;
    ADDRINT our_base_address = (ADDRINT)&tc2[0];

    while(current_bbl_index % bbl_num != last_bbl_index || i == 0)
    {
        bbl_index_module = current_bbl_index % bbl_num;
        if(bbl_map[bbl_index_module].visited)
        {
            cerr << "FATAL ERROR: BBL INDEX ALREADY VISITED\n";
            exit(1);
        }
        bbl_map[bbl_index_module].visited= true;

        unsigned bbl_start_entry = bbl_map[bbl_index_module].starting_ins_entry;
        unsigned terminating_ins_entry =bbl_map[bbl_index_module].terminating_ins_entry;

        // Rebuild each BBL, updating the addresses
        for (unsigned j = bbl_start_entry; j < terminating_ins_entry; j++) {
            total_size++;
            instr_map_t current_instr = instr_map[j];
            ADDRINT not_orederd_old_addr = current_instr.orig_ins_addr; // Save the original instruction address
            addr_map[not_orederd_old_addr] = new_address_cursor;
            current_instr.orig_ins_addr = new_address_cursor;
            new_address_cursor += current_instr.size;
            if (current_instr.size == 0) {
                cerr << " nothing here\n";
            }

            reordered_instr_map[ordered_ind] = current_instr;
            ordered_ind++;
        }
        total_size++;
        reordered_instr_map[ordered_ind].bbl_num =  current_bbl_index % bbl_num;
        // case RET
        if (instr_map[terminating_ins_entry].xed_category == XED_CATEGORY_RET)
        {

            instr_map_t current_instr = instr_map[terminating_ins_entry];
            ADDRINT not_orederd_old_addr = current_instr.orig_ins_addr; // Save the original new instruction address
            // Assign new addresses
            current_instr.orig_ins_addr = new_address_cursor;
            // Save the mapping between old and new addresses
            addr_map[not_orederd_old_addr] = new_address_cursor;
            new_address_cursor += current_instr.size;
            reordered_instr_map[ordered_ind] = current_instr;
            ordered_ind++;

        }
        // Handle conditional or unconditional branches, including indirect jumps like jmp qword ptr [0x61c018]
        else if (instr_map[terminating_ins_entry].xed_category == XED_CATEGORY_COND_BR ||
            instr_map[terminating_ins_entry].xed_category == XED_CATEGORY_UNCOND_BR) {
           // cerr << "current_bbl_index % bbl_num= " << dec << current_bbl_index % bbl_num << endl;
            xed_decoded_inst_t xedd2;
            // Initialize and decode the instruction at the given address
            if (!decode_instruction_at_address(instr_map[terminating_ins_entry].orig_ins_addr, &xedd2)) {
                cerr << "Error decoding instruction at address: 0x" << hex << instr_map[terminating_ins_entry].orig_ins_addr << endl;
            } else {
                // Get the instruction class and category (e.g., conditional/unconditional jump)
                xed_iclass_enum_t iclass_enum2 = xed_decoded_inst_get_iclass(&xedd2);
                xed_category_enum_t cat = xed_decoded_inst_get_category(&xedd2);

                // Case 1: Conditional jump
                if (cat == XED_CATEGORY_COND_BR) {
                   // cerr << "Conditional jump detected, handling as a conditional branch" << endl;
                    // Calculate relative address for conditional branch
                    ADDRINT old_target_address = ExtractTargetAddressFromMem(instr_map[terminating_ins_entry].orig_ins_addr);
                    instr_map[terminating_ins_entry].orig_targ_addr = old_target_address;
                    ADDRINT new_target_address =  old_target_address -(instr_map[terminating_ins_entry].orig_ins_addr + instr_map[terminating_ins_entry].size);
                     // Encode the new conditional jump
                    xed_encoder_instruction_t enc_instr;
                    xed_inst1(&enc_instr, dstate, iclass_enum2, 64, xed_relbr(new_target_address, 32));
                    xed_encoder_request_t enc_req;
                    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
                    if (xed_convert_to_encoder_request(&enc_req, &enc_instr)) {
                        xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
                        unsigned int new_size = 0;
                        xed_error_enum_t xed_error = xed_encode(&enc_req, enc_buf, XED_MAX_INSTRUCTION_BYTES, &new_size);
                        if (xed_error == XED_ERROR_NONE) {
                            // Copy encoded instruction
                            memcpy(reordered_instr_map[ordered_ind].encoded_ins, enc_buf, new_size);
                            addr_map[reordered_instr_map[ordered_ind].orig_ins_addr] = new_address_cursor;
                            reordered_instr_map[ordered_ind].size = new_size;
                            reordered_instr_map[ordered_ind].orig_ins_addr = new_address_cursor;
                            reordered_instr_map[ordered_ind].xed_category = cat;
                            reordered_instr_map[ordered_ind].orig_targ_addr = old_target_address;
                            new_address_cursor += new_size;
                            ordered_ind++;
                            //cerr << "New encoded conditional jump size: " << new_size << endl;
                        } else {
                            cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
                        }
                    } else {
                        cerr << "Conversion to encoder request failed for conditional jump" << endl;
                    }
                }

                // Case 3: Direct RIP-relative jumps (e.g., jmp 0xADDRESS)
                else if (iclass_enum2 == XED_ICLASS_JMP && xed_decoded_inst_number_of_memory_operands(&xedd2) == 0) {
                    //  cerr << "Direct RIP-relative jump detected (jmp 0xADDRESS)" << endl;
                    ADDRINT old_target_address = ExtractTargetAddressFromMem(instr_map[terminating_ins_entry].orig_ins_addr);
                    instr_map[terminating_ins_entry].orig_targ_addr = old_target_address;
                    ADDRINT instruction_address = instr_map[terminating_ins_entry].orig_ins_addr;
                    // Calculate relative offset for direct jump
                    ADDRINT relative_offset = old_target_address - (instruction_address + instr_map[terminating_ins_entry].size);
                    // Encode the direct RIP-relative jump
                    xed_encoder_instruction_t enc_instr;
                    xed_inst1(&enc_instr, dstate, iclass_enum2, 64, xed_relbr(relative_offset, 32));
                    xed_encoder_request_t enc_req;
                    xed_encoder_request_zero_set_mode(&enc_req, &dstate);

                    if (xed_convert_to_encoder_request(&enc_req, &enc_instr)) {
                        xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
                        unsigned int new_size = 0;
                        xed_error_enum_t xed_error = xed_encode(&enc_req, enc_buf, XED_MAX_INSTRUCTION_BYTES, &new_size);

                        if (xed_error == XED_ERROR_NONE) {
                            // Store the encoded jump
                            memcpy(reordered_instr_map[ordered_ind].encoded_ins, enc_buf, new_size);
                            addr_map[reordered_instr_map[ordered_ind].orig_ins_addr] = new_address_cursor;
                            reordered_instr_map[ordered_ind].size = new_size;
                            reordered_instr_map[ordered_ind].orig_ins_addr = new_address_cursor;
                            reordered_instr_map[ordered_ind].xed_category = cat;
                            reordered_instr_map[ordered_ind].orig_targ_addr = old_target_address;
                            new_address_cursor += new_size;
                            ordered_ind++;
                       //     cerr << "Direct RIP-relative jump encoded successfully (jmp 0xADDRESS)" << endl;
                        } else {
                            cerr << "Direct jump encoding error: " << xed_error_enum_t2str(xed_error) << endl;
                        }
                    } else {
                        cerr << "Direct jump conversion to encoder request failed" << endl;
                    }
                }

                // Case 2: Unconditional jump using register (e.g., jmp rax)
                else if (iclass_enum2 == XED_ICLASS_JMP && xed_decoded_inst_get_operand_width(&xedd2) == 64) {
                    xed_reg_enum_t reg = xed_decoded_inst_get_reg(&xedd2, XED_OPERAND_REG0);
              //      cerr << "Detected register: " << xed_reg_enum_t2str(reg) << endl;

                    if (reg != XED_REG_INVALID) {
                    //    cerr << "Register-based jump detected (e.g., jmp rax)" << endl;
                        // Copy original encoded instruction directly
                        memcpy(reordered_instr_map[ordered_ind].encoded_ins, instr_map[terminating_ins_entry].encoded_ins, instr_map[terminating_ins_entry].size);
                        addr_map[reordered_instr_map[ordered_ind].orig_ins_addr] = new_address_cursor;
                        reordered_instr_map[ordered_ind].size = instr_map[terminating_ins_entry].size;
                        reordered_instr_map[ordered_ind].orig_ins_addr = new_address_cursor;
						reordered_instr_map[ordered_ind].xed_category = cat;
                        reordered_instr_map[ordered_ind].orig_targ_addr = 0;
                        new_address_cursor += instr_map[terminating_ins_entry].size;
                        ordered_ind++;
                        //cerr << "Register-based jump copied successfully." << endl;
                    }
                }

                // Case 4: Indirect jumps (jmp qword ptr [RIP+offset])
                else if (iclass_enum2 == XED_ICLASS_JMP && xed_decoded_inst_number_of_memory_operands(&xedd2) > 0) {
                    ADDRINT target_address = ExtractTargetAddressFromMem(instr_map[terminating_ins_entry].orig_ins_addr);
                    instr_map[terminating_ins_entry].orig_targ_addr = target_address;
                    // cerr << "Handling indirect jump with target: " << target_address << endl;
                    // Encode the indirect jump instruction
                    xed_encoder_instruction_t enc_instr;
                    xed_inst1(&enc_instr, dstate, XED_ICLASS_JMP, 64, xed_mem_bd(XED_REG_RIP, xed_disp(target_address, 32), 64));
                    xed_encoder_request_t enc_req;
                    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
                    if (xed_convert_to_encoder_request(&enc_req, &enc_instr)) {
                        xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
                        unsigned int new_size = 0;
                        xed_error_enum_t xed_error = xed_encode(&enc_req, enc_buf, XED_MAX_INSTRUCTION_BYTES, &new_size);
                        if (xed_error == XED_ERROR_NONE) {
                            // Store the encoded instruction
                            memcpy(reordered_instr_map[ordered_ind].encoded_ins, enc_buf, new_size);
                            addr_map[reordered_instr_map[ordered_ind].orig_ins_addr] = new_address_cursor;
                            reordered_instr_map[ordered_ind].size = new_size;
                            reordered_instr_map[ordered_ind].orig_ins_addr = new_address_cursor;
                            reordered_instr_map[ordered_ind].xed_category = cat;
                            reordered_instr_map[ordered_ind].orig_targ_addr = 0;
                            new_address_cursor += new_size;
                            ordered_ind++;
                      //      cerr << "Indirect jump encoded successfully" << endl;
                        } else {
                            cerr << "Indirect jump encoding error: " << xed_error_enum_t2str(xed_error) << endl;
                        }
                    } else {
                        cerr << "Indirect jump conversion to encoder request failed" << endl;
                    }
                }
            }
        }

        ADDRINT current_fallthrough = bbl_map[bbl_index_module].fallthrough_addr; // if its terminate bbl will be != 0
        if (current_fallthrough != 0) {
            bbl_map[bbl_index_module].fallthrough_addr = new_address_cursor;
        }
        i++;
        current_bbl_index++;
    }
	ADDRINT last_inst = reordered_instr_map[num_of_instr_map_entries-1].orig_ins_addr + reordered_instr_map[num_of_instr_map_entries-1].size
                                                                                   -reordered_instr_map[0].orig_ins_addr;

   for (unsigned int i = 0; i < num_of_instr_map_entries; i++) {
        instr_map_t& current_instr = reordered_instr_map[i];
        //cerr <<"current_instr.xed_category : "<<  current_instr.xed_category<< endl;
        // Check if the instruction is a 'call' instruction
        if (current_instr.xed_category == XED_CATEGORY_CALL) {
            xed_decoded_inst_t xedd;
            // Decode the call instruction at the original address
            if (!decode_instruction_at_address(current_instr.orig_ins_addr, &xedd)) {
                cerr << "Error decoding 'call' instruction at address: 0x" << hex << current_instr.orig_ins_addr << endl;
                continue;
            }
            // Extract the call target (the function address it calls)
            ADDRINT call_target_address = ExtractTargetAddressFromMem(current_instr.orig_ins_addr);

            // Verify the call target address is mapped correctly
            if (addr_map.find(call_target_address) == addr_map.end()) {
                cerr << "Call target address not found in addr_map! Address: 0x" << hex << call_target_address << endl;
                continue;
            }

            // Get the new call target address
            ADDRINT new_call_target_address = addr_map[call_target_address];
            // Retrieve the size of the current instruction
            unsigned int call_instruction_size = current_instr.size;
            if (call_instruction_size == 0) {
                call_instruction_size = xed_decoded_inst_get_length(&xedd);  // Use XED to get the exact instruction length
            }

            // Calculate the new address of the current instruction
            ADDRINT current_new_address = addr_map[current_instr.orig_ins_addr];
            if (current_new_address == 0) {
                cerr << "Invalid new address for the current instruction in addr_map!" << endl;
                continue;
            }

            // Calculate the displacement (new_disp) as the difference between the target address and the next instruction address
            ADDRINT new_disp = new_call_target_address - (current_new_address + call_instruction_size);
            // Encode the new call instruction with updated displacement
            xed_encoder_instruction_t enc_instr;
            xed_inst1(&enc_instr, dstate, XED_ICLASS_CALL_NEAR, 64, xed_relbr(new_disp, 32));
            xed_encoder_request_t enc_req;
            xed_encoder_request_zero_set_mode(&enc_req, &dstate);
            if (xed_convert_to_encoder_request(&enc_req, &enc_instr)) {
                xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
                unsigned int new_size = 0;
                xed_error_enum_t xed_error = xed_encode(&enc_req, enc_buf, XED_MAX_INSTRUCTION_BYTES, &new_size);
                if (xed_error == XED_ERROR_NONE) {
                    // Store the encoded instruction
                    memcpy(current_instr.encoded_ins, enc_buf, new_size);
                    current_instr.size = new_size;
                    // Update new_address_cursor for the next instruction placement
                    new_address_cursor += new_size;
                //    cerr << "Call instruction re-encoded successfully" << endl;
                } else {
                    cerr << "Encoding error for call instruction: " << xed_error_enum_t2str(xed_error) << endl;
                }
            } else {
                cerr << "Conversion to encoder request failed for call instruction" << endl;
            }
        }

         else if (reordered_instr_map[i].xed_category == XED_CATEGORY_COND_BR ||
            reordered_instr_map[i].xed_category == XED_CATEGORY_UNCOND_BR) {
         //    cerr << "/////////////////" << endl;
             dump_instr_from_mem((ADDRINT *)instr_map[(bbl_map[hottest_bbl].starting_ins_entry+i) % num_of_instr_map_entries].encoded_ins,
                             instr_map[(bbl_map[hottest_bbl].starting_ins_entry+i) % num_of_instr_map_entries].orig_ins_addr);
            xed_decoded_inst_t xedd3;

            // Initialize and decode the instruction at the given address
            if (!decode_instruction_at_address( instr_map[(bbl_map[hottest_bbl].starting_ins_entry+i) % num_of_instr_map_entries].orig_ins_addr, &xedd3)) {

                cerr << "Error decoding instruction at address: 0x" << hex << reordered_instr_map[i].orig_ins_addr << endl;
            } else {
                // Get the instruction class and category (e.g., conditional/unconditional jump)
                xed_iclass_enum_t iclass_enum3 = xed_decoded_inst_get_iclass(&xedd3);
                xed_category_enum_t cat2 = xed_decoded_inst_get_category(&xedd3);

                // Case 1: Conditional jump
                if (cat2 == XED_CATEGORY_COND_BR) {
                 //   cerr << "Conditional jump detected, handling as a conditional branch" << endl;

                    // Calculate relative address for conditional branch
                    ADDRINT old_target_address = instr_map[(bbl_map[hottest_bbl].starting_ins_entry+i) % num_of_instr_map_entries].orig_targ_addr;
                    ADDRINT relative_offset = old_target_address - (instr_map[(bbl_map[hottest_bbl].starting_ins_entry+i) % num_of_instr_map_entries].orig_ins_addr + reordered_instr_map[i].size);
                    ADDRINT dest =  reordered_instr_map[i].orig_ins_addr + relative_offset - last_inst - our_base_address +reordered_instr_map[i].size ;

                    if (reordered_instr_map[i].orig_ins_addr + relative_offset + reordered_instr_map[i].size  >= last_inst +our_base_address)
                    {
                        relative_offset = dest + reordered_instr_map[0].orig_ins_addr - (reordered_instr_map[i].orig_ins_addr+ reordered_instr_map[i].size);
                        // Encode the new conditional jump
                        xed_encoder_instruction_t enc_instr;
                        xed_inst1(&enc_instr, dstate, iclass_enum3, 64, xed_relbr(relative_offset, 32));
                        xed_encoder_request_t enc_req;
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate);
                        if (xed_convert_to_encoder_request(&enc_req, &enc_instr)) {
                            xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
                            unsigned int new_size = 0;
                            xed_error_enum_t xed_error = xed_encode(&enc_req, enc_buf, XED_MAX_INSTRUCTION_BYTES, &new_size);
                            if (xed_error == XED_ERROR_NONE) {
                                // Copy encoded instruction
                                memcpy(reordered_instr_map[i].encoded_ins, enc_buf, new_size);
                          //      cerr << "New encoded conditional jump size: " << new_size << endl;
                            } else {
                                cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
                            }
                        } else {
                            cerr << "Conversion to encoder request failed for conditional jump" << endl;
                        }

                    }
                }



                // Case 3: Direct RIP-relative jumps (e.g., jmp 0xADDRESS)
                else if (iclass_enum3 == XED_ICLASS_JMP && xed_decoded_inst_number_of_memory_operands(&xedd3) == 0) {
                    // Calculate relative address for conditional branch
                    ADDRINT old_target_address = instr_map[(bbl_map[hottest_bbl].starting_ins_entry+i) % num_of_instr_map_entries].orig_targ_addr;
                    ADDRINT relative_offset = old_target_address - (instr_map[(bbl_map[hottest_bbl].starting_ins_entry+i) % num_of_instr_map_entries].orig_ins_addr + reordered_instr_map[i].size);
                    ADDRINT dest =  reordered_instr_map[i].orig_ins_addr + relative_offset - last_inst - our_base_address +reordered_instr_map[i].size ;
                    // Case 2: Unconditional jump using register (e.g., jmp rax)
                    if (iclass_enum3 == XED_ICLASS_JMP && xed_decoded_inst_get_operand_width(&xedd3) == 64) {
                        dump_instr_from_mem((ADDRINT *)instr_map[(bbl_map[hottest_bbl].starting_ins_entry+i) % num_of_instr_map_entries].encoded_ins,
                             instr_map[(bbl_map[hottest_bbl].starting_ins_entry+i) % num_of_instr_map_entries].orig_ins_addr);
                        xed_reg_enum_t reg = xed_decoded_inst_get_reg(&xedd3, XED_OPERAND_REG0);
                      //  cerr << "Detected register: " << xed_reg_enum_t2str(reg) << endl;
                        if (reg != XED_REG_INVALID) {
                        //    cerr << "Register-based jump detected (e.g., jmp rax)" << endl;
                            // Copy original encoded instruction directly
                            memcpy(reordered_instr_map[i].encoded_ins, instr_map[(bbl_map[hottest_bbl].starting_ins_entry+i) % num_of_instr_map_entries].encoded_ins, instr_map[(bbl_map[hottest_bbl].starting_ins_entry+i) % num_of_instr_map_entries].size);
                        //    cerr << "Register-based jump copied successfully." << endl;
                        }
                    }
                    
                    if (relative_offset + reordered_instr_map[i].orig_ins_addr + reordered_instr_map[i].size >= last_inst + our_base_address)
                    {
                        relative_offset = dest + reordered_instr_map[0].orig_ins_addr - (reordered_instr_map[i].orig_ins_addr+ reordered_instr_map[i].size);
                        // Encode the direct RIP-relative jump
                        xed_encoder_instruction_t enc_instr;
                        xed_inst1(&enc_instr, dstate, iclass_enum3, 64, xed_relbr(relative_offset, 32));
                        xed_encoder_request_t enc_req;
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate);
                        if (xed_convert_to_encoder_request(&enc_req, &enc_instr)) {
                            xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
                            unsigned int new_size = 0;
                            xed_error_enum_t xed_error = xed_encode(&enc_req, enc_buf, XED_MAX_INSTRUCTION_BYTES, &new_size);
                            if (xed_error == XED_ERROR_NONE) {
                                // Store the encoded jump
                                memcpy(reordered_instr_map[i].encoded_ins, enc_buf, new_size);
                             //   cerr << "Direct RIP-relative jump encoded successfully (jmp 0xADDRESS)" << endl;
                            } else {
                                //cerr << "Direct jump encoding error: " << xed_error_enum_t2str(xed_error) << endl;
                            }
                        } else {
                       //     cerr << "Direct jump conversion to encoder request failed" << endl;
                        }
                    }
                }
            }
        }
    }



    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
        instr_map[i] = reordered_instr_map[i];
    }

    //  fix all the branches, calls, and fallthroughs to the new addresses
    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
        // If it's a branch or call instruction
        if (instr_map[i].orig_targ_addr != 0) {
            ADDRINT new_target_addr = addr_map[instr_map[i].orig_targ_addr];
            instr_map[i].orig_targ_addr = new_target_addr;  // Update the branch target address
        }
    }



//    // Debug print of ordered_instr_map.
//    cerr << " ________________START_________________" << endl;
//    cerr << " ordered_ind: " << dec << ordered_ind << "\n";
//    cerr << " num_of_instr_map_entries: " << dec << num_of_instr_map_entries << "\n";
//    cerr << "ordered_instr_map:\n";
//    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
//       unsigned bbl_num = reordered_instr_map[i].bbl_num;
//       cerr << " heat: " << dec << bbl_map[bbl_num].heat_level << " BBL NUMBER: "<< bbl_num<<  " : ";
//       dump_instr_from_mem((ADDRINT *)reordered_instr_map[i].encoded_ins,
//                           reordered_instr_map[i].orig_ins_addr);
//    }
//    cerr << "\n";
//    cerr << " ________________END_________________" << endl;

    /******************************GADI's CODE for ordered map***************************************
        unsigned ordered_ind = 0;
        std::map<unsigned, std::vector<unsigned>>::reverse_iterator heat_it;
        for (heat_it = bbl_heat_map.rbegin(); heat_it != bbl_heat_map.rend(); heat_it++) {
           //unsigned heat_level = heat_it->first;
           std::vector<unsigned>bbl_vec = heat_it->second;
           for (auto vec_ind : bbl_vec) {
             unsigned bbl_start_entry = bbl_map[vec_ind].starting_ins_entry;
             unsigned bbl_terminate_entry = bbl_map[vec_ind].terminating_ins_entry;

             // populate the ordered map instr:
             for (unsigned i = bbl_start_entry; i <= bbl_terminate_entry; i++) {
               ordered_instr_map[ordered_ind] = instr_map[i];
               ordered_ind++;

               // Add a jump instruction to ordered_instr_map at the end of a bbl
               // if it terminates by a cond jump in order to preserve functionality.
               if (instr_map[i].xed_category == XED_CATEGORY_COND_BR) {
                 // Create a jump instr to next instr.
                 ADDRINT targ_addr = instr_map[i].orig_ins_addr + instr_map[i].size;
                 int olen = encode_jump_instr(instr_map[i].orig_ins_addr,
                                              targ_addr,
                                              ordered_instr_map[ordered_ind].encoded_ins);
                 if (olen < 0)
                   return;
                 ordered_instr_map[ordered_ind].orig_ins_addr = instr_map[i].orig_ins_addr;
                 ordered_instr_map[ordered_ind].new_ins_addr = 0x0;
                 ordered_instr_map[ordered_ind].orig_targ_addr = targ_addr;
                 ordered_instr_map[ordered_ind].xed_category = XED_CATEGORY_UNCOND_BR;
                 ordered_instr_map[ordered_ind].size = olen;
                 ordered_instr_map[ordered_ind].ins_type = RegularIns;
                 ordered_instr_map[ordered_ind].targ_map_entry = -1;
                 ordered_ind++;
               }
            }
          }
        }

        // Debug print of ordered_instr_map.
        cerr << " ordered_ind: " << dec << ordered_ind << "\n";
        cerr << " num_of_instr_map_entries: " << dec << num_of_instr_map_entries << "\n";
        cerr << "ordered_instr_map:\n";
        for (unsigned i = 0; i < ordered_ind; i++) {
           unsigned bbl_num = ordered_instr_map[i].bbl_num;
           cerr << " heat: " << dec << bbl_map[bbl_num].heat_level << " : ";
           dump_instr_from_mem((ADDRINT *)ordered_instr_map[i].encoded_ins,
                               ordered_instr_map[i].orig_ins_addr);
        }
        cerr << "\n";

        // Step 2.3: Copy ordered_instr_map to instr_map.
        //
        num_of_instr_map_entries = ordered_ind;
        for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
          instr_map[i] = ordered_instr_map[i];
        }
        cerr << "after modifying instr_map" << endl;
    ********************************END OF GADI's CODE for ordered map***************************************/


    // Step 3: Chaining - calculate direct branch and call instructions to point
    //         to corresponding target instr entries:
    //
    chain_all_direct_br_and_call_target_entries(0, num_of_instr_map_entries);
    cerr << "after chaining all branch targets" << endl;

    // Step 4: Set initial estimated new addrs for each instruction in tc2.
    //
    set_initial_estimated_new_ins_addrs_in_tc(tc2);
    cerr << "after setting initial estimated new ins addrs in tc2" << endl;

    // Step 5: fix rip-based, direct branch and direct call displacements:
    //
    int rc = fix_instructions_displacements();
    if (rc < 0 ) {
        cerr << "failed to fix displacments of translated instructions\n";
        return;
    }
    cerr << "after fixing instructions displacements" << endl;

    // Step 6: write translated instructions to tc2:
    //
    rc = copy_instrs_to_tc(tc2);
    if (rc < 0 ) {
        cerr << "failed to copy the instructions to the translation cache\n";
        return;
    }
    tc2_size = rc;
    cerr << "after write all new instructions to tc2" << endl;

    // Step 7: Commit the translated routines:
    //         Go over the candidate functions and replace the original ones
    //         by their new successfully translated ones:
    if (!KnobDoNotCommitTranslatedCode) {
        rc = commit_translated_rtns_to_tc2();
        if (rc < 0 ) {
            cerr << "failed to commit jump instructions from TC to TC2\n";
            return;
        }
        cerr << "after commit of translated routines from TC to TC2" << endl;
    }

    if (KnobDumpTranslatedCode2) {
        cerr << "Translation Cache 2 dump:" << endl;
        dump_tc(tc2, tc2_size);
    }

    PIN_ExitThread(0);
}


/****************************/
/* allocate_and_init_memory */
/****************************/
int allocate_and_init_memory(IMG img)
{
    // Calculate size of executable sections and allocate required memory:
    //
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
            continue;

        if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
            lowest_sec_addr = SEC_Address(sec);

        if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
            highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

        // need to avouid using RTN_Open as it is expensive...
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {

            if (rtn == RTN_Invalid())
                continue;

            max_ins_count += RTN_NumIns  (rtn);
        }
    }

    max_ins_count *= 10; // estimating that the num of instrs of the inlined
    // functions will not exceed the total nunmber of the entire code.

    // Allocate memory for the instr map needed to fix all branch targets in
    // translated routines:
    instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
    if (instr_map == NULL) {
        perror("calloc");
        return -1;
    }
/*
    ordered_instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
    if (ordered_instr_map == NULL) {
        perror("calloc");
        return -1;
    }
    */
    reordered_instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
    if (reordered_instr_map == NULL) {
        perror("calloc");
        return -1;
    }

    jump_to_orig_addr_map = (ADDRINT *)calloc(max_ins_count/10, sizeof(ADDRINT));
    if (jump_to_orig_addr_map == NULL) {
        perror("calloc");
        return -1;
    }

    // Allocate memory for the BBL counters:
    bbl_map = (bb_map_t *)calloc(max_ins_count/10, sizeof(bb_map_t));
    if (bbl_map == NULL) {
        perror("calloc");
        return -1;
    }

    // get a page size in the system:
    int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
        perror("sysconf");
        return -1;
    }

    ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    unsigned tclen = 10 * text_size + pagesize * 4;   // need a better estimate???
    // Check thet tclen is not larger than a 32 bit branch displacement
    if (tclen >= 0x7FFFFFFULL) {
        cerr << "size of TC is beyond the scope of a branch displacement" << endl;
        return -1;
    }

    // Allocate the needed tc and tc2 with RW+EXEC permissions and is not
    // located in an address that is more than 32bits afar:
    char * addr = (char *)mmap(NULL, 2 * tclen,
                               PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if ((ADDRINT) addr == 0xffffffffffffffff) {
        cerr << "failed to allocate tc" << endl;
        return -1;
    }
    tc = (char *)addr;

    // TC2 is allocated immeditely after TC:
    tc2 = (char *)(addr + tclen);

    return 0;
}



/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
VOID ImageLoad(IMG img, VOID *v)
{
    // Step 0: Check the image and the CPU:
    if (!IMG_IsMainExecutable(img))
        return;

    if (KnobDumpOrigCode)
        dump_image_instrs(img);

    int rc = 0;

    // step 1: Check size of executable sections and allocate required memory:
    rc = allocate_and_init_memory(img);
    if (rc < 0) {
        cerr << "failed to initialize memory for translation\n";
        return;
    }
    cerr << "after memory allocation" << endl;

    // Step 2: go over all routines and identify candidate routines and copy
    //         their code into the instr map IR:
    rc = find_candidate_rtns_for_translation(img);
    if (rc < 0) {
        cerr << "failed to find candidates for translation\n";
        return;
    }
    cerr << "after identifying candidate routines" << endl;

    // Step 3: Chaining - calculate direct branch and call instructions to point
    //         to corresponding target instr entries:
    chain_all_direct_br_and_call_target_entries(0, num_of_instr_map_entries);
    cerr << "after chaining all branch targets" << endl;

    // Step 4: Set initial estimated new addrs for each instruction in the tc.
    set_initial_estimated_new_ins_addrs_in_tc(tc);
    cerr << "after setting initial estimated new ins addrs in tc" << endl;

    // Step 5: fix rip-based, direct branch and direct call displacements:
    rc = fix_instructions_displacements();
    if (rc < 0 ) {
        cerr << "failed to fix displacments of translated instructions\n";
        return;
    }
    cerr << "after fixing instructions displacements" << endl;

    // Step 6: write translated instructions to the tc:
    rc = copy_instrs_to_tc(tc);
    if (rc < 0 ) {
        cerr << "failed to copy the instructions to the translation cache\n";
        return;
    }
    tc_size = rc;
    cerr << "after write all new instructions to memory tc" << endl;

    if (KnobDumpTranslatedCode) {
        cerr << "Translation Cache dump:" << endl;
        dump_tc(tc, tc_size);  // dump the entire tc

        //cerr << endl << "instructions map dump:" << endl;
        //dump_entire_instr_map();     // dump all translated instructions in map_instr
    }

    // Step 7: Commit the translated routines:
    //         Go over the candidate functions and replace the original ones
    //         by their new successfully translated ones:
    if (!KnobDoNotCommitTranslatedCode) {
        commit_translated_rtns_to_tc();
        cerr << "after commit of translated routines from orig code to TC" << endl;
    }
}



/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool translated routines of an Intel(R) 64 binary"
         << endl;
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize pin & symbol manager
    if( PIN_Init(argc,argv) )
        return Usage();

    PIN_InitSymbols();

    // Register ImageLoad
    IMG_AddInstrumentFunction(ImageLoad, 0);

    if (KnobApplyThreadedCommit) {
        // It is safe to create internal threads in the tool's main procedure and spawn new
        // internal threads from existing ones. All other places, like Pin callbacks and
        // analysis routines in application threads, are not safe for creating internal threads.
        THREADID tid = PIN_SpawnInternalThread(create_tc2_thread_func, NULL, 0, NULL);
        if (tid == INVALID_THREADID) {
            cerr << "failed to spawn a thread for commit" << endl;
        }
    }

    // Start the program, never returns
    PIN_StartProgramProbed();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
