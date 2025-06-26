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
#include <vector>
#include <algorithm>

#define MAX_BBL_NUM 10000

// BBL Execution Counts
static uint64_t bbl_exec_count[MAX_BBL_NUM] = {0};

// BBL Branch and Fall-Through Counts
static uint64_t taken_count[MAX_BBL_NUM] = {0};
static uint64_t fallthru_count[MAX_BBL_NUM] = {0};

// Indirect Jump Target Information
static uint64_t indirect_targets[MAX_BBL_NUM][4] = {{0}};
static uint64_t indirect_counts[MAX_BBL_NUM][4] = {{0}};

static ADDRINT bbl_addr_map[MAX_BBL_NUM] = {0};
static unsigned int bbl_num_map[MAX_BBL_NUM] = {0};
static unsigned bbl_total = 0;
std::map<ADDRINT, unsigned> addr_to_bbl_num;

// Temporary storage for registers
static uint64_t rax_mem, rbx_mem, rcx_mem;

using namespace std;

std::ofstream outfile;

/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE,    "pintool",
    "verbose", "0", "Verbose run");

KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "dump_tc", "0", "Dump Translated Code");

KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "no_tc_commit", "0", "Do not commit translated code");



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

const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

#define MAX_PROBE_JUMP_INSTR_BYTES  14

// tc containing the new code:
char *tc;
unsigned tc_cursor = 0;

// instruction map with an entry for each new instruction:
typedef struct {
    ADDRINT orig_ins_addr;
    ADDRINT new_ins_addr;
    ADDRINT orig_targ_addr;
    bool isRtnHead;
    bool isBblHead;
    bool isIndirectBranch;
    unsigned int bbl_num;
    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
    unsigned int size;
    int targ_map_entry;
} instr_map_t;

instr_map_t *instr_map = NULL;
unsigned num_of_instr_map_entries = 0;
unsigned max_ins_count = 0;

// Map of all instructions to be used for chaining.
std::map<ADDRINT, unsigned> entry_map;

/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

/*************************/
/* dump_instr_from_xedd */
/*************************/
void dump_instr_from_xedd (xed_decoded_inst_t* xedd, ADDRINT address)
{
    char disasm_buf[2048];
    xed_uint64_t runtime_address = static_cast<UINT64>(address);
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
  if (xed_code != XED_ERROR_NONE){
      cerr << "invalid opcode" << endl;
      return;
  }
  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(new_addr), 0, 0);
  cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;
}

/**************************/
/* dump_instr_map_entry */
/**************************/
void dump_instr_map_entry(int instr_map_entry)
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
    dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins, instr_map[instr_map_entry].new_ins_addr);
}

/* ============================================================= */
/* Helper Functions for Instrumentation                          */
/* ============================================================= */

int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size, bool isRtnHead, bool isBblHead, unsigned int bbl_num, bool isIndirectBranch = false);

// Helper to save a register to memory via RAX
void save_reg(xed_reg_enum_t reg_to_save, ADDRINT mem_addr) {
    xed_encoder_instruction_t enc_instr;
    xed_encoder_request_t enc_req;
    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
    unsigned int olen = 0;

    // MOV RAX, REG
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RAX), xed_reg(reg_to_save));
    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_convert_to_encoder_request(&enc_req, &enc_instr);
    xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen);
    xed_decoded_inst_t xedd;
    xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
    add_new_instr_entry(&xedd, 0, olen, false, false, 0);

    // MOV [mem_addr], RAX
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_mem_bd(XED_REG_INVALID, xed_disp(mem_addr, 64), 64), xed_reg(XED_REG_RAX));
    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_convert_to_encoder_request(&enc_req, &enc_instr);
    xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen);
    xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
    add_new_instr_entry(&xedd, 0, olen, false, false, 0);
}

// Helper to restore a register from memory via RAX
void restore_reg(xed_reg_enum_t reg_to_restore, ADDRINT mem_addr) {
    xed_encoder_instruction_t enc_instr;
    xed_encoder_request_t enc_req;
    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
    unsigned int olen = 0;

    // MOV RAX, [mem_addr]
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RAX), xed_mem_bd(XED_REG_INVALID, xed_disp(mem_addr, 64), 64));
    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_convert_to_encoder_request(&enc_req, &enc_instr);
    xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen);
    xed_decoded_inst_t xedd;
    xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
    add_new_instr_entry(&xedd, 0, olen, false, false, 0);

    // MOV REG, RAX
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(reg_to_restore), xed_reg(XED_REG_RAX));
    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_convert_to_encoder_request(&enc_req, &enc_instr);
    xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen);
    xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
    add_new_instr_entry(&xedd, 0, olen, false, false, 0);
}

/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */


/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size, bool isRtnHead, bool isBblHead, unsigned int bbl_num, bool isIndirectBranch)
{
    ADDRINT orig_targ_addr = 0x0;

    if (xed_decoded_inst_get_length (xedd) != size && pc != 0) {
        cerr << "Invalid instruction decoding" << endl;
        return -1;
    }

    if (xed_decoded_inst_get_category(xedd) == XED_CATEGORY_COND_BR ||
        xed_decoded_inst_get_category(xedd) == XED_CATEGORY_UNCOND_BR ||
        xed_decoded_inst_get_category(xedd) == XED_CATEGORY_CALL) {
        orig_targ_addr = INS_DirectControlFlowTargetAddress(pc);
    }
    
    xed_encoder_request_init_from_decode (xedd);

    unsigned int new_size = 0;
    xed_error_enum_t xed_error =
       xed_encode (xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), 
                   max_inst_len , &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }

    instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
    instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr;
    instr_map[num_of_instr_map_entries].targ_map_entry = -1;
    instr_map[num_of_instr_map_entries].size = new_size;
    instr_map[num_of_instr_map_entries].isRtnHead = isRtnHead;
    instr_map[num_of_instr_map_entries].isBblHead = isBblHead;
    instr_map[num_of_instr_map_entries].bbl_num = bbl_num;
    instr_map[num_of_instr_map_entries].isIndirectBranch = isIndirectBranch;

    num_of_instr_map_entries++;

    if (num_of_instr_map_entries >= max_ins_count) {
        cerr << "out of memory for map_instr" << endl;
        return -1;
    }

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
void chain_all_direct_br_and_call_target_entries()
{
    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
        if (instr_map[i].orig_targ_addr != 0) {
            auto it = addr_to_bbl_num.find(instr_map[i].orig_targ_addr);
            if (it != addr_to_bbl_num.end()) {
                // Find the instruction map entry for this BBL head
                for(unsigned j = 0; j < num_of_instr_map_entries; ++j) {
                    if(instr_map[j].isBblHead && instr_map[j].orig_ins_addr == it->first) {
                         instr_map[i].targ_map_entry = j;
                         break;
                    }
                }
            }
        }
    }
}


/***************************************/
/* set_new_estimated_ins_addrs_in_tc() */
/***************************************/
void set_estimated_new_ins_addrs_in_tc() {
  tc_cursor = 0;
  for (unsigned i=0; i < num_of_instr_map_entries; i++) {
    instr_map[i].new_ins_addr = (ADDRINT)&tc[tc_cursor];
    tc_cursor += instr_map[i].size;
  }
}

/**************************/
/* fix_rip_displacement() */
/**************************/
int fix_rip_displacement(int instr_map_entry)
{
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        return -1;
    }

    if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
        return 0;

    unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);
    if(memops == 0) return 0;
    
    xed_reg_enum_t base_reg = xed_decoded_inst_get_base_reg(&xedd,0);
    if (base_reg != XED_REG_RIP) return 0;

    xed_int64_t disp = xed_decoded_inst_get_memory_displacement(&xedd,0);
    unsigned int orig_size = xed_decoded_inst_get_length(&xedd);
    
    xed_int64_t new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size;
    xed_uint_t new_disp_byts = 4;

    xed_encoder_request_init_from_decode(&xedd);
    xed_encoder_request_set_base0(&xedd, XED_REG_INVALID);
    xed_encoder_request_set_memory_displacement(&xedd, new_disp, new_disp_byts);
    
    unsigned int new_size = 0;
    xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), XED_MAX_INSTRUCTION_BYTES, &new_size);
    if (xed_error != XED_ERROR_NONE) return -1;

    return new_size;
}

/**************************************/
/* fix_direct_br_or_call_displacement */
/**************************************/
int fix_direct_br_or_call_displacement(int instr_map_entry)
{
    if (instr_map[instr_map_entry].size == 0 || instr_map[instr_map_entry].orig_targ_addr == 0)
        return 0;

    if (instr_map[instr_map_entry].targ_map_entry < 0) return 0; // External branch

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);
    xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);

    ADDRINT new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;
    xed_int64_t new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + instr_map[instr_map_entry].size);

    xed_encoder_request_init_from_decode(&xedd);
    xed_encoder_request_set_branch_displacement(&xedd, new_disp, 4);

    unsigned int new_size = 0;
    xed_encode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), XED_MAX_INSTRUCTION_BYTES, &new_size);
    
    return new_size;
}


/************************************/
/* fix_instructions_displacements() */
/************************************/
int fix_instructions_displacements()
{
    int size_diff;
    do {
        size_diff = 0;
        for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
            instr_map[i].new_ins_addr += size_diff;

            int new_size = fix_rip_displacement(i);
            if (new_size > 0 && (unsigned int)new_size != instr_map[i].size) {
                size_diff += (new_size - instr_map[i].size);
                instr_map[i].size = new_size;
            }

            new_size = fix_direct_br_or_call_displacement(i);
            if (new_size > 0 && (unsigned int)new_size != instr_map[i].size) {
                size_diff += (new_size - instr_map[i].size);
                instr_map[i].size = new_size;
            }
        }
    } while (size_diff != 0);
    return 0;
}


/*****************************************/
/* find_candidate_rtns_for_translation() */
/*****************************************/
int find_candidate_rtns_for_translation(IMG img)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
            continue;

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            if (rtn == RTN_Invalid()) continue;
            RTN_Open(rtn);

            for (BBL bbl = RTN_BblHead(rtn); BBL_Valid(bbl); bbl = BBL_Next(bbl))
            {
                ADDRINT bbl_addr = BBL_Address(bbl);
                if (addr_to_bbl_num.find(bbl_addr) == addr_to_bbl_num.end())
                {
                    if (bbl_total >= MAX_BBL_NUM) continue;
                    addr_to_bbl_num[bbl_addr] = bbl_total;
                    bbl_addr_map[bbl_total] = bbl_addr;
                    bbl_num_map[bbl_total] = bbl_total;
                    bbl_total++;
                }
                unsigned int current_bbl_num = addr_to_bbl_num[bbl_addr];

                // Instrument BBL execution count
                xed_encoder_instruction_t enc_instr;
                xed_encoder_request_t enc_req;
                char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
                unsigned int olen = 0;
                
                // inc qword ptr [bbl_exec_count + current_bbl_num*8]
                xed_inst1(&enc_instr, dstate, XED_ICLASS_INC, 64, xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&bbl_exec_count[current_bbl_num], 64), 64));
                xed_encoder_request_zero_set_mode(&enc_req, &dstate);
                xed_convert_to_encoder_request(&enc_req, &enc_instr);
                xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen);
                xed_decoded_inst_t xedd_inc;
                xed_decode(&xedd_inc, reinterpret_cast<UINT8*>(encoded_ins), olen);
                add_new_instr_entry(&xedd_inc, 0, olen, false, true, current_bbl_num);


                for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
                {
                    xed_decoded_inst_t xedd;
                    xed_decode(&xedd, reinterpret_cast<const UINT8*>(INS_Address(ins)), INS_Size(ins));

                    if (INS_IsIndirectControlFlow(ins) && !INS_IsRet(ins) && !INS_IsCall(ins))
                    {
                        // Save registers
                        add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins), false, false, current_bbl_num, true);
                        
                        // Save RAX, RBX, RCX
                        xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64), xed_reg(XED_REG_RAX));
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate); xed_convert_to_encoder_request(&enc_req, &enc_instr);
                        xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen); xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
                        add_new_instr_entry(&xedd, 0, olen, false, false, 0);
                        
                        save_reg(XED_REG_RBX, (ADDRINT)&rbx_mem);
                        save_reg(XED_REG_RCX, (ADDRINT)&rcx_mem);
                        
                        // Convert jmp to MOV RAX, target
                        xed_decoded_inst_t* xedd_orig = INS_XedDec(ins);
                        xed_reg_enum_t base_reg = xed_decoded_inst_get_base_reg(xedd_orig, 0);
                        xed_reg_enum_t index_reg = xed_decoded_inst_get_index_reg(xedd_orig, 0);
                        xed_int64_t disp = xed_decoded_inst_get_memory_displacement(xedd_orig, 0);
                        xed_uint_t scale = xed_decoded_inst_get_scale(xedd_orig, 0);
                        
                        xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RAX), xed_mem_bisd(base_reg, index_reg, scale, xed_disp(disp, 32), 64));
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate); xed_convert_to_encoder_request(&enc_req, &enc_instr);
                        xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen); xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
                        add_new_instr_entry(&xedd, 0, olen, false, false, 0);

                        // MOV RBX, RAX
                        xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RBX), xed_reg(XED_REG_RAX));
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate); xed_convert_to_encoder_request(&enc_req, &enc_instr);
                        xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen); xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
                        add_new_instr_entry(&xedd, 0, olen, false, false, 0);

                        // AND RAX, 3
                        xed_inst2(&enc_instr, dstate, XED_ICLASS_AND, 64, xed_reg(XED_REG_RAX), xed_imm0(3, 8));
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate); xed_convert_to_encoder_request(&enc_req, &enc_instr);
                        xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen); xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
                        add_new_instr_entry(&xedd, 0, olen, false, false, 0);

                        // MOV RCX, &indirect_targets[bbl_num][0]
                        xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RCX), xed_imm0((UINT64)&indirect_targets[current_bbl_num][0], 64));
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate); xed_convert_to_encoder_request(&enc_req, &enc_instr);
                        xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen); xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
                        add_new_instr_entry(&xedd, 0, olen, false, false, 0);

                        // MOV [RCX + RAX*8], RBX
                        xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_mem_bisd(XED_REG_RCX, XED_REG_RAX, 8, xed_disp(0, 32), 64), xed_reg(XED_REG_RBX));
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate); xed_convert_to_encoder_request(&enc_req, &enc_instr);
                        xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen); xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
                        add_new_instr_entry(&xedd, 0, olen, false, false, 0);
                        
                        // Increment count
                        // MOV RCX, &indirect_counts[bbl_num][0]
                         xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RCX), xed_imm0((UINT64)&indirect_counts[current_bbl_num][0], 64));
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate); xed_convert_to_encoder_request(&enc_req, &enc_instr);
                        xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen); xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
                        add_new_instr_entry(&xedd, 0, olen, false, false, 0);
                        
                        // inc qword ptr [RCX + RAX*8]
                        xed_inst1(&enc_instr, dstate, XED_ICLASS_INC, 64, xed_mem_bisd(XED_REG_RCX, XED_REG_RAX, 8, xed_disp(0, 32), 64));
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate); xed_convert_to_encoder_request(&enc_req, &enc_instr);
                        xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen); xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
                        add_new_instr_entry(&xedd, 0, olen, false, false, 0);

                        // Restore registers
                        restore_reg(XED_REG_RCX, (ADDRINT)&rcx_mem);
                        restore_reg(XED_REG_RBX, (ADDRINT)&rbx_mem);
                        xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RAX), xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64));
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate); xed_convert_to_encoder_request(&enc_req, &enc_instr);
                        xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen); xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), olen);
                        add_new_instr_entry(&xedd, 0, olen, false, false, 0);
                    }
                    else
                    {
                         add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins), (RTN_Address(rtn) == INS_Address(ins)), false, current_bbl_num);
                    }
                }
                
                // Instrument taken/fall-through
                INS last_ins = BBL_InsTail(bbl);
                if(INS_IsDirectControlFlow(last_ins) && INS_HasFallThrough(last_ins)) {
                    // Instrument taken
                    xed_inst1(&enc_instr, dstate, XED_ICLASS_INC, 64, xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&taken_count[current_bbl_num], 64), 64));
                    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
                    xed_convert_to_encoder_request(&enc_req, &enc_instr);
                    xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen);
                    xed_decoded_inst_t xedd_taken;
                    xed_decode(&xedd_taken, reinterpret_cast<UINT8*>(encoded_ins), olen);
                    // Insert before the branch
                    num_of_instr_map_entries--;
                    add_new_instr_entry(&xedd_taken, 0, olen, false, false, 0);
                    add_new_instr_entry(INS_XedDec(last_ins), INS_Address(last_ins), INS_Size(last_ins), false, false, current_bbl_num);


                    // Instrument fall-through
                    xed_inst1(&enc_instr, dstate, XED_ICLASS_INC, 64, xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&fallthru_count[current_bbl_num], 64), 64));
                     xed_encoder_request_zero_set_mode(&enc_req, &dstate);
                    xed_convert_to_encoder_request(&enc_req, &enc_instr);
                    xed_encode(&enc_req, reinterpret_cast<UINT8*>(encoded_ins), sizeof(encoded_ins), &olen);
                    xed_decoded_inst_t xedd_fall;
                    xed_decode(&xedd_fall, reinterpret_cast<UINT8*>(encoded_ins), olen);
                    add_new_instr_entry(&xedd_fall, 0, olen, false, false, 0);
                }
            }
            RTN_Close(rtn);
        }
    }
    return 0;
}

/***************************/
/* int copy_instrs_to_tc() */
/***************************/
int copy_instrs_to_tc()
{
    int cursor = 0;
    for (unsigned i=0; i < num_of_instr_map_entries; i++) {
      if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
          return -1;
      }
      memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);
      cursor += instr_map[i].size;
    }
    return 0;
}


/*************************************/
/* void commit_translated_routines() */
/*************************************/
inline void commit_translated_routines()
{
    for (unsigned i=0; i < num_of_instr_map_entries; i++) {
        if (!instr_map[i].isRtnHead) continue;
        RTN rtn = RTN_FindByAddress(instr_map[i].orig_ins_addr);
        if (RTN_Valid(rtn) && RTN_IsSafeForProbedReplacement(rtn)) {
            RTN_ReplaceProbed(rtn, (AFUNPTR)instr_map[i].new_ins_addr);
        }
    }
}


/****************************/
/* allocate_and_init_memory */
/****************************/
int allocate_and_init_memory(IMG img)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
            continue;
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            max_ins_count += RTN_NumIns(rtn);
        }
    }

    max_ins_count *= 20;

    instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
    if (instr_map == NULL) return -1;

    int pagesize = sysconf(_SC_PAGE_SIZE);
    unsigned tclen = 20 * (highest_sec_addr - lowest_sec_addr) + pagesize;
    tc = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (tc == MAP_FAILED) return -1;
    
    return 0;
}


/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
typedef VOID (*EXITFUNCPTR)(INT code);
EXITFUNCPTR origExit;


// Data structure for final output
struct BBL_DATA {
    ADDRINT address;
    uint64_t exec_count;
    uint64_t taken;
    uint64_t fallthru;
    vector<pair<uint64_t, uint64_t>> indirects;
};

// Comparison function for sorting
bool compare_bbl_data(const BBL_DATA& a, const BBL_DATA& b) {
    return a.exec_count > b.exec_count;
}

VOID Fini(INT32 code, VOID* v)
{
    outfile.open("ex4.csv");
    vector<BBL_DATA> bbl_data_list;

    for (unsigned i = 0; i < bbl_total; ++i) {
        if (bbl_exec_count[i] > 0) {
            BBL_DATA data;
            data.address = bbl_addr_map[i];
            data.exec_count = bbl_exec_count[i];
            data.taken = taken_count[i];
            data.fallthru = fallthru_count[i];
            
            for(int j=0; j<4; ++j) {
                if(indirect_counts[i][j] > 0) {
                    data.indirects.push_back({indirect_targets[i][j], indirect_counts[i][j]});
                }
            }
            bbl_data_list.push_back(data);
        }
    }

    sort(bbl_data_list.begin(), bbl_data_list.end(), compare_bbl_data);
    
    for(const auto& data : bbl_data_list) {
        outfile << "0x" << hex << data.address << ", "
                << dec << data.exec_count << ", "
                << data.taken << ", "
                << data.fallthru;
        for(const auto& indirect : data.indirects) {
            outfile << ", 0x" << hex << indirect.first << ", " << dec << indirect.second;
        }
        outfile << endl;
    }

    outfile.close();
}

VOID ExitInProbeMode(INT code)
{
    Fini(code, 0);
    (*origExit)(code);
}

VOID ImageLoad(IMG img, VOID *v)
{   
    if (!IMG_IsMainExecutable(img)) return;

    RTN exitRtn = RTN_FindByName(img, "_exit");
    if (RTN_Valid(exitRtn) && RTN_IsSafeForProbedReplacement(exitRtn)) {
      origExit = (EXITFUNCPTR)RTN_ReplaceProbed(exitRtn, AFUNPTR(ExitInProbeMode));
    }
    
    if (allocate_and_init_memory(img) < 0) return;
    if (find_candidate_rtns_for_translation(img) < 0) return;
    chain_all_direct_br_and_call_target_entries();
    set_estimated_new_ins_addrs_in_tc();
    if (fix_instructions_displacements() < 0) return;
    set_estimated_new_ins_addrs_in_tc(); // Recalculate addresses after fixing
    if (copy_instrs_to_tc() < 0) return;
    if (!KnobDoNotCommitTranslatedCode) {
      commit_translated_routines();
    }
}



/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool translated routines of an Intel(R) 64 binary" << endl;
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    if( PIN_Init(argc,argv) ) return Usage();
    PIN_InitSymbols();
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgramProbed();
    return 0;
}