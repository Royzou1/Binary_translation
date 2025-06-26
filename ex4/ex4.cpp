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

// Profiling data structures
static uint64_t bbl_exec_count[MAX_BBL_NUM] = {0};
static uint64_t taken_count[MAX_BBL_NUM] = {0};
static uint64_t fallthru_count[MAX_BBL_NUM] = {0};
static uint64_t indirect_targets[MAX_BBL_NUM][4] = {{0}};
static uint64_t indirect_counts[MAX_BBL_NUM][4] = {{0}};
static uint64_t rax_mem, rbx_mem, rcx_mem; // For saving registers

static ADDRINT bbl_addr_map[MAX_BBL_NUM] = {0};
static unsigned bbl_total = 0;
std::map<ADDRINT, unsigned> addr_to_bbl_num;

using namespace std;

std::ofstream outfile;

/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE, "pintool", "verbose", "0", "Verbose run");
KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE, "pintool", "dump_tc", "0", "Dump Translated Code");
KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE, "pintool", "no_tc_commit", "0", "Do not commit translated code");

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
#if defined(TARGET_IA32E)
xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
xed_state_t dstate = {XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;
char *tc;
unsigned tc_cursor = 0;

typedef struct {
    ADDRINT orig_ins_addr;
    ADDRINT new_ins_addr;
    ADDRINT orig_targ_addr;
    bool isRtnHead;
    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
    unsigned int size;
    int targ_map_entry;
} instr_map_t;

instr_map_t *instr_map = NULL;
unsigned num_of_instr_map_entries = 0;
unsigned max_ins_count = 0;
std::map<ADDRINT, unsigned> entry_map;

/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size, bool isRtnHead) {
    ADDRINT orig_targ_addr = 0x0;
    if (xed_decoded_inst_get_length(xedd) != size && pc != 0) {
        return -1;
    }
    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);
    if (disp_byts > 0) {
        xed_int32_t disp = xed_decoded_inst_get_branch_displacement(xedd);
        orig_targ_addr = pc + xed_decoded_inst_get_length(xedd) + disp;
    }

    xed_encoder_request_init_from_decode(xedd);
    unsigned int new_size = 0;
    xed_encode(xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len, &new_size);
    
    instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
    instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr;
    instr_map[num_of_instr_map_entries].targ_map_entry = -1;
    instr_map[num_of_instr_map_entries].size = new_size;
    instr_map[num_of_instr_map_entries].isRtnHead = isRtnHead;
    num_of_instr_map_entries++;

    if (num_of_instr_map_entries >= max_ins_count) return -1;
    return new_size;
}

void add_encoded_instr(xed_encoder_instruction_t* enc_instr, ADDRINT pc = 0) {
    xed_encoder_request_t enc_req;
    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_convert_to_encoder_request(&enc_req, enc_instr);
    
    unsigned int new_size = 0;
    xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len, &new_size);

    instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
    instr_map[num_of_instr_map_entries].orig_targ_addr = 0;
    instr_map[num_of_instr_map_entries].targ_map_entry = -1;
    instr_map[num_of_instr_map_entries].size = new_size;
    instr_map[num_of_instr_map_entries].isRtnHead = false;
    num_of_instr_map_entries++;
}


void chain_all_direct_br_and_call_target_entries(unsigned from_entry, unsigned until_entry) {
    entry_map.clear();
    for (unsigned i = from_entry; i < until_entry; i++) {
        ADDRINT orig_ins_addr = instr_map[i].orig_ins_addr;
        if (orig_ins_addr) {
            entry_map.emplace(orig_ins_addr, i);
        }
    }
    for (unsigned i = from_entry; i < until_entry; i++) {
        ADDRINT orig_targ_addr = instr_map[i].orig_targ_addr;
        if (orig_targ_addr != 0 && entry_map.count(orig_targ_addr)) {
            instr_map[i].targ_map_entry = entry_map[orig_targ_addr];
        }
    }
}

void set_estimated_new_ins_addrs_in_tc() {
    tc_cursor = 0;
    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
        instr_map[i].new_ins_addr = (ADDRINT)&tc[tc_cursor];
        tc_cursor += instr_map[i].size;
    }
}

int fix_rip_displacement(int instr_map_entry)
{
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);
    xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);

    if (instr_map[instr_map_entry].orig_targ_addr != 0) return 0;
    unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);
    if(memops == 0 || xed_decoded_inst_get_base_reg(&xedd,0) != XED_REG_RIP) return 0;

    xed_int64_t disp = xed_decoded_inst_get_memory_displacement(&xedd,0);
    xed_decoded_inst_t xedd_orig;
    xed_decoded_inst_zero_set_mode(&xedd_orig, &dstate);
    xed_decode(&xedd_orig, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].orig_ins_addr), max_inst_len);
    unsigned int orig_size = xed_decoded_inst_get_length(&xedd_orig);
    xed_int64_t new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size;

    xed_encoder_request_init_from_decode(&xedd);
    xed_encoder_request_set_base0(&xedd, XED_REG_INVALID);
    xed_encoder_request_set_memory_displacement(&xedd, new_disp, 4);

    unsigned int new_size = 0;
    xed_encode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), XED_MAX_INSTRUCTION_BYTES, &new_size);
    return new_size;
}

int fix_direct_br_or_call_displacement(int instr_map_entry)
{
    if (instr_map[instr_map_entry].size == 0 || instr_map[instr_map_entry].orig_targ_addr == 0 || instr_map[instr_map_entry].targ_map_entry < 0)
        return 0;

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

int fix_instructions_displacements() {
    int size_diff;
    do {
        size_diff = 0;
        set_estimated_new_ins_addrs_in_tc();
        for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
            int old_size = instr_map[i].size;
            int new_size = old_size;
            int rip_new_size = fix_rip_displacement(i);
            if (rip_new_size > 0) new_size = rip_new_size;
            int br_new_size = fix_direct_br_or_call_displacement(i);
            if (br_new_size > 0) new_size = br_new_size;
            if (new_size != old_size) {
                instr_map[i].size = new_size;
                size_diff += (new_size - old_size);
            }
        }
    } while (size_diff != 0);
    set_estimated_new_ins_addrs_in_tc();
    return 0;
}


int copy_instrs_to_tc() {
    int cursor = 0;
    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
        if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) return -1;
        memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);
        cursor += instr_map[i].size;
    }
    return 0;
}

void commit_translated_routines() {
    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
        if (!instr_map[i].isRtnHead) continue;
        RTN rtn = RTN_FindByAddress(instr_map[i].orig_ins_addr);
        if (RTN_Valid(rtn) && RTN_IsSafeForProbedReplacement(rtn)) {
            RTN_ReplaceProbed(rtn, (AFUNPTR)instr_map[i].new_ins_addr);
        }
    }
}

// Main instrumentation function
VOID ImageLoad(IMG img, VOID *v) {
    if (!IMG_IsMainExecutable(img)) return;

    // Allocate memory once
    max_ins_count = 0;
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        if (!SEC_IsExecutable(sec)) continue;
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            max_ins_count += RTN_NumIns(rtn);
        }
    }
    max_ins_count *= 15; // Heuristic for instrumentation overhead
    instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
    unsigned tclen = max_ins_count * 15; // Max instruction length
    tc = (char *)mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    // Instrument routines
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        if (!SEC_IsExecutable(sec)) continue;
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            RTN_Open(rtn);
            unsigned rtn_entry = num_of_instr_map_entries;
            INS prev_ins = INS_Invalid();

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
                ADDRINT ins_addr = INS_Address(ins);
                bool is_bbl_head = !INS_Valid(prev_ins) || INS_IsControlFlow(prev_ins);
                unsigned int current_bbl_num = 0;

                if (is_bbl_head) {
                    if (addr_to_bbl_num.find(ins_addr) == addr_to_bbl_num.end()) {
                        if (bbl_total < MAX_BBL_NUM) {
                            addr_to_bbl_num[ins_addr] = bbl_total;
                            bbl_addr_map[bbl_total] = ins_addr;
                            bbl_total++;
                        }
                    }
                    current_bbl_num = addr_to_bbl_num[ins_addr];
                    
                    xed_encoder_instruction_t enc_instr;
                    xed_inst1(&enc_instr, dstate, XED_ICLASS_INC, 64, xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&bbl_exec_count[current_bbl_num], 64), 64));
                    add_encoded_instr(&enc_instr, 0);
                }

                if (INS_IsBranch(ins) && INS_IsConditional(ins) && INS_HasFallThrough(ins)) {
                    xed_encoder_instruction_t enc_instr;
                    xed_inst1(&enc_instr, dstate, XED_ICLASS_INC, 64, xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&taken_count[current_bbl_num], 64), 64));
                    add_encoded_instr(&enc_instr, 0);
                }

                if (INS_IsIndirectControlFlow(ins) && !INS_IsRet(ins) && !INS_IsCall(ins)) {
                    xed_encoder_instruction_t enc_instr;
                    // Save registers
                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64), xed_reg(XED_REG_RAX)); add_encoded_instr(&enc_instr);
                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rbx_mem, 64), 64), xed_reg(XED_REG_RBX)); add_encoded_instr(&enc_instr);
                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rcx_mem, 64), 64), xed_reg(XED_REG_RCX)); add_encoded_instr(&enc_instr);

                    // Convert jmp to mov rax, target
                    xed_decoded_inst_t* xedd_jmp = INS_XedDec(ins);
                    unsigned int memops = xed_decoded_inst_number_of_memory_operands(xedd_jmp);
                    
                    if (memops == 0) { // Register-based jump
                        xed_reg_enum_t targ_reg = xed_decoded_inst_get_reg(xedd_jmp, XED_OPERAND_REG0);
                        xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RAX), xed_reg(targ_reg));
                    } else { // Memory-based jump
                        xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd_jmp, 0);
                        xed_reg_enum_t index = xed_decoded_inst_get_index_reg(xedd_jmp, 0);
                        xed_uint_t scale = xed_decoded_inst_get_scale(xedd_jmp, 0);
                        xed_int64_t disp = xed_decoded_inst_get_memory_displacement(xedd_jmp, 0);
                        xed_uint_t disp_width = xed_decoded_inst_get_memory_displacement_width_bits(xedd_jmp, 0);
                        xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RAX), xed_mem_bisd(base, index, scale, xed_disp(disp, disp_width), 64));
                    }
                    add_encoded_instr(&enc_instr);

                    // Profile target in RAX
                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RBX), xed_reg(XED_REG_RAX)); add_encoded_instr(&enc_instr); // rbx = target
                    xed_inst2(&enc_instr, dstate, XED_ICLASS_AND, 64, xed_reg(XED_REG_RAX), xed_imm0(3, 8)); add_encoded_instr(&enc_instr); // rax = index (0-3)
                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RCX), xed_imm0((UINT64)&indirect_targets[current_bbl_num][0], 64)); add_encoded_instr(&enc_instr);
                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_mem_bisd(XED_REG_RCX, XED_REG_RAX, 8, xed_disp(0, 32), 64), xed_reg(XED_REG_RBX)); add_encoded_instr(&enc_instr);
                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RCX), xed_imm0((UINT64)&indirect_counts[current_bbl_num][0], 64)); add_encoded_instr(&enc_instr);
                    xed_inst1(&enc_instr, dstate, XED_ICLASS_INC, 64, xed_mem_bisd(XED_REG_RCX, XED_REG_RAX, 8, xed_disp(0, 32), 64)); add_encoded_instr(&enc_instr);

                    // Restore registers
                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RCX), xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rcx_mem, 64), 64)); add_encoded_instr(&enc_instr);
                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RBX), xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rbx_mem, 64), 64)); add_encoded_instr(&enc_instr);
                    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(XED_REG_RAX), xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64)); add_encoded_instr(&enc_instr);
                    
                    // Final jump (to the saved target address now in RAX)
                    xed_inst1(&enc_instr, dstate, XED_ICLASS_JMP, 64, xed_reg(XED_REG_RAX)); add_encoded_instr(&enc_instr);

                } else {
                    // Add original instruction if it's not the special indirect jump
                    xed_decoded_inst_t xedd;
                    xed_decode(&xedd, reinterpret_cast<const UINT8*>(ins_addr), INS_Size(ins));
                    add_new_instr_entry(&xedd, ins_addr, INS_Size(ins), RTN_Address(rtn) == ins_addr);
                }
                
                // Add fall-through instrumentation
                if (INS_IsBranch(ins) && INS_IsConditional(ins) && INS_HasFallThrough(ins)) {
                     xed_encoder_instruction_t enc_instr;
                     xed_inst1(&enc_instr, dstate, XED_ICLASS_INC, 64, xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&fallthru_count[current_bbl_num], 64), 64));
                     add_encoded_instr(&enc_instr, 0);
                }
                prev_ins = ins;
            }
            RTN_Close(rtn);
            chain_all_direct_br_and_call_target_entries(rtn_entry, num_of_instr_map_entries);
        }
    }
    
    // After all routines are processed, fix displacements and commit
    fix_instructions_displacements();
    copy_instrs_to_tc();
    if (!KnobDoNotCommitTranslatedCode) {
        commit_translated_routines();
    }
}


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

VOID Fini(INT32 code, VOID* v) {
    outfile.open("bb-profile.csv");
    vector<BBL_DATA> bbl_data_list;

    for (unsigned i = 0; i < bbl_total; ++i) {
        if (bbl_exec_count[i] > 0) {
            BBL_DATA data;
            data.address = bbl_addr_map[i];
            data.exec_count = bbl_exec_count[i];
            data.taken = taken_count[i];
            data.fallthru = fallthru_count[i];
            for (int j = 0; j < 4; ++j) {
                if (indirect_counts[i][j] > 0) {
                    data.indirects.push_back({indirect_targets[i][j], indirect_counts[i][j]});
                }
            }
            bbl_data_list.push_back(data);
        }
    }

    sort(bbl_data_list.begin(), bbl_data_list.end(), compare_bbl_data);
    
    for (const auto& data : bbl_data_list) {
        outfile << "0x" << hex << data.address << ", "
                << dec << data.exec_count << ", "
                << data.taken << ", "
                << data.fallthru;
        for (const auto& entry : data.indirects) {
            outfile << ", 0x" << hex << entry.first << ", " << dec << entry.second;
        }
        outfile << endl;
    }
    outfile.close();
}

INT32 Usage() {
    cerr << "This tool profiles basic blocks and translates routines of an Intel(R) 64 binary" << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgramProbed();
    return 0;
}