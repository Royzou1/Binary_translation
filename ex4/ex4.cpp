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
static unsigned bbl_total = 0;
std::map<ADDRINT, unsigned> addr_to_bbl_num;

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
// For XED:
#if defined(TARGET_IA32E)
    xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

// tc containing the new code:
char *tc;
unsigned tc_cursor = 0;

// instruction map with an entry for each new instruction:
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

// Map of all instructions to be used for chaining.
std::map<ADDRINT, unsigned> entry_map;

/* ============================================================= */
/* Analysis routines                                             */
/* ============================================================= */

VOID CountBbl(UINT32 bbl_num) {
    bbl_exec_count[bbl_num]++;
}

VOID CountTaken(UINT32 bbl_num) {
    taken_count[bbl_num]++;
}

VOID CountFallthrough(UINT32 bbl_num) {
    fallthru_count[bbl_num]++;
}

VOID RecordIndirect(UINT32 bbl_num, ADDRINT target_addr) {
    for (int i = 0; i < 4; i++) {
        if (indirect_targets[bbl_num][i] == target_addr || indirect_targets[bbl_num][i] == 0) {
            indirect_targets[bbl_num][i] = target_addr;
            indirect_counts[bbl_num][i]++;
            return;
        }
    }
    // If all slots are full, find the least frequent one to replace.
    UINT64 min_count = indirect_counts[bbl_num][0];
    int min_idx = 0;
    for (int i = 1; i < 4; i++) {
        if (indirect_counts[bbl_num][i] < min_count) {
            min_count = indirect_counts[bbl_num][i];
            min_idx = i;
        }
    }
    indirect_targets[bbl_num][min_idx] = target_addr;
    indirect_counts[bbl_num][min_idx] = 1;
}


/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */

/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size, bool isRtnHead)
{
    ADDRINT orig_targ_addr = 0x0;

    if (xed_decoded_inst_get_length (xedd) != size) {
        cerr << "Invalid instruction decoding" << endl;
        return -1;
    }

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);
    if (disp_byts > 0) {
      xed_int32_t disp = xed_decoded_inst_get_branch_displacement(xedd);
      orig_targ_addr = pc + xed_decoded_inst_get_length (xedd) + disp;
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

    num_of_instr_map_entries++;

    if (num_of_instr_map_entries >= max_ins_count) {
        cerr << "out of memory for map_instr" << endl;
        return -1;
    }

    return new_size;
}

/*************************************************/
/* chain_all_direct_br_and_call_target_entries() */
/*************************************************/
void chain_all_direct_br_and_call_target_entries(unsigned from_entry,
                                                 unsigned until_entry)
{
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
    xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);

    if (instr_map[instr_map_entry].orig_targ_addr != 0) return 0;

    unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);
    if(memops == 0 || xed_decoded_inst_get_base_reg(&xedd,0) != XED_REG_RIP) return 0;

    xed_int64_t disp = xed_decoded_inst_get_memory_displacement(&xedd,0);

    // To get original size, we need to decode original instruction
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

/**************************************/
/* fix_direct_br_or_call_displacement */
/**************************************/
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

/************************************/
/* fix_instructions_displacements() */
/************************************/
int fix_instructions_displacements()
{
    int size_diff;
    do {
        size_diff = 0;
        set_estimated_new_ins_addrs_in_tc();

        for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
            int old_size = instr_map[i].size;
            int new_size = old_size;

            int rip_new_size = fix_rip_displacement(i);
            if (rip_new_size > 0 && (unsigned int)rip_new_size != instr_map[i].size) {
                new_size = rip_new_size;
            }

            int br_new_size = fix_direct_br_or_call_displacement(i);
            if (br_new_size > 0 && (unsigned int)br_new_size != instr_map[i].size) {
                new_size = br_new_size;
            }

            if(new_size != old_size){
                instr_map[i].size = new_size;
                size_diff += (new_size - old_size);
            }
        }
    } while (size_diff != 0);
    set_estimated_new_ins_addrs_in_tc();
    return 0;
}


/*****************************************/
/* find_candidate_rtns_for_translation() */
/*****************************************/
VOID find_candidate_rtns_for_translation(RTN rtn, VOID *v)
{
    if (RTN_Invalid() == rtn) return;

    RTN_Open(rtn);

    unsigned rtn_entry = num_of_instr_map_entries;

    for (BBL bbl = RTN_BblHead(rtn); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        ADDRINT bbl_addr = BBL_Address(bbl);
        if (addr_to_bbl_num.find(bbl_addr) == addr_to_bbl_num.end()) {
            if (bbl_total >= MAX_BBL_NUM) {
                // If we are out of space, we can't profile this BBL.
                // We should also not translate it to avoid inconsistency.
                continue;
            }
            addr_to_bbl_num[bbl_addr] = bbl_total;
            bbl_addr_map[bbl_total] = bbl_addr;
            bbl_total++;
        }
        UINT32 current_bbl_num = addr_to_bbl_num[bbl_addr];

        INS head = BBL_InsHead(bbl);
        INS_InsertCall(head, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, current_bbl_num, IARG_END);

        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            xed_decoded_inst_t xedd;
            xed_decode(&xedd, reinterpret_cast<const UINT8*>(INS_Address(ins)), INS_Size(ins));
            add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins), (RTN_Address(rtn) == INS_Address(ins)));
        }

        INS tail = BBL_InsTail(bbl);
        if (INS_IsConditionalBranch(tail)) {
            INS_InsertCall(tail, IPOINT_TAKEN_BRANCH, (AFUNPTR)CountTaken, IARG_UINT32, current_bbl_num, IARG_END);
            INS_InsertCall(tail, IPOINT_AFTER, (AFUNPTR)CountFallthrough, IARG_UINT32, current_bbl_num, IARG_END);
        }

        if (INS_IsIndirectControlFlow(tail) && !INS_IsRet(tail) && !INS_IsCall(tail)) { // [cite: 4]
            INS_InsertCall(tail, IPOINT_BEFORE, (AFUNPTR)RecordIndirect,
                           IARG_UINT32, current_bbl_num,
                           IARG_BRANCH_TARGET_ADDR,
                           IARG_END);
        }
    }
    RTN_Close(rtn);
    chain_all_direct_br_and_call_target_entries(rtn_entry, num_of_instr_map_entries);
}

/***************************/
/* int copy_instrs_to_tc() */
/***************************/
int copy_instrs_to_tc()
{
    int cursor = 0;
    for (unsigned i=0; i < num_of_instr_map_entries; i++) {
      if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
          cerr << "ERROR: Non-matching instruction addresses: "
               << hex << (ADDRINT)&tc[cursor]
               << " vs. " << instr_map[i].new_ins_addr << endl;
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
            AFUNPTR new_fun = (AFUNPTR)instr_map[i].new_ins_addr;
            if (RTN_ReplaceProbed(rtn, new_fun) == NULL) {
                cerr << "RTN_ReplaceProbed failed for " << RTN_Name(rtn) << endl;
            }
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
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec)) continue;
        if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
            lowest_sec_addr = SEC_Address(sec);
        if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
            highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            max_ins_count += RTN_NumIns(rtn);
        }
    }

    max_ins_count *= 2; // Estimate for new instructions

    instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
    if (instr_map == NULL) return -1;

    int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) return -1;

    ADDRINT text_size = highest_sec_addr - lowest_sec_addr;
    unsigned tclen = 3 * text_size + pagesize;
    tc = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (tc == MAP_FAILED) return -1;

    return 0;
}


/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
typedef VOID (*EXITFUNCPTR)(INT32 code, VOID *v);
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
    outfile.open("bb-profile.csv");
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
                    // Check for duplicates before adding
                    bool found = false;
                    for(auto const& [addr, count] : data.indirects) {
                        if (addr == indirect_targets[i][j]) {
                            found = true;
                            break;
                        }
                    }
                    if(!found) {
                       data.indirects.push_back({indirect_targets[i][j], indirect_counts[i][j]});
                    }
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


VOID ImageLoad(IMG img, VOID *v)
{
    if (!IMG_IsMainExecutable(img)) return;

    // We will use a Fini function to handle program exit, so replacing _exit is not needed in probe mode
    // unless we need to do something very specific before the application's own _exit runs.
    // PIN_AddFiniFunction is generally safer.

    if (allocate_and_init_memory(img) < 0) {
        cerr << "failed to initialize memory for translation\n";
        return;
    }

    // Use RTN_AddInstrumentFunction to instrument routines as they are discovered
    RTN_AddInstrumentFunction(find_candidate_rtns_for_translation, 0);
}

VOID AppStart(VOID *v)
{
    // Now that all routines are instrumented and mapped, perform the translation steps
    if (fix_instructions_displacements() < 0) {
        cerr << "failed to fix displacements of translated instructions\n";
        return;
    }

    if (copy_instrs_to_tc() < 0) {
        cerr << "failed to copy the instructions to the translation cache\n";
        return;
    }

    if (!KnobDoNotCommitTranslatedCode) {
      commit_translated_routines();
    }
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool profiles basic blocks and translates routines of an Intel(R) 64 binary" << endl;
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

    // Register a function to be called when the application starts.
    // This is where we will do the final code translation after all routines have been seen.
    PIN_AddApplicationStartFunction(AppStart, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgramProbed();

    return 0;
}