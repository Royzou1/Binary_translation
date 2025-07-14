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
#define MAX_TARG 4 //up to 4 targets for each indirect jumps for each basic block

static uint64_t bb_map_targ_addr[MAX_BBL_NUM][MAX_TARG]={0};
static uint64_t bb_map_targ_count[MAX_BBL_NUM][MAX_TARG]={0};
static uint64_t bb_map_fall_count[MAX_BBL_NUM]={0};
static bool isPrevInsTerminates = false;

static uint64_t bb_map_mem[MAX_BBL_NUM] = {0}; 
static ADDRINT bb_addr_mem[MAX_BBL_NUM] = {0};
static unsigned bbl_num = 0;

using namespace std;

std::ofstream outfile;

// Data structure to store basic block counts
std::map<ADDRINT, UINT64> bbl_counts;


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

//For XED: Pass in the proper length: 15 is the max. But if you do not want to
//cross pages, you can pass less than 15 bytes, of course, the
//instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

#define MAX_PROBE_JUMP_INSTR_BYTES  14

// tc containing the new code:
char *tc;
unsigned tc_cursor = 0;


// Array of original target addresses that cannot
// be relocated in the TC.
ADDRINT *jump_to_orig_addr_map = nullptr;
unsigned jump_to_orig_addr_num = 0;

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
/* Service dump routines                                         */
/* ============================================================= */

/*************************/
/* dump_all_image_instrs */
/*************************/
void dump_all_image_instrs(IMG img)
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
      return;
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
      if (!instr_map[i].isRtnHead)
        continue;
      RTN rtn = RTN_FindByAddress(instr_map[i].orig_ins_addr);
      if (rtn == RTN_Invalid()) {
          cerr << "Unknwon"  << ":" << endl;
      } else {
        cerr << RTN_Name(rtn) << ":" << endl;
      }
      dump_instr_from_mem ((ADDRINT *)instr_map[i].new_ins_addr, instr_map[i].new_ins_addr);
    }
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


/*************/
/* dump_tc() */
/*************/
void dump_tc()
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;
  ADDRINT address = (ADDRINT)&tc[0];
  unsigned int size = 0;

  while (address < (ADDRINT)&tc[tc_cursor]) {

      address += size;

      xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);

      xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);

      BOOL xed_ok = (xed_code == XED_ERROR_NONE);
      if (!xed_ok){
          cerr << "invalid opcode" << endl;
          return;
      }

      xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(address), 0, 0);

      cerr << "0x" << hex << address << ": " << disasm_buf <<  endl;

      size = xed_decoded_inst_get_length (&new_xedd);
  }
}


/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */


/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size, bool isRtnHead)
{

    // copy orig instr to instr map:
    ADDRINT orig_targ_addr = 0x0;

    if (xed_decoded_inst_get_length (xedd) != size) {
        cerr << "Invalid instruction decoding" << endl;
        return -1;
    }

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
    entry_map.clear();

    for (unsigned i = from_entry; i < until_entry; i++) {
        instr_map[i].targ_map_entry = -1;
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
void set_estimated_new_ins_addrs_in_tc() {
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
                                             size , &new_size);
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
    // Ignore instructiosn of zero size.
    if (!instr_map[instr_map_entry].size)
      return 0;

    // check for cases of direct jumps/calls back to the original target address:
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

        cerr << "ERROR: Invalid direct jump from translated code to original code for:\n";
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

    xed_error_enum_t xed_error =
       xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
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
    //uncond jumps instructions with size=0 should remain with size=0
    // for beeing removed from tc
    if (!instr_map[instr_map_entry].size)
        return 0;
    
    // Check if it is indeed a direct branch or a direct call instr:
    if (instr_map[instr_map_entry].orig_targ_addr == 0)
      return 0;

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    xed_error_enum_t xed_code =
        xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
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
    // indirect branches via a rip offset which had previously been
    // formed by previouis calls to fix_direct_br_call_to_orig_addr()
    // in order to relpace direct jumps to orig targ addrs.
    if (instr_map[instr_map_entry].targ_map_entry < 0) {
       int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
       return rc;
    }

    ADDRINT new_targ_addr;
    new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;

    new_disp =
      (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size; // orig_size;

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
        xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048,
                           static_cast<UINT64>(instr_map[instr_map_entry].orig_ins_addr), 0, 0);
        cerr << " instr: " << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
          return -1;
    }

    new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;

    new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

    xed_error =
      xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
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

            // fix instr displacement:
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
    int rc;

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
            continue;

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            if (rtn == RTN_Invalid()) {
                cerr << "Warning: invalid routine " << RTN_Name(rtn) << endl;
                continue;
            }

            unsigned rtn_entry = num_of_instr_map_entries;
            RTN_Open(rtn);

            INS prev = INS_Invalid();

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {

                if (KnobVerbose) {
                    cerr << "old instr: ";
                    cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) <<  endl;
                }

                ADDRINT addr = INS_Address(ins);

                xed_decoded_inst_t xedd;
                xed_error_enum_t xed_code;

                xed_decoded_inst_zero_set_mode(&xedd, &dstate);
                xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
                if (xed_code != XED_ERROR_NONE) {
                    cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
                    return -1;
                }

                bool isRtnHead = (RTN_Address(rtn) == addr);
                rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins), isRtnHead);
                if (rc < 0) {
                    cerr << "ERROR: failed during instruction translation." << endl;
                    return -1;
                }

                //detect start of a basic block
                bool isInsStartsBBL = !INS_Valid(prev) || INS_IsControlFlow(prev);

                if (isInsStartsBBL) {
                    cerr << "Start BBL" << endl;
                    bbl_num++;
                    
                    xed_encoder_instruction_t enc_instr;
                    xed_encoder_request_t enc_req;
                    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
                    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
                    unsigned int olen = 0;
                    static uint64_t rax_mem;

                    bb_addr_mem[bbl_num] = INS_Address(ins);
                    cerr << "Start BBL before loop" << endl;
                    for (int i = 0; i < 5; i++) {
                        if (i == 0)
                            xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                                      xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64),
                                      xed_reg(XED_REG_RAX));
                        else if (i == 1)
                            xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                                      xed_reg(XED_REG_RAX),
                                      xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&bb_map_mem[bbl_num], 64), 64));
                        else if (i == 2)
                            xed_inst2(&enc_instr, dstate, XED_ICLASS_LEA, 64,
                                      xed_reg(XED_REG_RAX),
                                      xed_mem_bd(XED_REG_RAX, xed_disp(1, 8), 64));
                        else if (i == 3)
                            xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                                      xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&bb_map_mem[bbl_num], 64), 64),
                                      xed_reg(XED_REG_RAX));
                        else if (i == 4)
                            xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                                      xed_reg(XED_REG_RAX),
                                      xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64));

                        xed_encoder_request_zero_set_mode(&enc_req, &dstate);
                        if (!xed_convert_to_encoder_request(&enc_req, &enc_instr)) {
                            cerr << "conversion to encode request failed\n";
                            return -1;
                        }

                        xed_error_enum_t xed_error = xed_encode(&enc_req,
                                    reinterpret_cast<UINT8*>(encoded_ins), ilen, &olen);
                        if (xed_error != XED_ERROR_NONE) {
                            cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
                            return -1;
                        }

                        xed_decoded_inst_t xedd_instr;
                        xed_decoded_inst_zero_set_mode(&xedd_instr, &dstate);
                        if (xed_decode(&xedd_instr, reinterpret_cast<UINT8*>(encoded_ins), max_inst_len) != XED_ERROR_NONE) {
                            cerr << "xed decode failed at: 0x" << hex << addr << endl;
                            return -1;
                        }

                        rc = add_new_instr_entry(&xedd_instr, 0x0, olen, false);
                        if (rc < 0) {
                            cerr << "instruction translation failed\n";
                            return -1;
                        }
                    }
                    cerr << "Start BBL exit" << endl;
                }
                cerr << "Calc isTerminate" << endl;
                cerr.flush();  
                bool isInsTerminateBBL =   (INS_IsIndirectControlFlow(ins) || 
                                        INS_IsDirectControlFlow(ins) || 
                                        INS_IsRet(ins)) && 
                                        !INS_IsCall(ins);
                cerr << "done Calc isTerminate" << endl;
                cerr.flush();  
                
                if (isInsTerminateBBL) {
                    cerr << "isTerminate" << endl;
                    xed_encoder_instruction_t enc_instr;
                    xed_encoder_request_t enc_req;
                    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
                    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
                    unsigned int olen = 0;
                    static uint64_t rax_mem, rbx_mem, rcx_mem;

                    bb_addr_mem[bbl_num] = INS_Address(ins);
                    cerr << "not here 3" << endl;
                    // Retrieve the details about the indirect jmp operands of ‘INS ins’:
                    xed_decoded_inst_t *xedd = INS_XedDec(ins);
                    xed_reg_enum_t base_reg = xed_decoded_inst_get_base_reg(xedd, 0);
                    xed_reg_enum_t index_reg = xed_decoded_inst_get_index_reg(xedd, 0);
                    xed_int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
                    xed_uint_t scale = xed_decoded_inst_get_scale(xedd, 0);
                    xed_uint_t width = 
                    xed_decoded_inst_get_memory_displacement_width_bits(xedd,0);
                    unsigned mem_addr_width = xed_decoded_inst_get_memop_address_width(xedd,0);
                    xed_reg_enum_t targ_reg = XED_REG_INVALID;
                    unsigned memops = xed_decoded_inst_number_of_memory_operands(xedd);
                    cerr << "not here 4" << endl;
                    if (!memops)
                    targ_reg = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
                    // Debug print.
                    //dump_instr_from_xedd (xedd, bb_addr_mem[bbl_num]);
                    cerr << " base reg: " << xed_reg_enum_t2str(base_reg)
                    << " index reg " << xed_reg_enum_t2str(index_reg)
                    << " scale: " << scale
                    << " disp: " << disp
                    << " width: " << width
                    << " mem addr width: " << mem_addr_width
                    << " targ reg: " << targ_reg << xed_reg_enum_t2str(targ_reg)
                    << "\n";
                    cerr << "not here 4 " << endl;
                    for (int i = 0; i < 22; ++i) {
                        cerr << "encoding " << i << endl;
                        cerr.flush();

                        if (i == 0) {
                            // 0: store RAX → [rax_mem]
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_mem_bd(XED_REG_INVALID,
                                                xed_disp((ADDRINT)&rax_mem, 64), 64),
                                    xed_reg(XED_REG_RAX));
                        }
                        else if (i == 1) {
                            // 1: move RBX → RAX
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_reg(XED_REG_RAX),
                                    xed_reg(XED_REG_RBX));
                        }
                        else if (i == 2) {
                            // 2: store RAX → [rbx_mem]
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_mem_bd(XED_REG_INVALID,
                                                xed_disp((ADDRINT)&rbx_mem, 64), 64),
                                    xed_reg(XED_REG_RAX));
                        }
                        else if (i == 3) {
                            // 3: store RCX → RAX
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_reg(XED_REG_RAX),
                                    xed_reg(XED_REG_RCX));
                        }
                        else if (i == 4) {
                            // 4: store RAX → [rcx_mem]
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_mem_bd(XED_REG_INVALID,
                                                xed_disp((ADDRINT)&rcx_mem, 64), 64),
                                    xed_reg(XED_REG_RAX));
                        }
                        else if (i == 5) {
                            // 5: load [rax_mem] → RAX
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_reg(XED_REG_RAX),
                                    xed_mem_bd(XED_REG_INVALID,
                                                xed_disp((ADDRINT)&rax_mem, 64), 64));
                        }
                        else if (i == 6) {
                            // 6: compute jump target → RAX
                            if (targ_reg != XED_REG_INVALID) {
                                xed_inst2(&enc_instr, dstate,
                                        XED_ICLASS_MOV, 64,
                                        xed_reg(XED_REG_RAX),
                                        xed_reg(targ_reg));
                            } else {
                                xed_inst2(&enc_instr, dstate,
                                        XED_ICLASS_MOV, 64,
                                        xed_reg(XED_REG_RAX),
                                        xed_mem_bisd(base_reg, index_reg, scale,
                                                    xed_disp(disp, width), mem_addr_width));
                            }
                        }
                        else if (i == 7) {
                            // 7: RBX ← RAX
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_reg(XED_REG_RBX),
                                    xed_reg(XED_REG_RAX));
                        }
                        else if (i == 8) {
                            // 8: AND RBX, 3
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_AND, 64,
                                    xed_reg(XED_REG_RBX),
                                    xed_imm0(3, 8));
                        }
                        else if (i == 9) {
                            // 9: RCX ← &bb_map_targ_addr[bbl_num][0]
                            xed_inst2(&enc_instr, dstate,
                                XED_ICLASS_MOV, 64,
                                xed_reg(XED_REG_RCX),
                                xed_imm0((UINT64)&bb_map_targ_addr[bbl_num][0], 64));
                        }
                        else if (i == 10) {
                            // 10: RCX ← RCX + RBX*8
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_LEA, 64,
                                    xed_reg(XED_REG_RCX),
                                    xed_mem_bisd(XED_REG_RCX, XED_REG_RBX, 8,
                                                xed_disp(0, 0), 64));
                        }
                        else if (i == 11) {
                            // 11: [RCX] ← RAX
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_mem_bd(XED_REG_RCX,
                                                xed_disp(0, 0), 64),
                                    xed_reg(XED_REG_RAX));
                        }
                        else if (i == 12) {
                            // 12: RCX ← &bb_map_targ_count[bbl_num][0]
                            xed_inst2(&enc_instr, dstate,
                                XED_ICLASS_MOV, 64,
                                xed_reg(XED_REG_RCX),
                                xed_imm0((UINT64)&bb_map_targ_count[bbl_num][0], 64));
                        }
                        else if (i == 13) {
                            // 13: RCX ← RCX + RBX*8
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_LEA, 64,
                                    xed_reg(XED_REG_RCX),
                                    xed_mem_bisd(XED_REG_RCX, XED_REG_RBX, 8,
                                                xed_disp(0, 0), 64));
                        }
                        else if (i == 14) {
                            // 14: RAX ← [RCX]
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_reg(XED_REG_RAX),
                                    xed_mem_bd(XED_REG_RCX,
                                                xed_disp(0, 0), 64));
                        }
                        else if (i == 15) {
                            // 15: RAX ← RAX + 1
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_ADD, 64,
                                    xed_reg(XED_REG_RAX),
                                    xed_imm0(1, 8));
                        }
                        else if (i == 16) {
                            // 16: [RCX] ← RAX
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_mem_bd(XED_REG_RCX,
                                                xed_disp(0, 0), 64),
                                    xed_reg(XED_REG_RAX));
                        }
                        else if (i == 17) {
                            // 17: RAX ← [rcx_mem]
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_reg(XED_REG_RAX),
                                    xed_mem_bd(XED_REG_INVALID,
                                                xed_disp((ADDRINT)&rcx_mem, 64), 64));
                        }
                        else if (i == 18) {
                            // 18: RCX ← RAX
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_reg(XED_REG_RCX),
                                    xed_reg(XED_REG_RAX));
                        }
                        else if (i == 19) {
                            // 19: RAX ← [rbx_mem]
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_reg(XED_REG_RAX),
                                    xed_mem_bd(XED_REG_INVALID,
                                                xed_disp((ADDRINT)&rbx_mem, 64), 64));
                        }
                        else if (i == 20) {
                            // 20: RBX ← RAX
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_reg(XED_REG_RBX),
                                    xed_reg(XED_REG_RAX));
                        }
                        else if (i == 21) {
                            // 21: RAX ← [rax_mem]
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_reg(XED_REG_RAX),
                                    xed_mem_bd(XED_REG_INVALID,
                                                xed_disp((ADDRINT)&rax_mem, 64), 64));
                        }

                        // now encode and add to your instruction map
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate);
                        if (!xed_convert_to_encoder_request(&enc_req, &enc_instr)) {
                            cerr << "conversion to encode request failed\n";
                            return -1;
                        }
                        xed_error_enum_t xed_error = xed_encode(&enc_req,
                                                    reinterpret_cast<UINT8*>(encoded_ins),
                                                    ilen, &olen);
                        if (xed_error != XED_ERROR_NONE) {
                            cerr << "ENCODE ERROR: "
                                << xed_error_enum_t2str(xed_error) << endl;
                            return -1;
                        }
                        xed_decoded_inst_t xedd_instr;
                        xed_decoded_inst_zero_set_mode(&xedd_instr, &dstate);
                        if (xed_decode(&xedd_instr,
                                    reinterpret_cast<UINT8*>(encoded_ins),
                                    max_inst_len) != XED_ERROR_NONE) {
                            cerr << "xed decode failed at: 0x" << hex << addr << endl;
                            return -1;
                        }
                        rc = add_new_instr_entry(&xedd_instr, 0x0, olen, false);
                        if (rc < 0) {
                            cerr << "instruction translation failed\n";
                            return -1;
                        }

                        cerr << "encoded " << i << endl;
                        cerr.flush();
                    }

                    
                }
                
                cerr << "Calc is prev Terminate" << endl;

                if (isPrevInsTerminates) {
                    cerr << "not here 10" << endl;
                    cerr.flush();  
                    
                    xed_encoder_instruction_t enc_instr;
                    xed_encoder_request_t enc_req;
                    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
                    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
                    unsigned int olen = 0;
                    static uint64_t rax_mem;

                    bb_addr_mem[bbl_num] = INS_Address(ins);
                    cerr << "not here 11" << endl;
                    cerr.flush();  
                    for (int i = 0; i < 5; i++) {
                        if (i == 0) {
                            // 0: store RAX → [rax_mem]
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64),
                                    xed_reg(XED_REG_RAX));
                        }
                        else if (i == 1) {
                            // 1: load bb_map_fall_count[bbl_num] → RAX
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_reg(XED_REG_RAX),
                                    xed_mem_bd(XED_REG_INVALID,
                                                xed_disp((ADDRINT)&bb_map_fall_count[bbl_num], 64), 64));
                        }
                        else if (i == 2) {
                            // 2: RAX ← RAX + 1
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_LEA, 64,
                                    xed_reg(XED_REG_RAX),
                                    xed_mem_bd(XED_REG_RAX, xed_disp(1, 8), 64));
                        }
                        else if (i == 3) {
                            // 3: store RAX → bb_map_fall_count[bbl_num]
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_mem_bd(XED_REG_INVALID,
                                                xed_disp((ADDRINT)&bb_map_fall_count[bbl_num], 64), 64),
                                    xed_reg(XED_REG_RAX));
                        }
                        else if (i == 4) {
                            // 4: reload original RAX → RAX
                            xed_inst2(&enc_instr, dstate,
                                    XED_ICLASS_MOV, 64,
                                    xed_reg(XED_REG_RAX),
                                    xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64));
                        }
                        xed_encoder_request_zero_set_mode(&enc_req, &dstate);
                        if (!xed_convert_to_encoder_request(&enc_req, &enc_instr)) {
                            cerr << "conversion to encode request failed\n";
                            return -1;
                        }

                        xed_error_enum_t xed_error = xed_encode(&enc_req,
                                    reinterpret_cast<UINT8*>(encoded_ins), ilen, &olen);
                        if (xed_error != XED_ERROR_NONE) {
                            cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
                            return -1;
                        }

                        xed_decoded_inst_t xedd_instr;
                        xed_decoded_inst_zero_set_mode(&xedd_instr, &dstate);
                        if (xed_decode(&xedd_instr, reinterpret_cast<UINT8*>(encoded_ins), max_inst_len) != XED_ERROR_NONE) {
                            cerr << "xed decode failed at: 0x" << hex << addr << endl;
                            return -1;
                        }

                        rc = add_new_instr_entry(&xedd_instr, 0x0, olen, false);
                        if (rc < 0) {
                            cerr << "instruction translation failed\n";
                            return -1;
                        }
                    }
                    cerr << "not here 12" << endl;
                    cerr.flush();  

                }
                
                cerr.flush();  
                isPrevInsTerminates =  isInsTerminateBBL;
                cerr.flush();  

                prev = ins; // update previous instruction

            }
            cerr << "hereee" << endl;
            cerr.flush();  
            if (KnobVerbose) {
                cerr << "rtn name: " << RTN_Name(rtn) << endl;
            }

            RTN_Close(rtn);

            chain_all_direct_br_and_call_target_entries(rtn_entry, num_of_instr_map_entries);
            cerr << "heree1" << endl;
            cerr.flush();  
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
    // Commit the translated functions:
    // Go over the candidate functions and replace the original ones by their new successfully translated ones:

    for (unsigned i=0; i < num_of_instr_map_entries; i++) {

        //replace function by new function in tc

        if (!instr_map[i].isRtnHead)
          continue;

        RTN rtn = RTN_FindByAddress(instr_map[i].orig_ins_addr);

        //debug print:
        if (rtn == RTN_Invalid()) {
            cerr << "committing rtN: Unknown";
        } else {
            cerr << "committing rtN: " << RTN_Name(rtn);
        }
        cerr << " from: 0x" << hex << RTN_Address(rtn)
             << " to: 0x" << hex << instr_map[i].new_ins_addr << endl;


        if (RTN_IsSafeForProbedReplacement(rtn)) {

            AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[i].new_ins_addr);

            if (origFptr == NULL) {
                cerr << "RTN_ReplaceProbed failed.";
            } else {
                cerr << "RTN_ReplaceProbed succeeded. ";
            }
            cerr << " orig routine addr: 0x" << hex << RTN_Address(rtn)
                 << " replacement routine addr: 0x" << hex
                 << instr_map[i].new_ins_addr << endl;

            dump_instr_from_mem ((ADDRINT *)RTN_Address(rtn), RTN_Address(rtn));
        }
    }
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
            max_ins_count += RTN_NumIns  (rtn);
        }
    }

    max_ins_count *= 10; // estimating that the num of instrs of the inlined functions will not exceed the total nunmber of the entire code.

    // Allocate memory for the instr map needed to fix all branch targets in translated routines:
    instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
    if (instr_map == NULL) {
        perror("calloc");
        return -1;
    }

    jump_to_orig_addr_map = (ADDRINT *)calloc(max_ins_count/10, sizeof(ADDRINT));
    if (jump_to_orig_addr_map == NULL) {
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

    // Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:
    char * addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if ((ADDRINT) addr == 0xffffffffffffffff) {
        cerr << "failed to allocate tc" << endl;
        return -1;
    }

    tc = (char *)addr;
    return 0;
}


/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
typedef VOID (*EXITFUNCPTR)(INT code);
EXITFUNCPTR origExit;


// Comparison function for sorting
bool cmp(const std::pair<ADDRINT, UINT64>& a, const std::pair<ADDRINT, UINT64>& b)
{
    return a.second > b.second;
}

VOID Fini(INT32 code, VOID* v)
{

    outfile.open("bb-profile.csv");

    // Vector to store pairs of address and count
    std::vector<std::pair<ADDRINT, uint64_t>> sorted_bbls;

    for (unsigned i = 0; i < bbl_num; ++i) {
        if (bb_map_mem[i] > 0) {  // <-- Only include non-zero execution counts
            sorted_bbls.emplace_back(bb_addr_mem[i], bb_map_mem[i]);
        }
    }

    // Sort in descending order (most executed first)
    std::sort(sorted_bbls.begin(), sorted_bbls.end(),
        [](const std::pair<ADDRINT, uint64_t>& a, const std::pair<ADDRINT, uint64_t>& b) {
            return a.second > b.second;
        });

    // Write results as: <address>, <exec count>
    for (const auto& entry : sorted_bbls) {
        outfile << std::hex << entry.first << ", " << std::dec << entry.second << endl;
    }

    outfile.close();

/*
    std::vector<std::pair<ADDRINT, UINT64>> sorted_bbls(bbl_counts.begin(), bbl_counts.end());

    // Sort blocks by frequency (descending)
    std::sort(sorted_bbls.begin(), sorted_bbls.end(), cmp);

    // Write to CSV file
    outfile.open("bb-profile.csv");
    for (auto& entry : sorted_bbls) {
        outfile << std::hex << entry.first << ", " << std::dec << entry.second << std::endl;
    }

    outfile.close();
    
    //cerr << "Reached _exit." << endl;
    */
}

VOID ExitInProbeMode(INT code)
{
    Fini(code, 0);
    (*origExit)(code);
}

VOID ImageLoad(IMG img, VOID *v)
{   
    // Insert a call to function Fini when raching the _exit routine.
    RTN exitRtn = RTN_FindByName(img, "_exit");
    if (RTN_Valid(exitRtn) && RTN_IsSafeForProbedReplacement(exitRtn)) {
      origExit = (EXITFUNCPTR)RTN_ReplaceProbed(exitRtn, AFUNPTR(ExitInProbeMode));
    }

    // debug print of all images' instructions
    //dump_all_image_instrs(img);

    // Step 0: Check the image and the CPU:
    if (!IMG_IsMainExecutable(img))
      return;

    int rc = 0;

    // step 1: Check size of executable sections and allocate required memory:
    rc = allocate_and_init_memory(img);
    if (rc < 0) {
        cerr << "failed to initialize memory for translation\n";
        return;
    }
    cerr << "after memory allocation" << endl;

    // Step 2: go over all routines and identify candidate routines and copy their code into the instr map IR:
    rc = find_candidate_rtns_for_translation(img);
    if (rc < 0) {
        cerr << "failed to find candidates for translation\n";
        return;
    }
    cerr << "after identifying candidate routines" << endl;

    // Step 3: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
    chain_all_direct_br_and_call_target_entries(0, num_of_instr_map_entries);
    cerr << "after chaining all branch targets" << endl;

    // Step 4: Set initial estimated new addrs for each instruction in the tc.
    set_estimated_new_ins_addrs_in_tc();
    cerr << "after setting estimated new ins addrs in tc" << endl;

    // Step 5: fix rip-based, direct branch and direct call displacements:
    rc = fix_instructions_displacements();
    if (rc < 0 ) {
        cerr << "failed to fix displacments of translated instructions\n";
        return;
    }
    cerr << "after fix instructions displacements" << endl;

    // Step 6: write translated instructions to the tc:
    rc = copy_instrs_to_tc();
    if (rc < 0 ) {
        cerr << "failed to copy the instructions to the translation cache\n";
        return;
    }
    cerr << "after write all new instructions to memory tc" << endl;

   if (KnobDumpTranslatedCode) {
       cerr << "Translation Cache dump:" << endl;
       dump_tc();  // dump the entire tc

       //cerr << endl << "instructions map dump:" << endl;
       //dump_entire_instr_map();     // dump all translated instructions in map_instr
   }

    // Step 7: Commit the translated routines:
    //Go over the candidate functions and replace the original ones by their new successfully translated ones:
    if (!KnobDoNotCommitTranslatedCode) {
      commit_translated_routines();
      cerr << "after commit of translated routines" << endl;
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
    //out = new std::ofstream("xed-print.out");

    if( PIN_Init(argc,argv) )
        return Usage();

    PIN_InitSymbols();

    // Register ImageLoad
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Start the program, never returns
    PIN_StartProgramProbed();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
