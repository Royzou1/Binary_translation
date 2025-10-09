/*########################################################################################################*/
// cd <pin-3.30-path>/source/tools/SimpleExamples
// make btranslate-for-project.test
//  ../../../pin -t obj-intel64/btranslate-for-project.so -create_tc2 -- ~/workdir/tst
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
 * in an allocated Translation Cache (TC) along with instrumentation instructions that collect 
 * profiling for each BBL.
 * It then patches the original code to jump to the translated code in the TC.
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
#include <set>
#include <map>
#include <time.h>

using namespace std;
std::ofstream outfile;
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

KNOB<BOOL> KnobDumpProfile(KNOB_MODE_WRITEONCE,    "pintool",
    "dump_prof", "0", "Dump profiling information");

KNOB<BOOL> KnobProbeBackwardJumps(KNOB_MODE_WRITEONCE,    "pintool",
    "probe_back_jumps", "0",
    "Insert a probe jump to TC2 before each backward jump and at routine prolog \
    (relevant only with -create_tc2 flag)");

KNOB<BOOL>   KnobNoReorderCode(KNOB_MODE_WRITEONCE,    "pintool",
    "no_code_reorder", "0", "Do not reorder code in TC2 (relevant only with -create_tc2 flag)");

KNOB<UINT> KnobProfileThreshold(KNOB_MODE_WRITEONCE,    "pintool",
                                  "prof_threshold", "95", "Profile percentage threshold");


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
    ADDRINT og_not_changed;
    ADDRINT orig_ins_addr;
    ADDRINT new_ins_addr;
    ADDRINT orig_targ_addr;
    ins_enum_t ins_type;
    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
    unsigned int size;
    int targ_map_entry;
    unsigned bbl_num;
    xed_category_enum_t xed_category;
    bool indirect_profiled;
    INS ins;
} instr_map_t;


// Instrs map:
instr_map_t *instr_map = NULL;
unsigned num_of_instr_map_entries = 0;
unsigned max_ins_count = 0;

#define MAX_TARG_ADDRS 0x3

// Bbl map of all the bbl exec counters to be collected at runtime:
typedef struct {
  UINT64 counter;
  UINT64 fallthru_counter; // for BBLs that terminate with a cond branch.
  ADDRINT targ_addr[MAX_TARG_ADDRS+1];
  UINT64  targ_count[MAX_TARG_ADDRS+1];
  unsigned starting_ins_entry;
  unsigned terminating_ins_entry;
} bbl_map_t;

bbl_map_t *bbl_map;
unsigned bbl_num = 0;

std::map<ADDRINT, unsigned> entry_map;

/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */


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


/**************************************/
/*  dump_entire_instr_map_with_prof() */
/**************************************/
void dump_entire_instr_map_with_prof()
{
    for (unsigned i=0; i < num_of_instr_map_entries; i++) {
      //Print a new line after each BBL.
      if (i > 0 && instr_map[i].bbl_num != instr_map[i - 1].bbl_num)
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

      if (!instr_map[i].size)
        continue;

      // Print non-empty profile info.
      if (bbl_map[instr_map[i].bbl_num].counter ||
          bbl_map[instr_map[i].bbl_num].fallthru_counter) {
        cerr << " BBL heat: " << dec << bbl_map[instr_map[i].bbl_num].counter
             << " FT heat: " << dec << bbl_map[instr_map[i].bbl_num].fallthru_counter
             << " : ";
      }
      for (unsigned j = 0; j <= MAX_TARG_ADDRS; j++) {
        if (bbl_map[instr_map[i].bbl_num].targ_addr[j] ||
            bbl_map[instr_map[i].bbl_num].targ_count[j]) {
          cerr << " targ addr: 0x" << hex << bbl_map[instr_map[i].bbl_num].targ_addr[j]
               << " targ count: " << dec << bbl_map[instr_map[i].bbl_num].targ_count[j]
               << " : ";
        }
      }

      dump_instr_from_mem ((ADDRINT *)instr_map[i].encoded_ins, instr_map[i].orig_ins_addr);
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
  REG killed_reg_in_bbl = REG_INVALID();
  
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
  return killed_reg_in_bbl;
}


int encode_nop_instr(ADDRINT pc, char *encoded_nop_ins)
{
    xed_encoder_instruction_t enc_instr;
    xed_encoder_request_t enc_req;
    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
    unsigned int olen = 0;
    
    xed_inst0(&enc_instr, dstate, XED_ICLASS_NOP, 64);    
    
    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }           
    xed_error_enum_t xed_error = xed_encode(&enc_req,
              reinterpret_cast<UINT8*>(encoded_nop_ins), ilen, &olen);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
      return -1;
    }
    
    return olen;
}          


/****************************************************/
/* Encode a direct uncond jump from pc to targ_addr.*/
/****************************************************/
int encode_jump_instr(ADDRINT pc, ADDRINT target_addr, char *encoded_jmp_ins)
{
    xed_encoder_instruction_t enc_instr;
    xed_encoder_request_t enc_req;
    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
    unsigned int olen = 0;
    
    xed_int64_t disp = target_addr - pc - olen;
    
    // Check if it is a short jump or a long jump.
    if (disp >= -128 && disp <= 127)
      xed_inst1(&enc_instr, dstate, XED_ICLASS_JMP, 64, xed_relbr(disp, 8)); // Short jump.
    else        
      xed_inst1(&enc_instr, dstate,  XED_ICLASS_JMP, 64, xed_relbr(disp, 32)); // Long jump
    
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
    
    // Check if it is a short jump or a long jump.
    if (disp >= -128 && disp <= 127)
      xed_inst1(&enc_instr, dstate, XED_ICLASS_JMP, 64, xed_relbr(disp, 8)); // Short jump.
    else        
      xed_inst1(&enc_instr, dstate,  XED_ICLASS_JMP, 64, xed_relbr(disp, 32)); // Long jump.
    
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

int encode_reverse_cond_jump(char* encoded_ins, char* encoded_rcond_jump_ins,
                             ADDRINT curr_addr, ADDRINT targ_addr)
{
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);
    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), max_inst_len);
    BOOL xed_ok = (xed_code == XED_ERROR_NONE);
      if (!xed_ok){
          cerr << "invalid opcode" << endl;
          return -1;
      }
    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

    if (category_enum != XED_CATEGORY_COND_BR) 
        return 0;

    xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);

    if (iclass_enum == XED_ICLASS_JRCXZ)
        return 0;    // do not revert JRCXZ

    xed_iclass_enum_t     retverted_iclass;

    switch (iclass_enum) {

        case XED_ICLASS_JB:
            retverted_iclass = XED_ICLASS_JNB;
            break;

        case XED_ICLASS_JBE:
            retverted_iclass = XED_ICLASS_JNBE;
            break;

        case XED_ICLASS_JL:
            retverted_iclass = XED_ICLASS_JNL;
            break;
    
        case XED_ICLASS_JLE:
            retverted_iclass = XED_ICLASS_JNLE;
            break;

        case XED_ICLASS_JNB: 
            retverted_iclass = XED_ICLASS_JB;
            break;

        case XED_ICLASS_JNBE: 
            retverted_iclass = XED_ICLASS_JBE;
            break;

        case XED_ICLASS_JNL:
        retverted_iclass = XED_ICLASS_JL;
            break;

        case XED_ICLASS_JNLE:
            retverted_iclass = XED_ICLASS_JLE;
            break;

        case XED_ICLASS_JNO:
            retverted_iclass = XED_ICLASS_JO;
            break;

        case XED_ICLASS_JNP: 
            retverted_iclass = XED_ICLASS_JP;
            break;

        case XED_ICLASS_JNS: 
            retverted_iclass = XED_ICLASS_JS;
            break;

        case XED_ICLASS_JNZ:
            retverted_iclass = XED_ICLASS_JZ;
            break;

        case XED_ICLASS_JO:
            retverted_iclass = XED_ICLASS_JNO;
            break;

        case XED_ICLASS_JP: 
            retverted_iclass = XED_ICLASS_JNP;
            break;

        case XED_ICLASS_JS: 
            retverted_iclass = XED_ICLASS_JNS;
            break;

        case XED_ICLASS_JZ:
            retverted_iclass = XED_ICLASS_JNZ;
            break;

        default:
            return -1;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode (&xedd);

    // set the reverted opcode;
    xed_encoder_request_set_iclass (&xedd, retverted_iclass);

    // fix targ addr
    xed_int64_t new_disp = (targ_addr - curr_addr) - xed_decoded_inst_get_length(&xedd);
    xed_uint_t new_disp_byts = 4; // num_of_bytes(new_disp);  ???

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

    unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;

    xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(encoded_rcond_jump_ins), max_size, &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
        return -1;
    }
    
    // re-encode with new size
    new_disp = (targ_addr - curr_addr) - new_size;

    //Set the new branch displacement:
    xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

    xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(encoded_rcond_jump_ins), max_size , &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }
    
    return new_size;
}

/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */

/***************************/
/* disable_profiling_in_tc */
/***************************/
int disable_profiling_in_tc(instr_map_t * instr_map, unsigned num_of_instr_map_entries)
{
   for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
       // Check for the case of a NOP instr at the head of a 
       // pofiling code stub and replace it by a jump instr that skips it.       
       if (instr_map[i].ins_type == ProfilingIns &&
           instr_map[i].xed_category == XED_CATEGORY_WIDENOP) {
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
          unsigned int olen = 5; // skip jump instr is exactly 5 bytes long.
          
          disp += (instr_map[i].size - olen);
          xed_inst1(&enc_instr, dstate,  XED_ICLASS_JMP, 64, xed_relbr(disp, 32));
          
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

          if (olen > instr_map[i].size) {
             cerr << " unable to set a relative jump to skip the profiling code stub at: "
                  << hex << "0x" << instr_map[i].new_ins_addr << "\n";
             return -1;
          }

          // Write the bypassing jump instr on the NOP instr.
          memcpy((ADDRINT *)instr_map[i].new_ins_addr, encoded_jmp_ins, olen);
          i += (j - 1);
       }
    }
    return 0;
}    

/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, ins_enum_t ins_type, bool indirect_profiled, INS ins)
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
    instr_map[num_of_instr_map_entries].indirect_profiled = indirect_profiled;
    instr_map[num_of_instr_map_entries].ins = ins;
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

/********************/
/* add_prof_instr() */
/********************/
int add_prof_instr(ADDRINT ins_addr, xed_encoder_instruction_t *enc_instr, INS ins) {
    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
    unsigned int olen = 0;
  
    // Convert the encoding instr to a valid encoder request.
    xed_encoder_request_t enc_req;    
    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }
    
    // Encode instr.
    xed_error_enum_t xed_error = xed_encode(&enc_req,
              reinterpret_cast<UINT8*>(encoded_ins), ilen, &olen);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
      return -1;
    }
  
    // Decode instr.
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);
    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(&encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << ins_addr << endl;
        return -1;;
    }
    int rc = add_new_instr_entry(&xedd, ins_addr, ProfilingIns, false , ins);
    if (rc < 0) {
      cerr << "ERROR: failed during instructon translation." << endl;
      return -1;
    }
    return 0;
}


/**************************/
/* add_profiling_instrs() */
/**************************/
int add_profiling_instrs( INS ins, 
                          ADDRINT ins_addr, 
                          UINT64 *counter_addr, 
                          unsigned bbl_num, 
                          bool was_profiled,
                          bool &indirect_profiled)
{
  xed_encoder_instruction_t enc_instr;
  static uint64_t rax_mem = 0;
  bool is_indirect = INS_IsIndirectControlFlow(ins) && !INS_IsRet(ins) && !INS_IsCall(ins);
  if (!is_indirect && was_profiled) {
    //cerr << "skipped by using short" <<endl;
    return 0;
  }

  // Add NOP instr (to be overwritten later on by a jmp that skips
  // the profiling, once profiling is done).
  xed_inst0(&enc_instr, dstate, XED_ICLASS_NOP4, 64);
  if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
    return -1;

  // Save RAX - MOV RAX into rax_mem
  xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
            xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64), // Destination op.
            xed_reg(XED_REG_RAX));
  if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
    return -1;

  // Create profiling for indirect jump targets.
  if (is_indirect) {
    indirect_profiled = true;
    // Debug print.
    //cerr << " BBL terminates with indirect jump: "
    //     << " 0x" << hex << ins_addr << ": "
    //     << INS_Disassemble(ins) << "\n";

    static uint64_t rbx_mem = 0;
    static uint64_t rcx_mem = 0;

    // Retrieve the details about the mem operand.
    xed_decoded_inst_t *xedd = INS_XedDec(ins);
    xed_reg_enum_t base_reg = xed_decoded_inst_get_base_reg(xedd, 0);
    xed_reg_enum_t index_reg = xed_decoded_inst_get_index_reg(xedd, 0);
    xed_int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
    xed_uint_t scale = xed_decoded_inst_get_scale(xedd, 0);
    xed_uint_t width = xed_decoded_inst_get_memory_displacement_width_bits(xedd, 0);
    unsigned mem_addr_width = xed_decoded_inst_get_memop_address_width(xedd, 0);
    
    xed_reg_enum_t targ_reg = XED_REG_INVALID;
    unsigned memops = xed_decoded_inst_number_of_memory_operands(xedd);
    if (!memops)
      targ_reg = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);

    // Debug print.
    //dump_instr_from_xedd(xedd, ins_addr);
    //cerr << " base reg: " << xed_reg_enum_t2str(base_reg)
    //     << " index reg " << xed_reg_enum_t2str(index_reg)
    //     << " scale: " << dec << scale
    //     << " disp: 0x" << hex << disp
    //     << " width: " << dec << width
    //     << " mem addr width: " << dec << mem_addr_width
    //     << " targ reg: " << targ_reg << xed_reg_enum_t2str(targ_reg)
    //     << "\n";
    
    // save RBX into rbx_mem in 2 steps via RAX
    // save RCX into rcx_mem in 2 steps via RAX
    // Convert jmp [base_reg + index_reg*scale] to: MOV RAX, [base_reg + index_reg*scale]
    //         Or convert jmp targ_reg to: MOV RAX, targ_reg ==> RAX holds jump targ addr
    // MOV RBX, RAX ==> Now RBX also holds targ addr
    // AND RAX, MAX_TARG_ADDR ==> RAX holds index i = 0..MAX_TARG_ADDRS
    // MOV RCX, xed_imm0((ADDRINT)&bbl_map_targ_addr[bbl_num][0])
    // MOV [RCX + 8*RAX], RBX
    // MOV RBX, xed_imm0((ADDRINT)&bbl_map_targ_count[bbl_num][0])
    // MOV RCX, [RBX + 8*RAX]
    // LEA RCX, [RCX + 1]
    // MOV [RBX + 8*RAX], RCX
    // restore RCX from rcx_mem in 2 steps via RAX
    // restore RBX from rbx_mem in 2 steps via RAX

    // Save RBX step 1 - MOV RBX into RAX
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RAX),  // Destination op.
              xed_reg(XED_REG_RBX));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // Save RBX step 2 - MOV RAX into rbx_mem
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rbx_mem, 64), 64), // Destination op.
              xed_reg(XED_REG_RAX));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // Save RCX step 1 - MOV RCX into RAX
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RAX),   // Destination op.
              xed_reg(XED_REG_RCX));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // Save RCX step 2 - MOV RAX into rcx_mem
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rcx_mem, 64), 64), // Destination op.
              xed_reg(XED_REG_RAX));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // Replace RIP reg by an absolute displacement.
    // Convert 'jmp [rax*8+0x657118]' or: 'jmp [rip+0x42513c]'
    // to: mov rax, [rax*8+0x657118] or: mov rax, [<absolute addr>]
    //
    // Check if we need to restore RAX in case  it is used as base reg or index reg,
    // e.g., jmp [RIP+8*RAX] or: jmp [RAX+8*RBX]
    
    // Check if we need to restore RAX from rax_mem.
    if (targ_reg == XED_REG_RAX || base_reg == XED_REG_RAX || index_reg == XED_REG_RAX) {
      xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                xed_reg(XED_REG_RAX), // Destination reg op.
                xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64));
      if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
       return -1;
    }
    // Check if we need to convert [RIP+disp+index*scale] to [absolute_disp + index*scale]
    if (base_reg == XED_REG_RIP) {
      unsigned int orig_size = xed_decoded_inst_get_length (xedd);
      // Modify rip displacement by an absolute displacement val.
      xed_int64_t new_disp = ins_addr + disp + orig_size;
      xed_int64_t new_disp_width = 32; // set maximal disp width for now.
      xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                xed_reg(XED_REG_RAX),    // Destination reg op.
                xed_mem_bisd(XED_REG_INVALID, index_reg, scale, 
                             xed_disp(new_disp, new_disp_width),
                             mem_addr_width));
    } else if (targ_reg != XED_REG_RAX) { // avoid ceating the MOV RAX, RAX Nop.
        xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                 xed_reg(XED_REG_RAX),    // Destination reg op.
                 (targ_reg != XED_REG_INVALID ? xed_reg(targ_reg) :
                  xed_mem_bisd(base_reg, index_reg, scale, xed_disp(disp, width), mem_addr_width)));
    }
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // MOV RBX, RAX
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RBX),    // Destination reg op.
              xed_reg(XED_REG_RAX));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // AND RAX, MAX_TARG_ADDRS. (NOTE: Modifies RFLAGS).
    xed_inst2(&enc_instr, dstate, XED_ICLASS_AND, 64,
              xed_reg(XED_REG_RAX),    // Destination reg op.
              xed_imm0(MAX_TARG_ADDRS, 8));  // keep only MAX_TARG_ADDRS+1 targets for profiling.
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // MOV RCX, xed_imm0((ADDRINT)&bbl_map[bbl_num].targ_addr[0])
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RCX), // Destination reg op.
              xed_imm0((ADDRINT)&(bbl_map[bbl_num].targ_addr[0]), 64));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // MOV [RCX + 8*RAX], RBX
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_mem_bisd(XED_REG_RCX, // base reg
                           XED_REG_RAX, //index reg
                           8, // scale
                           xed_disp(0, 32), // disp
                           64),  // Destination reg op.
              xed_reg(XED_REG_RBX));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // MOV RBX, xed_imm0((ADDRINT)&bbl_map[bbl_num].targ_count[0])
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RBX), // Destination reg op.
              xed_imm0((ADDRINT)&(bbl_map[bbl_num].targ_count[0]), 64));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // MOV RCX, [RBX + 8*RAX]
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RCX),   // Destination reg op.
              xed_mem_bisd(XED_REG_RBX, // base reg
                           XED_REG_RAX, //index reg
                           8, // scale
                           xed_disp(0, 32), // disp
                           64));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // LEA RCX, [RCX + 1]
    xed_inst2(&enc_instr, dstate, XED_ICLASS_LEA, 64,
              xed_reg(XED_REG_RCX), // Destination reg op.
              xed_mem_bd(XED_REG_RCX, // base reg
                         xed_disp(1, 8), // disp
                         64));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // MOV [RBX + 8*RAX], RCX
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_mem_bisd(XED_REG_RBX, // base reg
                           XED_REG_RAX, //index reg
                           8, // scale
                           xed_disp(0, 32), // disp
                           64),     // Destination op.
              xed_reg(XED_REG_RCX));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // Restore RCX step 1- MOV from rcx_mem into RAX
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RAX), // Destination op.
              xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rcx_mem, 64), 64));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // Restore RCX step 2 - MOV RAX into RCX
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RCX),  // Destination op.
              xed_reg(XED_REG_RAX));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // Restore RBX step 1 - MOV from rbx_mem into RAX
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RAX), // Destination op.
              xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rbx_mem, 64), 64));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
    
    // Restore RBX step 2 - MOV RAX into RBX
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RBX),  // Destination op.
              xed_reg(XED_REG_RAX));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
  } // end of: 'if bbl terminates with indirect jump'.
  
  // Create the profiling instrs for counting the BBL frequency.
  //
  if (!was_profiled) {
    // MOV from bbl_map into RAX
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RAX),  // Destination reg op.
              xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)counter_addr, 64), 64));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;

    // LEA RAX, [RAX+1]
    xed_inst2(&enc_instr, dstate, XED_ICLASS_LEA,  64,  // operand width
              xed_reg(XED_REG_RAX), // Destination reg op.
              xed_mem_bd(XED_REG_RAX, xed_disp(1, 8), 64));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;

    // MOV from RAX into bbl_map
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)counter_addr, 64), 64), // Destination op.
              xed_reg(XED_REG_RAX));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
      return -1;
  }

  // Restore RAX - MOV from rax_mem into RAX
  xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
            xed_reg(XED_REG_RAX), // Destination reg op.
            xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64));
  if (add_prof_instr(ins_addr, &enc_instr, ins) < 0)
    return -1;
 
  return 0;
}

/**************************/
/* add_profiling_instrs_short() */
/**************************/
int add_profiling_instrs_short(INS ins, 
                              ADDRINT ins_addr, 
                              UINT64 *counter_addr,
                              unsigned bbl_num, 
                              REG killed_reg_pin)
{
    //cerr << "short route" <<endl;
    xed_encoder_instruction_t enc_instr;

    // 4-byte NOP placeholder for later patching
    xed_inst0(&enc_instr, dstate, XED_ICLASS_NOP4, 64);
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0) return -1;



    // MOV killed_reg, RAX
    if (killed_reg_pin == REG_INVALID()) return -1; // defensive
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(INS_XedExactMapFromPinReg(killed_reg_pin)),
              xed_reg(XED_REG_RAX));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0) return -1;

    // --- RAX = *counter_addr ---
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RAX),
              xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)counter_addr, 64), 64));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0) return -1;

    // --- RAX = RAX + 1 (LEA) ---
    xed_inst2(&enc_instr, dstate, XED_ICLASS_LEA, 64,
              xed_reg(XED_REG_RAX),
              // [RAX + 1]  (disp=1, disp width 8 bits; mem operand width is address width)
              xed_mem_bd(XED_REG_RAX, xed_disp(1, 8), 64));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0) return -1;

    // --- *counter_addr = RAX ---
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)counter_addr, 64), 64),
              xed_reg(XED_REG_RAX));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0) return -1;

    // --- Restore RAX ---
    // MOV RAX, killed_reg
    xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
              xed_reg(XED_REG_RAX),
              xed_reg(INS_XedExactMapFromPinReg(killed_reg_pin)));
    if (add_prof_instr(ins_addr, &enc_instr, ins) < 0) return -1;

  return 0;
}


/*************************************************/
/* chain_all_direct_br_and_call_target_entries() */
/*************************************************/
void chain_all_direct_br_and_call_target_entries(unsigned from_entry,
                                                 unsigned until_entry)
{
    //std::map<ADDRINT, unsigned> entry_map;
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
        if (!instr_map[i].size)
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
    // uncond jumps instructions with size=0
    // should remain with size=0 for beeing removed from tc
    if (!instr_map[instr_map_entry].size)
        return 0;

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
      return 0;

    //cerr << "Memory Operands" << endl;
    unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);
    if (!memops)
      return 0;

    xed_reg_enum_t base_reg = xed_decoded_inst_get_base_reg(&xedd, 0);
    if (base_reg != XED_REG_RIP)
      return 0;

    xed_int64_t disp = xed_decoded_inst_get_memory_displacement(&xedd, 0);

    //debug print:
    if (KnobVerbose) {
      cerr << " Before fixing rip offset\n";
      dump_instr_map_entry(instr_map_entry);
    }

    //xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
    xed_int64_t new_disp = 0;
    xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

    unsigned int orig_size = xed_decoded_inst_get_length (&xedd);

    // modify rip displacement. use direct addressing mode.
    new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size;
    xed_encoder_request_set_base0 (&xedd, XED_REG_INVALID);

    // Set the memory displacement using a bit length.
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

    //debug print:
    if (KnobVerbose) {
      cerr << " After fixing rip offset\n";
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
  
    // Debug print.
    cerr << "jump to orig addr: 0x" << hex << instr_map[instr_map_entry].orig_targ_addr << " : ";
    dump_instr_from_mem ((ADDRINT *)instr_map[instr_map_entry].encoded_ins,
                         instr_map[instr_map_entry].orig_ins_addr);

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

    // NOTE: We cannot zero the orig_targ_addr field in instr_map as follows:
    //  instr_map[instr_map_entry].orig_targ_addr = 0x0;
    // This is because the RIP displacement may become too large to fit into 4 bytes long.

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

    // fix direct branches/calls to original targ addresses or
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
                continue;
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
              continue;
            }

        }  // end int i=0; i ..

    } while (size_diff != 0);

   return 0;
 }


/***************/
/* create_tc() */
/***************/
int create_tc(IMG img)
{
    int rc = 0;
    // go over routines and check if they are candidates for translation and mark them for translation:

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
            continue;
                
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {                        
            // Open the RTN.
            RTN_Open( rtn );
            
            // Map all instructions that are a target of some direct jump or call in the rtn.
            std::map<ADDRINT, bool>is_targ_map;
            is_targ_map.empty();
            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
               if (INS_IsDirectControlFlow(ins)) {
                 ADDRINT targ_addr = INS_DirectControlFlowTargetAddress(ins);
                 is_targ_map[targ_addr] = true;
               }
            }

            bool was_profiled = false;
            bool indirect_profiled = false;


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
                
                // Insert a NOP7 instr at Rtn Head (or before a back jump)
                // to be overwritten later by a probing jump via mem from TC to TC2).
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
                  rc = add_new_instr_entry(&xedd, ins_addr, ins_type, false, ins);
                  if (rc < 0) {
                    cerr << "ERROR: failed during instructon translation." << endl;
                    return -1;
                  }
                  ins_type = RegularIns;
                }

                // Check if ins is a control transfer instr that terminates a BBL
                // or the next instr is a target of a direct branch or call.
                INS next_ins = INS_Next(ins);
                bool isNextInsJumpTarget = 
                    (!INS_Valid(next_ins) ? false : is_targ_map[INS_Address(next_ins)]);
                bool isInsTerminatesBBL = (isJumpOrRet(ins) || isNextInsJumpTarget);

                REG killed_reg = getKilledRegByIns(ins);
                bool found_reg = !(killed_reg == REG_INVALID() || REG_FullRegName(killed_reg) == REG_RAX);
                // short Add profiling instructions to count each BBL exec at runtime:
                //
                if (KnobApplyThreadedCommit) {
                  if (found_reg && !was_profiled) {
                    rc = add_profiling_instrs_short(ins, ins_addr, &bbl_map[bbl_num].counter, bbl_num, killed_reg);
                    if (rc < 0)
                      return -1;
                    was_profiled = true;
                  }
                }
                                        
                // Add profiling instructions to count each BBL exec at runtime:
                //
                indirect_profiled = false;

                if (KnobApplyThreadedCommit) {
                  if (isInsTerminatesBBL) {
                    rc = add_profiling_instrs(ins, ins_addr, &bbl_map[bbl_num].counter, bbl_num, was_profiled, indirect_profiled);
                    if (rc < 0)
                      return -1;
                  }
                }
          
                // Add ins to instr_map:
                //
                xed_decoded_inst_zero_set_mode(&xedd,&dstate);
                xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(ins_addr), max_inst_len);
                if (xed_code != XED_ERROR_NONE) {
                    cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << ins_addr << endl;
                    return -1;
                }

                rc = add_new_instr_entry(&xedd, INS_Address(ins), ins_type, indirect_profiled, ins);
                if (rc < 0) {
                    cerr << "ERROR: failed during instructon translation." << endl;
                    return -1;
                }
                
                
                if (isInsTerminatesBBL) {
                  bbl_map[bbl_num].terminating_ins_entry = num_of_instr_map_entries - 1;
                  bbl_num++;
                  was_profiled = false;
                  bbl_map[bbl_num].starting_ins_entry = num_of_instr_map_entries;
                }

                // Apply edge Profiling: For BBLs that end with a conditional branch,
                //     insert an increment of the fallthrough counter for this BBL,
                //     immediately after the cond branch which terminates the bbl.
                //     and before the next BBL.
                if (KnobApplyThreadedCommit && INS_Category(ins) == XED_CATEGORY_COND_BR) {
                  rc = add_profiling_instrs(ins, ins_addr, &bbl_map[bbl_num - 1].fallthru_counter, bbl_num-1, was_profiled, indirect_profiled);
                  if (rc < 0)
                    return -1;
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
        if (rtn == RTN_Invalid()) {
           cerr << "invalid rtN for commit for addr: 0x"
                << instr_map[i].orig_ins_addr << "\n";
           continue;
        }

        // Debug print.
        // cerr << "committing rtN: " << RTN_Name(rtn);
        // cerr << " from: 0x" << hex << RTN_Address(rtn)
        //      << " to: 0x" << hex << instr_map[i].new_ins_addr << endl;

        if (RTN_IsSafeForProbedReplacement(rtn)) {

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
       /*
       cerr << " committing rtN from: 0x" << hex << instr_map[i].orig_ins_addr
            << " to: 0x" << hex << instr_map[i].new_ins_addr 
            << " size: " << olen
            << endl;
       */
            //dump_instr_from_mem ((ADDRINT *)instr_map[i].orig_ins_addr, instr_map[i].orig_ins_addr);
  }
  
  return 0;
}

bool is_jump_reg_not_rax_rip(INS ins, xed_reg_enum_t &targ_reg) {
    xed_decoded_inst_t* xedd = INS_XedDec(ins);
    targ_reg = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);

    const UINT32 memops = INS_MemoryOperandCount(ins);
    for (UINT32 i = 0; i < memops; i++) {
        REG base = INS_OperandMemoryBaseReg(ins, i);  // note the 'i' arg
        if (base != REG_INVALID() && REG_FullRegName(base) == REG_RAX) return true;
    }
    return false;
}



int set_encode_and_size(xed_encoder_instruction_t *enc_instr, 
                        char* encode_ins, 
                        unsigned int * size)
{
  unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;

  // Convert the encoding instr to a valid encoder request.
  xed_encoder_request_t enc_req;    
  xed_encoder_request_zero_set_mode(&enc_req, &dstate);
  xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, enc_instr);
  if (!convert_ok) {
      cerr << "conversion to encode request failed" << endl;
      return -1;
  }

  // Encode instr.
  xed_error_enum_t xed_error = xed_encode(&enc_req,
            reinterpret_cast<UINT8*>(encode_ins), ilen, size);
  if (xed_error != XED_ERROR_NONE) {
      cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
    return -1;
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
    int rc = disable_profiling_in_tc(instr_map, num_of_instr_map_entries);
    if  (rc < 0)
      return;


       //add counters

    outfile.open("bb-profile-new.csv");
    
    size_t n = max_ins_count / 10;   // or std::size(arr) in C++17+

    for (size_t i = 0; i < n; ++i) {
        outfile << ", " << std::dec << i
                        << ", " << std::dec << bbl_map[i].counter << endl;
    }
    outfile.close();


    // Step 2.1: Modify instr_map to be used for TC2.
    //

    // saving the orignal ins address
    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
      instr_map[i].og_not_changed = instr_map[i].orig_ins_addr;
    }

    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {   
      /* debug print
      if (instr_map[i].indirect_profiled){
        cerr << "i = " << i << " indirect cmd" << endl;
        if (i < 11){
          cerr << "i is too small" << endl;
          exit(1);
        }
        else {
          for (int j = 1; j <=11; j++) {
            if (instr_map[i-j].ins_type != ProfilingIns) {
              cerr <<"cmd " << i-j << " isnt profiiling" <<endl;
              exit(1);
            }
          }
        }
      }
      */
      
      // Set new_ins_addr to be the orig_ins_addr. 
      instr_map[i].orig_ins_addr = instr_map[i].new_ins_addr;
                      
      // Skip the profiling instructions added in TC for each BBL.
      if (instr_map[i].ins_type == ProfilingIns)
        instr_map[i].size = 0;
      
      // Skip the wide NOP instr at the Rtn head which was reserved
      // for the probing jump from TC to TC2.
      if (instr_map[i].ins_type == RtnHeadIns &&
          instr_map[i].xed_category == XED_CATEGORY_WIDENOP)
        instr_map[i].size = 0;
      
      // Remove unused NOPs.
      if (instr_map[i].xed_category == XED_CATEGORY_WIDENOP ||
          instr_map[i].xed_category == XED_CATEGORY_NOP)
        instr_map[i].size = 0;

      // Fix orig_targ_addr by new_ins_addr and targ_map_entry.
      if (instr_map[i].targ_map_entry >= 0) {
        ADDRINT new_targ_addr = instr_map[instr_map[i].targ_map_entry].new_ins_addr;
        instr_map[i].orig_targ_addr = new_targ_addr;
      }


      /*****************de virtualtion *************************************/
      
      
      if (instr_map[i].indirect_profiled) {
        // 1) Print the disassembly
        cerr << "--------------------------------------------------" << endl;
        cerr << "instruction: " << INS_Disassemble(instr_map[i].ins) << endl;
        xed_decoded_inst_t *xedd = INS_XedDec(instr_map[i].ins);
        xed_reg_enum_t targ_reg = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
        //cerr << xed_reg_enum_t2str(targ_reg) << endl;
        cerr << "is_jump_reg_not_rax_rip: " <<is_jump_reg_not_rax_rip(instr_map[i].ins, targ_reg) << endl;
      }
 
      if (instr_map[i].indirect_profiled ) {
        bbl_map_t curr_bbl = bbl_map[instr_map[i].bbl_num];
        int index = 0; 
        int total_jumps_counter = 0;
        
        
        for (int j = 0 ; j <= MAX_TARG_ADDRS ; j++) {
          index = (curr_bbl.targ_count[j] > curr_bbl.targ_count[index]) ? j : index;
          total_jumps_counter += curr_bbl.targ_count[j];
        }
        cerr << "bbl num: " << instr_map[i].bbl_num << 
                ", counter: " << curr_bbl.counter <<  
                ", total count: " << total_jumps_counter << endl;
        
        if (total_jumps_counter == 0) {
          cerr << "zero jump were collected; counter is: "<< curr_bbl.counter << endl;
          continue;
        }
        
        if (((curr_bbl.targ_count[index] * 100) / total_jumps_counter) >= KnobProfileThreshold) {
          // jump [rax * 8 + immidiate]

          xed_reg_enum_t targ_reg;
          if (is_jump_reg_not_rax_rip(instr_map[i].ins, targ_reg)) {
            cerr << "rax is the boss!!!!!!!!!!" << endl;
            // check if shortcut is available
            ADDRINT hot_og = curr_bbl.targ_addr[index];
            unsigned targ_index = 0;
            for (targ_index = 0; targ_index <= num_of_instr_map_entries; i++) {
              if (instr_map[targ_index].og_not_changed == hot_og)
                break;
            }
            if (targ_index== num_of_instr_map_entries) {
              cerr << "target inst found" << endl;
            }
            else 
            {
              // emit shortcut
              cerr << "emit shortcut" << endl;
              xed_encoder_instruction_t enc_instr;
              static uint64_t rax_mem = 0;

              // Save RAX - MOV RAX into rax_mem
              xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64), // Destination op.
                xed_reg(XED_REG_RAX));

              set_encode_and_size(&enc_instr, 
                                  (instr_map[i-6].encoded_ins), 
                                  &(instr_map[i-6].size));

              //load hottest_og rax
              //ADDRINT* hottest_og_mem = &(curr_bbl.target_addr[index])
              xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                xed_reg(XED_REG_RAX), // Destination reg op.
                xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&curr_bbl.targ_addr[index], 64), 64));
              
              set_encode_and_size(&enc_instr, 
                                  (instr_map[i-5].encoded_ins), 
                                  &(instr_map[i-5].size));
              
              //compare rax target_reg
              xed_inst2(&enc_instr, dstate,
                XED_ICLASS_CMP, 64,
                xed_reg(XED_REG_RAX), xed_reg(targ_reg)); 
              
              set_encode_and_size(&enc_instr, 
                (instr_map[i-4].encoded_ins), 
                &(instr_map[i-4].size));

              // Restore RAX - MOV from rax_mem into RAX
              xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                xed_reg(XED_REG_RAX), // Destination reg op.
                xed_mem_bd(XED_REG_INVALID, xed_disp((ADDRINT)&rax_mem, 64), 64));

              set_encode_and_size(&enc_instr, 
                                  (instr_map[i-3].encoded_ins), 
                                  &(instr_map[i-3].size));

              
              //load hottetst_tc2 to targ_reg            
              xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64,
                xed_reg(targ_reg), // Destination reg op.
                xed_mem_bd(XED_REG_INVALID, 
                xed_disp((ADDRINT)&(instr_map[targ_index].new_ins_addr), 64), 64));

              set_encode_and_size(&enc_instr, 
                                  (instr_map[i-1].encoded_ins), 
                                  &(instr_map[i-1].size));

              //jne rip + olen(i-1)
              xed_encoder_instruction_t enc_jcc;
                xed_inst1(&enc_jcc, dstate, XED_ICLASS_JNZ /* JNE */, 64,
                xed_relbr((int8_t)instr_map[i-1].size, 8));   // rel8 = bytes to skip
              
              set_encode_and_size(&enc_instr, 
                (instr_map[i-2].encoded_ins), 
                &(instr_map[i-2].size));
              //Lable :
            }
          }
        }
      
      }
      /*********************************************************************/
    }
    
    for (unsigned i = 0; i < num_of_instr_map_entries; i++) {
       instr_map[i].targ_map_entry = -1;
    }
    
    cerr << "after modifying instr_map" << endl;

    // Debug print.
    if (KnobDumpProfile)
      dump_entire_instr_map_with_prof();
    
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
    rc = fix_instructions_displacements();
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
    
    // Allocate memory for the BBL counters:
    bbl_map = (bbl_map_t *)calloc(max_ins_count, sizeof(bbl_map_t));
    if (bbl_map == NULL) {
        perror("calloc");
        return -1;
    }
    
    jump_to_orig_addr_map = (ADDRINT *)calloc(max_ins_count/10, sizeof(ADDRINT));
    if (jump_to_orig_addr_map == NULL) {
        perror("calloc");
        return -1;
    }

    // Allocate memory for the BBL counters:
    bbl_map = (bbl_map_t *)calloc(max_ins_count/10, sizeof(bbl_map_t));
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

    clock_t start_clock = clock();

    // step 1: Check size of executable sections and allocate required memory:
    rc = allocate_and_init_memory(img);
    if (rc < 0) {
        cerr << "failed to initialize memory for translation\n";
        return;
    }
    cerr << "after memory allocation" << endl;

    // Step 2: go over all routines and identify candidate routines and copy
    //         their code into the instr map IR:
    rc = create_tc(img);
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
       //dump_entire_instr_map_with_prof();     // dump all translated instructions in map_instr
    }
    
    // Step 7: Commit the translated routines:
    //         Go over the candidate functions and replace the original ones
    //         by their new successfully translated ones:
    if (!KnobDoNotCommitTranslatedCode) {
      commit_translated_rtns_to_tc();
      cerr << "after commit of translated routines from orig code to TC" << endl;
    }
    
    clock_t end_clock = clock();
    cerr << " create_tc took: " << (double)(end_clock - start_clock) / CLOCKS_PER_SEC << " seconds\n";
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
