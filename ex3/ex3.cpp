//ex3
// ex3.cpp - Basic block profiling with Probe mode using PIN (with XED-based NOP insertion)

#include "pin.H"
extern "C" {
#include "xed-interface.h"
}

#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <algorithm>

#define MAX_BBL_NUM 10000

using std::cerr;
using std::endl;
using std::ofstream;
using std::map;
using std::pair;
using std::sort;
using std::vector;

static UINT64 rax_mem;
static UINT64 bb_map_mem[MAX_BBL_NUM];
static ADDRINT bb_addresses[MAX_BBL_NUM] = {0};
static UINT32 total_bbls = 0;

PIN_LOCK pinLock;
ofstream OutFile;

xed_state_t dstate = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };

// Called before each basic block executes (manually inserted instruction instrumentation)
VOID InstrumentBBL(BBL bbl, UINT32 bbl_id) {
    INS lastIns = BBL_InsTail(bbl);

    // Add XED-based NOP before jump
    if ((INS_IsDirectControlFlow(lastIns) || INS_IsIndirectControlFlow(lastIns)) &&
        !INS_IsRet(lastIns) && !INS_IsCall(lastIns)) {
        xed_encoder_instruction_t enc_instr;
        xed_inst0(&enc_instr, dstate, XED_ICLASS_NOP, 64);

        xed_encoder_request_t enc_req;
        xed_encoder_request_zero_set_mode(&enc_req, &dstate);
        if (!xed_convert_to_encoder_request(&enc_req, &enc_instr)) {
            cerr << "Error: failed to convert to encoder request for NOP" << endl;
            return;
        }
        UINT8 encoded[15];
        unsigned int encoded_len = 0;
        if (xed_encode(&enc_req, encoded, 15, &encoded_len) != XED_ERROR_NONE) {
            cerr << "Error: failed to encode NOP instruction" << endl;
            return;
        }

        INS_InsertFill(lastIns, IPOINT_BEFORE, encoded, encoded_len);
    }

    // Manual instrumentation to increment bb_map_mem[bbl_id]
    BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)[] (UINT32 id) {
        UINT64 tmp = bb_map_mem[id];
        tmp++;
        bb_map_mem[id] = tmp;
    }, IARG_UINT32, bbl_id, IARG_END);
}

VOID ImageLoad(IMG img, VOID *v) {
    if (!IMG_IsMainExecutable(img)) return;

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            RTN_Open(rtn);
            for (BBL bbl = RTN_BblHead(rtn); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
                if (total_bbls >= MAX_BBL_NUM) continue;
                UINT32 bbl_id = total_bbls;
                bb_addresses[bbl_id] = BBL_Address(bbl);
                InstrumentBBL(bbl, bbl_id);
                total_bbls++;
            }
            RTN_Close(rtn);
        }
    }
}

VOID Fini(INT32 code, VOID *v) {
    OutFile.open("bb-profile.csv");
    vector<pair<ADDRINT, UINT64>> bb_data;
    for (UINT32 i = 0; i < total_bbls; ++i) {
        if (bb_map_mem[i] > 0)
            bb_data.push_back(std::make_pair(bb_addresses[i], bb_map_mem[i]));
    }
    sort(bb_data.begin(), bb_data.end(), [](const auto &a, const auto &b) {
        return b.second < a.second;
    });
    for (const auto &p : bb_data) {
        OutFile << std::hex << p.first << ", " << std::dec << p.second << endl;
    }
    OutFile.close();
}

INT32 Usage() {
    cerr << "This tool profiles basic blocks with XED-inserted NOPs and manual counters, writing to bb-profile.csv" << endl;
    return -1;
}

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();
    PIN_InitLock(&pinLock);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgramProbed();
    return 0;
}
