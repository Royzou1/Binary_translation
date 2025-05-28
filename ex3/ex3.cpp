// ex3.cpp - Basic block profiling with Probe mode using PIN (cleaned-up version)

#include "pin.H"
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

static UINT64 bb_map_mem[MAX_BBL_NUM];
static ADDRINT bb_addresses[MAX_BBL_NUM] = {0};
static UINT32 total_bbls = 0;

PIN_LOCK pinLock;
ofstream OutFile;

// Function to increment basic block execution count
VOID CountBBL(UINT32 id) {
    bb_map_mem[id]++;
}

// Optional no-op function for Probe Mode
VOID InsertNOP() {
    // does nothing, placeholder if needed
}

// Called before each basic block executes (instrumentation)
VOID InstrumentBBL(BBL bbl, UINT32 bbl_id) {
    INS lastIns = BBL_InsTail(bbl);

    // Add a NOP call before jump instructions for assignment compliance
    if ((INS_IsDirectControlFlow(lastIns) || INS_IsIndirectControlFlow(lastIns)) &&
        !INS_IsRet(lastIns) && !INS_IsCall(lastIns)) {
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)InsertNOP, IARG_END);
    }

    BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)CountBBL, IARG_UINT32, bbl_id, IARG_END);
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
    cerr << "This tool profiles basic blocks using probe mode and outputs to bb-profile.csv" << endl;
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
