/* 0460275 - Spring - HW #2  */

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

// Global storage for execution counts
static UINT64 bb_counters[MAX_BBL_NUM] = {0};
static ADDRINT bb_addresses[MAX_BBL_NUM] = {0};
static UINT32 total_bbls = 0;

// Lock for thread safety (though probe mode is single-threaded safe)
PIN_LOCK pinLock;

// Output file
ofstream OutFile;

// Called before each basic block executes
VOID BBExecCount(UINT32 bbl_id) {
    bb_counters[bbl_id]++;
}

// Instrumentation function to profile basic blocks
VOID ImageLoad(IMG img, VOID *v) {
    if (!IMG_IsMainExecutable(img)) return;

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            RTN_Open(rtn);
            for (BBL bbl = RTN_BblHead(rtn); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
                if (total_bbls >= MAX_BBL_NUM) continue;
                UINT32 bbl_id = total_bbls;
                bb_addresses[bbl_id] = BBL_Address(bbl);
                BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)BBExecCount, IARG_UINT32, bbl_id, IARG_END);
                total_bbls++;
            }
            RTN_Close(rtn);
        }
    }
}

// Write out the profiling results to CSV
VOID Fini(INT32 code, VOID *v) {
    OutFile.open("bb-profile.csv");
    vector<pair<ADDRINT, UINT64>> bb_data;
    for (UINT32 i = 0; i < total_bbls; ++i) {
        if (bb_counters[i] > 0)
            bb_data.push_back(std::make_pair(bb_addresses[i], bb_counters[i]));
    }
    sort(bb_data.begin(), bb_data.end(), [](const auto &a, const auto &b) {
        return b.second < a.second; // descending
    });
    for (const auto &p : bb_data) {
        OutFile << std::hex << p.first << ", " << std::dec << p.second << endl;
    }
    OutFile.close();
}

// Usage
INT32 Usage() {
    cerr << "This tool profiles basic blocks and writes bb-profile.csv" << endl;
    return -1;
}

// Main
int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();
    PIN_InitLock(&pinLock);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgramProbed();
    return 0;
}
