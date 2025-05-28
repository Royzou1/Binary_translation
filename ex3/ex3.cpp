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

// Globals
static UINT64 bbl_counts[MAX_BBL_NUM] = {0};
static ADDRINT bbl_addresses[MAX_BBL_NUM] = {0};
static UINT32 total_bbls = 0;
PIN_LOCK pinLock;
ofstream OutFile;

// Called each time a BBL is executed
VOID CountBBL(UINT32 id) {
    bbl_counts[id]++;
}

// Instrument each trace with Probe-mode-compatible logic
VOID TraceInstrument(TRACE trace, VOID *v) {
    // Iterate over all basic blocks in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        INS tail = BBL_InsTail(bbl);

        if (INS_IsDirectControlFlow(tail) && !INS_IsCall(tail) && !INS_IsRet(tail)) {
            if (total_bbls >= MAX_BBL_NUM)
                continue;

            UINT32 id = total_bbls;
            bbl_addresses[id] = BBL_Address(bbl);

            BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)CountBBL,
                          IARG_UINT32, id,
                          IARG_END);

            total_bbls++;
        }
    }
}

// Write output
VOID Fini(INT32 code, VOID *v) {
    OutFile.open("bb-profile.csv");
    vector<pair<ADDRINT, UINT64>> data;

    for (UINT32 i = 0; i < total_bbls; i++) {
        if (bbl_counts[i] > 0)
            data.emplace_back(bbl_addresses[i], bbl_counts[i]);
    }

    sort(data.begin(), data.end(), [](const auto &a, const auto &b) {
        return b.second < a.second;
    });

    for (const auto &p : data) {
        OutFile << std::hex << p.first << ", " << std::dec << p.second << endl;
    }

    OutFile.close();
}

INT32 Usage() {
    cerr << "Usage: pintool in Probe mode tracking basic blocks ending in direct jumps." << endl;
    return -1;
}

int main(int argc, char *argv[]) {
    printf("Hello");
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();
    PIN_InitLock(&pinLock);

    TRACE_AddInstrumentFunction(TraceInstrument, 0);
    PIN_AddFiniFunction(Fini, 0);
    printf("in to the pintool");
    PIN_StartProgramProbed(); // Probe mode!
    return 0;
}
