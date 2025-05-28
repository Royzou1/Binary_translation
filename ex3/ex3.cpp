#include "pin.H"
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>

#define MAX_BBL_NUM 10000

static UINT64 bbl_counts[MAX_BBL_NUM]   = {0};
static ADDRINT bbl_addresses[MAX_BBL_NUM] = {0};
static UINT32 total_bbls = 0;
static std::ofstream OutFile;

// increments the counter for this BBL id
VOID CountBBL(UINT32 id) {
    bbl_counts[id]++;
}

// called once for every instruction in the binary
VOID Instruction(INS ins, VOID *v) {
    if (INS_IsDirectControlFlow(ins)
        && !INS_IsCall(ins)
        && !INS_IsRet(ins))
    {
        if (total_bbls >= MAX_BBL_NUM) return;
        UINT32 id = total_bbls++;
        bbl_addresses[id] = INS_Address(ins);
        // insert our counter before the jump executes
        INS_InsertCall(
            ins, IPOINT_BEFORE,
            AFUNPTR(CountBBL),
            IARG_UINT32, id,
            IARG_END
        );
    }
}

// Called when the application exits
VOID Fini(INT32 code, VOID *v) {
    OutFile.open("bb-profile.csv");
    if (!OutFile.is_open()) {
        std::cerr << "ERROR: could not open output file\n";
        return;
    }
    // collect and sort only the hot ones
    std::vector<std::pair<ADDRINT,UINT64>> data;
    for (UINT32 i = 0; i < total_bbls; i++) {
        if (bbl_counts[i] > 0)
            data.emplace_back(bbl_addresses[i], bbl_counts[i]);
    }
    std::sort(data.begin(), data.end(),
              [](auto &a, auto &b){ return a.second > b.second; });
    for (auto &p : data)
        OutFile << std::hex << p.first
                << ", " << std::dec << p.second << std::endl;
    OutFile.close();
}

INT32 Usage() {
    std::cerr << "Usage: pin -probe -t mytool.so -- <app>\n";
    return -1;
}

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) return Usage();
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgramProbed();  // stays in probe mode
    return 0;
}
