// probe_bbl_counter.cpp
#include "pin.H"
#include <fstream>
#include <vector>
#include <algorithm>
#include <iostream>

#define MAX_BBL_NUM 10000

//----------------------------------------------------------------------
// Globals
//----------------------------------------------------------------------
static UINT64    bbl_counts[MAX_BBL_NUM]    = {0};
static ADDRINT   bbl_addresses[MAX_BBL_NUM] = {0};
static UINT32    total_bbls                 = 0;
static PIN_LOCK  pinLock;
static std::ofstream outFile;

//----------------------------------------------------------------------
// CountBBL: bump the counter for this BBL id
//----------------------------------------------------------------------
VOID CountBBL(UINT32 id)
{
    // thread‐safe increment in probe mode
    PIN_GetLock(&pinLock, 1);
    bbl_counts[id]++;
    PIN_ReleaseLock(&pinLock);
}

//----------------------------------------------------------------------
// ImgLoadProbe: run once per image, install BBL probes
//----------------------------------------------------------------------
VOID ImgLoadProbe(IMG img, VOID* v)
{
    // iterate all sections → routines → basic blocks
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            RTN_Open(rtn);
            for (BBL bbl = RTN_BblHead(rtn); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
                INS tail = BBL_InsTail(bbl);
                // direct jump (not call or ret)?
                if (INS_IsDirectControlFlow(tail) && 
                    !INS_IsCall(tail) && 
                    !INS_IsRet(tail))
                {
                    if (total_bbls < MAX_BBL_NUM) {
                        UINT32 id = total_bbls++;
                        bbl_addresses[id] = BBL_Address(bbl);
                        // insert a probe‐mode call anywhere in this BBL
                        BBL_InsertCallProbed(
                            bbl, 
                            IPOINT_ANYWHERE, 
                            AFUNPTR(CountBBL),
                            IARG_UINT32, id,
                            IARG_END
                        );
                    }
                }
            }
            RTN_Close(rtn);
        }
    }
}

//----------------------------------------------------------------------
// Detach: called when Pin detaches (app exit in probe mode)
//---------------------------------------------------------------------- 
VOID Detach(INT32 code, VOID* v)
{
    outFile.open("bb-profile.csv");
    std::vector<std::pair<UINT64,ADDRINT>> data;
    data.reserve(total_bbls);

    // collect only executed BBLs
    for (UINT32 i = 0; i < total_bbls; i++) {
        if (bbl_counts[i] > 0)
            data.emplace_back(bbl_counts[i], bbl_addresses[i]);
    }
    // sort by count descending
    std::sort(data.begin(), data.end(),
              [](auto &a, auto &b){ return a.first > b.first; });

    // emit: address,count
    for (auto &p : data) {
        outFile << std::hex << p.second
                << "," << std::dec << p.first << "\n";
    }
    outFile.close();
}

//----------------------------------------------------------------------
// Usage helper
//----------------------------------------------------------------------
INT32 Usage()
{
    std::cerr << "probe_bbl_counter: track BBLs ending in direct jumps\n";
    std::cerr << "  (probe mode only)\n";
    std::cerr << KNOB_BASE::StringKnobSummary() << "\n";
    return -1;
}

//----------------------------------------------------------------------
// main()
//----------------------------------------------------------------------
int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();          // needed for IMG/RTN APIs
    PIN_InitLock(&pinLock);

    // probe‐mode instrumentation
    IMG_AddInstrumentFunction(ImgLoadProbe, nullptr);
    PIN_AddDetachFunction(Detach, nullptr);

    // start in probe mode
    PIN_StartProgramProbed();
    // never returns
    return 0;
}
