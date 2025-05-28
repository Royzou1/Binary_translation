// probe_bbl_counter.cpp

#include "pin.H"
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>

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
    PIN_GetLock(&pinLock, 1);
    bbl_counts[id]++;
    PIN_ReleaseLock(&pinLock);
}

//----------------------------------------------------------------------
// ImgLoadProbe: for each routine in each image, insert probes on BBLs
//----------------------------------------------------------------------

VOID ImgLoadProbe(IMG img, VOID* v)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            RTN_Open(rtn);
            for (BBL bbl = RTN_BblHead(rtn); BBL_Valid(bbl); bbl = BBL_Next(bbl))
            {
                INS tail = BBL_InsTail(bbl);
                // direct jump, but not a call or return?
                if (INS_IsDirectControlFlow(tail) &&
                    !INS_IsCall(tail) &&
                    !INS_IsRet(tail))
                {
                    if (total_bbls < MAX_BBL_NUM)
                    {
                        UINT32 id = total_bbls;
                        bbl_addresses[id] = BBL_Address(bbl);

                        BBL_InsertCallProbed(
                            bbl,
                            IPOINT_ANYWHERE,
                            AFUNPTR(CountBBL),
                            IARG_UINT32, id,
                            IARG_END
                        );

                        total_bbls++;
                    }
                }
            }
            RTN_Close(rtn);
        }
    }
}

//----------------------------------------------------------------------
// Detach: called when the application exits in probe mode
//----------------------------------------------------------------------

VOID Detach(INT32 code, VOID* v)
{
    outFile.open("bb-profile.csv");
    std::vector<std::pair<UINT64,ADDRINT>> data;
    data.reserve(total_bbls);

    for (UINT32 i = 0; i < total_bbls; i++)
    {
        if (bbl_counts[i] > 0)
            data.emplace_back(bbl_counts[i], bbl_addresses[i]);
    }

    std::sort(data.begin(), data.end(),
              [](auto &a, auto &b){ return a.first > b.first; });

    for (auto &p : data)
    {
        outFile << std::hex << p.second
                << "," << std::dec << p.first << std::endl;
    }
    outFile.close();
}

//----------------------------------------------------------------------
// Usage helper
//----------------------------------------------------------------------

INT32 Usage()
{
    std::cerr << "probe_bbl_counter: track basic blocks ending in direct jumps\n"
              << "Usage:  pin -t probe_bbl_counter.so -probe -- <app> [app args]\n";
    return -1;
}

//----------------------------------------------------------------------
// main()
//----------------------------------------------------------------------

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();
    PIN_InitLock(&pinLock);

    IMG_AddInstrumentFunction(ImgLoadProbe, nullptr);
    PIN_AddDetachFunction(Detach, nullptr);

    PIN_StartProgramProbed();  // probe mode
    return 0;
}
