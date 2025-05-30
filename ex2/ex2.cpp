#include "pin.H"
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <map>
#include <iomanip>
#include <unistd.h>

using std::cerr;
using std::endl;
using std::ofstream;
using std::pair;
using std::string;
using std::unordered_map;
using std::vector;
using std::map;

/* ============================================ */
/* Data Structure to hold BBL profiling info    */
/* ============================================ */
struct BblInfo {
    ADDRINT addr;
    UINT64 exec_count = 0;
    UINT64 taken = 0;
    UINT64 fallthru = 0;
    bool is_cond_jump = false;
    bool is_indirect_jump = false;
    map<ADDRINT, UINT64> indirect_targets;
};

unordered_map<ADDRINT, BblInfo> bbl_map;

/* ============================================ */
/* Counters for conditional and indirect jumps  */
/* ============================================ */

VOID CountExec(ADDRINT addr) {
    bbl_map[addr].exec_count++;
}

VOID CountCondBranch(ADDRINT addr, BOOL taken) {
    if (taken)
        bbl_map[addr].taken++;
    else
        bbl_map[addr].fallthru++;
}

VOID CountIndirectTarget(ADDRINT addr, ADDRINT target) {
    bbl_map[addr].indirect_targets[target]++;
}

/* ============================================ */
/* Instrument each BBL                          */
/* ============================================ */

VOID Trace(TRACE trace, VOID* v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        ADDRINT addr = BBL_Address(bbl);
        INS tail = BBL_InsTail(bbl);
        bbl_map[addr].addr=addr;

        BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)CountExec, IARG_ADDRINT, addr, IARG_END);

        if (INS_IsBranch(tail) && INS_HasFallThrough(tail)) {
            bbl_map[addr].is_cond_jump = true;

            INS_InsertCall(tail, IPOINT_TAKEN_BRANCH, (AFUNPTR)CountCondBranch,
                           IARG_ADDRINT, addr, IARG_BOOL, TRUE, IARG_END);

            INS_InsertCall(tail, IPOINT_AFTER, (AFUNPTR)CountCondBranch,
                           IARG_ADDRINT, addr, IARG_BOOL, FALSE, IARG_END);
        }

        
        if (INS_IsIndirectControlFlow(tail)) {
            bbl_map[addr].is_indirect_jump = true;

            INS_InsertCall(tail, IPOINT_BEFORE, (AFUNPTR)CountIndirectTarget,
                           IARG_ADDRINT, addr, IARG_BRANCH_TARGET_ADDR, IARG_END);
        }
    }
}

/* ============================================ */
/* Output results                               */
/* ============================================ */

VOID Fini(INT32 code, VOID* v) {
    vector<BblInfo> sorted;

    // Collect all executed basic blocks into a vector for sorting
    for (auto it = bbl_map.begin(); it != bbl_map.end(); ++it) {
        if (it->second.exec_count > 0)
            sorted.push_back(it->second);
    }

    // Sort by execution count in descending order
    std::sort(sorted.begin(), sorted.end(), [](const BblInfo& a, const BblInfo& b) {
        return a.exec_count > b.exec_count;
    });

    ofstream out("edge-profile.csv");

    //write titels for order
    out << "<BBL_address>\t<BBL_exec_count>\t<BBL_conditionals_jumped>\t<BBL_conditionals_fellthrough>";
    for (int i = 1; i <= 10; ++i) {
        out << "\t<BBL_indirect_" << i << "_address>\t<BBL_indirect_" << i << "_jumped>";
    }
    out << "\n";

    // Write profiling data
    for (size_t i = 0; i < sorted.size(); ++i) {
        const BblInfo& bbl = sorted[i];

        // Basic information for the BBL
        out << std::hex << bbl.addr << "\t"
            << std::dec << bbl.exec_count << "\t"
            << bbl.taken << "\t"
            << bbl.fallthru ;
            


        // Add up to 10 most frequent indirect targets
        int limit = 0;
        if (bbl.is_indirect_jump) {
            vector<pair<ADDRINT, UINT64>> targets(bbl.indirect_targets.begin(), bbl.indirect_targets.end());
            std::sort(targets.begin(), targets.end(), [](const pair<ADDRINT, UINT64>& a, const pair<ADDRINT, UINT64>& b) {
                return a.second > b.second;
            });

            for (size_t j = 0; j < targets.size() && limit < 10; ++j, ++limit) {
                out << "\t" << std::hex << targets[j].first << "\t" << std::dec << targets[j].second;
            }
        }

     

        out << "\n";
    }

    out.close();
}

/* ============================================ */
/* Main                                         */
/* ============================================ */

int main(int argc, char* argv[]) {
    if (PIN_Init(argc, argv)) {
        cerr << "PIN Init failed\n";
        return 1;
    }

    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram(); // Never returns
    return 0;
}
