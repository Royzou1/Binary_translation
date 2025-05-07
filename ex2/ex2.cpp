#include "pin.H"
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <map>
#include <vector>
#include <algorithm>
#include <iomanip>

using std::cerr;
using std::endl;
using std::hex;
using std::dec;
using std::ofstream;
using std::pair;
using std::string;
using std::unordered_map;
using std::vector;

/* ===================================================================== */
/* Data Structures */
/* ===================================================================== */

struct BBLInfo {
    ADDRINT addr;
    UINT64 exec_count = 0;
    UINT64 taken = 0;
    UINT64 fallthru = 0;
    bool is_conditional = false;
    bool is_indirect = false;
    std::map<ADDRINT, UINT64> indirect_targets;
};

unordered_map<ADDRINT, BBLInfo> bbl_map;

/* ===================================================================== */
/* Analysis Routines */
/* ===================================================================== */

VOID CountExec(ADDRINT addr) {
    bbl_map[addr].exec_count++;
}

VOID CountCondBranch(ADDRINT addr, BOOL taken) {
    if (taken) bbl_map[addr].taken++;
    else bbl_map[addr].fallthru++;
}

VOID CountIndirectTarget(ADDRINT addr, ADDRINT target) {
    bbl_map[addr].indirect_targets[target]++;
}

/* ===================================================================== */
/* Instrumentation */
/* ===================================================================== */

VOID Trace(TRACE trace, VOID* v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        ADDRINT addr = BBL_Address(bbl);
        BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)CountExec, IARG_ADDRINT, addr, IARG_END);

        INS tail = BBL_InsTail(bbl);

        if (INS_IsBranch(tail) && INS_HasFallThrough(tail)) {
            bbl_map[addr].is_conditional = true;
            INS_InsertCall(tail, IPOINT_TAKEN_BRANCH, (AFUNPTR)CountCondBranch, IARG_ADDRINT, addr, IARG_BOOL, TRUE, IARG_END);
            INS_InsertCall(tail, IPOINT_AFTER, (AFUNPTR)CountCondBranch, IARG_ADDRINT, addr, IARG_BOOL, FALSE, IARG_END);
        }

        if (INS_IsIndirectBranchOrCall(tail)) {
            bbl_map[addr].is_indirect = true;
            INS_InsertCall(tail, IPOINT_BEFORE, (AFUNPTR)CountIndirectTarget, IARG_ADDRINT, addr, IARG_BRANCH_TARGET_ADDR, IARG_END);
        }
    }
}

/* ===================================================================== */
/* Output */
/* ===================================================================== */

VOID Fini(INT32 code, VOID* v) {
    vector<BBLInfo> all;
    for (auto& it : bbl_map) {
        if (it.second.exec_count > 0)
            all.push_back(it.second);
    }

    std::sort(all.begin(), all.end(), [](const BBLInfo& a, const BBLInfo& b) {
        return a.exec_count > b.exec_count;
    });

    ofstream out("edge-profile.csv");

    for (const auto& bbl : all) {
        out << hex << bbl.addr << ", " << dec << bbl.exec_count;

        if (bbl.is_conditional)
            out << ", " << bbl.taken << ", " << bbl.fallthru;
        else
            out << ", , ";

        if (bbl.is_indirect) {
            vector<pair<ADDRINT, UINT64>> targets(bbl.indirect_targets.begin(), bbl.indirect_targets.end());
            std::sort(targets.begin(), targets.end(), [](const auto& a, const auto& b) {
                return a.second > b.second;
            });

            int count = 0;
            for (auto& [target, execs] : targets) {
                if (++count > 10) break;
                out << ", " << hex << target << " , " << dec << execs;
            }
        }
        out << "\n";
    }

    out.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

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
