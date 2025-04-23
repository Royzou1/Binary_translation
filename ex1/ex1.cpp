#include "pin.H"
#include <fstream>
#include <iostream>
#include <map>
#include <vector>
#include <algorithm>
#include <iomanip>    // for std::hex, std::dec

using std::string;
using std::map;
using std::vector;
using std::ofstream;

// ------------------------------------------------------------------
// Struct to hold everything we need about each routine
struct routine_attributes {
    string  image_name;
    ADDRINT image_address;
    string  name;
    ADDRINT address;
    UINT64  instruction_count   = 0;
    UINT64  number_of_times_called = 0;
};

// Global map from routine start address → its attributes
static map<ADDRINT, routine_attributes> routineMap;

// Output file handle
static ofstream OutFile;

// Called before every instruction within a routine
VOID CountInstruction(ADDRINT rtnAddr) {
    routineMap[rtnAddr].instruction_count++;
}

// Called at the entry point of a routine
VOID RoutineEntry(ADDRINT rtnAddr) {
    routineMap[rtnAddr].number_of_times_called++;
}

// Instrument all routines
VOID RoutineInstrumentation(RTN rtn, VOID* v) {
    if (!RTN_Valid(rtn)) return;
    RTN_Open(rtn);

    // Find the image that contains this routine
    IMG img = SEC_Img(RTN_Sec(rtn));
    if (!IMG_Valid(img)) {
        RTN_Close(rtn);
        return;
    }

    // Initialize our record for this routine
    routine_attributes attr;
    attr.image_name    = IMG_Name(img);
    attr.image_address = IMG_LoadOffset(img);
    attr.name          = RTN_Name(rtn);
    attr.address       = RTN_Address(rtn);
    routineMap[attr.address] = attr;

    // Count calls
    RTN_InsertCall(
        rtn, IPOINT_BEFORE, (AFUNPTR)RoutineEntry,
        IARG_ADDRINT, RTN_Address(rtn),
        IARG_END);

    // Count *every* instruction
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)CountInstruction,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_END);
    }

    RTN_Close(rtn);
}

// At program end: filter, sort, and dump CSV
VOID Fini(INT32 code, VOID* v) {
    OutFile.open("rtn-output.csv");
    vector<routine_attributes> executed;

    // Keep only routines with at least one instruction
    for (auto& kv : routineMap) {
        const auto& attr = kv.second;
        if (attr.instruction_count > 0) {
            executed.push_back(attr);
        }
    }

    // Sort descending by instruction_count
    std::sort(executed.begin(), executed.end(),
        [](auto& a, auto& b) {
            return a.instruction_count > b.instruction_count;
        });

    // Write CSV: image, 0ximage_addr, name, 0xrtn_addr, inst_count, call_count
    for (auto& r : executed) {
        OutFile
            << r.image_name << ", "
            << "0x" << std::hex << r.image_address << std::dec << ", "
            << r.name       << ", "
            << "0x" << std::hex << r.address       << std::dec << ", "
            << r.instruction_count << ", "
            << r.number_of_times_called
            << "\n";
    }
    OutFile.close();
}

int main(int argc, char* argv[]) {
    // Initialize Pin and its symbol table
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        std::cerr << "Usage: pin -t ex1.so -- <target_app> [args]\n";
        return 1;
    }

    // Register our instrumentation callbacks
    RTN_AddInstrumentFunction(RoutineInstrumentation, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);

    // Start the program under Pin’s control
    PIN_StartProgram();
    return 0;
}
