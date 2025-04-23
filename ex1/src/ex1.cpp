#include "pin.H"
#include <fstream>
#include <iostream>
#include <map>
#include <vector>
#include <algorithm>

using std::string;
using std::map;
using std::vector;
using std::ofstream;

struct routine_attributes {
    string image_name;
    ADDRINT image_address;
    string name;              
    ADDRINT address;
    UINT64 instruction_count = 0;
    UINT64 number_of_times_called = 0;
};

map<RTN, routine_attributes> routineMap;
ofstream OutFile;

// Count instructions executed in a routine
VOID CountInstruction(RTN rtn) {
    routineMap[rtn].instruction_count++;
}

// Count number of times the routine is called
VOID RoutineEntry(RTN rtn) {
    routineMap[rtn].number_of_times_called++;
}

// Instrument each routine
VOID Routine(RTN rtn, VOID* v) {
    if (!RTN_Valid(rtn)) return;

    RTN_Open(rtn);
    routine_attributes attr;

    IMG img = SEC_Img(RTN_Sec(rtn));
    attr.image_name = IMG_Name(img);
    attr.image_address = IMG_LoadOffset(img);
    attr.name = RTN_Name(rtn);
    attr.address = RTN_Address(rtn);

    routineMap[rtn] = attr;

    // Track each routine call
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)RoutineEntry, IARG_PTR, rtn, IARG_END);

    // Track instruction execution within routine
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CountInstruction, IARG_PTR, rtn, IARG_END);
    }

    RTN_Close(rtn);
}

// Sort routines by instruction count descending
bool SortByInstructions(const std::pair<RTN, routine_attributes>& a,
                        const std::pair<RTN, routine_attributes>& b) {
    return a.second.instruction_count > b.second.instruction_count;
}

// Output to CSV at end
VOID Fini(INT32 code, VOID* v) {
    vector<std::pair<RTN, routine_attributes>> vec(routineMap.begin(), routineMap.end());
    std::sort(vec.begin(), vec.end(), SortByInstructions);

    OutFile.open("rtn-output.csv");
    for (const auto& entry : vec) {
        const routine_attributes& attr = entry.second;
        if (attr.instruction_count == 0) continue;

        OutFile << attr.image_name << ","
                << "0x" << std::hex << attr.image_address << ","
                << attr.name << ","
                << "0x" << std::hex << attr.address << ","
                << std::dec << attr.instruction_count << ","
                << attr.number_of_times_called << "\n";
    }
    OutFile.close();
}

// Main entry point
int main(int argc, char* argv[]) {
    if (PIN_Init(argc, argv)) {
        std::cerr << "PIN_Init failed\n";
        return 1;
    }

    RTN_AddInstrumentFunction(Routine, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);

    PIN_StartProgram(); // Never returns
    return 0;
}
