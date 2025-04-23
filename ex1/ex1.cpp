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
    UINT64 number_of_times_called = 0;
};

map<ADDRINT, routine_attributes> routineMap;
ofstream OutFile;

// Count number of times the routine is called
VOID RoutineEntry(ADDRINT addr) {
    routineMap[addr].number_of_times_called++;
}

// Instrument each routine
VOID Routine(RTN rtn, VOID* v) {
    if (!RTN_Valid(rtn)) return;

    RTN_Open(rtn);

    IMG img = SEC_Img(RTN_Sec(rtn));
    if (!IMG_IsMainExecutable(img)) {
        RTN_Close(rtn);
        return;
    }

    routine_attributes attr;
    attr.image_name = IMG_Name(img);
    attr.image_address = IMG_LoadOffset(img);
    attr.name = RTN_Name(rtn);
    attr.address = RTN_Address(rtn);

    routineMap[attr.address] = attr;

    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)RoutineEntry, IARG_ADDRINT, attr.address, IARG_END);

    RTN_Close(rtn);
}

// Sort routines by number of calls descending
bool SortByCalls(const std::pair<ADDRINT, routine_attributes>& a,
                 const std::pair<ADDRINT, routine_attributes>& b) {
    return a.second.number_of_times_called > b.second.number_of_times_called;
}

// Output to CSV at end
VOID Fini(INT32 code, VOID* v) {
    vector<std::pair<ADDRINT, routine_attributes>> vec(routineMap.begin(), routineMap.end());
    std::sort(vec.begin(), vec.end(), SortByCalls);

    OutFile.open("rtn-output.csv");
    for (const auto& entry : vec) {
        const routine_attributes& attr = entry.second;
        if (attr.number_of_times_called == 0) continue;

        OutFile << attr.image_name << ","
                << "0x" << std::hex << attr.image_address << ","
                << attr.name << ","
                << "0x" << std::hex << attr.address << ","
                << std::dec << attr.number_of_times_called << "\n";
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
