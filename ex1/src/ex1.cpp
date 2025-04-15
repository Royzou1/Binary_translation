#include "pin.H"
#include <iostream>
#include <fstream>

std::ofstream outfile;

VOID Routine(RTN rtn, VOID* v) {
    // Just a placeholder routine hook
    std::cerr << "Routine: " << RTN_Name(rtn) << std::endl;
}

VOID Fini(INT32 code, VOID* v) {
    std::cerr << "Done." << std::endl;
}

int main(int argc, char* argv[]) {
    if (PIN_Init(argc, argv)) {
        std::cerr << "PIN Init failed" << std::endl;
        return 1;
    }

    RTN_AddInstrumentFunction(Routine, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram(); // Never returns

    return 0;
}
