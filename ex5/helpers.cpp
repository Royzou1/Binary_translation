#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <values.h>
#include <set>
#include <map>
#include <time.h>

using namespace std;


bool is_fall_through(INS ins)
    INS next_ins = INS_Next(ins);
    bool isNextInsJumpTarget = 
        (!INS_Valid(next_ins) ? false : is_targ_map[INS_Address(next_ins)]);
    return  || isNextInsJumpTargetreturn;
    