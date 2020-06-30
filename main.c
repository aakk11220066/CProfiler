#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>

void myExit(int retVal){
    //perror("ptrace");
    exit(retVal);
}

#define C_TRYCATCH(syscall) if ((syscall) < 0) myExit(1)
#define C_CATCHERRNULL(retVal) if (!(retVal)) myExit(1)
#define C_CATCHERR(retVal) if ((retVal) < 0) myExit(1)

#define DEFAULT_ERRNO 0
#define MAX_VAR_NAME_LENGTH 256
#define MAX_REG_NAME_LENGTH 3
#define WORD_PROFILE_LENGTH 7

typedef unsigned long long int registerContent;

struct StringStringMap;
struct StringStringMap create_StringStringMap();
//note: does not free target from heap
void destroy_StringStringMap(struct StringStringMap* target);
struct StringStringPair* at_StringStringMap(
        const struct StringStringMap* map,
        const char* key);
void insert_StringStringMap(
        struct StringStringMap* map,
        const struct StringStringPair* mapping);
void erase_StringStringMap(
        struct StringStringMap* map,
        const char* key);
//NOTE: map is a pointer
#define StringStringMapFOREACH(item, map) \
    for(struct StringStringPair* item = (map)->mappings; item != NULL; item = item->_next)

struct StringStringPair;
struct StringStringPair create_StringStringPair(const char* key, const char* data);
void destroy_StringStringPair(struct StringStringPair* target);

struct StringRegistercontentMap;
struct StringRegistercontentMap create_StringRegistercontentMap();
//note: does not free target from heap
void destroy_StringRegistercontentMap(struct StringRegistercontentMap* target);
struct StringRegistercontentPair* at_StringRegistercontentMap(
        const struct StringRegistercontentMap* map, 
        const char* key);
void insert_StringRegistercontentMap(
        struct StringRegistercontentMap* map,
        const struct StringRegistercontentPair* mapping);
void erase_StringRegistercontentMap(
        struct StringRegistercontentMap* map,
        const char* key);
//NOTE: map is a pointer
#define StringRegistercontentMapFOREACH(item, map) \
    for(struct StringRegistercontentPair* item = map->mappings; item; item = item->_next)

struct StringRegistercontentPair;
struct StringRegistercontentPair create_StringRegistercontentPair(const char* key, const registerContent data);
void destroy_StringRegistercontentPair(struct StringRegistercontentPair* target);

//get input from user, return a mapping of (variable name, r name)
struct StringStringMap getRegisterMap();

//tell debuggee to run a single instruction
void singleStep(pid_t debuggee);

//inserts given byte at requested address
//returns overwritten byte
unsigned char insertByte(void *targetAddress, pid_t debuggee, unsigned char replacement);

//inserts debug interrupt at requested address
//returns overwritten byte
unsigned char insertBreakpoint(void* breakpointAddress, pid_t debuggee);

//locally restore debuggee to natural state (without breakpoint)
//1. restores overwritten byte to original placement
//2. backs up rip by one instruction (one byte)
//3. runs a single instruction of debuggee
//4. replaces debug interrupt back into breakpointAddress
void stepPastBreakpoint(void* breakpointAddress, unsigned char replacedByte, pid_t debuggee);

//1. places trace on self (with ptrace(PTRACE_TRACEME))
//2. execute debuggee program
//3. wait to begin actual run until told to continue, to allow time for emplacement of breakpoints
void loadDebuggedProgram(char* programArgs[]);

//Returns the value of a requested register (given by register name) from a user_regs_struct
registerContent getVarValueFromUser_regs_struct(const struct user_regs_struct* regs, const char* requestedRegister);

//returns values of variables in (currently paused) debugged program
struct StringRegistercontentMap storeVariables(const struct StringStringMap* variableMap, pid_t debuggee);

//Informs user (prints to screen) that variable varName changed from oldValue to newValue in inspected code
void printDifference(const char* varName, const registerContent oldValue, const registerContent newValue);

//compare data from requested variables with previous data on them, print to user
void compareVariables(
        const struct StringRegistercontentMap* oldVariableValues,
        const struct StringStringMap* variableMap,
        pid_t debuggee);

//signals debuggee (who was waiting in step 3 of loadDebuggedProgram for setup to complete) to get started running
void startDebuggeeRun(pid_t debuggee);

//manage debugging the code
void runDebugger(char *programArgs[], void *beginAddress, void *endAddress,
                 const struct StringStringMap* variableMap);

//-------------------------C implementations for C++ structures-----------------------
struct StringStringPair{ //this is a linked list
    const char* first;
    const char* second;

    //private
    struct StringStringPair* _next;
};
struct StringStringPair create_StringStringPair(const char* key, const char* data){
    assert(key && data);
    struct StringStringPair result = {
            (const char*)malloc(sizeof(char)*(MAX_VAR_NAME_LENGTH+1)),
            (const char*)malloc(sizeof(char)*(WORD_PROFILE_LENGTH+1)),
            NULL};
    C_CATCHERRNULL(result.first);
    C_CATCHERRNULL(result.second);
    strcpy(((char*)(result.first)), key);
    strcpy(((char*)(result.second)), data);
    return result;
}
void destroy_StringStringPair(struct StringStringPair* target){
    if (!target) return;
    free((char*)(target->first));
    free((char*)(target->second));
    free(target);
}

struct StringRegistercontentPair{ //this is a linked list
    const char* first; //key
    registerContent second; //second

    //private
    struct StringRegistercontentPair* _next;
};
struct StringRegistercontentPair create_StringRegistercontentPair(const char* key, const registerContent data){
    assert(key);
    struct StringRegistercontentPair result = {
            (const char*)malloc(sizeof(char)*(MAX_VAR_NAME_LENGTH+1)),
            data,
            NULL};
    C_CATCHERRNULL(result.first);
    strcpy(((char*)(result.first)), key);
    return result;
}
void destroy_StringRegistercontentPair(struct StringRegistercontentPair* target){
    if (!target) return;
    free((char*)(target->first));
    free(target);
}

#define MAP_CREATE(MAP_TYPE) do { \
    struct MAP_TYPE result = {NULL}; \
    return result; \
} while (false)
#define MAP_DESTROY(PAIR_TYPE, PAIR_DESTROY, target) do{ \
    struct PAIR_TYPE* nextPair = NULL; \
    for (struct PAIR_TYPE* targetPair = target->mappings; targetPair; targetPair = nextPair){ \
        nextPair = targetPair->_next; \
        PAIR_DESTROY (targetPair); \
    } \
} while (false)
#define MAP_AT(FOREACH, map, key) do{ \
    FOREACH(current, map){ \
        if (!strcmp(current->first, key)) return current; \
    } \
    assert(false); \
} while (false)
#define MAP_INSERT(PAIR_TYPE, map, mapping) do { \
    struct PAIR_TYPE* newPair = (struct PAIR_TYPE*) malloc(sizeof(*newPair)); \
    C_CATCHERRNULL(newPair); \
    \
    *newPair = *mapping; \
    newPair->_next = map->mappings; \
    map->mappings = newPair; \
} while (false)
#define LINKED_LIST_ERASE(PREV_NEXT_FIELD, PAIR_TYPE, PAIR_DESTROY) do{ \
    struct PAIR_TYPE* grandson = PREV_NEXT_FIELD->_next; \
    PAIR_DESTROY (PREV_NEXT_FIELD); \
    PREV_NEXT_FIELD = grandson; \
} while (false)
#define MAP_ERASE(FOREACH, PAIR_TYPE, PAIR_DESTROY, map, key) do{ \
    if (map->mappings && !strcmp(map->mappings->first, key)){ \
        LINKED_LIST_ERASE(map->mappings, PAIR_TYPE, PAIR_DESTROY); \
    } \
    FOREACH(prevPair, map){ \
        if (prevPair->_next && !strcmp(prevPair->_next->first, key)){ \
            LINKED_LIST_ERASE(prevPair, PAIR_TYPE, PAIR_DESTROY); \
        } \
    } \
} while (false)

struct StringStringMap{
    struct StringStringPair* mappings;
};
struct StringStringMap create_StringStringMap(){
    MAP_CREATE(StringStringMap);
}
//note: does not free target from heap
void destroy_StringStringMap(struct StringStringMap* target){
    MAP_DESTROY(StringStringPair, destroy_StringStringPair, target);
}
struct StringStringPair* at_StringStringMap(
        const struct StringStringMap* map,
        const char* key){

    MAP_AT(StringStringMapFOREACH, map, key);
}
void insert_StringStringMap(
        struct StringStringMap* map,
        const struct StringStringPair* mapping){

    MAP_INSERT(StringStringPair, map, mapping);
}
void erase_StringStringMap(
        struct StringStringMap* map,
        const char* key){

    MAP_ERASE(StringStringMapFOREACH, StringStringPair, destroy_StringStringPair, map, key);
}

struct StringRegistercontentMap{
    struct StringRegistercontentPair* mappings;
};
struct StringRegistercontentMap create_StringRegistercontentMap(){
    MAP_CREATE(StringRegistercontentMap);
}
//note: does not free target from heap
void destroy_StringRegistercontentMap(struct StringRegistercontentMap* target){
    MAP_DESTROY(StringRegistercontentPair, destroy_StringRegistercontentPair, target);
}
struct StringRegistercontentPair* at_StringRegistercontentMap(
        const struct StringRegistercontentMap* map,
        const char* key){

    MAP_AT(StringRegistercontentMapFOREACH, map, key);
}
void insert_StringRegistercontentMap(
        struct StringRegistercontentMap* map,
        const struct StringRegistercontentPair* mapping){

    MAP_INSERT(StringRegistercontentPair, map, mapping);
}
void erase_StringRegistercontentMap(
        struct StringRegistercontentMap* map,
        const char* key){
    
    MAP_ERASE(StringRegistercontentMapFOREACH, StringRegistercontentPair, 
            destroy_StringRegistercontentPair, map, key);
}

//------------------------------------------PROFILER IMPLEMENTATIONS--------------------------
int main(int argc, char* argv[]) {
    struct StringStringMap variableMap = getRegisterMap(); //mapping of variableName,register name

    registerContent beginAddress = 0;
    registerContent endAddress = 0;
    if (sscanf(argv[1], "%llx", &beginAddress) == EOF) exit(1);
    if (sscanf(argv[2], "%llx", &endAddress) == EOF) exit(1);

    //note: argv is null-terminated
    runDebugger(argv+3, (void *) beginAddress, (void *) endAddress, &variableMap);

    destroy_StringStringMap(&variableMap);
    return 0;
}

//get input from user, return a mapping of (variable name, r name)
struct StringStringMap getRegisterMap(){
    char variable[MAX_VAR_NAME_LENGTH+1];
    char strRegister[WORD_PROFILE_LENGTH+1];
    struct StringStringMap result;

    do{
        scanf("%s", variable);
        scanf("%s", strRegister);
        struct StringStringPair newMapping = create_StringStringPair(variable, strRegister);
        insert_StringStringMap(&result, &newMapping);
    } while (strcmp(variable,"run") || strcmp(strRegister,"profile"));
    erase_StringStringMap(&result, "run"); //alternatively, just erase front

    return result;
}

//tell debuggee to run a single instruction
void singleStep(pid_t debuggee){
    C_TRYCATCH(ptrace(PTRACE_SINGLESTEP, debuggee, NULL, NULL));
    int debugeeSinglestepStatus = 0;
    C_TRYCATCH(wait(&debugeeSinglestepStatus)); //wait for debuggee to return from singlestep
}

//inserts given byte at requested address
//returns overwritten byte
unsigned char insertByte(void *targetAddress, pid_t debuggee, unsigned char replacement) {

    //get word that will be overwritten
    unsigned long modifiedWord = ptrace(PTRACE_PEEKTEXT, debuggee, targetAddress, NULL);
    if (errno != DEFAULT_ERRNO) C_CATCHERR(modifiedWord);
    unsigned char replacedByte = (unsigned char) modifiedWord;

    //replace first byte of word with debug interrupt
    const unsigned long debugInterruptCode = replacement;
    const unsigned long clearMask = 0xffffffffffffff00;
    modifiedWord = (modifiedWord & clearMask);
    modifiedWord |= debugInterruptCode;

    //poketext word in
    C_TRYCATCH(ptrace(PTRACE_POKETEXT, debuggee, targetAddress, (void*) modifiedWord));

    return replacedByte;
}

//inserts debug interrupt at requested address
//returns overwritten byte
unsigned char insertBreakpoint(void *breakpointAddress, pid_t debuggee) {
    return insertByte(breakpointAddress, debuggee, 0xcc);
}

//locally restore debuggee to natural state (without breakpoint)
//1. restores overwritten byte to original placement
//2. backs up rip by one instruction (one byte)
//3. runs a single instruction of debuggee
//4. replaces debug interrupt back into breakpointAddress
void stepPastBreakpoint(void* breakpointAddress, unsigned char replacedByte, pid_t debuggee){
    //1. restores overwritten byte to original placement
    insertByte(breakpointAddress, debuggee, replacedByte);

    //2. backs up rip by one instruction (one byte)
    struct user_regs_struct debuggeeRegisters;
    C_TRYCATCH(ptrace(PTRACE_GETREGS, debuggee, NULL, &debuggeeRegisters));
    --debuggeeRegisters.rip;
    C_TRYCATCH(ptrace(PTRACE_SETREGS, debuggee, NULL, &debuggeeRegisters));

    //3. runs a single instruction of debuggee
    singleStep(debuggee);

    //4. replaces debug interrupt back into breakpointAddress
    insertBreakpoint(breakpointAddress, debuggee);
}

//1. places trace on self (with ptrace(PTRACE_TRACEME))
//2. execute debuggee program
//3. wait to begin actual run until told to continue, to allow time for emplacement of breakpoints
void loadDebuggedProgram(char* programArgs[]) {
    //1. places trace on self (with ptrace(PTRACE_TRACEME))
    const pid_t SELF = 0;
    C_TRYCATCH(ptrace(PTRACE_TRACEME, SELF, NULL, NULL));

    //2. execute debuggee program
    C_TRYCATCH(execv(programArgs[0], programArgs));

    //3. wait to begin actual run until told to continue, to allow time for emplacement of breakpoints
}

//Returns the value of a requested register (given by register name) from a user_regs_struct
registerContent getVarValueFromUser_regs_struct(const struct user_regs_struct* regs, const char* requestedRegister) {
    //64-bit registers
    if (!strcmp(requestedRegister, "rax")) return regs->rax;
    if (!strcmp(requestedRegister, "rbx")) return regs->rbx;
    if (!strcmp(requestedRegister, "rcx")) return regs->rcx;
    if (!strcmp(requestedRegister, "rdx")) return regs->rdx;
    if (!strcmp(requestedRegister, "rsi")) return regs->rsi;

    //32-bit registers
    if (!strcmp(requestedRegister, "eax")) return (unsigned long long int)(unsigned int) regs->rax;
    if (!strcmp(requestedRegister, "ebx")) return (unsigned long long int)(unsigned int) regs->rbx;
    if (!strcmp(requestedRegister, "ecx")) return (unsigned long long int)(unsigned int) regs->rcx;
    if (!strcmp(requestedRegister, "edx")) return (unsigned long long int)(unsigned int) regs->rdx;
    if (!strcmp(requestedRegister, "esi")) return (unsigned long long int)(unsigned int) regs->rsi;

    //16-bit registers
    if (!strcmp(requestedRegister, "ax")) return (unsigned long long int)(unsigned short) regs->rax;
    if (!strcmp(requestedRegister, "bx")) return (unsigned long long int)(unsigned short) regs->rbx;
    if (!strcmp(requestedRegister, "cx")) return (unsigned long long int)(unsigned short) regs->rcx;
    if (!strcmp(requestedRegister, "dx")) return (unsigned long long int)(unsigned short) regs->rdx;
    if (!strcmp(requestedRegister, "si")) return (unsigned long long int)(unsigned short) regs->rsi;

    //8-bit low registers
    if (!strcmp(requestedRegister, "al")) return (unsigned long long int)(unsigned char) regs->rax;
    if (!strcmp(requestedRegister, "bl")) return (unsigned long long int)(unsigned char) regs->rbx;
    if (!strcmp(requestedRegister, "cl")) return (unsigned long long int)(unsigned char) regs->rcx;
    if (!strcmp(requestedRegister, "dl")) return (unsigned long long int)(unsigned char) regs->rdx;
    if (!strcmp(requestedRegister, "sil")) return (unsigned long long int)(unsigned char) regs->rsi;

    //8-bit high registers
    if (!strcmp(requestedRegister, "ah")) return
                ((unsigned long long int)(((unsigned short) regs->rax)) >> 8);
    if (!strcmp(requestedRegister, "bh")) return
                ((unsigned long long int)(((unsigned short) regs->rbx)) >> 8);
    if (!strcmp(requestedRegister, "ch")) return
                ((unsigned long long int)(((unsigned short) regs->rcx)) >> 8);
    if (!strcmp(requestedRegister, "dh")) return
                ((unsigned long long int)(((unsigned short) regs->rdx)) >> 8);
    //not an intel register:
    // if (!requestedRegister.compare("sih")) return
    //      ((unsigned long long int)(((unsigned short) regs.rsi)) >> 8);

    printf("%s is not a register!", requestedRegister);
    myExit(1);
}

//returns values of variables in (currently paused) debugged program
struct StringRegistercontentMap storeVariables(const struct StringStringMap* variableMap, pid_t debuggee){
    struct StringRegistercontentMap variableValues = create_StringRegistercontentMap();

    struct user_regs_struct debuggeeRegisters;
    C_TRYCATCH(ptrace(PTRACE_GETREGS, debuggee, NULL, &debuggeeRegisters));

    StringStringMapFOREACH(varToReg_mapping, variableMap){
        registerContent varValue = getVarValueFromUser_regs_struct(&debuggeeRegisters, varToReg_mapping->second);
        struct StringRegistercontentPair newVariableEntry = 
                create_StringRegistercontentPair(varToReg_mapping->first, varValue);
        insert_StringRegistercontentMap(&variableValues, &newVariableEntry);
    }

    return variableValues;
}


//Informs user (prints to screen) that variable varName changed from oldValue to newValue in inspected code
void printDifference(const char* varName, const registerContent oldValue, const registerContent newValue){
    C_TRYCATCH(printf("PRF:: %s: %lld->%lld\n", varName, oldValue, newValue));
}

//compare data from requested variables with previous data on them, print to user
void compareVariables(
        const struct StringRegistercontentMap* oldVariableValues,
        const struct StringStringMap* variableMap,
        pid_t debuggee){

    struct StringRegistercontentMap newVariableValues = storeVariables(variableMap, debuggee);

    StringRegistercontentMapFOREACH(oldVariable, oldVariableValues){
        const registerContent newValue = at_StringRegistercontentMap(&newVariableValues,oldVariable->first)->second;
        if (oldVariable->second != newValue){
            printDifference(oldVariable->first, oldVariable->second, newValue);
        }
    }

    destroy_StringRegistercontentMap(&newVariableValues);
}

//signals debuggee (who was waiting in step 3 of loadDebuggedProgram for setup to complete) to get started running
void startDebuggeeRun(pid_t debuggee){
    C_TRYCATCH(ptrace(PTRACE_CONT, debuggee, NULL, NULL));
}

//manage debugging the code
void runDebugger(char *programArgs[], void *beginAddress, void *endAddress,
                 const struct StringStringMap* variableMap) {

    pid_t debuggee;
    if (!(debuggee = fork())) loadDebuggedProgram(programArgs); //child process that runs debugged program then exits
    //debugger process continues here

    //run debugged process
    int debuggeeStatus = 0;
    C_TRYCATCH(wait(&debuggeeStatus)); //wait for debuggee to finish loading program
    unsigned char replacedBeginByte = insertBreakpoint(beginAddress, debuggee);
    unsigned char replacedEndByte = insertBreakpoint(endAddress, debuggee);

    startDebuggeeRun(debuggee);
    do { //FIXME: possible bug: if debuggee receives a signal during run, will return control to debugger before reached inspected code, and debugger will return no signal (instead of caught signal)
        C_TRYCATCH(wait(&debuggeeStatus)); //wait for debuggee to reach beginning of inspected code
        if (WIFEXITED(debuggeeStatus)) break;
        struct StringRegistercontentMap storedVariables = storeVariables(variableMap, debuggee);

        stepPastBreakpoint(beginAddress, replacedBeginByte, debuggee);
        C_TRYCATCH(ptrace(PTRACE_CONT, debuggee, NULL, NULL)); //resume run

        C_TRYCATCH(wait(&debuggeeStatus)); //wait for debuggee to reach end of inspected code
        if (WIFEXITED(debuggeeStatus)) break;
        stepPastBreakpoint(endAddress, replacedEndByte, debuggee);
        compareVariables(&storedVariables, variableMap, debuggee);
        C_TRYCATCH(ptrace(PTRACE_CONT, debuggee, NULL, NULL)); //resume run
        destroy_StringRegistercontentMap(&storedVariables);
    } while (true);
}
