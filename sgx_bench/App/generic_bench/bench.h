/*
 * bench.h
 *
 * This benchmark incorporates code and concepts from
 * the source code of nbench.
 * (http://www.tux.org/~mayer/linux/bmark.html)
 */

typedef struct {
    int adjust;  /*Whether to adjust iterations of test or not*/
    unsigned long req_secs;  /*How many seconds needed*/
    unsigned long numtimes;  /*Adjustment factor*/
    double per_sec;  /*Number of iterations per second*/
} BenchStruct;

#define MIN_SECONDS 5 /*Minimum number of seconds for a bench to run*/
#define MIN_TICKS 60 /*Minimum number of ticks between start/stop of stopwatch*/
#define MAX_TIMES 4294967296 /*Maximum number of times a bench should be run before giving up (2^32)-1*/

int doBench(BenchStruct* bs, unsigned long (*bench)(BenchStruct*));
int doConfidenceBench(double* mean, double* stdev, unsigned long (*bench)(BenchStruct*));
