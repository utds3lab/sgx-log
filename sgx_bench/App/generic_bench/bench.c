/*
 * bench.c
 *
 * This benchmark incorporates code and concepts from
 * the source code of nbench.
 * (http://www.tux.org/~mayer/linux/bmark.html)
 */

#include "bench.h"
#include "helpers.h"
#include <stdio.h>
#include <stdlib.h>

static void demoTask(){
    int i=0;
    while(i<1000)i++;
}

static unsigned long demoIter(BenchStruct* bs){
    unsigned long elapsed, i, numtimes;
    numtimes = bs->numtimes;

    elapsed = StartStopwatch();

    for(i = 0; i < numtimes; i++){
        demoTask();
    }

    elapsed = StopStopwatch(elapsed);

    return elapsed;
}

int doBench(BenchStruct* bs, unsigned long (*bench)(BenchStruct*)){
    unsigned long accumtime;
    double iterations;
    if(bs->adjust==0){
        /*Self-adjustment to have each iteration last a minimum duration*/
        bs->numtimes=1;
        while(1){
            /*Do a single iteration; check if it's less than minimum*/
            if( (*bench)(bs) > MIN_TICKS ) break;
            bs->numtimes = bs->numtimes << 1;
            if( bs->numtimes > MAX_TIMES ){
                printf("Fatal: Exceeded maximum bench iteration\n");
                exit(-1);
            }
        }
    }

    /*Perform iterations until elapsed time is great enough*/
    accumtime = 0L;
    iterations = (double)0.0;

    do{
        accumtime+=(*bench)(bs);
        iterations+=(double)1.0;
    }while(TicksToSecs(accumtime) < bs->req_secs);

    /*Report result*/
    bs->per_sec = iterations*(double)bs->numtimes/
        TicksToFracSecs(accumtime);

//    printf("accumtime=%ld;iterations=%f;per_sec=%f\n",
//        accumtime,iterations,bs->per_sec);

    if(bs->adjust == 0){
        bs->adjust = 1;
    }

    return 0;
}

/*Returns -1 on failure*/
int doConfidenceBench(double* mean, double* stdev, unsigned long (*bench)(BenchStruct*)){
    double scores[30];        /*Least 5, most 30*/
    double c_half_interval;   /*Confidence half-interval*/
    int tries,i;

    BenchStruct bs;
    bs.adjust = 0;
    bs.req_secs = MIN_SECONDS;
    bs.numtimes = 10;
    bs.per_sec = 0;

    /*First 5 scores are always obtained.  If we need more, we will get them.*/
    for(i = 0; i < 5; i++){
        doBench(&bs,bench);
        scores[i] = bs.per_sec;

//        printf("(%d) numtimes=%ld\n",
//            i,bs.numtimes);
    }
    tries = 5;

    /*25 more tries before we give up if we cannot get good confidence*/

    while(1){
        if( 0!=calc_confidence(scores,
            tries,
            &c_half_interval,
            mean,
            stdev)) return -1;

        /*If we meet our desired criteria, done.*/
        /*Length of half-interval must be <= 5% of the mean*/
        if(c_half_interval/(*mean) <= (double)0.05)
            break;

        /*We have failed to obtain our desired confidence*/
        if(tries == 30) return -1;

        doBench(&bs,bench);
        scores[tries] = bs.per_sec;

        printf("(%d) numtimes=%ld;half=%f;mean=%f,stdev=%f (%f)\n",
            tries,bs.numtimes,c_half_interval,*mean,*stdev,c_half_interval/(*mean));

        tries+=1;
    }
    return 0;
}



/*void main(int argc, char** argv){
    double mean,stdev;
    int result;
    printf("Performing benchmark:\n");
    result = doConfidenceBench(&mean,&stdev,&demoIter);
    if( result == -1 ){ printf("Failed\n"); }
    printf("Mean: %f Standard dev: %f\n",mean,stdev);
}*/
