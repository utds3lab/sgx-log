/*
 * helpers.c
 *
 * This benchmark incorporates code and concepts from
 * the source code of nbench.
 * (http://www.tux.org/~mayer/linux/bmark.html)
 */

#include <stdio.h>
#include <math.h>
#include <time.h>

/********************
** calc_confidence **
*********************
** Given a set of numtries scores, calculate the confidence
** half-interval.  We'll also return the sample mean and sample
** standard deviation.
** NOTE: This routines presumes a confidence of 95% and
** a confidence coefficient of .95
** returns 0 if there is an error, otherwise -1
*/
int calc_confidence(double scores[], /* Array of scores */
		int num_scores,             /* number of scores in array */
                double *c_half_interval,    /* Confidence half-int */
                double *smean,              /* Standard mean */
                double *sdev)               /* Sample stand dev */
{
/* Here is a list of the student-t distribution up to 29 degrees of
   freedom. The value at 0 is bogus, as there is no value for zero
   degrees of freedom. */
double student_t[30]={0.0 , 12.706 , 4.303 , 3.182 , 2.776 , 2.571 ,
                             2.447 , 2.365 , 2.306 , 2.262 , 2.228 ,
                             2.201 , 2.179 , 2.160 , 2.145 , 2.131 ,
                             2.120 , 2.110 , 2.101 , 2.093 , 2.086 ,
                             2.080 , 2.074 , 2.069 , 2.064 , 2.060 ,
		             2.056 , 2.052 , 2.048 , 2.045 };
int i;          /* Index */
if ((num_scores<2) || (num_scores>30)) {
  printf("Internal error: calc_confidence called with an illegal number of scores\n");
  return(-1);
}
/*
** First calculate mean.
*/
*smean=(double)0.0;
for(i=0;i<num_scores;i++){
  *smean+=scores[i];
}
*smean/=(double)num_scores;

/* Get standard deviation */
*sdev=(double)0.0;
for(i=0;i<num_scores;i++) {
  *sdev+=(scores[i]-(*smean))*(scores[i]-(*smean));
}
*sdev/=(double)(num_scores-1);
*sdev=sqrt(*sdev);

/* Now calculate the length of the confidence half-interval.  For a
** confidence level of 95% our confidence coefficient gives us a
** multiplying factor of the upper .025 quartile of a t distribution
** with num_scores-1 degrees of freedom, and dividing by sqrt(number of
** observations). See any introduction to statistics.
*/
*c_half_interval=student_t[num_scores-1] * (*sdev) / sqrt((double)num_scores);
return(0);
}

unsigned long StartStopwatch()
{
    return((unsigned long)clock());
}

unsigned long StopStopwatch(unsigned long startticks)
{
    return((unsigned long)clock()-startticks);
}

unsigned long TicksToSecs(unsigned long tickamount)
{
    return((unsigned long)(tickamount/CLOCKS_PER_SEC));
}

double TicksToFracSecs(unsigned long tickamount)
{
    return((double)tickamount/(double)CLOCKS_PER_SEC);
}
