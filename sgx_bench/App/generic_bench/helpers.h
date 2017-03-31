/*
 * helpers.h
 *
 * This benchmark incorporates code and concepts from
 * the source code of nbench.
 * (http://www.tux.org/~mayer/linux/bmark.html)
 */

int calc_confidence(double scores[], /* Array of scores */
		int num_scores,             /* number of scores in array */
                double *c_half_interval,    /* Confidence half-int */
                double *smean,              /* Standard mean */
                double *sdev);               /* Sample stand dev */

unsigned long StartStopwatch();

unsigned long StopStopwatch(unsigned long startticks);

unsigned long TicksToSecs(unsigned long tickamount);

double TicksToFracSecs(unsigned long tickamount);
