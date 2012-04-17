#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

/* 
 * Define our own signal number.
 * It is hard coded since SIGRTMIN is different in user and kernel space.
 */ 
#define SIG_TEST 44 

#define SPIN_DOWN 1234

/* signal processing handler */
void signal_handler(int signal_num, siginfo_t *info, void *unused) {
	int ret; 
	int value_from_kernel = info->si_int; 

	printf("signal number: %d\n", signal_num); 

	if(value_from_kernel == SPIN_DOWN) {
		/* TODO: specify device by signal */
		ret = system("hdparm -y device"); 
		if(ret == -1 ) 
			perror("hdparm"); 
		else
			printf("spin down device\n"); 
	}
}

int main ( int argc, char **argv )
{
    int greendm_fd; 		/* pointer to debug entry of greendm */
    char pid_buf[10];		/* store user_disk_spin pid */
    /* 
	 * setup the signal handler for SIG_TEST 
     * SA_SIGINFO -> signal handler function has to have 3 arguments
     */
    struct sigaction sig;
    sig.sa_sigaction = signal_handler;		/* specify signal handler */
    sig.sa_flags = SA_SIGINFO;
    sigaction(SIG_TEST, &sig, NULL); 		/* setup processing */

    /* 
	 * kernel needs to know the pid to be able to send a signal.
     * we use debugfs for this.
	 * NOTE: make sure debugfs is mounted!
     */
    greendm_fd = open("/sys/kernel/debug/signal_greendm", O_WRONLY);
    if(greendm_fd < 0) {
        perror("open");
        return -1;
    }
    sprintf(pid_buf, "%i", getpid());
    if (write(greendm_fd, pid_buf, strlen(pid_buf) + 1) < 0) {
        perror("write"); 
        return -1;
    }
    
    return 0;
}
