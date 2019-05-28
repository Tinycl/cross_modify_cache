#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <x86intrin.h>
#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include <signal.h>

#define ARRAYSIZE 257
#define clflush(addr)           \
    asm volatile("clflush (%0)" \
                 :              \
                 : "r(addr)"    \
                 : "memory")    \
    }
#define pipeline_flush() asm volatile("mov $0, %%eax\n\tcpuid" \
                                      :                        \
                                      :                        \
                                      : "rax", "rbx", "rcx", "rdx", "memory")

enum EXEC_CODE_THREAD_STATES
{
    EXEC_CODE_THREAD_INIT = 1,
    EXEC_CODE_THREAD_EXEC = 2,
    EXEC_CODE_THREAD_WAIT = 3,
};
enum THREAD
{
    EXEC_CODE_THREAD = 1,
    MODIFY_CODE_THREAD = 2,
};

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond1;
static pthread_cond_t cond2;

static char *shellcodeaddr;
size_t pagesize;
enum EXEC_CODE_THREAD_STATES globalexeccodethreadstate;
enum THREAD globalthreadflag;
static char srcsingle;
static char destsingle;
static char srcarray[ARRAYSIZE];
static char destarray[ARRAYSIZE];
static char resultarray[ARRAYSIZE];
static volatile char finishflag = 0;

void myArithmeticWithNoPara()
{
    int a, b, c;
    a = 10;
    b = 20;
    c = a + b;
    c = c * a + c * b;
    c = c / 2;
}

void myAssignWithPara(char *a, char *b)
{
    *a = 'c';
    *b = 'd';
}

void myMemcpyWithPara(char *pdest, char *psrc)
{

    unsigned int i = 0;
    double temp1 = 0.5;
    double temp2 = 0.6;
    volatile double temp3 = 0;
    for (i = 0; i < 10; i++)
    {
        temp3 = (temp1 + i) * (temp2 + i + 0.5) + i * 0.1 + i / 0.1 - 0.1;
    }
    for (i = 0; i < ARRAYSIZE; i++)
    {
        pdest[i] = psrc[i];
    }
    //memcpy(pdest,psrc,sizeof(char)*ARRAYSIZE);  have problem
}

void myModifyWithPara(char *pdest, char *psrc)
{

    unsigned int i = 0;
    double temp1 = 0.5;
    double temp2 = 0.6;
    volatile double temp3 = 0;
    char a[10];
    char b[10];
    for (i = 0; i < 10; i++)
    {
        a[i] = i + 1;
        b[i] = i + 2;
        if (i < 5)
        {
            a[i] += b[i];
        }
    }
    for (i = 0; i < 10; i++)
    {
        temp3 = (temp1 + i) * (temp2 + i + 0.5) + i * 0.1 + i / 0.1 - 0.1;
    }
    for (i = 0; i < ARRAYSIZE; i++)
    {
        pdest[i] = psrc[i];
    }
}
void *threadFunExecCode(void *arg)
{
    cpu_set_t mask, get;
    int flag = 0;
    int cpunum = 0;
    unsigned int index = 0;
    int cpu = 0;
    cpu = 7;
    cpunum = sysconf(_SC_NPROCESSORS_CONF);
    // pthread_detach(pthread_self());   //before this need to confirm run different core
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1)
    {
        printf("set affinity failed.. \n");
    }
    if (sched_getaffinity(0, sizeof(get), &get) == -1)
    {
        printf("get affinity failed.. \n");
    }
    while (flag == 0)
    {
        for (index = 0; index < cpunum; index++)
        {
            if (CPU_ISSET(index, &get)) // conform thread is attach
            {
                flag = 1;
                break;
            }
        }
    }
    while (1) //!finishflag
    {
        pthread_mutex_lock(&mtx);
        while (globalthreadflag != EXEC_CODE_THREAD)
        {
            pthread_cond_wait(&cond1, &mtx);
        }
        if (globalexeccodethreadstate == EXEC_CODE_THREAD_INIT)
        {
            printf("thread exec code on core %d init code:\n", cpu);
            /* allocate code streams and memcpy code stream opcodes*/
            memcpy((unsigned char *)shellcodeaddr, (unsigned char *)myMemcpyWithPara, sizeof(unsigned char) * 353);
            /* exec code stream*/
            ((void (*)(char *psrc, char *pdest))shellcodeaddr)(destarray, srcarray);
            /* flush data */
            for (index = 0; index < ARRAYSIZE; index++)
            {
                _mm_clflush(&destarray[index]);
                _mm_clflush(&srcarray[index]);
            }
            /*
            for (index = 0; index < pagesize; index++)
            {
                _mm_clflush(&shellcodeaddr[index]);
            }
            */
        }
        if (globalexeccodethreadstate == EXEC_CODE_THREAD_EXEC)
        {
            printf("thread exec code on core %d exec code:\n", cpu);
            /* exec serializing instructions */
            _mm_mfence();
            _mm_lfence();
            pipeline_flush();
            /* exec modify code*/
            ((void (*)(char *pdest, char *src))shellcodeaddr)(srcarray, destarray);
            /*
            for (index = 0; index < pagesize; index++)
            {
                _mm_clflush(&shellcodeaddr[index]);
            }
            */
            finishflag = 1;
        }
        //sleep(1);
        globalthreadflag = MODIFY_CODE_THREAD;
        pthread_mutex_unlock(&mtx);
        pthread_cond_signal(&cond2);
    }
    return;
}

void *threadFunModifyCode(void *arg)
{
    cpu_set_t mask, get;
    int flag = 0;
    int cpunum = 0;
    unsigned int index = 0;
    int cpu = 0;
    cpu = 2;
    cpunum = sysconf(_SC_NPROCESSORS_CONF);
    //pthread_detach(pthread_self());
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1)
    {
        printf("set affinity failed.. \n");
    }
    if (sched_getaffinity(0, sizeof(get), &get) == -1)
    {
        printf("get affinity failed.. \n");
    }
    while (flag == 0)
    {
        for (index = 0; index < cpunum; index++)
        {
            if (CPU_ISSET(index, &get)) // conform thread is attach
            {
                flag = 1;
                break;
            }
        }
    }
    while (1)
    {
        pthread_mutex_lock(&mtx);
        while (globalthreadflag != MODIFY_CODE_THREAD)
        {
            pthread_cond_wait(&cond2, &mtx);
        }
        if (finishflag)
        {
            //break;
            myModifyWithPara(resultarray, srcarray);
            for (index = 0; index < ARRAYSIZE; index++)
            {
                if ((unsigned char)destarray[index] != (unsigned char)resultarray[index])
                {
                    printf("destarray[%d] is 0x%x fail\n", index, (unsigned char)destarray[index]);
                    printf("result[%d] is 0x%x fail\n", index, (unsigned char)resultarray[index]);
                    return;
                }
            }
            for (index = 0; index < ARRAYSIZE; index++)
            {
                _mm_clflush(&destarray[index]);
                _mm_clflush(&srcarray[index]);
                _mm_clflush(&resultarray[index]);
            }
        }
        printf("thread modify code on core %d modify code:\n", cpu);

        /*
        shellcodeaddr[0] = 0x66;
        shellcodeaddr[1] = 0x90;
   	    shellcodeaddr[2] = 0xc3;
        */
        /*modify code */
        memcpy((unsigned char *)shellcodeaddr, (unsigned char *)myModifyWithPara, sizeof(unsigned char) * 437);

        //sleep(1);
        globalexeccodethreadstate = EXEC_CODE_THREAD_EXEC;
        globalthreadflag = EXEC_CODE_THREAD;
        pthread_mutex_unlock(&mtx);
        pthread_cond_signal(&cond1);
    }
    return;
}

int main()
{

    unsigned int i = 0;
    pthread_t pid_exec = 0;
    pthread_t pid_modify = 0;
    cpu_set_t mask, get;
    int cpu = 0;
    int cpunum = 0;
    char flag = 0;
    cpunum = sysconf(_SC_NPROCESSORS_CONF);
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    pthread_detach(pthread_self());
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1)
    {
        printf("set affinity failed.. \n");
        return -1;
    }
    if (sched_getaffinity(0, sizeof(get), &get) == -1)
    {
        printf("get affinity failed.. \n");
        return -1;
    }
    while (flag == 0)
    {
        for (i = 0; i < cpunum; i++)
        {
            if (CPU_ISSET(i, &get)) // conform thread is attach
            {
                flag = 1;
                break;
            }
        }
    }
    printf("base thread on core %d\n", cpu);
    pagesize = getpagesize();
    shellcodeaddr = (char *)mmap(NULL, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANON, 0, 0);
    memset(shellcodeaddr, 0xcc, pagesize);
    for (i = 0; i < pagesize; i++)
    {
        _mm_clflush(&shellcodeaddr[i]);
    }
    for (i = 0; i < ARRAYSIZE; i++)
    {
        srcarray[i] = 0x55;
        resultarray[i] = 0x55;
        destarray[i] = 0x00;
        _mm_clflush(&srcarray[i]);
        _mm_clflush(&resultarray[i]);
        _mm_clflush(&destarray[i]);
    }

    /*use local variable can pass,global varible need rip address, rip need changge so wrong. so use fun with paras*/
    //memcpy((unsigned char*)shellcodeaddr, (unsigned char*)myArithmeticWithNoPara, sizeof(unsigned char)*64);
    ////myArithmeticWithNoPara();
    //((void (*)(void)) shellcodeaddr)();
    //printf("%02x \n", (unsigned char)shellcodeaddr[63]);

    /* use fun para to change global variable to complete assignment*/
    //srcsingle = 'a';
    //destsingle = 'b';
    // memcpy((unsigned char*)shellcodeaddr, (unsigned char*)(myAssignWithPara), sizeof(unsigned char)*29);
    ////myAssignWithPara(&src, &dest);
    // ((void (*)(char *a, char *b))shellcodeaddr)(&srcsingle,&destsingle);
    // printf("%02x \n", (unsigned char)shellcodeaddr[0]);
    //printf("src is %c, dest is %c\n",srcsingle,destsingle);

    /*use fun with para to memcpy array*/
    ////myMemcpyWithPara(destarray,srcarray);
    // memcpy((unsigned char *)shellcodeaddr, (unsigned char *)myMemcpyWithPara,sizeof(unsigned char)*75);
    //((void (*)(char *psrc, char *pdest))shellcodeaddr)(destarray,srcarray);

    // printf("destarray[0] is %c\n", destarray[0]);

    //return 0;

    pthread_cond_init(&cond1, NULL);
    pthread_cond_init(&cond2, NULL);
    pthread_create(&pid_exec, NULL, threadFunExecCode, NULL);
    pthread_create(&pid_modify, NULL, threadFunModifyCode, NULL);
    globalthreadflag = EXEC_CODE_THREAD;
    globalexeccodethreadstate = EXEC_CODE_THREAD_INIT;
    sleep(2);
    pthread_cond_signal(&cond1);

    pthread_join(pid_exec, NULL);
    pthread_join(pid_modify, NULL);

    //memcpy((unsigned char *)shellcodeaddr, (unsigned char *)myModifyWithPara, sizeof(unsigned char) * 337);
    //((void (*)(char *p))shellcodeaddr)(destarray);

    /*
    printf("base thread check data:\n");
    myModifyWithPara(resultarray,srcarray);
    for (i = 0; i < ARRAYSIZE; i++)
    {
        if ((unsigned char)destarray[i] != (unsigned char)resultarray[i])
        {
            printf("destarray[%d] is 0x%x fail\n", i, (unsigned char)destarray[i]);
            printf("result[%d] is 0x%x fail\n", i, (unsigned char)resultarray[i]);
            break;
        }
    }
    */
    pthread_mutex_destroy(&mtx);
    pthread_cond_destroy(&cond1);
    pthread_cond_destroy(&cond2);

    return 0;
}
