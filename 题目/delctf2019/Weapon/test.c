#include<stdio.h>
#include<stdlib.h>
int main(){
    void *p;
    malloc(0x20);
    malloc(0x20);
    p = malloc(0x170);
    malloc(0x60);
    free(p);
    return 0;

}
