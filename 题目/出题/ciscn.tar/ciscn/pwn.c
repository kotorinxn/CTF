#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <fcntl.h> 
#include <string.h>
//Global Variables
struct table{
    int flag;
    char *name;// save heap point
    char *dessert;
    char s[8]
}ptr[21];


void handler(){
    puts("[-] Time out ... \n");
    exit(1);
}

void init(){
    char *logo = 
        " ___  __    ________  _________  ________  ________  ___      \n"     
        "|\\  \\|\\  \\ |\\   __  \\|\\___   ___\\\\   __  \\|\\   __  \\|\\  \\     \n"    
        "\\ \\  \\/  /|\\ \\  \\|\\  \\|___ \\  \\_\\ \\  \\|\\  \\ \\  \\|\\  \\ \\  \\    \n"   
        " \\ \\   ___  \\ \\  \\\\\\  \\   \\ \\  \\ \\ \\  \\\\\\  \\ \\   _  _\\ \\  \\   \n"  
        "  \\ \\  \\\\ \\  \\ \\  \\\\\\  \\   \\ \\  \\ \\ \\  \\\\\\  \\ \\  \\\\  \\\\ \\  \\  \n" 
        "   \\ \\__\\\\ \\__\\ \\_______\\   \\ \\__\\ \\ \\_______\\ \\__\\\\ _\\\\ \\__\\ \n"
        "    \\|__| \\|__|\\|_______|    \\|__|  \\|_______|\\|__|\\|__|\\|__| \n"
        "**************************************************************\n"
        "****             Welcome to be dessert of kotori          ****\n"
        "**************************************************************\n";
    puts(logo);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr,0,2,0);
    signal(14,handler); 
    alarm(200);
}

void menu(){
    puts("======  menu  =====");
    puts("1.make friends with kotori");
    puts("2.show yourself");
    puts("3.change yourself");
    puts("4.eat yourself");
    puts("5.leave");    
}

void add_friends(){
    char *p;
    char *d;
    int i;
    int len = 9;
    int max = (ptr[20].flag >> 8);
    int size;
    for(i = 0; i < 20 && ptr[i].flag != 0; i++);
    if(i >= 20){
        puts("sorry,you can't make friends with kotori now");
        return;
    }
    puts("kotori is happy to make friends with you!");
    puts("input your name:");
    p = malloc(0x10);
    if(p == NULL){
        puts("malloc failed!");
        exit(0);
    }
    ptr[i].name = p;
    read(0, p, 0x10);
    puts("what dessert do you want to be?");
    puts("sizeof dessert:");
    if(scanf("%d",&size) <= 0){
        exit(0);
    }
    if(size > max){
        puts("too large");
        exit(0);
    }
    d = malloc(size);
    if(d == NULL){
        puts("malloc failed!");
        exit(0);
    }
    ptr[i].flag = 1;
    ptr[i].dessert = d;
    puts("write your description of dessert:");
    read(0, d, size);
    printf("your dessert's magic number is %x \n", ((unsigned int)ptr[i].dessert & 0xfff));
    puts("anymore?you can leave a few chars:");
    read(0, ptr[i].s, len);
    puts("ok, bye~");
}

void show_dessert(){
    int idx;
    puts("tell kotori your index:");
    if(scanf("%d",&idx) <= 0){
        exit(0);
    }
    if(idx < 0 || idx > 19){
        puts("bad guy,kotori is angry!");
        return;
    }
    if(ptr[idx].flag == 0){
        puts("nothing there!");
        return;
    }
    puts("your name:");
    puts(ptr[idx].name);
    puts("your dessert:");
    puts(ptr[idx].dessert);
}

void change_dessert(){
    int idx;
    int max = (ptr[20].flag >> 8);
    int size;
    char *d;
    puts("tell kotori your index:");
    if(scanf("%d",&idx) <= 0){
        exit(0);
    }
    if(idx < 0 || idx > 19){
        puts("bad guy,kotori is angry!");
        return;
    }
    if(ptr[idx].flag == 0){
        puts("nothing there!");
        return;
    }
    puts("your new size:");
    if(scanf("%d",&size) <= 0){
        exit(0);
    }
    if(size > max){
        puts("too large!");
        exit(0);
    }
    d = malloc(size);
    if(d == NULL){
        puts("malloc failed!");
        exit(0);
    }
    ptr[idx].dessert = d;
    puts("write your new description of dessert:");
    read(0, d, size);
    printf("your new dessert's magic number is %x \n", ((unsigned int)ptr[idx].dessert & 0xfff));
}

void eat(){
    int idx;
    int *p1,*p2;
    puts("tell kotori your index:");
    if(scanf("%d",&idx) <= 0){
        exit(0);
    }
    if(idx < 0 || idx > 19){
        puts("bad guy,kotori is angry!");
        return;
    }
    if(ptr[idx].flag == 0){
        puts("nothing there!");
        return;
    }
    ptr[idx].flag = 0;
    p1 = ptr[idx].name;
    p2 = ptr[idx].dessert;
    free(p1);
    free(p2);
    p1 = NULL;
    p2 = NULL;
}

int main(){
    int option;
    int *p;
    ptr[20].flag = 0x3000;
    init();
    p = malloc(0x100);
    memset(p,0,0x100);
    free(p);
    while(1){
        menu();
        printf(">");
        if(scanf("%u",&option)<=0){
            exit(0);
        }
        switch(option){
            case 1:
                add_friends();
                break;
                break;
            case 2:
                show_dessert();
                break;
            case 3:
                change_dessert();
                break;
            case 4:
                eat();
                break;
            case 5:
                exit(0);
                break;

        }    

    }

    return 0;
}
