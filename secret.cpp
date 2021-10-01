#include "secret.hpp"

int main(int argc, char *argv[]) {
    int opt;
    char *optstr = "r:s:l";

    while ((opt = getopt(argc, argv, optstr)) != EOF) {
        switch (opt) {
        case 'r':
            printf("argument r\n");
            break;
        case 's':
            printf("argument s\n");
            break;
        case 'l':
            printf("argument l\n");
            break;
        default:
            break;
        }
    }
    
}