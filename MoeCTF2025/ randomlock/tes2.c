#include <stdio.h>
#include <stdlib.h>
unsigned seed = 2;
void change()
{
    if ((seed & 1) != 0)
    {
        seed = 3 * seed + 1;
    }
    else
    {
        seed >>= 1;
    }
}
void get_seed()
{
    int result;
    for (int n120 = 1; n120 <= 120; ++n120)
        change();
    while (1)
    {
        result = seed & 1;
        if ((seed & 1) != 0)
            break;
        change();
    }
    srand(seed);
}
int get_v6()
{
    return rand() % 10000;
}
