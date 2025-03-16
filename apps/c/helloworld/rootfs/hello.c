#include <stdio.h>

int g = 10;

int main(int argc, char *argv[])
{
    int a = 11;

    // 打印传入的参数数量
    printf("Number of arguments: %d\n", argc);

    // 遍历所有参数并打印
    for (int i = 0; i < argc; i++) {
        printf("Argument %d: %s, ptr: %p\n", i, argv[i], argv[i]);
    }

    printf("hello world\n");
    printf("a = %d &a=%p\n", a, &a);
    printf("g = %d &g=%p\n", g, &g);
    return 0;
}
