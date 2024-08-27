+++
author = "JonathanYS"
title = 'PicoCTF 2024 FS0 Writeup'
date = "2024-03-31"
url = "/posts/Write-ups/picoctf-2024-fs0-writeup/"
image = "images/2024-thumbs/picoctf-2024-fs0-writeup.jpg"
license = "Licensed under CC BY-NC-SA 4.0"
description = "PicoCTF 2024 - Format String 0 challenge Write-up"
categories = [
    "Write-ups"
]
tags = [
    "pwn",
    "cybersecurity",
	"binary exploitation",
]
+++


# format string 0
Hello everyone.
Firstly, this challenge is attached to the source code file and the binary itself. You may see this from the files that I provided (except for the binary file, which currently has a download issue. I believe this will be resolved soon.). If you wish to obtain the required flag for this challenge, you would need to connect to the server operating these challenges using the challenge instance, using <b style="color:blue;">netcat</b>.

In this challenge, we could notice and understand what are the operations required from us to get the flag even without looking at the source code. I noticed that it is quite common among picoCTF challenges to be represented in this form. Of course, I am going to cover the source code as well for our understanding of what's going on under the hood.
Let's begin.

Available files: [format-string-0.c](/attached_files/writeups/2024/picoctf-2024-fs0-writeup/format-string-0.c)

## First look
We connect to the server through the provided instance. In my case:
```
nc mimas.picoctf.net 64224
```
We get the following output:
```
Welcome to our newly-opened burger place Pico 'n Patty! Can you help the picky customers find their favorite burger?
Here comes the first customer Patrick who wants a giant bite.
Please choose from the following burgers: Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe
Enter your recommendation:
```
As we may understand from the challenge name ("format string...") and from the named burgers. We might need to select the named burger that includes a string format specifier. We can see that the second named burger included a string format specifier by the <b style="color:blue;">%</b> symbol. Let's select that name and see the result. We get the following output:
```
Enter your recommendation: Gr%114d_Cheese
Gr
 4202954_Cheese
Good job! Patrick is happy! Now can you serve the second customer?
Sponge Bob wants something outrageous that would break the shop (better be served quick before the shop owner kicks you out!)
Please choose from the following burgers: Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak
Enter your recommendation:
```
Now, the reason for the numbers displayed on screen (<b style="color:blue;">4202954</b>) is that the string format specifier in the name of the burger we inputted, includes an integer string format specifier (<b style="color:blue;">%d</b>):

Gr<b style="color:blue;">%114d</b>_Cheese

The whole idea of a format string vulnerability is that it enables the attacker to read or write arbitrary data from and to the stack. So when we input this name of burger to the program, we get an integer formed data that is actually from the stack. It may contain valuable data in many cases.
The number 114 before the letter 'd' is for the maximum field width. The conversion will stop after the specified number of characters has been processed. For more information read the following discussion on Stackoverflow: https://stackoverflow.com/questions/16231136/what-does-a-number-between-and-format-specifier-mean-in-scanf.
Now, the reason for this message: "(better be served quick before the shop owner kicks you out!)", is to notify you that if you don't enter an input soon, the connection between your machine and the server will be closed. There is a timeout of connection when using <b style="color:blue;">netcat</b> to connect to a server, when there is no input for some time. After that, we need to enter another name of a burger from a list of names of burgers. This time we can see two names that have the <b style="color:blue;">%</b> symbol. But we can see that only one name includes a real string format specifier. The first name includes a <b style="color:blue;">%t</b>, which is not a real format string specifier. In contrast, the third name includes 3 real format string specifiers of string type. This means that if we enter the name of this burger we would get a string form of data from the stack. I have a hunch that it would be the flag. Let's enter it. After entering this name, we get the following output:
```
Enter your recommendation: Cla%sic_Che%s%steak
ClaCla%sic_Che%s%steakic_Che(null)
picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_74f6c0e7}
```
Which includes the required flag.
By the way, if we tried to input just format string specifiers, it wouldn't work, because the program checks that the input is one of the three named burgers in the lists provided.

## Under The Hood
Let's examine the important parts of this program (marked in green).
<pre><code><b style="color:green;">#define BUFSIZE 32</b>
#define FLAGSIZE 64

<b style="color:green;">char flag[FLAGSIZE];</b>

int main(int argc, char **argv){
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("%s %s", "Please create 'flag.txt' in this directory with your",
                        "own debugging flag.\n");
        exit(0);
    }

    <b style="color:green;">fgets(flag, FLAGSIZE, f);</b>
    signal(SIGSEGV, sigsegv_handler);

    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    <b style="color:green;">serve_patrick();</b>
  
    return 0;
}

void serve_patrick() {
    printf("%s %s\n%s\n%s %s\n%s",
            "Welcome to our newly-opened burger place Pico 'n Patty!",
            "Can you help the picky customers find their favorite burger?",
            "Here comes the first customer Patrick who wants a giant bite.",
            "Please choose from the following burgers:",
            "Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe",
            "Enter your recommendation: ");
    fflush(stdout);

    char choice1[BUFSIZE];
    scanf("%s", choice1);
    char *menu1[3] = {"Breakf@st_Burger", "Gr%114d_Cheese", "Bac0n_D3luxe"};
    if (!on_menu(choice1, menu1, 3)) {
        printf("%s", "There is no such burger yet!\n");
        fflush(stdout);
    } else {
        <b style="color:green;">int count = printf(choice1);
        if (count > 2 * BUFSIZE) {
            serve_bob();
        }</b> else {
            printf("%s\n%s\n",
                    "Patrick is still hungry!",
                    "Try to serve him something of larger size!");
            fflush(stdout);
        }
    }
}

void serve_bob() {
    printf("\n%s %s\n%s %s\n%s %s\n%s",
            "Good job! Patrick is happy!",
            "Now can you serve the second customer?",
            "Sponge Bob wants something outrageous that would break the shop",
            "(better be served quick before the shop owner kicks you out!)",
            "Please choose from the following burgers:",
            "Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak",
            "Enter your recommendation: ");
    fflush(stdout);

    char choice2[BUFSIZE];
    scanf("%s", choice2);
    char *menu2[3] = {"Pe%to_Portobello", "$outhwest_Burger", "Cla%sic_Che%s%steak"};
    if (!on_menu(choice2, menu2, 3)) {
        printf("%s", "There is no such burger yet!\n");
        fflush(stdout);
    } else {
        <b style="color:green;">printf(choice2);</b>
        fflush(stdout);
    }
}
}</code></pre>
Please pay attention to the third marked line. At this line, the program copies the contents of flag.txt (f) to the local variable flag. You need to understand that after this line gets executed, the local variable flag is present on the stack, in a register. Now, because there is a problem when downloading the actual binary, we can't run <b style="color:blue;">checksec</b> on it. But, because I participated in this CTF and the binary download worked, I can write that this binary is 64-bit. The reason that this is an important detail (for our understanding) is that in 64-bit binaries, the first variables are stored in the registers first - RDI, RSI, RDX, RCX, R8, R9, stack..., in that order. And, the memory addresses in 64-bit binaries are 8 bytes long (64 bits).

If we look at the fifth marked line, we can see that after we enter our choice there is an integer variable that is storing <b style="color:blue;">printf(choice1)</b> (choice1 = our input). After that line, the program checks if that variable is greater than two times the size of BUFSIZE which is equal to 64 (as we can calculate from the first marked line). If you recall the number we got when we entered the name of a burger the first time, we got a very large number, 4202954 to be exact. Now, this number alone, without the other characters with it, is greater than 64. That is why the program calls <b style="color:blue;">serve_bob()</b> function. This large number is some value from the stack, printed in decimal, it could include the flag, but it isn't clear to us. The reason we get values from the stack in this situation is that the string we input includes format string specifier (<b style="color:blue;">%d - Gr%114d_Cheese</b>). And, when the program prints our input without specifying any parameters to the format string specifier, the program prints the values that are present on the stack instead, as the parameters.

Next, when we input <b style="color:blue;">Cla%sic_Che%s%steak</b>, the program then prints the values, without specifying any parameters. And then, takes values off the stack instead, and prints them to us. The number of format string specifiers of type string is enough in this case (3), to print the entire flag value off the stack.
