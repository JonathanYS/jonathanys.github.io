+++
author = "JonathanYS"
title = 'PicoCTF 2021 Stonks Writeup'
date = "2024-03-31"
url = "/posts/Write-ups/picoctf-2021-stonks-writeup/"
image = "images/2024-thumbs/picoctf-2021-stonks-writeup.jpg"
license = "Licensed under CC BY-NC-SA 4.0"
description = "PicoCTF 2021 - Stonks challenge Write-up"
categories = [
    "Write-ups"
]
tags = [
    "pwn",
    "cybersecurity",
	"binary exploitation",
]
disableComments = false
+++


# Stonks
This challenge was part of the PicoCTF 2021 and was part of the Binary Exploitation genre. It was very fun to solve.
Let's start with the examination.

Available files: [vuln.c](attached_files/writeups/2024/picoctf-2021-stonks-writeup/vuln.c)

## Examination
After reading a bit of the code we can detect a Format String vulnerability.
The interesting function in this program is <b style="color:blue;">buy_stonks</b>.



<pre><code>int buy_stonks(Portfolio *p) {
    if (!p) {
        return 1;
    }
    <b style="color:green;">char api_buf[FLAG_BUFFER];
    FILE *f = fopen("api","r");</b>
    if (!f) {
        printf("Flag file not found. Contact an admin.\n");
        exit(1);
    }
    <b style="color:green;">fgets(api_buf, FLAG_BUFFER, f);</b>

    int money = p->money;
    int shares = 0;
    Stonk *temp = NULL;
    printf("Using patented AI algorithms to buy stonks\n");
    while (money > 0) {
        shares = (rand() % money) + 1;
        temp = pick_symbol_with_AI(shares);
        temp->next = p->head;
        p->head = temp;
        money -= shares;
    }
    printf("Stonks chosen\n");

    // TODO: Figure out how to read token from file, for now just ask

    char *user_buf = malloc(300 + 1);
    printf("What is your API token?\n");
    <b style="color:green;">scanf("%300s", user_buf);</b>
    printf("Buying stonks with token:\n");
    <b style="color:green;">printf(user_buf);</b>

    // TODO: Actually use key to interact with API

    view_portfolio(p);

    return 0;
}</code></pre>

The fact that there is a variable called api_buf that stores the flag's contents and is on the stack, alerts us that it might be possible to use some kind of leaking technique, to get the actual flag.
As we can see from the picture above, the program reads the contents of the flag from a file called api. The program asks us to enter some input (maximum of 300 bytes) and then prints it using printf() function from libc. A clear Format-String Vulnerability.

## Payload
We will enter lots of %xs to leak the flag value on the stack.


![Input example](/images/2024/picoctf-2021-stonks-writeup/input_example.png)

## Interpreting The Output
Now, this might look like gibrish to us. But all of these values are hexadecimal values, and some of them incoorapte to ascii values. To convert these values to ascii values, we will use the following technique.
```sh
echo -n {your-hexadecimal-values} | perl -pe 's/([0-9a-f]{2})/chr hex $1/gie'
```
Source of this method [here](https://stackoverflow.com/questions/1604765/how-to-convert-hex-to-ascii-characters-in-the-linux-shell#7681385).

This is the output of the above command:
<pre><code>���H�?���������p��9     !c�<b style="color:green;">ocip{FTC0l_I4_t5m_ll0m_y_y3nbc7ceac6��}�</b>�*���T@~�~4Ο�
                                                                                �\���#�~%h������2D�����p��~ ��2x���P����~����2x�H�i!A`��2d��2x�H���?���3,��3$����2��ݯ���p��p}����3$��3,��2���p���
�M�_��P�0������b�H�Q��3$�H�0���`��3��)@�����></code></pre>

Now, the output still looks not so familiar to the human eye. This is because of two reasons:
1. The addresses of this binary are stored in little-endian (and we know that this is a 32-bit binary, by the length of the addresses).
2. We are leaking a lot of addresses from the stack. Lots of them don't have any connection to ascii values.

We will need to identify the exact values of the flag. We can do that by looking at the ascii table and determine what is the value of the letter 'o', which is the start of the little-endian flag that we are looking for. The ascii value is <b style="color:blue;">6f</b>. We can confidently delete all the values up until this value. Little-endian means that the addresses are reversed. Every 4 bytes. "pico" is the first 4 bytes of our flag and that is why the letter "o" will be the first letter of it in little-endian.
After we do this, we can copy the entire flag up until the character "}", and place it in a python program inside a variable. The following python code will help us in reversing the entire flag to be in big-endian and thus be readable for us:

```python
if __name__ == '__main__':
    message = 'ocip{FTC0l_I4_t5m_ll0m_y_y3nbc7ceac6��}�'
    new_message = ""
    count = 0
    part_message = ""
    for _ in message:
        part_message += _
        count += 1
        if count == 4:
            new_message += "".join((list(reversed(part_message))))
            count = 0
            part_message = ""
    print(new_message)
```

After this function, we may take the output and delete all the <b style="color:blue;">�</b> characters.
The more elegant and maybe better way to do this operation would be to use RegEx.

**We have the flag!**
