# MALWLAB - Task 2
## Formalities
- Authors: *Fabio Schmidt*, *Jonas Eggenberg*
- Tutor: *Dr. Tim Blazytko*
- Date: *15.03.2024*
- Due Date: *27.03.2024*

// 2 remove: explain what you paste. also facts must be explained by text (see feedback of week 1)


## Introduction
This write-up contains an analysis of the task2.exe file of the second MALWLAB assignment. The following questions were used (not exclusively) as a guide line throughout this text.

*Questions to Guide the Analysis*<br>
* Which functionality/features does the malware support? Keep it high level.
* How does the sample gain persistence?
* Locate the code for C&C command dispatching. What are the individual commands?
* What’s the encryption/decryption key for C&C server communication?
* Some strings in the sample are encrypted. Where and how are they decrypted?
* Decrypt some of the strings. What are they used for?
* What’s the purpose of the function CheckLKM?

Furthermore a table of contents was added to provide some clarity between all the chapters and to quickly jump from one to another.

## Table of Contents
1. [Initial Analysis](#init_analysis)
2. [Dynamic Analysis](#dynamic_analysis)
3. [Static Analysis](#static_analysis)
4. [Summary](#summary)
5. [References](#references)
<br>

## Initial Analysis <a name="init_analysis"></a>
The following chapter will present an initial analysis, separated from the static and dynamic analysis presented in direct succession. This chapter consists primarily of information gathering, which is used as basis for the following chapters.

### Important Timestamps

#### Virus Total
* SHA-256: *c0b0225201fd3a4c08245e58bbb4b844e0d3426e89b9ac3fc34db37d994fb182*
* Community Score: *45/64*
* Category: *Trojan*
* Creation Time: - 
* First Seen In The Wild: -
* First Submission: *2022-03-18 15:03:03 UTC*
* Last Submission: *2024-03-14 20:49:19 UTC*
* Dropped Files: *None*

#### Detect It Easy
DiE presents us with the following initial informations.
* ELF32
    * Operation system: Red Hat Linux(ABI:2.6.9)[386,32-bit,EXEC]
    * Compiler: GCC(4.1.2 20080704 (Red Hat 4.1.2-46))
    * Language: C/C++

As we can see by the output, the binary is of the type `ELF` (the counterpart to the PE file format on the Windows operating system) and was written in C and/or C++. This fact is further strenghtend by the outputted strings in one of the next chapters. Many files can be found with the `.c` extension.


### To be packed, or not to be packed?
#### Detect it Easy
Opening the malware via the program leads to the following graph:
<br>
<img src="img/DIE_graph.png" width="600">
<br>
Detect it Easy already states with a rather high percentual probability, that the binary is not packed. By looking at the graph and the sections, we can see rather low entropy values and as such validate this assumption. As defined in the previous task (see the writeup of task1.exe) a value of greater or equal to seven should hint to a packed program (to the contrary to this case). 

### Strings
Some but not all of the interesting strings, that were found are listed here. Thousands of strings were found.

Listed are the API-functions and strings of the task2.bin, which are most likely to be found in combination with malware samples.
* Definately Malicious
    * `/etc/cron.hourly.gcc.sh` - name is intentional to look like a legit program (`gcc.c`), uses `/lib/libudev.so.6` as an executable (libudev is normally used for accessing `udev`, the device manager of the Linux Kernel), runs a for loop to bring up all network connections even if turned off // 2do check the file if it really does this
    * some of the contents of the `gcc.sh` script:
        ```
        for i in `cat /proc/net/dev|grep :|awk -F: {'print $1'}`; do ifconfig $i up& done

        cp /lib/libudev.so /lib/libudev.so.6
        ```
    * `/proc/rs_dev` / `CheckLKM` - checks if rootkit meets installation requirements such as an exact kernel header match and no technologies present that can block the rootkit’s installation, like secure boot or enforced signed loadable kernel module (LKM) loading
    * `hide.c` - possible program, that contains logic to hide/delete the malware
    * `DelService` - possible removal of the malware, after exectution?
* Networking 
    * Connection: Keep-Alive
    * POST %s HTTP/1.1
    * GET %s HTTP/1.1
    * /proc/net/tcp
    * socket:[
    * http_download
    * ... 
* Kernel Version Check 
    * FATAL: kernel too old
    * FATAL: cannot determine kernel version
* Locale
    * /etc/localtime
    * usr/share/oneinfo
    * Sunday, Monday, Tuesday ... - may be used for cronjob functionanitlies
    * timezone
* Process Management (including Forking Functionalities)
    * proc/self/exe
    * _dl_open_hook - possible hooking exploit
    * Owner died - may spawn multiple instances of itself (botnet), may be a message that the parent and/or child process has died
    * LinuxExec
    * kill_process
    * sleep
    * sched_setscheduler
    * fork_handler_pool
    * __libc_fork
* Encryption
    * encrypt.c
    * CalcFileCRC
* Miscellaneous
    * CalcFindIpCrc - no idea, but a search leads to chinese websites
    * _nl_current_LC_TELEPHONE_used - no idea, but a search leads to chinese websites 

## Dynamic Analysis <a name="dynamic_analysis"></a>
After having gathered some initial information, it is not a bad idea to try to run the malware, to get an initial idea on how the malware operates.  

#### Cuckoo


#### AnyRun

* Category: *Sinkhole*, *Trojan*
* HTTP Requests:
    * GET | 404: Not Found - http://aaa.dsaj2a.org/config.rar
* Connections:
    * Multiple Connections to different locations (approximately 28)
    * The malware connects to locations like **Germany**, the **United Kingdom** and by a vast majority to the **United States**. 
    * Examples:
        <br><img src="img/anysoft_connections.png" width="600"><br>
* DNS Requests:
    * Around 154 requests (including duplicates)
    * Not all connections were successfull / responded
    * Approximately a quarter have been correctly marked as maliscious.
        * Examples:
            ```
            aaa.dsaj2a.org
            ww.gzcfr5axf6.com (multiple times)
            ww.gzcfr5axf7.com (multiple times)            
            ```
* Threats:
        ```
        AV TROJAN DDoS.XOR sharing XOR Key Checkin
        ET MALWARE DDoS.XOR Checkin
        ET MALWARE DDoS.XOR Checkin via HTTP
        ```
    * "XOR.DDOS" was named after its denial-of-service-related activities on Linux endpoints and servers as well as its usage of XOR-based encryption for its communications.
* Process Graph (appended as pdf):
    * Looking at the graph will present us with a detailed view of all the processes which are somewhat in relation to the malware. Not all of them are relevant, but some can give us an insight of the functionalities of the malware. 
    * First, the trojan tries SSH brute force on thousands of Linux machines at the same time from the already compromised machine, and once it gains an initial foothold. It will download the malicious ELF file using curl and it takes careful measures before and after saving the file, leaving no traces for forensics.
* Processes:

Most notably about 


## Static Analysis <a name="static_analysis"></a>
This chapter provides an attempt of

### Imports
\-

### Exports
* 

### Ghidra

### IDA


### Binary Ninja




## Summary <a name="summary"></a>
With the foundings at hand, we could establish a basic idea of the malwares operational scope. It seems to be a trojan with keylogging functionalities. We assume that since the malware wasn't unpacked, no DNS requests to a C&C server were attempted.
This exercise deepended our knowledge with the named tools, which can then be reused in further exercises.

## References <a name="references"></a>
* Practical Malware Analysis: The Hands-On Guide to Dissecting Malicious Software - by Michael Sikorski & Andrew Honig (also some explanatory passages where cited from the book unaltered)
* Online Sandboxing Tool AnyRun - https://any.run/
* Hybrid Analysis - https://www.hybrid-analysis.com/
* Cuckoo - https://cuckoo.cert.ee/
* Wireshark Tutorial on LinkedIn - https://www.linkedin.com/advice/0/how-do-you-use-wireshark-analyze-malware-network
* How to Detect Raising New XORDDOS Linux Trojan - https://www.socinvestigation.com/how-to-detect-raising-new-xorddos-linux-trojan/
* What is libudev in Linux? - https://www.quora.com/What-is-libudev-in-Linux
* Is this file (gcc.sh) in cron.hourly malware? - https://stackoverflow.com/questions/36623596/is-this-file-gcc-sh-in-cron-hourly-malware
* Extra Exploitation Technique 1: _dl_open - https://dangokyo.me/2018/01/20/extra-exploitation-technique-1-_dl_open/
* Rise in XorDdos: A deeper look at the stealthy DDoS malware targeting Linux devices - https://www.microsoft.com/en-us/security/blog/2022/05/19/rise-in-xorddos-a-deeper-look-at-the-stealthy-ddos-malware-targeting-linux-devices/