peepdf is a **Python3 tool to explore PDF files** in order to find out if the file can be harmful or not. The aim of this tool is to provide all the necessary components that
a security researcher could need in a PDF analysis without using 3 or 4 tools to make
all the tasks. With peepdf it's possible to see all the objects in the document showing
the suspicious elements, supports all the most used filters and encodings, it can parse different versions of a file, object streams and encrypted files. With the installation
of python3's version of googles V8 library [stPyV8](https://github.com/area1/stpyv8) and [Pylibemu](https://github.com/buffer/pylibemu) it provides **Javascript and shellcode analysis** wrappers too. Apart of this it's able to create new PDF files and to modify/obfuscate existent ones.

**Maintenance and new features**  
 - This is a half finished python3 port with a few outstanding issues. I pulled a few broken pieces together and made the install instruction in hopes that it helps a wider audience. pull requests and testing appreciated

**Installation:** Here's what I did to make the extra libraries work  
 - Note: This installs peepdf as a user, no sudo needed.

  * This repo:  
`git clone https://github.com/harakan/peepdf`  
`cd peepdf && python3 setup.py install --user` 
  * Required python libraries:  
`pip3 install -r requirements`
  * (OPTIONAL) Infamous PyV8 Library for executing javascript. This uses the new stpyv8 fork and installs system wide for now.:  
`git clone git@github.com:area1/stpyv8.git`  
`sudo bash install-ubuntu.sh`  
`sudo python3 setup.py install`  
  * (OPTIONAL) Install the libemu:  
`pip3 install pylibemu --user`  

... and hopefully that works! Here's a few extra things to try if stuff doesn't:
 * pip3 doesn't work with Windows 10's linux subsystem python3.5 version. Here's a fix:  
 1st: `sudo apt install python3-pip` 2nd if 1st doesn't work: `curl -fsSL https://bootstrap.pypa.io/pip/3.5/get-pip.py | python3.5`  

**Hints to get you started:**  
  
 * Basic usage which works for most pdfs: `peepdf -lf myPDF.pdf`  
 * Interactive Console: `peepdf -lfi myPDF.pdf`  
 * `peepdf -h`:  
```
Options:
  -h, --help            show this help message and exit
  -i, --interactive     Sets console mode.
  -s SCRIPTFILE, --load-script=SCRIPTFILE
                        Loads the commands stored in the specified file and
                        execute them.
  -c, --check-vt        Checks the hash of the PDF file on VirusTotal.
  -f, --force-mode      Sets force parsing mode to ignore errors.
  -l, --loose-mode      Sets loose parsing mode to catch malformed objects.
  -m, --manual-analysis
                        Avoids automatic Javascript analysis. Useful with
                        eternal loops like heap spraying.
  -g, --grinch-mode     Avoids colorized output in the interactive console.
  -v, --version         Shows program's version number.
  -x, --xml             Shows the document information in XML format.
  -j, --json            Shows the document information in JSON format.
  -C COMMANDS, --command=COMMANDS
                        Specifies a command from the interactive console to be
                        executed.  
``` 

**Analysis:**

  * Decodings: hexadecimal, octal, name objects
  * More used filters
  * References in objects and where an object is referenced
  * Strings search (including streams)
  * Physical structure (offsets)
  * Logical tree structure
  * Metadata
  * Modifications between versions (changelog)
  * Compressed objects (object streams)
  * Analysis and modification of Javascript (PyV8): unescape, replace, join
  * Shellcode analysis (Libemu python wrapper, pylibemu)
  * Variables (set command)
  * Extraction of old versions of the document
  * Easy extraction of objects, Javascript code, shellcodes (>, >>, $>, $>>)
  * Checking hashes on **VirusTotal**


**Creation/Modification:**

  * Basic PDF creation
  * Creation of PDF with Javascript executed wen the document is opened
  * Creation of object streams to compress objects
  * Embedded PDFs
  * Strings and names obfuscation
  * Malformed PDF output: without endobj, garbage in the header, bad header...
  * Filters modification
  * Objects modification


**Execution modes:**

  * Simple command line execution
  * **Powerful interactive console** (colorized or not)
  * Batch mode


**TODO:**

  * Embedded PDFs analysis
  * Improving automatic Javascript analysis
  * Some broken features including decoding errors that happened during the port

**Example Output:**
```
File: myPDF.pdf
MD5: b51d433e5f675ca46bfb816512f9afe3
SHA1: c5012522518ec46e989187cc2a4b7bce2a384ab5
SHA256: f6aceeb1399f059cb48692526a599c54fec31ee5a8c8016848bee4a831b40d2a
Size: 964220 bytes
Version: 1.4
Binary: True
Linearized: True
Encrypted: False
Updates: 1
Objects: 72
Streams: 30
URIs: 0
Comments: 0
Errors: 0

Version 0:
        Catalog: 34
        Info: 32
        Objects (1): [33]
        Streams (0): []

Version 1:
        Catalog: No
        Info: No
        Objects (71): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72]
                Errors (9): [36, 37, 15, 16, 21, 22, 23, 28, 29]
        Streams (30): [72, 36, 37, 43, 44, 49, 50, 53, 57, 61, 65, 69, 71, 2, 4, 6, 8, 10, 12, 14, 15, 16, 19, 21, 22, 23, 26, 28, 29, 31]
                Encoded (30): [72, 36, 37, 43, 44, 49, 50, 53, 57, 61, 65, 69, 71, 2, 4, 6, 8, 10, 12, 14, 15, 16, 19, 21, 22, 23, 26, 28, 29, 31]
                Decoding errors (9): [36, 37, 15, 16, 21, 22, 23, 28, 29]
```

**Related articles:**

  * [Spammed CVE-2013-2729 PDF exploit dropping ZeuS-P2P/Gameover](http://eternal-todo.com/blog/cve-2013-2729-exploit-zeusp2p-gameover)
  * [New peepdf v0.2 (Version Black Hat Vegas 2012)](http://eternal-todo.com/blog/peepdf-v0.2-black-hat-usa-arsenal-vegas)
  * [peepdf supports CCITTFaxDecode encoded streams](http://eternal-todo.com/blog/peepdf-ccittfaxdecode-support)
  * [Explanation of the changelog of peepdf for Black Hat Europe Arsenal 2012](http://eternal-todo.com/blog/peepdf-black-hat-arsenal-2012)
  * [How to extract streams and shellcodes from a PDF, the easy way](http://eternal-todo.com/blog/extract-streams-shellcode-peepdf)
  * [Static analysis of a CVE-2011-2462 PDF exploit](http://eternal-todo.com/blog/cve-2011-2462-exploit-analysis-peepdf)
  * [Analysis of a malicious PDF from a SEO Sploit Pack](http://eternal-todo.com/blog/seo-sploit-pack-pdf-analysis)
  * Analysing the [Honeynet Project challenge PDF file](http://www.honeynet.org/challenges/2010_6_malicious_pdf) with peepdf [Part 1](http://eternal-todo.com/blog/analysing-honeynet-pdf-challenge-peepdf-i) [Part 2](http://eternal-todo.com/blog/analysing-honeynet-pdf-challenge-peepdf-ii)
  * [Analyzing Suspicious PDF Files With Peepdf](http://blog.zeltser.com/post/6780160077/peepdf-malicious-pdf-analysis)


**Python2 version previously included in:**

  * [REMnux](http://zeltser.com/remnux/)
  * [BackTrack 5](https://www.backtrack-linux.com/forensics-auditor/)
  * [Kali Linux](http://www.kali.org/)

**You are free to contribute with feedback, bugs, patches, etc. Any help is welcome**
