# lldb_reversing
Dreg's setup for lldb reversing. The simplest and easiest possible, without scripting. lldb debugging setup.

Features: starti, hexdump, context layout (stack + disasm + regs), intel syntax, disasm including opcodes, rflags easy use...

![image](https://github.com/therealdreg/lldb_reversing/assets/9882181/71e0effa-73a8-4103-8114-b757ef4e96e7)

This repository can serve as template for customizing your LLDB, creating your own Python scripts for LLDB, how to make LLDB aliases that accept arguments, etc...

## Setup

Just create this file: ~/.lldbinit 

### x32-bit setup:
```
settings set stop-disassembly-display never
settings set target.x86-disassembly-flavor intel
command alias starti process launch --stop-at-entry
command alias regs register read eax ebx ecx edx edi esi ebp esp pc rflags
command alias diss di -b -c 10 -A i386 -s $pc
command alias dissn di -b -c %1 -A i386 -s $pc
command regex dissp 's|(.+)|di -b -A i386 -c 10 -s %1|'
command alias disspn di -b -A i386 -c %1
command alias ss memory read -s 4 -c 10 -l 1 -f x $sp
command alias ssn memory read -s 4 -c %1 -l 1 -f x $sp
command regex ssp 's|(.+)|memory read -s 4 -c 10 -l 1 -f x %1|'
command alias sspn memory read -s 4 -c %1 -l 1 -f x
command regex hexdump 's|(.+)|memory read -s 1 -c 128 -l 16 -f Y %1|'
command alias hexdumpn memory read -s 1 -c %1 -l 16 -f Y
command alias ctx script lldb.debugger.HandleCommand('regs'); lldb.debugger.HandleCommand('diss'); lldb.debugger.HandleCommand('ss');
ta st a -o "ctx"

#uncomment for pfl support
#command script import ~/pfl.py
#command alias regs script lldb.debugger.HandleCommand('register read eax ebx ecx edx edi esi ebp esp pc') ; lldb.debugger.HandleCommand('pfl')
```

### x64-bit setup:
```
settings set stop-disassembly-display never
settings set target.x86-disassembly-flavor intel
command alias starti process launch --stop-at-entry
command alias regs register read rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 pc rflags
command alias diss di -b -c 10 -A x86_64  -s $pc
command alias dissn di -b -c %1 -A x86_64  -s $pc
command regex dissp 's|(.+)|di -b -A x86_64 -c 10 -s %1|'
command alias disspn di -b -A x86_64 -c %1   
command alias ss memory read -s 8 -c 10 -l 1 -f x $sp
command alias ssn memory read -s 8 -c %1 -l 1 -f x $sp
command regex ssp 's|(.+)|memory read -s 8 -c 10 -l 1 -f x %1|'
command alias sspn memory read -s 8 -c %1 -l 1 -f x
command regex hexdump 's|(.+)|memory read -s 1 -c 128 -l 16 -f Y %1|'
command alias hexdumpn memory read -s 1 -c %1 -l 16 -f Y
command alias ctx script lldb.debugger.HandleCommand('regs'); lldb.debugger.HandleCommand('diss'); lldb.debugger.HandleCommand('ss');
ta st a -o "ctx"

#uncomment for pfl support
#command script import ~/pfl.py
#command alias regs script lldb.debugger.HandleCommand('register read rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 pc') ; lldb.debugger.HandleCommand('pfl')
```

-----

This script is super simple, customize it to your needs... 

If you want to use both 32-bit and 64-bit on the same machine here a dirty trick: 

Create different lldbinit files in your home directory, one for 32-bit ( ~/32_.lldbinit ) and one for 64-bit ( ~/64_.lldbinit ), and create two aliases in your ~/.bashrc:
```
alias lldb32="ln -f -s ~/32_.lldbinit ~/.lldbinit && lldb"
alias lldb64="ln -f -s ~/64_.lldbinit ~/.lldbinit && lldb"
source ~/.bashrc
```

Example of use:

```
lldb32 -- ./program32bits firstparam secondparam
lldb64 -- ./program64bits firstparam secondparam
```

----

**NOTE**: I'm using 's|

In regular expressions, the forward slash / is often used as a delimiter. An alternative delimiter | is used. This allows the regex to cleanly separate the pattern from the rest of the command without misunderstanding the slashes as part of regex syntax. 

Why? Because some GDB commands use /. For example: x/10x, and this way we can use the / character without any problem. For example:
```
command regex newcmd 's|(.+)|x/1xw %1+16|'
```

Practical example:
```
newcmd $sp
```

Executed LLDB Command:
```
x/1xw $sp+16
```

-----

Python-chr() trick could also be used to avoid regex error. For example using: ' (ASCII 39):
```
command regex newcmd 's|(.+)|script lldb.debugger.HandleCommand("memory read -s 1 -c 128 -l 16 -f Y " + chr(39) + "(char *)(%1+8)" + chr(39));|'
```

chr(39) is used to insert single quotes, ensuring that it is correctly interpreted as a string without breaking the overall command syntax due to unescaped quotes

Practical example:
```
newcmd $sp
```

Executed LLDB Command:
```
script lldb.debugger.HandleCommand("memory read -s 1 -c 128 -l 16 -f Y '(char *)($sp+8)'")
```

Final command:
```
memory read -s 1 -c 128 -l 16 -f Y '(char *)($sp+8)'
```

## Commands

- **pfl** (disabled by default): Displays the state of register flags
```
(lldb) pfl
rflags: 0x0000000000000202 [IF]
```
- **spfl** +zf -pf (disabled by default): Sets register flags according to the provided modifiers: + or -
```
rflags: 0x0000000000000246 [PF ZF IF]
(lldb) spfl +CF -ZF
(lldb) pfl
rflags: 0x0000000000000207 [CF PF IF]
```
- **ctx**:  Displays the current context, including registers, disassembly, and stack
```
(lldb) ctx
     eax = 0x00000000
     ebx = 0xffffdff0
     ecx = 0x00000000
     edx = 0x00000000
     edi = 0x00000000
     esi = 0x00000000
     ebp = 0x00000000
     esp = 0xffffd67c
     rip = 0x0000000008048080
->  0x8048080: 6a 26           push   0x26
    0x8048082: 68 9c 90 04 08  push   0x804909c
    0x8048087: 6a 01           push   0x1
    0x8048089: b8 04 00 00 00  mov    eax, 0x4
    0x804808e: 50              push   eax
    0x804808f: cd 80           int    0x80
    0x8048091: 6a 00           push   0x0
    0x8048093: b8 01 00 00 00  mov    eax, 0x1
    0x8048098: 50              push   eax
    0x8048099: cd 80           int    0x80
0xffffd67c: 0x00000001
0xffffd680: 0xffffd8b0
0xffffd684: 0x00000000
0xffffd688: 0xffffd8ca
0xffffd68c: 0xffffd8d4
0xffffd690: 0xffffd90a
0xffffd694: 0xffffd917
0xffffd698: 0xffffd927
0xffffd69c: 0xffffd943
0xffffd6a0: 0xffffd958
rflags: 0x0000000000000207 [CF PF IF]
```
- **ss**: Displays a summary of the stack
```
     esp = 0xffffd67c
(lldb) ss
0xffffd67c: 0x00000001
0xffffd680: 0xffffd8b0
0xffffd684: 0x00000000
0xffffd688: 0xffffd8ca
0xffffd68c: 0xffffd8d4
0xffffd690: 0xffffd90a
0xffffd694: 0xffffd917
0xffffd698: 0xffffd927
0xffffd69c: 0xffffd943
0xffffd6a0: 0xffffd958
```
- **ssn** 4: Displays a user-specified number of entries from the stack pointer
```
     esp = 0xffffd67c
(lldb) ssn 4
0xffffd67c: 0x00000001
0xffffd680: 0xffffd8b0
0xffffd684: 0x00000000
0xffffd688: 0xffffd8ca
```
- **ssp** $pc+4: Displays a list of pointers (stack-style) at the specified address
```
     rip = 0x0000000008048080
(lldb) ssp $pc+4
0x08048084: 0x6a080490
0x08048088: 0x0004b801
0x0804808c: 0xcd500000
0x08048090: 0xb8006a80
0x08048094: 0x00000001
0x08048098: 0x0080cd50
0x0804809c: 0x6c6c6548
0x080480a0: 0x7244206f
0x080480a4: 0x66206765
0x080480a8: 0x206d6f72
```
- **sspn** 3 $pc+4: Displays a user-specified number list of pointers (stack-style) at the specified address
```
     rip = 0x0000000008048080
(lldb) sspn 3 $pc+4
0x08048084: 0x6a080490
0x08048088: 0x0004b801
0x0804808c: 0xcd500000
```
- **hexdump** $pc+2: Displays the content in hexadecimal+ascii format at the specified address
```
     rip = 0x0000000008048080
(lldb) hexdump $pc+2
0x08048082: 68 9c 90 04 08 6a 01 b8 04 00 00 00 50 cd 80 6a  h....j......P..j
0x08048092: 00 b8 01 00 00 00 50 cd 80 00 48 65 6c 6c 6f 20  ......P...Hello 
0x080480a2: 44 72 65 67 20 66 72 6f 6d 20 33 32 20 62 69 74  Dreg from 32 bit
0x080480b2: 20 63 6f 64 65 20 46 72 65 65 42 53 44 21 21 0a   code FreeBSD!!.
0x080480c2: 00 2e 73 68 73 74 72 74 61 62 00 2e 74 65 78 74  ..shstrtab..text
0x080480d2: 00 2e 64 61 74 61 00 00 00 00 00 00 00 00 00 00  ..data..........
0x080480e2: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0x080480f2: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```
- **hexdumpn** 30 $pc+0x10: Displays a user-specified number of bytes in hexadecimal+ascii format at the specified address
```
     rip = 0x0000000008048080
(lldb) hexdumpn 30 $pc+0x10
0x08048090: 80 6a 00 b8 01 00 00 00 50 cd 80 00 48 65 6c 6c  .j......P...Hell
0x080480a0: 6f 20 44 72 65 67 20 66 72 6f 6d 20 33 32        o Dreg from 32
```
- **regs**: Displays the values of registers
```
(lldb) regs
     eax = 0x00000000
     ebx = 0xffffdff0
     ecx = 0x00000000
     edx = 0x00000000
     edi = 0x00000000
     esi = 0x00000000
     ebp = 0x00000000
     esp = 0xffffd67c
     rip = 0x0000000008048080
rflags: 0x0000000000000207 [CF PF IF]
```
- **diss**: Displays the disassembly of instructions + opcodes
```
     rip = 0x0000000008048080
(lldb) diss
->  0x8048080: 6a 26           push   0x26
    0x8048082: 68 9c 90 04 08  push   0x804909c
    0x8048087: 6a 01           push   0x1
    0x8048089: b8 04 00 00 00  mov    eax, 0x4
    0x804808e: 50              push   eax
    0x804808f: cd 80           int    0x80
    0x8048091: 6a 00           push   0x0
    0x8048093: b8 01 00 00 00  mov    eax, 0x1
    0x8048098: 50              push   eax
    0x8048099: cd 80           int    0x80
```
- **dissn** 2: Displays a user-specified number of instructions + opcodes
```
     rip = 0x0000000008048080
(lldb) dissn 2
->  0x8048080: 6a 26           push   0x26
    0x8048082: 68 9c 90 04 08  push   0x804909c
```
- **dissp** $pc-10: Displays the disassembly of instructions + opcodes at the specified address
```
     rip = 0x0000000008048080
(lldb) dissp $pc-10
    0x8048076: 00 00           add    byte ptr [eax], al
    0x8048078: 00 00           add    byte ptr [eax], al
    0x804807a: 00 00           add    byte ptr [eax], al
    0x804807c: 00 00           add    byte ptr [eax], al
    0x804807e: 00 00           add    byte ptr [eax], al
->  0x8048080: 6a 26           push   0x26
    0x8048082: 68 9c 90 04 08  push   0x804909c
    0x8048087: 6a 01           push   0x1
    0x8048089: b8 04 00 00 00  mov    eax, 0x4
    0x804808e: 50              push   eax
```
- **disspn** 5 -s $pc+2: Displays a user-specified number of instructions + opcodes at the specified address
```
     rip = 0x0000000008048080
(lldb) disspn 5 -s $pc+2
    0x8048082: 68 9c 90 04 08  push   0x804909c
    0x8048087: 6a 01           push   0x1
    0x8048089: b8 04 00 00 00  mov    eax, 0x4
    0x804808e: 50              push   eax
    0x804808f: cd 80           int    0x80
```
- **starti**: Initiates program execution and stops at the first entry point
```
dreg@~$ lldb asm/helloworld
Stop hook #1 added.
warning: Overwriting existing definition for 'regs'.
(lldb) target create "asm/helloworld"
Current executable set to '/home/dreg/asm/helloworld' (i386).
(lldb) starti
     eax = 0x00000000
     ebx = 0xffffdff0
....
```

Once the execution is finished, if you want to use starti again, you must rerun the target command, for example: 
```
target create asm/helloworld
starti
```

### spfl & pfl (format & set rflags)

I'm making an exception by adding this script because visualizing+set the rflags in a simple way is something fundamental...

To enable pfl+spfl command uncomment the last two lines of the file: ~/.lldbinit:

Now, create ~/pfl.py file:
```
# mod by Dreg from: https://gist.github.com/stek29/cdbbbe018f0aaf0b2a9a58c9173becb8
# show rflags: pfl
# set rflags: spfl +zf -pf

import lldb
import shlex

FLAGS = [
	['CF', 'Carry Flag'],
	[None, 'Reserved'],
	['PF', 'Parity Flag'],
	[None, 'Reserved'],
	['AF', 'Adjust Flag'],
	[None, 'Reserved'],
	['ZF', 'Zero Flag'],
	['SF', 'Sign Flag'],
	['TF', 'Trap Flag'],
	['IF', 'Interrupt Enable Flag'],
	['DF', 'Direction Flag'],
	['OF', 'Overflow Flag'],
	['IOPL_H', 'I/O privilege level High bit'],
	['IOPL_L', 'I/O privilege level Low bit'],
	['NT', 'Nested Task Flag'],
	[None, 'Reserved'],

	# eflags
	['RF', 'Resume Flag'],
	['VM', 'Virtual 8086 mode flag'],
	['AC', 'Alignment check'],
	['VIF', 'Virtual interrupt flag'],
	['VIP', 'Virtual interrupt pending'],
	['ID', 'Able to use CPUID instruction'],
	# 22-31 reserved

	# rflags 32-63 reserved
]

def parse_flags(val):
	""" Returns list of set flags """
	set_flags = list()

	for bit, desc in enumerate(FLAGS):
		if val & (1 << bit) and desc[0] is not None:
			set_flags.append(desc)

	return set_flags

def flag_list_to_str(l):
	return ' '.join((desc[0] for desc in l))

def get_flags_reg(frame):
	grs = list()
	
	for rs in frame.GetRegisters():
		if rs.GetName().lower() == 'general purpose registers':
			grs = rs
			break

	for reg in grs:
		if 'flags' in reg.GetName():
			return reg

	return None

def fmt_lst(fl_reg, lst):
	val = fl_reg.GetValueAsUnsigned()
	lst = [x.upper() for x in lst]
	found = list()

	for bit, desc in enumerate(FLAGS):
		if desc[0] is not None and desc[0] in lst:
			lst.remove(desc[0])
			found.append([desc[0], bool(val & (1 << bit))])

	ret = list()
	# lst must be empty at this point
	# anything left wasn't found
	if lst:
		ret.append('ERROR: Unknown flags: [%s]' % ' '.join(lst))

	for x in found:
		ret.append('%s: %d'%(x[0], int(x[1])))

	return '\n'.join(ret)

def fmt_short(fl_reg):
	val = fl_reg.GetValueAsUnsigned()
	reg_print_width = fl_reg.GetByteSize() * 2
	descs = parse_flags(val)

	return ('%s: 0x%.*x [%s]' % (
		fl_reg.GetName(), 		# register name
		reg_print_width, 		# how many hex digits to print
		val, 					# value
		flag_list_to_str(descs) # parsed value (list of set flags)
	))

def modify_flags(debugger, fl_reg, modifications):
    val = fl_reg.GetValueAsUnsigned()
    for mod in modifications:
        if mod[0] == '+':
            # Set the flag
            flag_bit = [desc[0] for desc in FLAGS].index(mod[1:].upper())
            val |= (1 << flag_bit)
        elif mod[0] == '-':
            # Clear the flag
            flag_bit = [desc[0] for desc in FLAGS].index(mod[1:].upper())
            val &= ~(1 << flag_bit)
    debugger.HandleCommand('register write rflags ' + hex(val))

def spfl(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    fl_reg = get_flags_reg(frame)
    if fl_reg is None:
        print("ERROR: Cant find flags register!")
        return

    lst = shlex.split(command)

    if lst:
        modifications = lst[0:]
        modify_flags(debugger, fl_reg, modifications)

def pfl(debugger, command, result, internal_dict):
	target = debugger.GetSelectedTarget()
	process = target.GetProcess()
	thread = process.GetSelectedThread()
	frame = thread.GetSelectedFrame()

	fl_reg = get_flags_reg(frame)
	if fl_reg is None:
		print("ERROR: Cant find flags register!")
		return

	lst = shlex.split(command)

	ret = ''

	if lst:
		# dirty argparse hack
		# XXX handle flags and eflags diff for fun? :)
		if '-l' in lst:
			lst = [desc[0] for desc in FLAGS if desc[0] is not None]

		ret = fmt_lst(fl_reg, lst)
	else:
		ret = fmt_short(fl_reg)

	print(ret)

if __name__ == '__main__':
    lldb.SBDebugger.Initialize()
    debugger = lldb.SBDebugger.Create()
    
    lldb.SBDebugger.Destroy(debugger)
    lldb.SBDebugger.Terminate()

def __lldb_init_module(debugger, internal_dict):
	debugger.HandleCommand('command script add -f pfl.pfl pfl')
	debugger.HandleCommand('command script add -f pfl.spfl spfl')
```

Done!

----

**WARNING**: I'll only accept PRs that maintain the spirit of keeping it super simple. If you want something more advanced, use llef 

https://github.com/foundryzero/llef

![image](https://github.com/therealdreg/lldb_reversing/assets/9882181/7301e1ed-637b-4059-a32f-1f2985a6125b)

----

# Tips & tricks

Set register:
```
register write $eax `$ebx+2`
```

Dereference pointer:
```
hexdump '*(char **)($sp+4)'
```

Conditional breakpoint:
```
br set -a `$pc+2` -c '$eax==4'
```

Hexdump a big chunk:
```
hexdumpn 3000 $sp --force
```

Python args (two):
```
script lldb.debugger.HandleCommand("process launch --stop-at-entry -- {0} {1}".format("\x41"*90, "/home/dreg/AAA"))
```

stdin from file (~ char can cause problems):
```
process launch --stop-at-entry --stdin /home/dreg/poc.txt
```

# Good doc

- GDB to LLDB command map: https://lldb.llvm.org/use/map.html
- https://stackoverflow.com/questions/10198975/how-can-i-create-a-lldb-alias-that-evaluates-its-argument-using-expression
- https://stackoverflow.com/questions/7690181/i-cant-get-this-simple-lldb-alias-to-work/12195214#12195214
```
It seems arguments (%1, %2, etc) doesn't work to alias an expression. There is a workaround by using a regular expression instead:

command regex ps 's/(.+)/print [self %1]/'

In "command alias" the %N substitutions only work for complete argument or option values and not for parts of an argument or option value. That limitation, and not something specific to expressions, is why the examples in this question don't work. –
Jim Ingham Jan 14, 2014 at 18:25
```

# Tested

```
dreg@~$ uname -a
FreeBSD rootkit 14.0-RELEASE FreeBSD 14.0-RELEASE #0 releng/14.0-n265380-f9716eee8ab4: Fri Nov 10 05:57:23 UTC 2023     root@releng1.nyi.freebsd.org:/usr/obj/usr/src/amd64.amd64/sys/GENERIC amd64
dreg@~$ lldb --version
lldb version 15.0.7
dreg@~$ lldb -P
/usr/local/llvm15/lib/python3.9/site-packages

(lldb) script import sys
(lldb) script sys.version
'3.9.18 (main, Apr  9 2024, 01:10:56) \n[Clang 16.0.6 (https://github.com/llvm/llvm-project.git llvmorg-16.0.6-0-g7cbf1'
(lldb) script sys.path
['/usr/local/llvm15/lib', '/home/dreg', '/usr/local/llvm15/lib/python3.9/site-packages', '/usr/local/lib/python39.zip', '/usr/local/lib/python3.9', '/usr/local/lib/python3.9/lib-dynload', '/usr/local/lib/python3.9/site-packages', '.']
```
 
