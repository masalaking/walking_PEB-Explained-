# walking_PEB-Explained-
This is a simple way to walk the PEB of any DLL within a process, and given a desired DLL from a process traverse the PE file to find a function.

What is PEB  + PEB walking (Process Enviornment Block)
The PEB is a data structure that provides vital information about a process, including pointers to the loaded modules (DLLs).
PEB Walking refers to the process of traversing the PEB_LDR_DATA structure, which holds linked lists of all the loaded modules. By iterating through these lists, you can locate DLLs like Kernel32.dll, which contains important system functions and syscall information.
A diagram seems to make this concept easier to understand so I pulled this from a repo I saw online.

![image](https://github.com/user-attachments/assets/68653476-549e-428e-8868-e05d26c80525)
Photo taken from : https://red4mber.github.io/posts/hells-gate/

Here is a step by step of what to do to access the PEB and traverse it:
- Read the PEB from inline assembly code
- There is a data field called the PEB_LDR_DATA pointer that points to the LDR DATA
- Then to read the modules you must access the first element of the InMemoryOrderModuleList linked list
- It is a doubly linked list, with the FLINK being the forward pointer and the BLINK being the backward
-Read the pointers to the DLL bases

This can be useful, but for my purpose it is more useful to then access the desired DLL to use its functions without calling GetProcAddress, or LoadLibraryA().
The next step is to then use the pointer to the Base address of the desired DLL to parse its PE file (Portable Exectuable File). 

The simplified structure of the PE file that is useful to us can be seen as this 
![image](https://github.com/user-attachments/assets/bfb7902c-433b-4713-ba26-a9f597d8c9bf)







