# walking_PEB-Explained-
This is a simple way to walk the PEB of any DLL within a process, and given a desired DLL from a process traverse the PE file to find a function.

What is PEB  + PEB walking (Process Enviornment Block)
The PEB is a data structure that provides vital information about a process, including pointers to the loaded modules (DLLs).
PEB Walking refers to the process of traversing the PEB_LDR_DATA structure, which holds linked lists of all the loaded modules. By iterating through these lists, you can locate DLLs like Kernel32.dll, which contains important system functions and syscall information.
A diagram seems to make this concept easier to understand so I pulled this from a repo I saw online. As you can see to access the PEB 
![image](https://github.com/user-attachments/assets/68653476-549e-428e-8868-e05d26c80525)
Photo taken from : https://red4mber.github.io/posts/hells-gate/






