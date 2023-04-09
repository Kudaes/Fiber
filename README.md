# Description

A fiber is a unit of execution that must be manually scheduled by the application rather than rely on the priority-based scheduling mechanism built into Windows. Fibers are often called lightweight threads. For more detailed information about what are and how fibers work consult the [official documentation](https://learn.microsoft.com/en-us/windows/win32/procthread/fibers).
Fibers allow to have multiple execution flows in a single thread, each one with its own registers' state and stack. On the other hand, fibers are **invisible** to the kernel, which makes them a stealthier (and cheaper) method to execute in-memory code than spawning new threads.

One thread can create multiple fibers, and switch between them at desire by calling the [SwitchToFiber](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-switchtofiber) function. Before that, the current thread itself must have become a fiber by calling [ConvertThreadToFiber](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-convertthreadtofiber) since only a fiber can create other fibers. Finally, in order to create a fiber that, when scheduled, executes an in-memory code (for example, after reflectively loaded a PE or some shellcode) it is just needed to make a call to [CreateFiber](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiber).

The SwitchToFiber function is the most important part of this process and where all the magic occurs. This function allows to schedule one fiber or another, all happening on user space. According to the official documentation, "the SwitchToFiber function saves the state information of the current fiber and restores the state of the specified fiber". This mean that when this function is called, the registers' values and the stack are switched from the current fiber state to the target fiber state, allowing to "hide" the stack of the current fiber once the process is completed. This also allows to continue the execution of the target fiber from the same point where the execution was stopped (the same way that it happens when the scheduler switches between threads according to its own priority logic). 

And this is exactly what this simple PoC does:

* First, we have a loader, which will use DInvoke to manually map the dll that contains our payload.
* After that, the loader will turn the current thread into a fiber (known from now on as a control fiber). The control fiber will enjoy of a "normal" stack since the loader is being run from a PE on disk.
* The loader will then create a new fiber to run the `run()` function exported by the manually mapped dll. This fiber will be known as the payload fiber from now on.
* The control fiber will switch to the payload fiber, which will execute whatever code the payload contains. Once the payload needs to enter on an alertable state (for example, when a call to Sleep is required), the payload fiber switches back to the control fiber, hiding its stack (which may contain several IOC os malicious activity).
* The control fiber performs the call to Sleep. When the call returns, it will switch again to the payload fiber so it can continue its execution.

This process repeats indefinitely.

# Advantages

The use of fibers may be advantageous for some types of payloads (like a C2 beacon) for some of these reasons:

* Fibers allow to run in-memory code without the need of using the instructions `JMP` or `CALL` from the loader pointing to unbacked memory regions.
* This execution is performed without the creation of new threads, preventing the generation of callbacks from the kernel that can be collected by an EDR.
* The payload fiber's stack can be hidden when the payload enters on an alertable state or when it needs to wait for a pending I/O operation. This is done using a control fiber with a normal stack that runs code from disk. This "hiding" is cheaper and easier to implement that the regular thread stack spoofing process.
* The fibers are invisible to the kernel and all the switching procedure happens on user space, which makes it easier to hide from an EDR. 

# Cons

* Only one fiber can be scheduled at a time on a thread, which means that in order to get real concurrency using fibers you need to spawn more threads.
* Although the payload fiber's stack is hidden when the control fiber is switched back, it remains in the process memory and it could be spotted by a memory inspection.
* Obfuscation is still needed in order to hide the in-memory implant, this is just about hiding the stack and the execution method.

# Compilation 

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	C:\Users\User\Desktop\Fiber> set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

After that, simply compile both the payload and the loader and run the last one:

	C:\Users\User\Desktop\Fiber\payload> cargo build --release
	C:\Users\User\Desktop\Fiber\loader> cargo build --release
	C:\Users\User\Desktop\Fiber\loader\target\release> loader.exe

# Usage

There is not much mistery on this PoC execution. All it has to be done is to run the loader and use any tool like ProcessHacker to inspect the thread stack. Since the payload switches back to the control fiber before sleeping, the payload fiber's stack remains hidden most of the time.
The code is commented to show how to use, create and schedule fibers. You will notice that both the loader and the payload offered as example are "stuck" on an infinite loop, which allows to indefinitely switch between fibers and continue the execution. 
If a different payload wants to be tested, just modify the path located on line 32 of the file src::main.rs of the loader. In that case, the new dll has to export a `run(PVOID)` function that will receive as input parameter the address of the control fiber. This function has to switch back to the control fiber in order to call the Sleep function, although you can modify this behavior at will to fit your requirements. 

Another way to test this tool with a random payload is to perform IAT hooking to redirect any call to the Sleep function made by the payload to a function located on the loader, allowing to switch back to the control fiber when this call occurs. Up to you.
