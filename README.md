# Interactive Shellcode Injection

**Interactive Shellcode Injection** is a technique where a process such as `cmd`, `conhost`, `powershell`, or `ssh` is created **without** the need to start it in a suspended state.

## How it works

1. Create the target process normally
2. Redirect its **standard input** to a controlled handle
3. Inject shellcode into a chosen memory region
4. Hijack the process's **main thread** while it is in a **wait state**

## Execution flow

For processes like `cmd`, `conhost`, and `powershell`, the main thread typically enters a waiting state while expecting user input. Once input is sent through the redirected standard input, the thread resumes and can be redirected to execute the injected shellcode.

For `ssh`, no user input is required. By passing `-o ConnectTimeout=x`, the process will remain blocked for **x seconds** during the connection attempt. Since the main thread is already in a wait state during that time, it can be hijacked and used to execute the injected shellcode.

## Notes

- No suspended process creation is required
- Works by taking advantage of a naturally waiting main thread
- Can be applied to both interactive and connection-based processes such as `ssh`

![GIF of injection](./images/uRo5koU57n.gif)
