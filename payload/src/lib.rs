use data::PVOID;

///
///  The only param expected by this function is the address of the
///  control fiber. The control fiber is running code backed on disk,
///  which means it's stack won't be considered malicious per se. 
///  Each time this payloads needs to get into an alertable state (like, for example,
///  when it calls Sleep) or when it gets stuck on a pending I/O operation, it can
///  switch back to the control fiber.
/// 
#[no_mangle]
pub extern fn run(params: PVOID)
{
    unsafe
    {
        loop 
        {   
            /*
                This payload only switches back to the control fiber in order to hide its stack trace, which
                points to unbacked memory regions. However, this same behaviour could be included in real payloads like,
                for example, a C2 beacon pinging back to its control server looking for new orders. Since C2 beacons stay most of the 
                time "sleeping", changing from the beacon fiber to the control fiber would allow to hide the malformed stack 
                without the need of spoofing it. 
             */
            println!("[PayloaZzZ] Sleeping... Check the stack!");
            println!("--------------------------");
            let k32 = dinvoke::get_module_base_address("kernel32.dll");
            let _ret: Option<()>;
            let func: data::SwitchToFiber;
            // Using DInvoke to call SwitchToFiber, since this is a PoC it is not needed
            // this kind of stealth.
            dinvoke::dynamic_invoke!(k32,"SwitchToFiber",func,_ret,params); 
            println!("[Payload] I'm alive!");
        }

        
    }

}