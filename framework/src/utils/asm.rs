#[inline]
pub fn rdtsc_unsafe() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[inline]
pub fn rdtscp_unsafe() -> u64 {
    unsafe {
        let mut aux: u32 = 0;
        let tsc = core::arch::x86_64::__rdtscp(&mut aux as *mut u32);
        ((tsc as u64) << 32) | (aux as u64)
    }
}

#[inline]
pub fn pause() {
    unsafe {
        core::arch::x86_64::_mm_pause();
    }
}
