#[derive(Debug)]
pub struct Stack {
    /// stack
    ptr: *mut u8,
    /// index of top byte of stack
    bottom: usize,
}

impl Stack {
    // define a new stack from top and size
    pub fn from_address(top: usize, size: usize) -> Self {
        Self {
            ptr: top as *mut u8,
            bottom: top - size,
        }
    }

    pub fn sp(&self) -> usize {
        self.ptr as usize
    }

    /// push data to stack and return the addr of sp
    pub fn push<T: core::fmt::LowerHex>(&mut self, data: &[T], align: usize) -> usize {
        // move sp to right place
        self.ptr = self.ptr.wrapping_sub(core::mem::size_of_val(data));
        self.ptr = memory_addr::align_down(self.ptr as usize, align) as *mut u8;

        assert!(
            self.ptr as usize > self.bottom,
            "sys_execve: stack overflow."
        );

        // write data into stack
        let sp = self.ptr as *mut T;
        unsafe {
            sp.copy_from_nonoverlapping(data.as_ptr(), data.len());
        }

        sp as usize
    }
}
