use crate::MAP_SIZE;

pub struct Bitmap {
    pub trace_bits: Box<[u8; MAP_SIZE]>,
    pub virgin_bits: Box<[u8; MAP_SIZE]>,
    pub prev_loc: u64,
}
impl Bitmap {
    pub fn new() -> Self {
        Self {
            trace_bits: Box::new([0; MAP_SIZE]),
            virgin_bits: Box::new([0xff; MAP_SIZE]),
            prev_loc: 0,
        }
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.trace_bits.fill(0);
        self.prev_loc = 0;
    }

    #[inline(always)]
    pub fn hit(&mut self, cur_loc: u64) {
        let idx =
            ((self.prev_loc ^ cur_loc) as usize)
            & (MAP_SIZE - 1);

        self.trace_bits[idx] =
            self.trace_bits[idx].wrapping_add(1);

        self.prev_loc = cur_loc >> 1;
    }
}

