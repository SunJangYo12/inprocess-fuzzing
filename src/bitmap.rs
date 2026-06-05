use crate::MAP_SIZE;

pub struct Bitmap {
    pub trace_bits: Box<[u8; MAP_SIZE]>,
    pub virgin_bits: Box<[u8; MAP_SIZE]>,
    pub prev_loc: u64,
    pub last_pc: u64,
    count_class_lookup16: Box<[u16; 65536]>,
}
impl Bitmap {
    pub fn new() -> Self {
        Self {
            trace_bits: Box::new([0; MAP_SIZE]),
            virgin_bits: Box::new([0xff; MAP_SIZE]),
            prev_loc: 0,
            last_pc: 0,
            count_class_lookup16: Self::table_class_bit(),
        }
    }
    fn table_class_bit() -> Box<[u16; 65536]> {
        let mut lookup8 = [0u8; 256];
        lookup8[0] = 0;
        lookup8[1] = 1;
        lookup8[2] = 2;
        lookup8[3] = 4;

        for i in 4..=7 {
            lookup8[i] = 8;
        }
        for i in 8..=15 {
            lookup8[i] = 16;
        }
        for i in 16..=31 {
            lookup8[i] = 32;
        }
        for i in 32..=127 {
            lookup8[i] = 64;
        }
        for i in 128..=255 {
            lookup8[i] = 128;
        }

        let mut lookup16 = Box::new([0u16; 65536]);
        for b1 in 0..256usize {
            for b2 in 0..256usize {
                lookup16[(b1 << 8) | b2] =
                    ((lookup8[b1] as u16) << 8)
                    | lookup8[b2] as u16;
            }
        }
        lookup16
    }


    #[inline(always)]
    /// bersihkan noise bit saat loop dll di traces_bit
    pub fn classify_counts(&mut self) {
        let mem = self.trace_bits.as_mut_ptr() as *mut u32;

        for i in 0..(MAP_SIZE >> 2) {
            unsafe {
                let cur = mem.add(i);

                if *cur != 0 {
                    let mem16 = cur as *mut u16;

                    *mem16.add(0) =
                        self.count_class_lookup16[
                            *mem16.add(0) as usize
                        ];

                    *mem16.add(1) =
                        self.count_class_lookup16[
                            *mem16.add(1) as usize
                        ];
                }
            }
        }
    }

    #[inline(always)]
    pub fn has_new_bits(&mut self) -> i32 {
        let mut ret = 0;
        unsafe {
            let current = self.trace_bits.as_ptr() as *const u32;
            let virgin = self.virgin_bits.as_mut_ptr() as *mut u32;

            for i in 0..(MAP_SIZE / 4) {
                let cur_word = *current.add(i);
                let vir_word = *virgin.add(i);

                if cur_word != 0 && (cur_word & vir_word) != 0 {
                    if ret < 2 {
                        let cur = self.trace_bits.as_ptr().add(i * 4);
                        let vir = self.virgin_bits.as_ptr().add(i * 4);

                        if (*cur.add(0) != 0 && *vir.add(0) == 0xff)
                            || (*cur.add(1) != 0 && *vir.add(1) == 0xff)
                            || (*cur.add(2) != 0 && *vir.add(2) == 0xff)
                            || (*cur.add(3) != 0 && *vir.add(3) == 0xff)
                        {
                            ret = 2;
                        } else {
                            ret = 1;
                        }
                    }
                    *virgin.add(i) &= !cur_word;
                }
            }
        }
        ret
    }

    #[inline(always)] //inline compiler copy code ini ke pemanggil
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

