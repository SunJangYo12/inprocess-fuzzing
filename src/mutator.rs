use rand::Rng;

const ARITH_MAX: u32 = 35;

const HAVOC_BLK_SMALL: usize = 32;
const HAVOC_BLK_MEDIUM: usize = 128;
const HAVOC_BLK_LARGE: usize = 1500;
const HAVOC_BLK_XL: usize = 32768;

const INTERESTING_8: &[i8] = &[
    -128, -1, 0, 1, 16, 32, 64, 100, 127,
];

pub struct HavocMutator {
    pub havoc_stack_pow2: u32,
}

impl HavocMutator {
    pub fn new() -> Self {
        Self {
            havoc_stack_pow2: 7,
        }
    }

    fn choose_block_len<R: Rng>(
        &self,
        rng: &mut R,
        limit: usize,
    ) -> usize {
        let (mut min_value, max_value);

        match rng.random_range(0..3) {
            0 => {
                min_value = 1;
                max_value = HAVOC_BLK_SMALL;
            }
            1 => {
                min_value = HAVOC_BLK_SMALL;
                max_value = HAVOC_BLK_MEDIUM;
            }
            _ => {
                if rng.random_range(0..10) != 0 {
                    min_value = HAVOC_BLK_MEDIUM;
                    max_value = HAVOC_BLK_LARGE;
                } else {
                    min_value = HAVOC_BLK_LARGE;
                    max_value = HAVOC_BLK_XL;
                }
            }
        }

        if min_value >= limit {
            min_value = 1;
        }

        min_value
            + rng.random_range(
                0..=(max_value.min(limit) - min_value),
            )
    }

    pub fn mutate<R: Rng>(
        &self,
        rng: &mut R,
        buf: &mut Vec<u8>,
    ) {
        if buf.is_empty() {
            return;
        }

        let use_stacking =
            1usize << (1 + rng.random_range(0..self.havoc_stack_pow2));

        for _ in 0..use_stacking {

            match rng.random_range(0..15) {

                // bit flip
                0 => {
                    let bit =
                        rng.random_range(0..buf.len() * 8);

                    let byte = bit / 8;
                    let mask = 128 >> (bit & 7);

                    buf[byte] ^= mask as u8;
                }

                // interesting 8
                1 => {
                    let pos =
                        rng.random_range(0..buf.len());

                    let val =
                        INTERESTING_8[rng.random_range(
                            0..INTERESTING_8.len()
                        )];

                    buf[pos] = val as u8;
                }

                // add byte
                2 => {
                    let pos =
                        rng.random_range(0..buf.len());

                    let add =
                        1 + rng.random_range(0..ARITH_MAX);

                    buf[pos] =
                        buf[pos].wrapping_add(add as u8);
                }

                // sub byte
                3 => {
                    let pos =
                        rng.random_range(0..buf.len());

                    let sub =
                        1 + rng.random_range(0..ARITH_MAX);

                    buf[pos] =
                        buf[pos].wrapping_sub(sub as u8);
                }

                // random xor
                4 => {
                    let pos =
                        rng.random_range(0..buf.len());

                    let x =
                        1 + rng.random_range(0..255);

                    buf[pos] ^= x as u8;
                }

                // delete block
                5 | 6 => {

                    if buf.len() < 2 {
                        continue;
                    }

                    let del_len =
                        self.choose_block_len(
                            rng,
                            buf.len() - 1,
                        );

                    let del_from =
                        rng.random_range(
                            0..=(buf.len() - del_len)
                        );

                    buf.drain(
                        del_from..del_from + del_len
                    );
                }

                // clone block
                7 => {

                    if buf.is_empty() {
                        continue;
                    }

                    let clone_len =
                        self.choose_block_len(
                            rng,
                            buf.len(),
                        );

                    let clone_from =
                        rng.random_range(
                            0..=(buf.len() - clone_len)
                        );

                    let clone_to =
                        rng.random_range(
                            0..=buf.len()
                        );

                    let chunk =
                        buf[clone_from..
                            clone_from + clone_len]
                            .to_vec();

                    buf.splice(
                        clone_to..clone_to,
                        chunk,
                    );
                }

                // overwrite block
                8 => {

                    if buf.len() < 2 {
                        continue;
                    }

                    let copy_len =
                        self.choose_block_len(
                            rng,
                            buf.len() - 1,
                        );

                    let from =
                        rng.random_range(
                            0..=(buf.len() - copy_len)
                        );

                    let to =
                        rng.random_range(
                            0..=(buf.len() - copy_len)
                        );

                    let tmp =
                        buf[from..from + copy_len]
                            .to_vec();

                    buf[to..to + copy_len]
                        .copy_from_slice(&tmp);
                }

                // random byte
                _ => {
                    let pos =
                        rng.random_range(0..buf.len());

                    buf[pos] = rng.random();
                }
            }
        }
    }
}


