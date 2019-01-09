#![feature(test)]
extern crate test;

use byteorder::{BigEndian, ReadBytesExt};
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::Cursor;
use std::io::SeekFrom;
use test::Bencher;

static FILE_PATH: &str = "database_fixture";
static RECORD_SIZE: u64 = 14; // bytes

pub fn check_pwned(target: [u8; 10]) -> u32 {
    let mut buffer: [u8; 14] = [0; 14];
    let mut f = File::open(FILE_PATH).expect("Fail to open the file");
    check_pwn(0, record_count(), target, &mut f, &mut buffer)
}

fn record_count() -> u64 {
    let metadata = fs::metadata(FILE_PATH).expect("Fail to read file size");
    metadata.len() / RECORD_SIZE
}

fn check_pwn(
    start: u64,
    end: u64,
    target: [u8; 10],
    f: &mut std::fs::File,
    buffer: &mut [u8; 14],
) -> u32 {
    if end - start == 0 {
        let record = read_line(f, buffer, start);
        if &target[0..10] == &record[0..10] {
            let mut rdr = Cursor::new(&record[10..]);
            rdr.read_u32::<BigEndian>().unwrap()
        } else {
            0
        }
    } else if end - start == 1 {
        let record = read_line(f, buffer, start);
        if &target[0..10] == &record[0..10] {
            let mut rdr = Cursor::new(&record[10..]);
            rdr.read_u32::<BigEndian>().unwrap()
        } else {
            check_pwn(start, start, target, f, buffer)
        }
    } else {
        let middle_index = start + (end - start) / 2;
        let record = read_line(f, buffer, middle_index);

        if &target[0..10] > &record[0..10] {
            check_pwn(middle_index, end, target, f, buffer)
        } else if &target[0..10] < &record[0..10] {
            check_pwn(start, middle_index, target, f, buffer)
        } else {
            let mut rdr = Cursor::new(&record[10..]);
            rdr.read_u32::<BigEndian>().unwrap()
        }
    }
}

pub fn read_line(f: &mut std::fs::File, buffer: &mut [u8; 14], line_num: u64) -> [u8; 14] {
    f.seek(SeekFrom::Start(line_num * RECORD_SIZE))
        .expect("Fail to seek record");
    f.read_exact(buffer).expect("Fail to read buffer");
    buffer.clone()
}

#[bench]
fn binary_search_has_match(b: &mut Bencher) {
    let target = [221, 93, 88, 98, 146, 95, 31, 149, 60, 171];
    b.iter(|| {
        check_pwn(target);
    });
}

#[bench]
fn binary_search_no_match(b: &mut Bencher) {
    let target = [221, 93, 88, 98, 146, 95, 31, 149, 60, 11];
    b.iter(|| {
        check_pwn(target);
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn check_all_exisiting_records() {
        assert_eq!(187, crate::check_pwn([4, 5, 58, 123, 138, 105, 87, 130, 42, 26]));
        assert_eq!(2, crate::check_pwn([17, 174, 226, 73, 23, 62, 136, 125, 51, 27]));
        assert_eq!(
            342,
            crate::run([45, 177, 142, 29, 152, 231, 171, 127, 73, 222])
        );
        assert_eq!(
            522,
            crate::run([52, 251, 51, 0, 185, 167, 123, 235, 220, 152])
        );
        assert_eq!(9, crate::run([53, 47, 120, 41, 162, 56, 75, 0, 28, 193]));
        assert_eq!(1, crate::run([90, 212, 49, 72, 201, 10, 143, 45, 41, 111]));
        assert_eq!(
            248,
            crate::run([165, 17, 180, 26, 189, 82, 154, 35, 117, 166])
        );
        assert_eq!(
            823,
            crate::run([221, 93, 88, 98, 146, 95, 31, 149, 60, 171])
        );
        assert_eq!(
            127,
            crate::run([224, 153, 106, 55, 193, 61, 68, 195, 176, 96])
        );
        assert_eq!(
            122,
            crate::run([228, 177, 247, 160, 235, 36, 35, 105, 236, 166])
        );
    }

    #[test]
    fn check_non_exisiting_records() {
        assert_eq!(0, crate::run([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        assert_eq!(
            0,
            crate::run([228, 17, 47, 160, 235, 36, 35, 105, 236, 166])
        );
    }
}
