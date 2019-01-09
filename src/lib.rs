use byteorder::{BigEndian, ReadBytesExt};
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::Cursor;
use std::io::SeekFrom;

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
