// #![feature(test)]
// extern crate test;

// use test::Bencher;

// #[bench]
// fn binary_search_has_match(b: &mut Bencher) {
//     let target = [221, 93, 88, 98, 146, 95, 31, 149, 60, 171];
//     b.iter(|| {
//         haveibeenpwned::check_pwned(target);
//     });
// }

// #[bench]
// fn binary_search_no_match(b: &mut Bencher) {
//     let target = [221, 93, 88, 98, 146, 95, 31, 149, 60, 11];
//     b.iter(|| {
//         haveibeenpwned::check_pwned(target);
//     });
// }
