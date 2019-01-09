use haveibeenpwned;

#[cfg(test)]
mod tests {
    #[test]
    fn check_all_exisiting_records() {
        assert_eq!(187, haveibeenpwned::check_pwned([4, 5, 58, 123, 138, 105, 87, 130, 42, 26]));
        assert_eq!(2, haveibeenpwned::check_pwned([17, 174, 226, 73, 23, 62, 136, 125, 51, 27]));
        assert_eq!(
            342,
            haveibeenpwned::check_pwned([45, 177, 142, 29, 152, 231, 171, 127, 73, 222])
        );
        assert_eq!(
            522,
            haveibeenpwned::check_pwned([52, 251, 51, 0, 185, 167, 123, 235, 220, 152])
        );
        assert_eq!(9, haveibeenpwned::check_pwned([53, 47, 120, 41, 162, 56, 75, 0, 28, 193]));
        assert_eq!(1, haveibeenpwned::check_pwned([90, 212, 49, 72, 201, 10, 143, 45, 41, 111]));
        assert_eq!(
            248,
            haveibeenpwned::check_pwned([165, 17, 180, 26, 189, 82, 154, 35, 117, 166])
        );
        assert_eq!(
            823,
            haveibeenpwned::check_pwned([221, 93, 88, 98, 146, 95, 31, 149, 60, 171])
        );
        assert_eq!(
            127,
            haveibeenpwned::check_pwned([224, 153, 106, 55, 193, 61, 68, 195, 176, 96])
        );
        assert_eq!(
            122,
            haveibeenpwned::check_pwned([228, 177, 247, 160, 235, 36, 35, 105, 236, 166])
        );
    }

    #[test]
    fn check_non_exisiting_records() {
        assert_eq!(0, haveibeenpwned::check_pwned([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        assert_eq!(
            0,
            haveibeenpwned::check_pwned([228, 17, 47, 160, 235, 36, 35, 105, 236, 166])
        );
    }
}
