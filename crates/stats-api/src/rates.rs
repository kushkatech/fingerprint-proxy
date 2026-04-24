pub fn per_second(count: u64, window_seconds: u64) -> f64 {
    if window_seconds == 0 {
        return 0.0;
    }
    count as f64 / window_seconds as f64
}

pub fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    numerator as f64 / denominator as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_second_is_zero_for_zero_window() {
        assert_eq!(per_second(10, 0), 0.0);
    }

    #[test]
    fn ratio_is_zero_for_zero_denominator() {
        assert_eq!(ratio(5, 0), 0.0);
    }
}
