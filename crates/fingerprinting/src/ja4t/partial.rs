use crate::ja4t::Ja4TInput;

pub fn format_partial(input: &Ja4TInput) -> String {
    let window_size = input.window_size.expect("partial requires window_size");
    let options = input
        .option_kinds_in_order
        .iter()
        .map(|k| k.to_string())
        .collect::<Vec<String>>()
        .join("-");
    let mss = input.mss.map(|v| v.to_string()).unwrap_or_default();
    let window_scale = input
        .window_scale
        .map(|v| v.to_string())
        .unwrap_or_default();
    format!("{window_size}_{options}_{mss}_{window_scale}")
}
