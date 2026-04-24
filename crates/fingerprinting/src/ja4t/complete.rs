use crate::ja4t::Ja4TInput;

pub fn format_complete(input: &Ja4TInput) -> String {
    format_ja4t_string(
        input.window_size.expect("complete requires window_size"),
        &input.option_kinds_in_order,
        input.mss.expect("complete requires mss"),
        input.window_scale.expect("complete requires window_scale"),
    )
}

fn format_ja4t_string(window_size: u16, option_kinds: &[u8], mss: u16, window_scale: u8) -> String {
    let options = option_kinds
        .iter()
        .map(|k| k.to_string())
        .collect::<Vec<String>>()
        .join("-");
    format!("{window_size}_{options}_{mss}_{window_scale}")
}
