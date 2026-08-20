//! Unicode normalization used by NOVA evaluators.

use unicode_normalization::UnicodeNormalization;

pub(super) fn normalize_for_matching(input: &str) -> String {
    let normalized = input.nfkc().collect::<String>();
    let mut output = String::with_capacity(normalized.len());
    for character in normalized.chars() {
        match confusable_replacement(character) {
            Some(replacement) => output.push_str(replacement),
            None => output.push(character),
        }
    }
    output
}

fn confusable_replacement(character: char) -> Option<&'static str> {
    match character {
        '\u{0430}' => Some("a"),
        '\u{0435}' => Some("e"),
        '\u{043e}' => Some("o"),
        '\u{0440}' => Some("p"),
        '\u{0441}' => Some("c"),
        '\u{0445}' => Some("x"),
        '\u{0443}' => Some("y"),
        '\u{0456}' => Some("i"),
        '\u{0458}' => Some("j"),
        '\u{0455}' => Some("s"),
        '\u{04bb}' => Some("h"),
        '\u{0501}' => Some("d"),
        '\u{0261}' => Some("g"),
        '\u{03bd}' => Some("v"),
        '\u{0410}' | '\u{0391}' => Some("A"),
        '\u{0415}' | '\u{0395}' => Some("E"),
        '\u{041e}' | '\u{039f}' => Some("O"),
        '\u{0420}' | '\u{03a1}' => Some("P"),
        '\u{0421}' => Some("C"),
        '\u{0422}' | '\u{03a4}' => Some("T"),
        '\u{0425}' | '\u{03a7}' => Some("X"),
        '\u{0423}' | '\u{03a5}' => Some("Y"),
        '\u{041c}' | '\u{039c}' => Some("M"),
        '\u{041d}' | '\u{0397}' => Some("H"),
        '\u{0412}' | '\u{0392}' => Some("B"),
        '\u{041a}' | '\u{039a}' => Some("K"),
        '\u{0406}' | '\u{0399}' => Some("I"),
        '\u{039d}' => Some("N"),
        '\u{0396}' => Some("Z"),
        '\u{03bf}' => Some("o"),
        '\u{03b1}' => Some("a"),
        '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{200e}' | '\u{200f}' | '\u{feff}'
        | '\u{00ad}' | '\u{2060}' | '\u{2061}' | '\u{2062}' | '\u{2063}' | '\u{2064}' => Some(""),
        '\u{2113}' => Some("l"),
        '\u{212c}' => Some("B"),
        '\u{2130}' => Some("E"),
        '\u{2131}' => Some("F"),
        '\u{2133}' => Some("M"),
        '\u{211b}' => Some("R"),
        '\u{212e}' => Some("e"),
        '\u{2170}' => Some("i"),
        '\u{2171}' => Some("ii"),
        '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2015}' => Some("-"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: NFKC, confusables, and invisible characters normalize to the
    /// same text NOVA v0.3.0 evaluates.
    #[test]
    fn normalize_for_matching_collapses_supported_obfuscation() {
        assert_eq!(normalize_for_matching("\u{0456}g\u{200b}nore"), "ignore");
        assert_eq!(
            normalize_for_matching("\u{ff49}\u{ff47}\u{ff4e}\u{ff4f}\u{ff52}\u{ff45}"),
            "ignore"
        );
    }

    /// Contract: characters outside the NOVA confusable map survive
    /// normalization.
    #[test]
    fn normalize_for_matching_preserves_unmapped_unicode() {
        assert_eq!(normalize_for_matching("caf\u{e9}"), "caf\u{e9}");
    }
}
