//! Human-readable durations of the configuration (FR-CFG-2): one or more
//! components made of an unsigned integer and a unit, such as `"5s"`,
//! `"500ms"` or `"1m30s"`. Units: `ms`, `s`, `m`, `h`.

use std::time::Duration;

pub fn parse(text: &str) -> Result<Duration, String> {
    let err = || format!("invalid duration {text:?} (expected for example \"5s\", \"500ms\", \"1m30s\")");
    let mut rest = text.trim();
    if rest.is_empty() {
        return Err(err());
    }
    let mut total = Duration::ZERO;
    while !rest.is_empty() {
        let digits = rest.find(|c: char| !c.is_ascii_digit()).ok_or_else(err)?;
        if digits == 0 {
            return Err(err());
        }
        let value: u64 = rest[..digits].parse().map_err(|_| err())?;
        rest = &rest[digits..];
        let unit_len = rest.find(|c: char| c.is_ascii_digit()).unwrap_or(rest.len());
        let part = match &rest[..unit_len] {
            "ms" => Duration::from_millis(value),
            "s" => Duration::from_secs(value),
            "m" => Duration::from_secs(value.checked_mul(60).ok_or_else(err)?),
            "h" => Duration::from_secs(value.checked_mul(3600).ok_or_else(err)?),
            _ => return Err(err()),
        };
        total = total.checked_add(part).ok_or_else(err)?;
        rest = &rest[unit_len..];
    }
    Ok(total)
}

/// Formats a duration the way the configuration writes it.
pub fn format(d: Duration) -> String {
    let ms = d.as_millis();
    if !ms.is_multiple_of(1000) {
        format!("{ms}ms")
    } else {
        format!("{}s", ms / 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units_and_combinations() {
        assert_eq!(parse("5s"), Ok(Duration::from_secs(5)));
        assert_eq!(parse("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse("1m30s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse("1h"), Ok(Duration::from_secs(3600)));
        assert_eq!(parse("0s"), Ok(Duration::ZERO));
    }

    #[test]
    fn rejects_malformed_text() {
        for bad in [
            "",
            "5",
            "s",
            "5 s",
            "-1s",
            "1.5s",
            "5sec",
            "5S",
            "1m30",
            "99999999999999999999h",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn formats_round_trip() {
        assert_eq!(format(Duration::from_secs(60)), "60s");
        assert_eq!(format(Duration::from_millis(1500)), "1500ms");
    }
}
