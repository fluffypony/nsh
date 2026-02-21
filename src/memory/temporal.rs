use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};

pub fn parse_temporal_expression(
    expr: &str,
    now: DateTime<Utc>,
) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let lower = expr.to_lowercase();

    if lower.contains("today") {
        let start = Utc
            .with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
            .single()?;
        return Some((start, now));
    }

    if lower.contains("yesterday") {
        let yesterday = now - Duration::days(1);
        let start = Utc
            .with_ymd_and_hms(yesterday.year(), yesterday.month(), yesterday.day(), 0, 0, 0)
            .single()?;
        let end = Utc
            .with_ymd_and_hms(yesterday.year(), yesterday.month(), yesterday.day(), 23, 59, 59)
            .single()?;
        return Some((start, end));
    }

    if lower.contains("this week") {
        let weekday = now.weekday().num_days_from_monday();
        let start = now - Duration::days(weekday as i64);
        let start = Utc
            .with_ymd_and_hms(start.year(), start.month(), start.day(), 0, 0, 0)
            .single()?;
        return Some((start, now));
    }

    if lower.contains("last week") {
        let weekday = now.weekday().num_days_from_monday();
        let this_monday = now - Duration::days(weekday as i64);
        let last_monday = this_monday - Duration::days(7);
        let last_sunday = this_monday - Duration::days(1);
        let start = Utc
            .with_ymd_and_hms(last_monday.year(), last_monday.month(), last_monday.day(), 0, 0, 0)
            .single()?;
        let end = Utc
            .with_ymd_and_hms(
                last_sunday.year(),
                last_sunday.month(),
                last_sunday.day(),
                23,
                59,
                59,
            )
            .single()?;
        return Some((start, end));
    }

    if lower.contains("this morning") {
        let start = Utc
            .with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
            .single()?;
        let end = Utc
            .with_ymd_and_hms(now.year(), now.month(), now.day(), 12, 0, 0)
            .single()?;
        return Some((start, end.min(now)));
    }

    if lower.contains("this afternoon") {
        let start = Utc
            .with_ymd_and_hms(now.year(), now.month(), now.day(), 12, 0, 0)
            .single()?;
        return Some((start, now));
    }

    if lower.contains("last month") {
        let (year, month) = if now.month() == 1 {
            (now.year() - 1, 12)
        } else {
            (now.year(), now.month() - 1)
        };
        let start = Utc.with_ymd_and_hms(year, month, 1, 0, 0, 0).single()?;
        let end_day = days_in_month(year, month);
        let end = Utc
            .with_ymd_and_hms(year, month, end_day, 23, 59, 59)
            .single()?;
        return Some((start, end));
    }

    if lower.contains("last hour") {
        let start = now - Duration::hours(1);
        return Some((start, now));
    }

    if lower.contains("recently") {
        let start = now - Duration::hours(2);
        return Some((start, now));
    }

    if lower.contains("earlier") {
        let start = Utc
            .with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
            .single()?;
        let end = now - Duration::hours(1);
        return Some((start, end));
    }

    if lower.contains("two days ago") {
        let target = now - Duration::days(2);
        let start = Utc
            .with_ymd_and_hms(target.year(), target.month(), target.day(), 0, 0, 0)
            .single()?;
        let end = Utc
            .with_ymd_and_hms(target.year(), target.month(), target.day(), 23, 59, 59)
            .single()?;
        return Some((start, end));
    }

    None
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 2, 21, 14, 30, 0).unwrap()
    }

    #[test]
    fn parse_today() {
        let (start, end) = parse_temporal_expression("today", test_now()).unwrap();
        assert_eq!(start.day(), 21);
        assert_eq!(end, test_now());
    }

    #[test]
    fn parse_yesterday() {
        let (start, end) = parse_temporal_expression("yesterday", test_now()).unwrap();
        assert_eq!(start.day(), 20);
        assert_eq!(end.day(), 20);
    }

    #[test]
    fn parse_last_hour() {
        let (start, end) = parse_temporal_expression("last hour", test_now()).unwrap();
        assert_eq!(start.hour(), 13);
        assert_eq!(end, test_now());
    }

    #[test]
    fn parse_recently() {
        let (start, end) = parse_temporal_expression("recently", test_now()).unwrap();
        assert_eq!(start.hour(), 12);
        assert_eq!(end, test_now());
    }

    #[test]
    fn parse_this_morning() {
        let (start, end) = parse_temporal_expression("this morning", test_now()).unwrap();
        assert_eq!(start.hour(), 0);
        assert_eq!(end.hour(), 12);
    }

    #[test]
    fn parse_two_days_ago() {
        let (start, end) = parse_temporal_expression("two days ago", test_now()).unwrap();
        assert_eq!(start.day(), 19);
        assert_eq!(end.day(), 19);
    }

    #[test]
    fn parse_unknown_returns_none() {
        assert!(parse_temporal_expression("next century", test_now()).is_none());
    }

    #[test]
    fn parse_last_month() {
        let (start, end) = parse_temporal_expression("last month", test_now()).unwrap();
        assert_eq!(start.month(), 1);
        assert_eq!(end.month(), 1);
        assert_eq!(end.day(), 31);
    }

    #[test]
    fn days_in_february_leap_year() {
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(2025, 2), 28);
    }
}
