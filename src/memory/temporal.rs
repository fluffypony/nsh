#[cfg(test)]
use chrono::Timelike;
use chrono::{DateTime, Datelike, Duration, TimeZone, Utc};

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
            .with_ymd_and_hms(
                yesterday.year(),
                yesterday.month(),
                yesterday.day(),
                0,
                0,
                0,
            )
            .single()?;
        let end = Utc
            .with_ymd_and_hms(
                yesterday.year(),
                yesterday.month(),
                yesterday.day(),
                23,
                59,
                59,
            )
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
            .with_ymd_and_hms(
                last_monday.year(),
                last_monday.month(),
                last_monday.day(),
                0,
                0,
                0,
            )
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

    #[test]
    fn parse_this_week() {
        let (start, end) = parse_temporal_expression("this week", test_now()).unwrap();
        assert!(start <= test_now());
        assert_eq!(end, test_now());
        // Start should be a Monday
        assert_eq!(start.weekday().num_days_from_monday(), 0);
    }

    #[test]
    fn parse_last_week() {
        let (start, end) = parse_temporal_expression("last week", test_now()).unwrap();
        // Should be the previous Monday to Sunday
        assert!(start < test_now());
        assert!(end < test_now());
        assert_eq!(start.weekday().num_days_from_monday(), 0);
        assert_eq!(end.hour(), 23);
        assert_eq!(end.minute(), 59);
    }

    #[test]
    fn parse_this_afternoon() {
        let (start, end) = parse_temporal_expression("this afternoon", test_now()).unwrap();
        assert_eq!(start.hour(), 12);
        assert_eq!(end, test_now());
    }

    #[test]
    fn parse_earlier() {
        let (start, end) = parse_temporal_expression("earlier", test_now()).unwrap();
        assert_eq!(start.hour(), 0);
        assert!(end < test_now());
    }

    #[test]
    fn parse_case_insensitive() {
        assert!(parse_temporal_expression("TODAY", test_now()).is_some());
        assert!(parse_temporal_expression("Yesterday", test_now()).is_some());
        assert!(parse_temporal_expression("LAST HOUR", test_now()).is_some());
    }

    #[test]
    fn parse_embedded_in_sentence() {
        let result = parse_temporal_expression("what did I do yesterday afternoon", test_now());
        assert!(result.is_some(), "should detect 'yesterday' in longer text");
        let (start, _) = result.unwrap();
        assert_eq!(start.day(), 20);
    }

    #[test]
    fn parse_multiple_temporal_matches_first_wins() {
        // "today" appears before "yesterday" in the check order
        let result = parse_temporal_expression("today and yesterday", test_now());
        assert!(result.is_some());
        let (start, _) = result.unwrap();
        assert_eq!(start.day(), 21); // today wins
    }

    #[test]
    fn parse_last_month_january_wraps_to_december() {
        // If now is January, last month should be December of previous year
        let jan_now = Utc.with_ymd_and_hms(2026, 1, 15, 10, 0, 0).unwrap();
        let (start, end) = parse_temporal_expression("last month", jan_now).unwrap();
        assert_eq!(start.month(), 12);
        assert_eq!(start.year(), 2025);
        assert_eq!(end.month(), 12);
        assert_eq!(end.day(), 31);
    }

    #[test]
    fn parse_last_month_march_gets_feb() {
        let mar_now = Utc.with_ymd_and_hms(2026, 3, 15, 10, 0, 0).unwrap();
        let (start, end) = parse_temporal_expression("last month", mar_now).unwrap();
        assert_eq!(start.month(), 2);
        assert_eq!(end.month(), 2);
        assert_eq!(end.day(), 28); // 2026 is not a leap year
    }

    #[test]
    fn parse_last_month_march_leap_year() {
        let mar_leap = Utc.with_ymd_and_hms(2024, 3, 15, 10, 0, 0).unwrap();
        let (start, end) = parse_temporal_expression("last month", mar_leap).unwrap();
        assert_eq!(start.month(), 2);
        assert_eq!(end.day(), 29); // 2024 is a leap year
    }

    #[test]
    fn days_in_month_all_months() {
        assert_eq!(days_in_month(2026, 1), 31);
        assert_eq!(days_in_month(2026, 2), 28);
        assert_eq!(days_in_month(2026, 3), 31);
        assert_eq!(days_in_month(2026, 4), 30);
        assert_eq!(days_in_month(2026, 5), 31);
        assert_eq!(days_in_month(2026, 6), 30);
        assert_eq!(days_in_month(2026, 7), 31);
        assert_eq!(days_in_month(2026, 8), 31);
        assert_eq!(days_in_month(2026, 9), 30);
        assert_eq!(days_in_month(2026, 10), 31);
        assert_eq!(days_in_month(2026, 11), 30);
        assert_eq!(days_in_month(2026, 12), 31);
    }

    #[test]
    fn days_in_month_century_not_leap() {
        assert_eq!(days_in_month(1900, 2), 28);
        assert_eq!(days_in_month(2100, 2), 28);
    }

    #[test]
    fn days_in_month_400_year_leap() {
        assert_eq!(days_in_month(2000, 2), 29);
        assert_eq!(days_in_month(2400, 2), 29);
    }

    #[test]
    fn parse_this_morning_before_noon() {
        let morning_now = Utc.with_ymd_and_hms(2026, 2, 21, 9, 0, 0).unwrap();
        let (start, end) = parse_temporal_expression("this morning", morning_now).unwrap();
        assert_eq!(start.hour(), 0);
        // End should be min(12:00, now) = now since we're before noon
        assert_eq!(end.hour(), 9);
    }

    #[test]
    fn parse_recently_window() {
        let (start, end) = parse_temporal_expression("recently", test_now()).unwrap();
        // "recently" = last 2 hours
        let diff = end - start;
        assert_eq!(diff.num_hours(), 2);
    }

    #[test]
    fn parse_two_days_ago_range() {
        let (start, end) = parse_temporal_expression("two days ago", test_now()).unwrap();
        assert_eq!(start.hour(), 0);
        assert_eq!(end.hour(), 23);
        assert_eq!(end.minute(), 59);
        assert_eq!(end.second(), 59);
    }

    #[test]
    fn parse_random_text_returns_none() {
        assert!(parse_temporal_expression("cargo build --release", test_now()).is_none());
        assert!(parse_temporal_expression("fix the bug", test_now()).is_none());
        assert!(parse_temporal_expression("", test_now()).is_none());
    }
}
