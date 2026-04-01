//! Extract Willow `Area` from UCAN policy predicates.
//!
//! The canonical WillowArea policy block uses well-known `wil_` prefixed
//! selectors that map deterministically to Willow's `Area` struct:
//!
//! | Policy predicate | Area field |
//! |---|---|
//! | `["==", ".wil_subspace", bytes]` | `subspace_id` |
//! | `["or", ["==", ".wil_path", s], ["like", ".wil_path", s/*]]` | `path` (prefix) |
//! | `[">=", ".wil_time_start", int]` | `times.start` |
//! | `["<=", ".wil_time_end", int]` | `times.end` |
//!
//! Predicate semantics express **area containment**: an invocation's
//! claimed area must fit within each delegation's granted area. Entry-
//! level validation uses Willow-native `area.includes_entry()`.

use std::collections::BTreeMap;

use ipld_core::ipld::Ipld;
use thiserror::Error;
use ucan::delegation::policy::{
    predicate::Predicate,
    selector::{filter::Filter, select::Select},
};
use ucan::number::Number;
use ucan::promise::Promised;
use willow_data_model::grouping::{AreaSubspace, Range, RangeEnd};

use crate::proto::{
    data_model::{Path, PathExt as _},
    grouping::Area,
    keys::UserId,
};

// Canonical `wil_` policy selector names.
pub const WIL_SUBSPACE: &str = "wil_subspace";
pub const WIL_PATH: &str = "wil_path";
pub const WIL_TIME_START: &str = "wil_time_start";
pub const WIL_TIME_END: &str = "wil_time_end";

/// Errors from WillowArea extraction.
#[derive(Debug, Error)]
pub enum AreaExtractError {
    #[error("invalid wil_subspace: expected 32-byte value")]
    InvalidSubspace,
    #[error("invalid wil_path: {0}")]
    InvalidPath(String),
    #[error("invalid wil_time_start: expected non-negative integer")]
    InvalidTimeStart,
    #[error("invalid wil_time_end: expected non-negative integer")]
    InvalidTimeEnd,
    #[error("wil_time_end must be greater than wil_time_start")]
    InvalidTimeRange,
}

// -- Selector constructors ---------------------------------------------------

/// Build a `Select` for a single `.field_name` access.
fn field_selector<T>(name: &str) -> Select<T> {
    Select::new(vec![Filter::Field(name.to_owned())])
}

/// Check if a `Select` matches a single `.field_name` pattern.
fn selector_is_field<T>(sel: &Select<T>, name: &str) -> bool {
    *sel == Select::new(vec![Filter::Field(name.to_owned())])
}

// -- Extraction --------------------------------------------------------------

/// Extracted WillowArea fields from UCAN policy predicates.
///
/// All fields are optional — absent means "any" / "full range".
#[derive(Debug, Default)]
struct RawWillowArea {
    subspace: Option<[u8; 32]>,
    path: Option<String>,
    time_start: Option<u64>,
    time_end: Option<u64>,
}

/// Extract a Willow `Area` from a slice of UCAN `Predicate`s.
///
/// Only `wil_`-prefixed selectors are examined. Non-`wil_` predicates
/// are ignored (they're application-level constraints evaluated at
/// invocation time).
pub fn extract_willow_area(predicates: &[Predicate]) -> Result<Area, AreaExtractError> {
    let raw = extract_raw(predicates)?;
    raw_to_area(raw)
}

/// Scan predicates for `wil_*` selectors and collect raw values.
fn extract_raw(predicates: &[Predicate]) -> Result<RawWillowArea, AreaExtractError> {
    let mut raw = RawWillowArea::default();

    for pred in predicates {
        match pred {
            Predicate::Equal(selector, value) => {
                if selector_is_field(selector, WIL_SUBSPACE) {
                    raw.subspace = Some(ipld_to_32_bytes(value)?);
                }
            }
            Predicate::Or(inner) => {
                // Or(Equal(".wil_path", s), Like(".wil_path", s/*))
                // Extract the path from the Equal arm.
                for p in inner {
                    if let Predicate::Equal(selector, value) = p {
                        if selector_is_field(selector, WIL_PATH) {
                            raw.path = Some(ipld_to_string(value).ok_or_else(|| {
                                AreaExtractError::InvalidPath("expected string".to_owned())
                            })?);
                        }
                    }
                }
            }
            Predicate::GreaterThanOrEqual(selector, value) => {
                if selector_is_field(selector, WIL_TIME_START) {
                    raw.time_start =
                        Some(number_to_u64(value).ok_or(AreaExtractError::InvalidTimeStart)?);
                }
            }
            Predicate::LessThanOrEqual(selector, value) => {
                if selector_is_field(selector, WIL_TIME_END) {
                    raw.time_end =
                        Some(number_to_u64(value).ok_or(AreaExtractError::InvalidTimeEnd)?);
                }
            }
            _ => {}
        }
    }

    Ok(raw)
}

/// Convert raw extracted values into a Willow `Area`.
fn raw_to_area(raw: RawWillowArea) -> Result<Area, AreaExtractError> {
    let subspace = match raw.subspace {
        Some(bytes) => AreaSubspace::Id(UserId::from(bytes)),
        None => AreaSubspace::Any,
    };

    let path = match raw.path {
        Some(ref s) => parse_willow_path(s)
            .map_err(|e| AreaExtractError::InvalidPath(e.to_string()))?,
        None => Path::new_empty(),
    };

    let time_start = raw.time_start.unwrap_or(0);
    let times = match raw.time_end {
        Some(end) => {
            if end <= time_start {
                return Err(AreaExtractError::InvalidTimeRange);
            }
            Range::new(time_start, RangeEnd::Closed(end))
        }
        None => Range::new(time_start, RangeEnd::Open),
    };

    Ok(Area::new(subspace, path, times))
}

// -- Construction ------------------------------------------------------------

/// Build UCAN policy predicates from a Willow `Area`.
///
/// Inverse of `extract_willow_area`. Used when creating delegation tokens.
pub fn area_to_predicates(area: &Area) -> Vec<Predicate> {
    let mut preds = Vec::new();

    // Subspace
    if let AreaSubspace::Id(user_id) = area.subspace() {
        let selector: Select<Ipld> = field_selector(WIL_SUBSPACE);
        let value = Ipld::Bytes(user_id.as_bytes().to_vec());
        preds.push(Predicate::Equal(selector, value));
    }

    // Path prefix — Or(Equal(path), Like(path/*)) expresses Willow's
    // component-level prefix matching using UCAN built-in predicates.
    // The Equal arm matches the exact path; the Like arm matches any
    // sub-path (glob `*` matches all characters including `/`).
    if !area.path().is_empty() {
        let path_str = path_to_string(area.path());
        preds.push(Predicate::Or(vec![
            Predicate::Equal(
                field_selector(WIL_PATH),
                Ipld::String(path_str.clone()),
            ),
            Predicate::Like(
                field_selector(WIL_PATH),
                format!("{path_str}/*"),
            ),
        ]));
    }

    // Time start (only if non-zero)
    if area.times().start > 0 {
        let selector: Select<Number> = field_selector(WIL_TIME_START);
        preds.push(Predicate::GreaterThanOrEqual(
            selector,
            Number::Integer(i128::from(area.times().start)),
        ));
    }

    // Time end — LessThanOrEqual for area containment semantics
    // (the claimed area end can equal the delegation's end).
    if let RangeEnd::Closed(end) = area.times().end {
        let selector: Select<Number> = field_selector(WIL_TIME_END);
        preds.push(Predicate::LessThanOrEqual(
            selector,
            Number::Integer(i128::from(end)),
        ));
    }

    preds
}

// -- Invocation args ---------------------------------------------------------

/// Convert a Willow `Area` to UCAN invocation arguments.
///
/// Used when building invocations — the args describe what area the
/// invocation is exercising. `syntatic_checks()` validates these args
/// against the delegation chain's predicates.
pub fn area_to_args(area: &Area) -> BTreeMap<String, Promised> {
    let mut args = BTreeMap::new();

    if let AreaSubspace::Id(user_id) = area.subspace() {
        args.insert(
            WIL_SUBSPACE.to_owned(),
            Promised::Bytes(user_id.as_bytes().to_vec()),
        );
    }

    if !area.path().is_empty() {
        args.insert(
            WIL_PATH.to_owned(),
            Promised::String(path_to_string(area.path())),
        );
    }

    if area.times().start > 0 {
        args.insert(
            WIL_TIME_START.to_owned(),
            Promised::Integer(i128::from(area.times().start)),
        );
    }

    if let RangeEnd::Closed(end) = area.times().end {
        args.insert(
            WIL_TIME_END.to_owned(),
            Promised::Integer(i128::from(end)),
        );
    }

    args
}

// -- Path conversion ---------------------------------------------------------

/// Encode a Willow `Path` as a `/`-separated string.
fn path_to_string(path: &Path) -> String {
    path.components()
        .map(|c| String::from_utf8_lossy(c.as_ref()).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Parse a `/`-separated path string into a Willow `Path`.
fn parse_willow_path(s: &str) -> Result<Path, anyhow::Error> {
    if s.is_empty() {
        return Ok(Path::new_empty());
    }
    let components: Vec<&[u8]> = s.split('/').map(str::as_bytes).collect();
    Path::from_bytes(&components).map_err(|e| anyhow::anyhow!("invalid path: {e}"))
}

// -- Helpers -----------------------------------------------------------------

fn ipld_to_32_bytes(ipld: &Ipld) -> Result<[u8; 32], AreaExtractError> {
    match ipld {
        Ipld::Bytes(b) if b.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(b);
            Ok(out)
        }
        _ => Err(AreaExtractError::InvalidSubspace),
    }
}

fn ipld_to_string(ipld: &Ipld) -> Option<String> {
    match ipld {
        Ipld::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn number_to_u64(n: &Number) -> Option<u64> {
    match n {
        Number::Integer(i) => u64::try_from(*i).ok(),
        Number::Float(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucan::delegation::policy::predicate::glob;

    #[test]
    fn full_area_from_empty_predicates() {
        let area = extract_willow_area(&[]).unwrap();
        assert!(area.subspace().is_any());
        assert!(area.path().is_empty());
        assert_eq!(area.times().start, 0);
        assert!(matches!(area.times().end, RangeEnd::Open));
    }

    #[test]
    fn roundtrip_area_with_all_fields() {
        let user_bytes = [42u8; 32];
        let original = Area::new(
            AreaSubspace::Id(UserId::from(user_bytes)),
            parse_willow_path("code/seasonal-clock").unwrap(),
            Range::new(1_700_000_000, RangeEnd::Closed(1_800_000_000)),
        );

        let predicates = area_to_predicates(&original);
        let extracted = extract_willow_area(&predicates).unwrap();

        assert_eq!(extracted.subspace(), original.subspace());
        assert_eq!(extracted.path(), original.path());
        assert_eq!(extracted.times().start, original.times().start);
        assert_eq!(extracted.times().end, original.times().end);
    }

    #[test]
    fn path_predicate_uses_or_equal_like() {
        let area = Area::new(
            AreaSubspace::Any,
            parse_willow_path("data").unwrap(),
            Range::new(0, RangeEnd::Open),
        );

        let predicates = area_to_predicates(&area);
        assert_eq!(predicates.len(), 1);
        assert!(matches!(&predicates[0], Predicate::Or(inner) if inner.len() == 2));
    }

    #[test]
    fn path_glob_matches_subpath() {
        // Verify the glob pattern "data/*" matches sub-paths correctly.
        assert!(glob("data/messages", "data/*"));
        assert!(glob("data/sub/deep", "data/*"));
        assert!(!glob("data2", "data/*"));
        assert!(!glob("data", "data/*"));
    }

    #[test]
    fn path_or_predicate_matches_exact_and_subpath() {
        // Or(Equal("data"), Like("data/*")) matches both exact and sub-paths.
        let path_str = "data";
        let pred = Predicate::Or(vec![
            Predicate::Equal(
                field_selector(WIL_PATH),
                Ipld::String(path_str.to_owned()),
            ),
            Predicate::Like(field_selector(WIL_PATH), format!("{path_str}/*")),
        ]);

        let check = |val: &str| -> bool {
            let args = Ipld::Map(
                [(WIL_PATH.to_owned(), Ipld::String(val.to_owned()))]
                    .into_iter()
                    .collect(),
            );
            pred.run(&args).unwrap()
        };

        assert!(check("data"), "exact match");
        assert!(check("data/messages"), "sub-path");
        assert!(check("data/sub/deep"), "deep sub-path");
        assert!(!check("data2"), "different component");
        assert!(!check("dat"), "partial match");
    }

    #[test]
    fn time_end_uses_le() {
        let area = Area::new(
            AreaSubspace::Any,
            Path::new_empty(),
            Range::new(100, RangeEnd::Closed(200)),
        );

        let predicates = area_to_predicates(&area);
        let has_le = predicates.iter().any(|p| {
            matches!(p, Predicate::LessThanOrEqual(sel, _) if selector_is_field(sel, WIL_TIME_END))
        });
        assert!(has_le, "time_end should use LessThanOrEqual");
    }

    #[test]
    fn area_to_args_roundtrip() {
        let user_bytes = [7u8; 32];
        let area = Area::new(
            AreaSubspace::Id(UserId::from(user_bytes)),
            parse_willow_path("msgs/chat").unwrap(),
            Range::new(100, RangeEnd::Closed(200)),
        );

        let args = area_to_args(&area);
        assert_eq!(args.len(), 4);
        assert!(matches!(args.get(WIL_SUBSPACE), Some(Promised::Bytes(b)) if b.len() == 32));
        assert!(matches!(args.get(WIL_PATH), Some(Promised::String(s)) if s == "msgs/chat"));
        assert!(matches!(args.get(WIL_TIME_START), Some(Promised::Integer(100))));
        assert!(matches!(args.get(WIL_TIME_END), Some(Promised::Integer(200))));
    }

    #[test]
    fn area_to_args_full_area_is_empty() {
        let area = Area::new_full();
        let args = area_to_args(&area);
        assert!(args.is_empty());
    }
}
