//! Table display helpers for CLI output.
//!
//! Provides [`KeyValueRow`] for building key-value summary tables,
//! and helper functions that format NFT data, proof summaries, and
//! verification results as human-readable tables printed to stdout.

use tabled::Tabled;

/// A single key-value row for tabular CLI output.
///
/// Used to build summary tables displayed after each command completes.
#[derive(Tabled)]
pub struct KeyValueRow {
    /// The field label.
    #[tabled(rename = "Field")]
    pub field: String,
    /// The field value.
    #[tabled(rename = "Value")]
    pub value: String,
}

/// Build a table string from a slice of [`KeyValueRow`] values.
///
/// Returns the formatted table as a string ready for printing.
pub fn build_table(rows: &[KeyValueRow]) -> String {
    use tabled::{settings::Style, Table};
    Table::new(rows).with(Style::rounded()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_value_row_fields() {
        let row = KeyValueRow {
            field: "Currency".to_string(),
            value: "EUR".to_string(),
        };
        assert_eq!(row.field, "Currency");
        assert_eq!(row.value, "EUR");
    }
}
