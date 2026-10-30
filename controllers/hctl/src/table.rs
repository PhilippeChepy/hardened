//! Tables, their columns aligned.

use std::io::{self, Write};
use std::iter;

/// Prints `header` then `rows`, each column as wide as its widest cell.
pub fn print<const N: usize>(
    out: &mut impl Write,
    header: [&str; N],
    rows: impl IntoIterator<Item = [String; N]>,
) -> io::Result<()> {
    let rows: Vec<[String; N]> = iter::once(header.map(str::to_owned)).chain(rows).collect();
    let mut widths = [0; N];
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    for row in &rows {
        let line: String = row
            .iter()
            .zip(widths)
            .map(|(cell, width)| format!("{cell:<width$}  "))
            .collect();
        writeln!(out, "{}", line.trim_end())?;
    }
    Ok(())
}
