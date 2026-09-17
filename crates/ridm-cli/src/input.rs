//! Reading what should not be on a command line: passwords, secrets and
//! documents. A flag names the source (`--password-stdin`, `-f -`) so a
//! script never depends on a terminal being there.

use std::io::{BufRead as _, IsTerminal as _, Read as _, Write as _};

use zeroize::Zeroizing;

use crate::error::{CliError, Result};

/// One line from stdin, without its line ending.
pub fn line_from_stdin(what: &str) -> Result<Zeroizing<String>> {
    let mut s = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut s)
        .map_err(|e| CliError::failed(format!("reading {what} from stdin: {e}")))?;
    let s = Zeroizing::new(s.trim_end_matches(['\r', '\n']).to_string());
    if s.is_empty() {
        return Err(CliError::usage(format!("no {what} on stdin")));
    }
    Ok(s)
}

/// Ask twice and compare, so a typo is caught before it is stored.
#[cfg(feature = "bootstrap")]
pub fn new_password(label: &str) -> Result<Zeroizing<String>> {
    let first = rpassword::prompt_password(format!("{label}: "))
        .map_err(|e| CliError::failed(format!("reading password: {e}")))?;
    let second = rpassword::prompt_password("Repeat: ")
        .map_err(|e| CliError::failed(format!("reading password: {e}")))?;
    if first != second {
        return Err(CliError::failed("passwords do not match"));
    }
    if first.is_empty() {
        return Err(CliError::usage("password is empty"));
    }
    Ok(Zeroizing::new(first))
}

/// Ask once: the secret already exists, there is nothing to confirm.
pub fn existing_secret(label: &str) -> Result<Zeroizing<String>> {
    let s = rpassword::prompt_password(format!("{label}: "))
        .map_err(|e| CliError::failed(format!("reading {label}: {e}")))?;
    if s.is_empty() {
        return Err(CliError::usage(format!("{label} is empty")));
    }
    Ok(Zeroizing::new(s))
}

/// A line typed at the terminal, or `None` when there is no terminal.
#[cfg(feature = "bootstrap")]
pub fn ask(label: &str) -> Result<Option<String>> {
    if !std::io::stdin().is_terminal() {
        return Ok(None);
    }
    print!("{label}");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    let s = s.trim().to_string();
    Ok((!s.is_empty()).then_some(s))
}

/// Yes or no, defaulting to no; `true` without a terminal (a pipeline that
/// did not pass `--yes` has already been refused by the caller).
pub fn confirm(question: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::usage(format!(
            "{question} — nothing to ask on a pipe; pass --yes to proceed"
        )));
    }
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    Ok(matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// A whole document from a file, or from stdin for `-`.
pub fn document(path: &str) -> Result<String> {
    if path == "-" {
        let mut s = String::new();
        std::io::stdin()
            .lock()
            .read_to_string(&mut s)
            .map_err(|e| CliError::failed(format!("reading the document from stdin: {e}")))?;
        if s.trim().is_empty() {
            return Err(CliError::usage("no document on stdin"));
        }
        return Ok(s);
    }
    std::fs::read_to_string(path).map_err(|e| CliError::failed(format!("{path}: {e}")))
}
