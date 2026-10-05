//! The FIPS build's start-up checks (docs/src/deploy/fips.md). Before the
//! server or a subcommand touches anything, the AWS-LC FIPS module must pass
//! its power-on self-test, and the host must be in FIPS mode
//! (`/proc/sys/crypto/fips_enabled` = 1) unless `FIPS_ALLOW_NON_FIPS_HOST`
//! says otherwise. The standard build has nothing to check.

/// What the checks found, for the start-up log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The linked AWS-LC version (e.g. `"3.0.0"`).
    pub module_version: &'static str,
    /// The FIPS module version the build corresponds to.
    pub fips_version: Option<u32>,
    /// The host is in FIPS mode. `false` only when `FIPS_ALLOW_NON_FIPS_HOST`
    /// let the process start anyway.
    pub host_fips: bool,
}

#[cfg(feature = "fips")]
const HOST_FIPS_FILE: &str = "/proc/sys/crypto/fips_enabled";

/// `None` in the standard build. In the FIPS build, `Err` names the check
/// that failed and the process must not start.
#[cfg(feature = "fips")]
pub fn check() -> Result<Option<Status>, String> {
    aws_lc_rs::try_fips_mode()
        .map_err(|e| format!("the AWS-LC FIPS module is not in FIPS mode: {e}"))?;
    let host_fips = std::fs::read_to_string(HOST_FIPS_FILE).is_ok_and(|v| host_says_fips(&v));
    let allow =
        crate::config::parse_bool("FIPS_ALLOW_NON_FIPS_HOST", false).map_err(|e| e.to_string())?;
    host_decision(host_fips, allow)?;
    Ok(Some(Status {
        module_version: aws_lc_rs::awslc_version(),
        fips_version: aws_lc_rs::fips_version(),
        host_fips,
    }))
}

#[cfg(not(feature = "fips"))]
pub fn check() -> Result<Option<Status>, String> {
    Ok(None)
}

/// The kernel's `fips_enabled` reads `1` in FIPS mode.
#[cfg(any(feature = "fips", test))]
fn host_says_fips(contents: &str) -> bool {
    contents.trim() == "1"
}

/// A non-FIPS host is refused unless the operator allowed it.
#[cfg(any(feature = "fips", test))]
fn host_decision(host_fips: bool, allow_non_fips_host: bool) -> Result<(), String> {
    if host_fips || allow_non_fips_host {
        Ok(())
    } else {
        Err("this is the FIPS build, and the host is not in FIPS mode \
             (/proc/sys/crypto/fips_enabled is not 1). Enable FIPS mode on the host, \
             or set FIPS_ALLOW_NON_FIPS_HOST=true for development and CI only"
            .to_string())
    }
}

/// The warning printed when `FIPS_ALLOW_NON_FIPS_HOST` let a FIPS build start
/// on a host that isn't in FIPS mode.
pub const NON_FIPS_HOST_WARNING: &str = "FIPS_ALLOW_NON_FIPS_HOST is set and the host is NOT in \
     FIPS mode: this deployment is not running in a FIPS-validated configuration. Use this \
     for development and CI only";

/// Run [`check`], print the override warning to stderr, and exit the process
/// when a check fails. For the binaries' `main`, before logging is set up.
pub fn check_or_exit(program: &str) -> Option<Status> {
    match check() {
        Ok(status) => {
            if status.as_ref().is_some_and(|s| !s.host_fips) {
                eprintln!("{program}: WARNING: {NON_FIPS_HOST_WARNING}");
            }
            status
        }
        Err(err) => {
            eprintln!("{program}: {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernel_flag_reads_one_in_fips_mode() {
        assert!(host_says_fips("1\n"));
        assert!(!host_says_fips("0\n"));
        assert!(!host_says_fips(""));
    }

    #[test]
    fn a_non_fips_host_needs_the_override() {
        assert!(host_decision(true, false).is_ok());
        assert!(host_decision(false, true).is_ok());
        let err = host_decision(false, false).unwrap_err();
        assert!(err.contains("FIPS_ALLOW_NON_FIPS_HOST"));
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn the_standard_build_has_nothing_to_check() {
        assert_eq!(check(), Ok(None));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn the_fips_module_passes_its_self_test() {
        assert!(aws_lc_rs::try_fips_mode().is_ok());
        assert!(!aws_lc_rs::awslc_version().is_empty());
    }
}
