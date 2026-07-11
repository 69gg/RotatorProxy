use std::{error::Error as _, io};

pub fn is_file_descriptor_exhaustion(err: &io::Error) -> bool {
    if is_file_descriptor_exhaustion_code(err.raw_os_error()) {
        return true;
    }

    let mut source = err.source();
    while let Some(err) = source {
        if let Some(err) = err.downcast_ref::<io::Error>()
            && is_file_descriptor_exhaustion_code(err.raw_os_error())
        {
            return true;
        }
        source = err.source();
    }

    file_descriptor_exhaustion_from_message(&err.to_string()).is_some()
}

pub fn file_descriptor_exhaustion_from_message(message: &str) -> Option<io::Error> {
    file_descriptor_exhaustion_codes()
        .into_iter()
        .map(io::Error::from_raw_os_error)
        .find(|err| message.contains(&err.to_string()))
}

fn is_file_descriptor_exhaustion_code(code: Option<i32>) -> bool {
    code.is_some_and(|code| file_descriptor_exhaustion_codes().contains(&code))
}

#[cfg(unix)]
fn file_descriptor_exhaustion_codes() -> [i32; 2] {
    [libc::EMFILE, libc::ENFILE]
}

#[cfg(not(unix))]
fn file_descriptor_exhaustion_codes() -> [i32; 0] {
    []
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn recognizes_process_and_system_file_descriptor_exhaustion() {
        for code in [libc::EMFILE, libc::ENFILE] {
            let err = io::Error::from_raw_os_error(code);
            assert!(is_file_descriptor_exhaustion(&err));

            let wrapped = io::Error::other(io::Error::from_raw_os_error(code));
            assert!(is_file_descriptor_exhaustion(&wrapped));

            let message = format!(
                "external transport failed: {}",
                io::Error::from_raw_os_error(code)
            );
            assert!(file_descriptor_exhaustion_from_message(&message).is_some());
        }
    }

    #[test]
    fn rejects_unrelated_io_errors() {
        let err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        assert!(!is_file_descriptor_exhaustion(&err));
        assert!(file_descriptor_exhaustion_from_message("connection refused").is_none());
    }
}
