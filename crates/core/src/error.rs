use std::error::Error;
use std::fmt;

pub type FpResult<T> = Result<T, FpError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidConfiguration,
    InvalidProtocolData,
    ValidationFailed,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FpError {
    pub kind: ErrorKind,
    pub message: String,
}

impl FpError {
    pub fn invalid_configuration(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::InvalidConfiguration,
            message: message.into(),
        }
    }

    pub fn invalid_protocol_data(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::InvalidProtocolData,
            message: message.into(),
        }
    }

    pub fn validation_failed(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::ValidationFailed,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Internal,
            message: message.into(),
        }
    }
}

impl fmt::Display for FpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl Error for FpError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    pub severity: IssueSeverity,
    pub path: String,
    pub message: String,
}

impl ValidationIssue {
    pub fn error(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: IssueSeverity::Error,
            path: path.into(),
            message: message.into(),
        }
    }

    pub fn warning(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: IssueSeverity::Warning,
            path: path.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub issues: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn push(&mut self, issue: ValidationIssue) {
        self.issues.push(issue);
    }

    pub fn has_errors(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| issue.severity == IssueSeverity::Error)
    }

    pub fn into_result(self) -> Result<(), ValidationReport> {
        if self.has_errors() {
            Err(self)
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, issue) in self.issues.iter().enumerate() {
            if idx > 0 {
                writeln!(f)?;
            }
            write!(
                f,
                "[{:?}] {}: {}",
                issue.severity, issue.path, issue.message
            )?;
        }
        Ok(())
    }
}

impl Error for ValidationReport {}
