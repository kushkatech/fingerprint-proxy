use crate::logging::filtering::filter_sensitive_context;
use crate::logging::levels::LogLevel;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredLogField {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredLogEvent {
    pub timestamp_unix_ms: u64,
    pub level: LogLevel,
    pub component: String,
    pub message: String,
    pub context: BTreeMap<String, String>,
}

impl StructuredLogEvent {
    pub fn new(
        timestamp_unix_ms: u64,
        level: LogLevel,
        component: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_unix_ms,
            level,
            component: component.into(),
            message: message.into(),
            context: BTreeMap::new(),
        }
    }

    pub fn with_context_field(mut self, field: StructuredLogField) -> Self {
        self.context.insert(field.key, field.value);
        self
    }

    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    pub fn filtered(self) -> Self {
        Self {
            context: filter_sensitive_context(&self.context),
            ..self
        }
    }

    pub fn to_log_line(&self) -> String {
        let mut line = format!(
            "ts={} level={} component={} message={}",
            self.timestamp_unix_ms,
            self.level.as_str(),
            self.component,
            self.message
        );

        if !self.context.is_empty() {
            let serialized_context = self
                .context
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<String>>()
                .join(",");
            line.push_str(" context={");
            line.push_str(&serialized_context);
            line.push('}');
        }

        line
    }
}
