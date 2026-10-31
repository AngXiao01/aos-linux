//! Right and channel patterns (SPEC §9.1, §9.3).
//!
//! A right is dot-separated identifiers, optionally ending in `.*`, or the
//! single pattern `*`. A channel pattern is `*`, `name:*`, `name:prefix*` or
//! an exact channel.

use aos_types::id::is_ident;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternError(pub String);

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PatternError {}

pub fn parse_right(s: &str) -> Result<(), PatternError> {
    if s == "*" {
        return Ok(());
    }
    let (body, star) = match s.strip_suffix(".*") {
        Some(body) => (body, true),
        None => (s, false),
    };
    let ok = !body.is_empty() && body.split('.').all(is_ident) && !s.contains("..") && (!star || !body.ends_with('.'));
    if ok { Ok(()) } else { Err(PatternError(format!("invalid right {s:?}"))) }
}

pub fn parse_channel(s: &str) -> Result<(), PatternError> {
    if s == "*" || channel_shape(s) { Ok(()) } else { Err(PatternError(format!("invalid channel pattern {s:?}"))) }
}

fn channel_shape(s: &str) -> bool {
    let Some((name, rest)) = s.split_once(':') else {
        return false;
    };
    if !is_ident(name) || rest.is_empty() || rest.contains(':') {
        return false;
    }
    let body = rest.strip_suffix('*').unwrap_or(rest);
    body.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// `grant` allows exercising the concrete right `need`.
pub fn right_covers(grant: &str, need: &str) -> bool {
    if grant == "*" || grant == need {
        return true;
    }
    let Some(prefix) = grant.strip_suffix(".*") else {
        return false;
    };
    need.starts_with(prefix) && need[prefix.len()..].starts_with('.') && need.len() > prefix.len() + 1
}

/// `child` is no broader than `parent`.
pub fn right_within(parent: &str, child: &str) -> bool {
    if parent == "*" || parent == child {
        return true;
    }
    let Some(prefix) = parent.strip_suffix(".*") else {
        return false;
    };
    if !child.starts_with(prefix) || !child[prefix.len()..].starts_with('.') {
        return false;
    }
    let rest = &child[prefix.len() + 1..];
    !rest.is_empty() && !rest.starts_with('.')
}

pub fn channel_covers(grant: &str, channel: &str) -> bool {
    if grant == "*" || grant == channel {
        return true;
    }
    if let Some(name) = grant.strip_suffix(":*") {
        return channel.starts_with(&format!("{name}:")) && channel.len() > name.len() + 1;
    }
    if let Some(prefix) = grant.strip_suffix('*') {
        return channel.starts_with(prefix) && !channel[prefix.len()..].contains('*');
    }
    false
}

/// Every channel `child` would allow is allowed by `parent`.
pub fn channel_within(parent: &str, child: &str) -> bool {
    if parent == "*" || parent == child {
        return true;
    }
    if let Some(name) = parent.strip_suffix(":*") {
        if let Some(rest) = child.strip_prefix(&format!("{name}:")) {
            return !rest.is_empty();
        }
        return false;
    }
    if let Some(prefix) = parent.strip_suffix('*') {
        if child == parent {
            return true;
        }
        return child.starts_with(prefix) && !child.ends_with('*') && child.len() > prefix.len();
    }
    false
}

pub fn covers_task_create(right: &str) -> bool {
    right_covers(right, "sys.task.create")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_attenuate() {
        assert!(right_covers("ml.*", "ml.dataset.write"));
        assert!(right_covers("ml.dataset.*", "ml.dataset.write"));
        assert!(!right_covers("ml.dataset.*", "ml.experiment.create"));
        assert!(!right_covers("ml.dataset.read", "ml.dataset.write"));
        assert!(right_within("ml.*", "ml.dataset.*"));
        assert!(right_within("ml.dataset.*", "ml.dataset.write"));
        assert!(!right_within("ml.dataset.*", "ml.*"));
        assert!(!right_within("ml.dataset.read", "ml.dataset.*"));
        assert!(covers_task_create("*"));
        assert!(covers_task_create("sys.*"));
        assert!(covers_task_create("sys.task.*"));
        assert!(!covers_task_create("ml.*"));
    }

    #[test]
    fn channels_attenuate() {
        assert!(channel_covers("deliver:*", "deliver:minio-acme"));
        assert!(channel_covers("deliver:minio-*", "deliver:minio-acme"));
        assert!(!channel_covers("deliver:minio-*", "deliver:other"));
        assert!(channel_within("*", "deliver:*"));
        assert!(channel_within("deliver:*", "deliver:minio-*"));
        assert!(channel_within("deliver:*", "deliver:minio-acme"));
        assert!(!channel_within("deliver:minio-*", "deliver:*"));
        assert!(!channel_within("model:default", "model:*"));
        assert!(channel_within("model:default", "model:default"));
    }
}
