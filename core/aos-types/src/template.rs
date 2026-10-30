//! `{path}` templates for `view_hint.title`, `idempotency_key` and Lens text
//! (SPEC §8.7). `{{` and `}}` stand for literal braces.

use std::fmt;
use std::str::FromStr;

use crate::id::is_ident;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    Literal(String),
    /// A dotted field path such as `dataset.name`.
    Path(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    segments: Vec<Segment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateError(pub String);

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TemplateError {}

impl Template {
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub fn paths(&self) -> impl Iterator<Item = &[String]> {
        self.segments.iter().filter_map(|s| match s {
            Segment::Path(p) => Some(p.as_slice()),
            Segment::Literal(_) => None,
        })
    }

    /// Substitutes every path; fails on the first path `resolve` cannot fill.
    pub fn render(&self, mut resolve: impl FnMut(&[String]) -> Option<String>) -> Result<String, TemplateError> {
        let mut out = String::new();
        for seg in &self.segments {
            match seg {
                Segment::Literal(s) => out.push_str(s),
                Segment::Path(p) => match resolve(p) {
                    Some(v) => out.push_str(&v),
                    None => return Err(TemplateError(format!("unresolved path {}", p.join(".")))),
                },
            }
        }
        Ok(out)
    }
}

impl FromStr for Template {
    type Err = TemplateError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut segments = Vec::new();
        let mut literal = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '{' if chars.peek() == Some(&'{') => {
                    chars.next();
                    literal.push('{');
                }
                '}' if chars.peek() == Some(&'}') => {
                    chars.next();
                    literal.push('}');
                }
                '}' => return Err(TemplateError("unmatched '}'".into())),
                '{' => {
                    let mut path = String::new();
                    loop {
                        match chars.next() {
                            Some('}') => break,
                            Some(c) => path.push(c),
                            None => return Err(TemplateError("unclosed '{'".into())),
                        }
                    }
                    let parts: Vec<String> = path.split('.').map(str::to_owned).collect();
                    if !parts.iter().all(|p| is_ident(p)) {
                        return Err(TemplateError(format!("invalid path {path:?}")));
                    }
                    if !literal.is_empty() {
                        segments.push(Segment::Literal(std::mem::take(&mut literal)));
                    }
                    segments.push(Segment::Path(parts));
                }
                c => literal.push(c),
            }
        }
        if !literal.is_empty() {
            segments.push(Segment::Literal(literal));
        }
        Ok(Template { segments })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_renders() {
        let t: Template = "{dataset.name} v{number} {{raw}}".parse().unwrap();
        let paths: Vec<_> = t.paths().map(|p| p.join(".")).collect();
        assert_eq!(paths, ["dataset.name", "number"]);
        let out = t
            .render(|p| match p.join(".").as_str() {
                "dataset.name" => Some("fall".into()),
                "number" => Some("13".into()),
                _ => None,
            })
            .unwrap();
        assert_eq!(out, "fall v13 {raw}");
        assert!(t.render(|_| None).is_err());
    }

    #[test]
    fn rejects_malformed() {
        for bad in ["{", "}", "{}", "{a..b}", "{A}", "x}y", "{a b}"] {
            assert!(bad.parse::<Template>().is_err(), "{bad}");
        }
    }
}
