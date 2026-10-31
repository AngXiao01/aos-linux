//! A YAML subset large enough for type and action declarations.
//!
//! Block maps, block lists, flow maps and lists, quotes and comments. No
//! anchors, tags or multiline `|` blocks.

use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub enum Yaml {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Seq(Vec<Yaml>),
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        let Yaml::Map(items) = self else { return None };
        items.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn need(&self, key: &str) -> Result<&Yaml, Error> {
        self.get(key).ok_or_else(|| Error(format!("missing {key}")))
    }

    pub fn as_str(&self) -> Result<&str, Error> {
        match self {
            Yaml::Str(s) => Ok(s),
            _ => Err(Error("expected string".into())),
        }
    }

    pub fn as_bool(&self) -> Result<bool, Error> {
        match self {
            Yaml::Bool(b) => Ok(*b),
            _ => Err(Error("expected bool".into())),
        }
    }

    pub fn as_i64(&self) -> Result<i64, Error> {
        match self {
            Yaml::Int(n) => Ok(*n),
            _ => Err(Error("expected integer".into())),
        }
    }

    pub fn as_f64(&self) -> Result<f64, Error> {
        match self {
            Yaml::Float(f) => Ok(*f),
            Yaml::Int(n) => Ok(*n as f64),
            _ => Err(Error("expected number".into())),
        }
    }

    pub fn as_seq(&self) -> Result<&[Yaml], Error> {
        match self {
            Yaml::Seq(s) => Ok(s),
            _ => Err(Error("expected list".into())),
        }
    }

    pub fn as_map(&self) -> Result<&[(String, Yaml)], Error> {
        match self {
            Yaml::Map(m) => Ok(m),
            _ => Err(Error("expected map".into())),
        }
    }

    pub fn keys(&self) -> Result<Vec<&str>, Error> {
        Ok(self.as_map()?.iter().map(|(k, _)| k.as_str()).collect())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub fn parse(input: &str) -> Result<Yaml, Error> {
    let mut p = Parser { s: input, i: 0 };
    p.skip_blank();
    if p.eof() {
        return Ok(Yaml::Null);
    }
    let value = p.parse_block(0)?;
    p.skip_blank();
    if !p.eof() {
        return Err(Error("trailing input".into()));
    }
    Ok(value)
}

struct Parser<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Parser<'a> {
    fn eof(&self) -> bool {
        self.i >= self.s.len()
    }

    fn rest(&self) -> &'a str {
        &self.s[self.i..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i += c.len_utf8();
        Some(c)
    }

    fn err(&self, msg: impl Into<String>) -> Error {
        let seen = self.s[..self.i].bytes().filter(|b| *b == b'\n').count() + 1;
        Error(format!("line {seen}: {}", msg.into()))
    }

    fn indent_here(&self) -> usize {
        self.rest().chars().take_while(|c| *c == ' ').count()
    }

    fn skip_spaces(&mut self) {
        while self.peek() == Some(' ') {
            self.bump();
        }
    }

    fn skip_blank(&mut self) {
        loop {
            let save = self.i;
            self.skip_spaces();
            match self.peek() {
                Some('#') => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                    if self.peek() == Some('\n') {
                        self.bump();
                    }
                }
                Some('\n') => {
                    self.bump();
                }
                _ => {
                    self.i = save;
                    return;
                }
            }
        }
    }

    fn finish_line(&mut self) -> Result<(), Error> {
        self.skip_spaces();
        if self.peek() == Some('#') {
            while self.peek().is_some_and(|c| c != '\n') {
                self.bump();
            }
        }
        match self.peek() {
            None => Ok(()),
            Some('\n') => {
                self.bump();
                Ok(())
            }
            _ => Err(self.err("expected end of line")),
        }
    }

    fn parse_block(&mut self, min_indent: usize) -> Result<Yaml, Error> {
        self.skip_blank();
        if self.eof() {
            return Ok(Yaml::Null);
        }
        let col = self.indent_here();
        if col < min_indent {
            return Ok(Yaml::Null);
        }
        if self.starts_seq(col) {
            return self.parse_seq(col);
        }
        if self.starts_key(col) {
            return self.parse_map(col);
        }
        self.consume_indent(col)?;
        let value = self.parse_inline(false)?;
        self.finish_line()?;
        Ok(value)
    }

    fn consume_indent(&mut self, n: usize) -> Result<(), Error> {
        for _ in 0..n {
            if self.bump() != Some(' ') {
                return Err(self.err("expected indent"));
            }
        }
        if self.peek() == Some('\t') {
            return Err(self.err("tabs are not allowed"));
        }
        Ok(())
    }

    fn starts_seq(&self, indent: usize) -> bool {
        let rest = self.rest();
        let spaces: String = rest.chars().take(indent).collect();
        if spaces != " ".repeat(indent) {
            return false;
        }
        let after = &rest[spaces.len()..];
        after.starts_with("- ") || after.starts_with("-\n") || after == "-"
    }

    fn starts_key(&self, indent: usize) -> bool {
        let rest = self.rest();
        if !rest.starts_with(&" ".repeat(indent)) {
            return false;
        }
        let line = rest[indent..].split('\n').next().unwrap_or("");
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with(['{', '[', '"', '\'']) {
            return false;
        }
        match line.find(':') {
            Some(i) => {
                let key = line[..i].trim();
                !key.is_empty() && !key.contains(' ') && !key.contains('{')
            }
            None => false,
        }
    }

    fn parse_map(&mut self, indent: usize) -> Result<Yaml, Error> {
        let mut items = Vec::new();
        loop {
            self.skip_blank();
            if self.eof() || !self.starts_key(indent) {
                break;
            }
            self.consume_indent(indent)?;
            let key = self.parse_key()?;
            if items.iter().any(|(k, _)| k == &key) {
                return Err(self.err(format!("duplicate key {key}")));
            }
            if self.bump() != Some(':') {
                return Err(self.err("expected ':'"));
            }
            self.skip_spaces();
            let value = if matches!(self.peek(), None | Some('\n') | Some('#')) {
                self.finish_line()?;
                self.parse_block(indent + 1)?
            } else {
                let v = self.parse_inline(false)?;
                self.finish_line()?;
                v
            };
            items.push((key, value));
        }
        Ok(Yaml::Map(items))
    }

    fn parse_seq(&mut self, indent: usize) -> Result<Yaml, Error> {
        let mut items = Vec::new();
        loop {
            self.skip_blank();
            if self.eof() || !self.starts_seq(indent) {
                break;
            }
            self.consume_indent(indent)?;
            if self.bump() != Some('-') {
                return Err(self.err("expected '-'"));
            }
            if self.peek() == Some(' ') {
                self.bump();
            }
            self.skip_spaces();
            let value = if matches!(self.peek(), None | Some('\n') | Some('#')) {
                self.finish_line()?;
                self.parse_block(indent + 2)?
            } else {
                let v = self.parse_inline(false)?;
                self.finish_line()?;
                v
            };
            items.push(value);
        }
        Ok(Yaml::Seq(items))
    }

    fn parse_key(&mut self) -> Result<String, Error> {
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == ':' || c == '\n' || c == '#' {
                break;
            }
            self.bump();
        }
        let key = self.s[start..self.i].trim();
        if key.is_empty() {
            return Err(self.err("empty key"));
        }
        Ok(key.to_owned())
    }

    fn parse_inline(&mut self, flow: bool) -> Result<Yaml, Error> {
        self.skip_spaces();
        match self.peek() {
            Some('{') => self.parse_flow_map(),
            Some('[') => self.parse_flow_seq(),
            Some('"') => self.parse_double(),
            Some('\'') => self.parse_single(),
            Some('|') | Some('>') => Err(self.err("multiline blocks are not supported")),
            _ => self.parse_plain(flow),
        }
    }

    fn parse_flow_map(&mut self) -> Result<Yaml, Error> {
        self.bump();
        let mut items = Vec::new();
        loop {
            self.skip_flow()?;
            if self.peek() == Some('}') {
                self.bump();
                break;
            }
            let key = match self.peek() {
                Some('"') => {
                    let Yaml::Str(s) = self.parse_double()? else { unreachable!() };
                    s
                }
                Some('\'') => {
                    let Yaml::Str(s) = self.parse_single()? else { unreachable!() };
                    s
                }
                _ => self.parse_flow_key()?,
            };
            if items.iter().any(|(k, _)| k == &key) {
                return Err(self.err(format!("duplicate key {key}")));
            }
            self.skip_flow()?;
            if self.bump() != Some(':') {
                return Err(self.err("expected ':'"));
            }
            self.skip_flow()?;
            let value = self.parse_inline(true)?;
            items.push((key, value));
            self.skip_flow()?;
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some('}') => {
                    self.bump();
                    break;
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
        Ok(Yaml::Map(items))
    }

    fn parse_flow_key(&mut self) -> Result<String, Error> {
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == ':' || c == ',' || c == '}' || c == '{' || c == '\n' || c == '#' {
                break;
            }
            self.bump();
        }
        let key = self.s[start..self.i].trim();
        if key.is_empty() {
            return Err(self.err("empty key"));
        }
        Ok(key.to_owned())
    }

    fn parse_flow_seq(&mut self) -> Result<Yaml, Error> {
        self.bump();
        let mut items = Vec::new();
        loop {
            self.skip_flow()?;
            if self.peek() == Some(']') {
                self.bump();
                break;
            }
            items.push(self.parse_inline(true)?);
            self.skip_flow()?;
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some(']') => {
                    self.bump();
                    break;
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
        Ok(Yaml::Seq(items))
    }

    fn skip_flow(&mut self) -> Result<(), Error> {
        loop {
            match self.peek() {
                Some(' ') => {
                    self.bump();
                }
                Some('\n') => {
                    self.bump();
                }
                Some('#') => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                }
                Some('\t') => return Err(self.err("tabs are not allowed")),
                _ => return Ok(()),
            }
        }
    }

    fn parse_double(&mut self) -> Result<Yaml, Error> {
        self.bump();
        let mut out = String::new();
        loop {
            match self.bump() {
                Some('"') => return Ok(Yaml::Str(out)),
                Some('\\') => {
                    let c = match self.bump() {
                        Some('n') => '\n',
                        Some('t') => '\t',
                        Some('\\') => '\\',
                        Some('"') => '"',
                        Some(c) => return Err(self.err(format!("bad escape \\{c}"))),
                        None => return Err(self.err("unclosed string")),
                    };
                    out.push(c);
                }
                Some(c) => out.push(c),
                None => return Err(self.err("unclosed string")),
            }
        }
    }

    fn parse_single(&mut self) -> Result<Yaml, Error> {
        self.bump();
        let mut out = String::new();
        loop {
            match self.bump() {
                Some('\'') if self.peek() == Some('\'') => {
                    self.bump();
                    out.push('\'');
                }
                Some('\'') => return Ok(Yaml::Str(out)),
                Some(c) => out.push(c),
                None => return Err(self.err("unclosed string")),
            }
        }
    }

    /// `flow` stops at `,`, `}` or `]`.
    fn parse_plain(&mut self, flow: bool) -> Result<Yaml, Error> {
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == '\n' || c == '#' || (flow && matches!(c, ',' | '}' | ']')) {
                break;
            }
            self.bump();
        }
        let text = self.s[start..self.i].trim();
        if text.is_empty() {
            return Ok(Yaml::Null);
        }
        Ok(classify(text))
    }
}

fn classify(text: &str) -> Yaml {
    match text {
        "true" => Yaml::Bool(true),
        "false" => Yaml::Bool(false),
        "null" | "~" => Yaml::Null,
        _ => {
            if let Some(n) = parse_int(text) {
                Yaml::Int(n)
            } else if let Some(f) = parse_float(text) {
                Yaml::Float(f)
            } else {
                Yaml::Str(text.to_owned())
            }
        }
    }
}

fn parse_int(text: &str) -> Option<i64> {
    let (sign, digits) = match text.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, text),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    digits.parse::<i64>().ok().map(|n| n * sign)
}

fn parse_float(text: &str) -> Option<f64> {
    let body = text.strip_prefix('-').unwrap_or(text);
    let (whole, frac) = body.split_once('.')?;
    if whole.is_empty()
        || frac.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    if whole.len() > 1 && whole.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_declaration_shapes() {
        let y = parse(
            r#"
# comment
type: ml/DatasetVersion
major: 1
fields:
  dataset: { ref: ml/Dataset, required: true }
  number: { int: {min: 1}, required: true }
  note: { text: {max: 2000} }
  members: { blob: {}, required: true }
relations:
  children: { many: ml/DatasetVersion, via: parent }
view_hint:
  title: "{dataset.name} v{number}"
  primary_fields: [sample_count, note]
"#,
        )
        .unwrap();
        assert_eq!(y.need("type").unwrap().as_str().unwrap(), "ml/DatasetVersion");
        assert_eq!(y.need("major").unwrap().as_i64().unwrap(), 1);
        let fields = y.need("fields").unwrap().as_map().unwrap();
        assert_eq!(fields.len(), 4);
        let number = y.need("fields").unwrap().get("number").unwrap();
        assert_eq!(number.get("int").unwrap().get("min").unwrap().as_i64().unwrap(), 1);
        assert!(number.get("required").unwrap().as_bool().unwrap());
        let list = y.need("view_hint").unwrap().get("primary_fields").unwrap().as_seq().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn parses_action_cost_and_list() {
        let y = parse(
            r#"
action: ml.dataset.dedupe
version: 1
preconditions:
  - "version.sample_count > 0"
effects:
  reads: [ml/DatasetVersion, ml/Sample]
  egress: []
cost:
  cpu_seconds_estimate: "0.002 * version.sample_count"
threshold: { float: {min: 0.5, max: 1.0}, default: 0.95 }
"#,
        )
        .unwrap();
        assert_eq!(y.need("preconditions").unwrap().as_seq().unwrap()[0].as_str().unwrap(), "version.sample_count > 0");
        assert!(y.need("effects").unwrap().get("egress").unwrap().as_seq().unwrap().is_empty());
        assert_eq!(y.get("threshold").unwrap().get("default").unwrap().as_f64().unwrap(), 0.95);
    }
}
