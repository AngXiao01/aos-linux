//! The CEL subset used by preconditions and cost expressions (SPEC §8.7):
//! literals, paths, comparisons, arithmetic, `&&` `||` `!`, `in` and `size()`.

use std::collections::BTreeMap;
use std::fmt;

use aos_types::{FieldValue, Object, ObjectId};

#[derive(Clone, Debug, PartialEq)]
pub struct Expr {
    source: String,
    node: Node,
}

#[derive(Clone, Debug, PartialEq)]
enum Node {
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    List(Vec<Node>),
    Path(Vec<String>),
    Not(Box<Node>),
    Neg(Box<Node>),
    Bin(BinOp, Box<Node>, Box<Node>),
    Size(Box<Node>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BinOp {
    And,
    Or,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    List(Vec<Val>),
}

impl Val {
    pub fn as_bool(&self) -> Result<bool, String> {
        match self {
            Val::Bool(b) => Ok(*b),
            _ => Err("expected a bool".into()),
        }
    }

    pub fn as_number(&self) -> Result<f64, String> {
        match self {
            Val::Int(n) => Ok(*n as f64),
            Val::Float(f) if f.is_finite() => Ok(*f),
            _ => Err("expected a number".into()),
        }
    }

    fn display(&self) -> String {
        match self {
            Val::Bool(b) => b.to_string(),
            Val::Int(n) => n.to_string(),
            Val::Float(f) => f.to_string(),
            Val::Text(s) => s.clone(),
            Val::List(_) => "<list>".into(),
        }
    }
}

pub fn parse(source: &str) -> Result<Expr, String> {
    let mut p = Parser { s: source, i: 0 };
    p.skip();
    let node = p.parse_or()?;
    p.skip();
    if !p.eof() {
        return Err(format!("trailing input in {source:?}"));
    }
    Ok(Expr { source: source.to_owned(), node })
}

pub fn eval_bool(
    expr: &Expr,
    inputs: &BTreeMap<String, FieldValue>,
    mut load: impl FnMut(ObjectId) -> Result<Object, String>,
) -> Result<bool, String> {
    eval_node(&expr.node, inputs, &mut load)?.as_bool()
}

pub fn eval_number(
    expr: &Expr,
    inputs: &BTreeMap<String, FieldValue>,
    mut load: impl FnMut(ObjectId) -> Result<Object, String>,
) -> Result<f64, String> {
    eval_node(&expr.node, inputs, &mut load)?.as_number()
}

/// Resolves a template path (`counter.value`) against action inputs.
pub fn resolve_path(
    path: &[String],
    inputs: &BTreeMap<String, FieldValue>,
    mut load: impl FnMut(ObjectId) -> Result<Object, String>,
) -> Result<String, String> {
    Ok(eval_node(&Node::Path(path.to_vec()), inputs, &mut load)?.display())
}

fn eval_node(
    node: &Node,
    inputs: &BTreeMap<String, FieldValue>,
    load: &mut impl FnMut(ObjectId) -> Result<Object, String>,
) -> Result<Val, String> {
    match node {
        Node::Bool(b) => Ok(Val::Bool(*b)),
        Node::Int(n) => Ok(Val::Int(*n)),
        Node::Float(f) => Ok(Val::Float(*f)),
        Node::Text(s) => Ok(Val::Text(s.clone())),
        Node::List(items) => Ok(Val::List(items.iter().map(|n| eval_node(n, inputs, load)).collect::<Result<_, _>>()?)),
        Node::Path(path) => walk(path, inputs, load),
        Node::Not(inner) => Ok(Val::Bool(!eval_node(inner, inputs, load)?.as_bool()?)),
        Node::Neg(inner) => {
            let n = eval_node(inner, inputs, load)?.as_number()?;
            Ok(if n.fract() == 0.0 && n.abs() < i64::MAX as f64 { Val::Int(-(n as i64)) } else { Val::Float(-n) })
        }
        Node::Size(inner) => {
            let n = match eval_node(inner, inputs, load)? {
                Val::Text(s) => s.chars().count() as i64,
                Val::List(items) => items.len() as i64,
                _ => return Err("size() expects text or a list".into()),
            };
            Ok(Val::Int(n))
        }
        Node::Bin(op, lhs, rhs) => eval_bin(*op, lhs, rhs, inputs, load),
    }
}

fn eval_bin(
    op: BinOp,
    lhs: &Node,
    rhs: &Node,
    inputs: &BTreeMap<String, FieldValue>,
    load: &mut impl FnMut(ObjectId) -> Result<Object, String>,
) -> Result<Val, String> {
    if op == BinOp::And {
        let l = eval_node(lhs, inputs, load)?.as_bool()?;
        return Ok(Val::Bool(l && eval_node(rhs, inputs, load)?.as_bool()?));
    }
    if op == BinOp::Or {
        let l = eval_node(lhs, inputs, load)?.as_bool()?;
        return Ok(Val::Bool(l || eval_node(rhs, inputs, load)?.as_bool()?));
    }
    let l = eval_node(lhs, inputs, load)?;
    let r = eval_node(rhs, inputs, load)?;
    if op == BinOp::In {
        let Val::List(items) = r else { return Err("`in` expects a list on the right".into()) };
        return Ok(Val::Bool(items.iter().any(|item| values_eq(&l, item))));
    }
    if matches!(op, BinOp::Eq | BinOp::Ne) {
        let eq = values_eq(&l, &r);
        return Ok(Val::Bool(if op == BinOp::Eq { eq } else { !eq }));
    }
    let (lf, rf) = (l.as_number()?, r.as_number()?);
    let both_int = matches!(l, Val::Int(_)) && matches!(r, Val::Int(_));
    match op {
        BinOp::Add => num(lf + rf, both_int),
        BinOp::Sub => num(lf - rf, both_int),
        BinOp::Mul => num(lf * rf, both_int),
        BinOp::Div if rf == 0.0 => Err("division by zero".into()),
        BinOp::Div => num(lf / rf, false),
        BinOp::Rem if rf == 0.0 => Err("division by zero".into()),
        BinOp::Rem if both_int => Ok(Val::Int((l.as_number()? as i64) % (r.as_number()? as i64))),
        BinOp::Rem => num(lf % rf, false),
        BinOp::Lt => Ok(Val::Bool(lf < rf)),
        BinOp::Le => Ok(Val::Bool(lf <= rf)),
        BinOp::Gt => Ok(Val::Bool(lf > rf)),
        BinOp::Ge => Ok(Val::Bool(lf >= rf)),
        BinOp::And | BinOp::Or | BinOp::Eq | BinOp::Ne | BinOp::In => unreachable!("handled above"),
    }
}

fn num(f: f64, as_int: bool) -> Result<Val, String> {
    if !f.is_finite() {
        return Err("non-finite number".into());
    }
    if as_int { Ok(Val::Int(f as i64)) } else { Ok(Val::Float(f)) }
}

fn values_eq(a: &Val, b: &Val) -> bool {
    match (a, b) {
        (Val::Bool(x), Val::Bool(y)) => x == y,
        (Val::Text(x), Val::Text(y)) => x == y,
        (Val::Int(x), Val::Int(y)) => x == y,
        (Val::List(x), Val::List(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| values_eq(p, q)),
        _ => a.as_number().ok().zip(b.as_number().ok()).is_some_and(|(p, q)| p == q),
    }
}

fn field_val(v: &FieldValue) -> Result<Val, String> {
    match v {
        FieldValue::Bool(b) => Ok(Val::Bool(*b)),
        FieldValue::Int(n) => Ok(Val::Int(*n)),
        FieldValue::Float(f) => Ok(Val::Float(f.0)),
        FieldValue::Text(s) => Ok(Val::Text(s.clone())),
        FieldValue::Ref(r) => Ok(Val::Text(format!("ref:{}", r.id))),
        FieldValue::List(items) => Ok(Val::List(items.iter().map(field_val).collect::<Result<_, _>>()?)),
        other => Err(format!("cannot use a {} value in an expression", other.kind_name())),
    }
}

struct Parser<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Parser<'a> {
    fn eof(&self) -> bool {
        self.i >= self.s.len()
    }

    fn peek(&self) -> Option<char> {
        self.s[self.i..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i += c.len_utf8();
        Some(c)
    }

    fn skip(&mut self) {
        while self.peek().is_some_and(|c| c.is_whitespace()) {
            self.bump();
        }
    }

    fn starts(&self, s: &str) -> bool {
        self.s[self.i..].starts_with(s)
    }

    fn eat(&mut self, s: &str) -> bool {
        if self.starts(s) {
            self.i += s.len();
            true
        } else {
            false
        }
    }

    fn parse_or(&mut self) -> Result<Node, String> {
        let mut node = self.parse_and()?;
        loop {
            self.skip();
            if self.eat("||") {
                node = Node::Bin(BinOp::Or, Box::new(node), Box::new(self.parse_and()?));
            } else {
                break;
            }
        }
        Ok(node)
    }

    fn parse_and(&mut self) -> Result<Node, String> {
        let mut node = self.parse_not()?;
        loop {
            self.skip();
            if self.eat("&&") {
                node = Node::Bin(BinOp::And, Box::new(node), Box::new(self.parse_not()?));
            } else {
                break;
            }
        }
        Ok(node)
    }

    fn parse_not(&mut self) -> Result<Node, String> {
        self.skip();
        if self.eat("!") {
            return Ok(Node::Not(Box::new(self.parse_not()?)));
        }
        self.parse_rel()
    }

    fn parse_rel(&mut self) -> Result<Node, String> {
        let left = self.parse_add()?;
        self.skip();
        let op = if self.eat("==") {
            BinOp::Eq
        } else if self.eat("!=") {
            BinOp::Ne
        } else if self.eat("<=") {
            BinOp::Le
        } else if self.eat(">=") {
            BinOp::Ge
        } else if self.eat("<") {
            BinOp::Lt
        } else if self.eat(">") {
            BinOp::Gt
        } else if self.eat_ident("in") {
            BinOp::In
        } else {
            return Ok(left);
        };
        Ok(Node::Bin(op, Box::new(left), Box::new(self.parse_add()?)))
    }

    fn eat_ident(&mut self, word: &str) -> bool {
        if !self.starts(word) {
            return false;
        }
        let after = self.i + word.len();
        let boundary = self.s[after..].chars().next().is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
        if boundary {
            self.i = after;
            true
        } else {
            false
        }
    }

    fn parse_add(&mut self) -> Result<Node, String> {
        let mut node = self.parse_mul()?;
        loop {
            self.skip();
            let op = if self.eat("+") {
                BinOp::Add
            } else if self.eat("-") {
                BinOp::Sub
            } else {
                break;
            };
            node = Node::Bin(op, Box::new(node), Box::new(self.parse_mul()?));
        }
        Ok(node)
    }

    fn parse_mul(&mut self) -> Result<Node, String> {
        let mut node = self.parse_unary()?;
        loop {
            self.skip();
            let op = if self.eat("*") {
                BinOp::Mul
            } else if self.eat("/") {
                BinOp::Div
            } else if self.eat("%") {
                BinOp::Rem
            } else {
                break;
            };
            node = Node::Bin(op, Box::new(node), Box::new(self.parse_unary()?));
        }
        Ok(node)
    }

    fn parse_unary(&mut self) -> Result<Node, String> {
        self.skip();
        if self.eat("-") {
            return Ok(Node::Neg(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Node, String> {
        self.skip();
        if self.eat("(") {
            let node = self.parse_or()?;
            self.skip();
            if !self.eat(")") {
                return Err("unclosed '('".into());
            }
            return Ok(node);
        }
        if self.eat("[") {
            let mut items = Vec::new();
            loop {
                self.skip();
                if self.eat("]") {
                    break;
                }
                items.push(self.parse_or()?);
                self.skip();
                if self.eat("]") {
                    break;
                }
                if !self.eat(",") {
                    return Err("expected ',' or ']'".into());
                }
            }
            return Ok(Node::List(items));
        }
        if self.peek() == Some('"') {
            return Ok(Node::Text(self.parse_string()?));
        }
        if self.peek().is_some_and(|c| c.is_ascii_digit()) {
            return self.parse_number();
        }
        let ident = self.parse_ident()?;
        self.skip();
        if ident == "size" && self.eat("(") {
            let inner = self.parse_or()?;
            self.skip();
            if !self.eat(")") {
                return Err("unclosed size(".into());
            }
            return Ok(Node::Size(Box::new(inner)));
        }
        if ident == "true" {
            return Ok(Node::Bool(true));
        }
        if ident == "false" {
            return Ok(Node::Bool(false));
        }
        let mut path = vec![ident];
        while self.eat(".") {
            path.push(self.parse_ident()?);
        }
        Ok(Node::Path(path))
    }

    fn parse_ident(&mut self) -> Result<String, String> {
        self.skip();
        let start = self.i;
        let Some(c) = self.peek() else { return Err("expected a name".into()) };
        if !c.is_ascii_lowercase() {
            return Err(format!("expected a name, found {c}"));
        }
        while self.peek().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            self.bump();
        }
        Ok(self.s[start..self.i].to_owned())
    }

    fn parse_number(&mut self) -> Result<Node, String> {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.bump();
        }
        let float = if self.peek() == Some('.') {
            self.bump();
            if !self.peek().is_some_and(|c| c.is_ascii_digit()) {
                return Err("bad number".into());
            }
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.bump();
            }
            true
        } else {
            false
        };
        let text = &self.s[start..self.i];
        if float {
            Ok(Node::Float(text.parse().map_err(|_| format!("bad number {text}"))?))
        } else {
            Ok(Node::Int(text.parse().map_err(|_| format!("bad number {text}"))?))
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.bump();
        let mut out = String::new();
        loop {
            match self.bump() {
                Some('"') => return Ok(out),
                Some('\\') => {
                    let c = match self.bump() {
                        Some('n') => '\n',
                        Some('\\') => '\\',
                        Some('"') => '"',
                        Some(c) => return Err(format!("bad escape \\{c}")),
                        None => return Err("unclosed string".into()),
                    };
                    out.push(c);
                }
                Some(c) => out.push(c),
                None => return Err("unclosed string".into()),
            }
        }
    }
}

/// Walks `path`, loading referenced objects. A ref input's first step is the
/// object it points at; `id` yields that object's id.
pub fn walk(
    path: &[String],
    inputs: &BTreeMap<String, FieldValue>,
    load: &mut impl FnMut(ObjectId) -> Result<Object, String>,
) -> Result<Val, String> {
    let Some((head, rest)) = path.split_first() else { return Err("empty path".into()) };
    let Some(value) = inputs.get(head) else { return Err(format!("unknown input {head}")) };
    if rest.is_empty() {
        return field_val(value);
    }
    let obj = match value {
        FieldValue::Ref(r) => load(r.id)?,
        _ => return Err(format!("{head} is not a reference")),
    };
    walk_from_object(&obj, rest, load)
}

fn walk_from_object(
    obj: &Object,
    path: &[String],
    load: &mut impl FnMut(ObjectId) -> Result<Object, String>,
) -> Result<Val, String> {
    let Some((seg, rest)) = path.split_first() else {
        return Ok(Val::Text(obj.id.to_string()));
    };
    let val = object_step(obj, seg)?;
    if rest.is_empty() {
        return Ok(val);
    }
    let id = match &val {
        Val::Text(text) => {
            // ref fields are encoded as `ref:<id>` by field_val; object_step
            // returns that for ref fields.
            text.strip_prefix("ref:").ok_or_else(|| format!("cannot read .{seg}"))?.to_owned()
        }
        _ => return Err(format!("cannot read past {seg}")),
    };
    let id: ObjectId = id.parse().map_err(|_| format!("bad ref {id}"))?;
    let next = load(id)?;
    walk_from_object(&next, rest, load)
}

fn object_step(obj: &Object, seg: &str) -> Result<Val, String> {
    if obj.tombstone {
        return Err(format!("{} is deleted", obj.id));
    }
    match seg {
        "id" => Ok(Val::Text(obj.id.to_string())),
        "version" => Ok(Val::Int(obj.version as i64)),
        _ => match obj.fields.get(seg) {
            Some(v) => field_val(v),
            None => Err(format!("{} has no field {seg}", obj.id)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_types::{ObjectId, TypeRef};

    fn inputs(value: i64) -> BTreeMap<String, FieldValue> {
        BTreeMap::from([("sample_count".into(), FieldValue::Int(value))])
    }

    #[test]
    fn preconditions_and_costs() {
        let expr = parse("sample_count > 0 && sample_count < 10").unwrap();
        assert!(eval_bool(&expr, &inputs(3), |_| unreachable!()).unwrap());
        assert!(!eval_bool(&expr, &inputs(0), |_| unreachable!()).unwrap());
        let cost = parse("0.002 * sample_count").unwrap();
        let n = eval_number(&cost, &inputs(1000), |_| unreachable!()).unwrap();
        assert!((n - 2.0).abs() < 1e-9);
        let size = parse("size(\"abcd\") == 4").unwrap();
        assert!(eval_bool(&size, &BTreeMap::new(), |_| unreachable!()).unwrap());
        let inn = parse("\"fall\" in [\"fall\", \"lying\"]").unwrap();
        assert!(eval_bool(&inn, &BTreeMap::new(), |_| unreachable!()).unwrap());
    }

    #[test]
    fn path_walks_a_reference() {
        let id = ObjectId(aos_types::Ulid::from_u128(3));
        let mut obj = empty(id);
        obj.fields.insert("value".into(), FieldValue::Int(4));
        let inputs = BTreeMap::from([("counter".into(), FieldValue::Ref(aos_types::ObjRef::latest(id)))]);
        let expr = parse("counter.value >= 0").unwrap();
        assert!(eval_bool(&expr, &inputs, |_| Ok(obj.clone())).unwrap());
        assert_eq!(
            resolve_path(&["counter".into(), "id".into()], &inputs, |_| Ok(obj.clone())).unwrap(),
            id.to_string()
        );
    }

    fn empty(id: ObjectId) -> Object {
        use aos_types::{Origin, Provenance, Sensitivity, Taint, TxId};
        Object {
            id,
            type_ref: "demo/Counter@1".parse::<TypeRef>().unwrap(),
            version: 1,
            fields: BTreeMap::new(),
            provenance: Provenance {
                actor: aos_types::Actor::User,
                origin: Origin::Internal,
                taint: Taint::Clean,
                derived_from: Default::default(),
                tx: TxId(aos_types::Ulid::from_u128(1)),
            },
            sensitivity: Sensitivity::Private,
            extra: BTreeMap::new(),
            tombstone: false,
        }
    }
}
