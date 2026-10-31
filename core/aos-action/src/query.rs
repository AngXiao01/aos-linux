//! The host query language (SPEC §13.1), evaluated over a branch snapshot.
//! `member_of` and `aggregate` are part of the ML provider (M6) and are
//! rejected here rather than silently ignored.

use std::cmp::Ordering;

use aos_types::cbor::Value;
use aos_types::codec::{self, FromCbor, SchemaError};
use aos_types::{FieldValue, Object};

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;

pub fn execute(objects: &[Object], query: &Value) -> Result<Value, String> {
    let mut q = aos_types::codec::Record::new(query).map_err(|e| e.to_string())?;
    let from = q.req("from", codec::text).map_err(|e| e.to_string())?.to_owned();
    if from.split_once('@').is_some() && from.parse::<aos_types::TypeRef>().is_err() {
        return Err(format!("bad type {from}"));
    }
    let filter = q.opt("where", |v| Ok(v)).map_err(|e| e.to_string())?;
    let select_vals = q.opt("select", |v| codec::array(v).map(|a| a.to_vec())).map_err(|e| e.to_string())?;
    let order = q.opt("order_by", |v| codec::array(v).map(|a| a.to_vec())).map_err(|e| e.to_string())?;
    let limit = q.opt("limit", codec::uint).map_err(|e| e.to_string())?.unwrap_or(DEFAULT_LIMIT as u64) as usize;
    let cursor = q
        .opt("cursor", |v| match v {
            Value::Null => Ok(None),
            Value::Text(s) => Ok(Some(s.clone())),
            _ => Err(SchemaError::new("expected text or null")),
        })
        .map_err(|e| e.to_string())?;
    q.finish().map_err(|e| e.to_string())?;
    if limit == 0 || limit > MAX_LIMIT {
        return Err(format!("limit must be 1..={MAX_LIMIT}"));
    }
    let offset: usize = match cursor.flatten() {
        None => 0,
        Some(s) => s.parse().map_err(|_| format!("bad cursor {s}"))?,
    };
    let select: Vec<String> = match select_vals {
        Some(vals) => vals
            .iter()
            .map(|v| codec::text(v).map(|s| s.to_owned()).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?,
        None => vec!["id".into()],
    };
    let mut rows: Vec<&Object> = objects.iter().filter(|o| !o.tombstone && type_matches(&from, o)).collect();
    if let Some(filter) = filter {
        let mut kept = Vec::new();
        for obj in rows {
            if eval_clause(obj, filter)? {
                kept.push(obj);
            }
        }
        rows = kept;
    }
    if let Some(order) = order {
        let keys = parse_order(&order)?;
        rows.sort_by(|a, b| {
            for (field, desc) in &keys {
                let cmp = cmp_value(&project(a, field), &project(b, field));
                let cmp = if *desc { cmp.reverse() } else { cmp };
                if cmp != Ordering::Equal {
                    return cmp;
                }
            }
            a.id.cmp(&b.id)
        });
    } else {
        rows.sort_by_key(|o| o.id);
    }
    let page = rows.iter().skip(offset).take(limit);
    let items: Vec<Value> = page
        .map(|obj| {
            let mut map = aos_types::cbor::Map::new();
            for field in &select {
                map.insert(Value::from(field.as_str()), aos_types::ToCbor::to_cbor(&project(obj, field)));
            }
            Value::Map(map)
        })
        .collect();
    let next = offset + items.len();
    let cursor = if next < rows.len() { Value::from(next.to_string()) } else { Value::Null };
    Ok(aos_types::codec::record([("items", Value::Array(items)), ("cursor", cursor)]))
}

fn type_matches(from: &str, obj: &Object) -> bool {
    if let Some((name, major)) = from.split_once('@') {
        obj.type_ref.to_string() == format!("{name}@{major}") || obj.type_ref.to_string() == from
    } else {
        obj.type_ref.name.to_string() == from
    }
}

fn parse_order(items: &[Value]) -> Result<Vec<(String, bool)>, String> {
    let mut out = Vec::new();
    for item in items {
        let mut r = aos_types::codec::Record::new(item).map_err(|e| e.to_string())?;
        let field = r.req("field", codec::text).map_err(|e| e.to_string())?.to_owned();
        let dir = r.opt("dir", codec::text).map_err(|e| e.to_string())?.unwrap_or("asc");
        r.finish().map_err(|e| e.to_string())?;
        let desc = match dir {
            "asc" => false,
            "desc" => true,
            other => return Err(format!("bad direction {other}")),
        };
        out.push((field, desc));
    }
    Ok(out)
}

fn eval_clause(obj: &Object, clause: &Value) -> Result<bool, String> {
    let map = clause.as_map().ok_or("where clause must be a map")?;
    let keys: Vec<&str> = map.iter().filter_map(|(k, _)| k.as_text()).collect();
    if keys.iter().any(|k| *k == "member_of" || *k == "aggregate") {
        return Err("member_of and aggregate are not available in this milestone".into());
    }
    if keys.iter().any(|k| *k == "all") {
        let items = map.get(&Value::from("all")).and_then(|v| v.as_array()).ok_or("all must be a list")?;
        return items.iter().try_fold(true, |acc, c| Ok(acc && eval_clause(obj, c)?));
    }
    if keys.iter().any(|k| *k == "any") {
        let items = map.get(&Value::from("any")).and_then(|v| v.as_array()).ok_or("any must be a list")?;
        return items.iter().try_fold(false, |acc, c| Ok(acc || eval_clause(obj, c)?));
    }
    if keys.iter().any(|k| *k == "not") {
        let inner = map.get(&Value::from("not")).ok_or("not needs a clause")?;
        return Ok(!eval_clause(obj, inner)?);
    }
    let field = map.get(&Value::from("field")).and_then(|v| v.as_text()).ok_or("comparison needs field")?.to_owned();
    let left = project(obj, &field);
    for op in ["eq", "ne", "lt", "lte", "gt", "gte", "in"] {
        if let Some(rhs) = map.get(&Value::from(op)) {
            let right = FieldValue::from_cbor(rhs).map_err(|e| e.to_string())?;
            return Ok(compare(op, &left, &right)?);
        }
    }
    Err("comparison needs eq, ne, lt, lte, gt, gte or in".into())
}

fn compare(op: &str, left: &FieldValue, right: &FieldValue) -> Result<bool, String> {
    if op == "in" {
        let FieldValue::List(items) = right else { return Err("in expects a list".into()) };
        return Ok(items.iter().any(|item| field_eq(left, item)));
    }
    if op == "eq" {
        return Ok(field_eq(left, right));
    }
    if op == "ne" {
        return Ok(!field_eq(left, right));
    }
    let ord = cmp_value(left, right);
    Ok(match op {
        "lt" => ord == Ordering::Less,
        "lte" => ord != Ordering::Greater,
        "gt" => ord == Ordering::Greater,
        "gte" => ord != Ordering::Less,
        _ => return Err(format!("bad operator {op}")),
    })
}

fn field_eq(a: &FieldValue, b: &FieldValue) -> bool {
    match (a, b) {
        (FieldValue::Int(x), FieldValue::Float(y)) | (FieldValue::Float(y), FieldValue::Int(x)) => *x as f64 == y.0,
        _ => a == b,
    }
}

fn cmp_value(a: &FieldValue, b: &FieldValue) -> Ordering {
    match (a, b) {
        (FieldValue::Int(x), FieldValue::Int(y)) => x.cmp(y),
        (FieldValue::Text(x), FieldValue::Text(y)) => x.cmp(y),
        (FieldValue::Bool(x), FieldValue::Bool(y)) => x.cmp(y),
        _ => sort_key(a).cmp(&sort_key(b)),
    }
}

fn project(obj: &Object, path: &str) -> FieldValue {
    match path {
        "id" => FieldValue::text(obj.id.to_string()),
        "version" => FieldValue::Int(obj.version as i64),
        "provenance.taint" => FieldValue::text(obj.provenance.taint.as_str()),
        "provenance.actor" => FieldValue::text(obj.provenance.actor.to_string()),
        _ => obj.fields.get(path).cloned().unwrap_or(FieldValue::Null),
    }
}

fn sort_key(v: &FieldValue) -> String {
    match v {
        FieldValue::Int(n) => format!("i:{n}"),
        FieldValue::Float(f) => format!("f:{}", f.0),
        FieldValue::Text(s) => format!("t:{s}"),
        FieldValue::Bool(b) => format!("b:{b}"),
        FieldValue::Ref(r) => format!("r:{r}"),
        other => format!("x:{}", other.kind_name()),
    }
}
