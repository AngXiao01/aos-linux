//! The action and type catalog (SPEC §8.6). Also re-evaluates preconditions
//! when a branch is merged (SPEC §7.5).

use std::collections::BTreeMap;
use std::path::Path;

use aos_branch::{Preconditions, ReadView};
use aos_log::TxRecord;
use aos_types::schema::{TypeDecl, TypeName, TypeRef};
use aos_types::yaml;
use aos_types::{Object, ObjectId};

use crate::decl::{self, ActionDecl};
use crate::expr;

#[derive(Clone, Debug, Default)]
pub struct Catalog {
    types: BTreeMap<TypeRef, TypeDecl>,
    actions: BTreeMap<String, ActionDecl>,
}

impl Catalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// System types the runtime writes: violations, egress intents and jobs.
    pub fn system() -> Self {
        let mut cat = Catalog::new();
        for src in [
            include_str!("../decls/sys/ActionViolation.yaml"),
            include_str!("../decls/sys/EgressIntent.yaml"),
            include_str!("../decls/sys/EgressReceipt.yaml"),
            include_str!("../decls/sys/Job.yaml"),
        ] {
            cat.add_yaml(src).expect("system declaration");
        }
        cat
    }

    pub fn add_yaml(&mut self, text: &str) -> Result<(), String> {
        let doc = yaml::parse(text).map_err(|e| e.to_string())?;
        if decl::is_action_doc(&doc) {
            self.insert_action(decl::parse_action(text)?)?;
        } else if doc.get("type").is_some() {
            self.insert_type(decl::parse_type(text)?)?;
        } else {
            return Err("declaration is neither a type nor an action".into());
        }
        Ok(())
    }

    pub fn load_dir(&mut self, dir: &Path) -> Result<(), String> {
        let mut files = Vec::new();
        walk(dir, &mut files)?;
        files.sort();
        let texts: Vec<_> = files
            .iter()
            .map(|path| std::fs::read_to_string(path).map(|text| (path.clone(), text)).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        // Types before actions, so a declaration may mention a type defined in
        // a file that sorts later.
        for (path, text) in
            texts.iter().filter(|(_, text)| yaml::parse(text).ok().is_some_and(|d| !decl::is_action_doc(&d)))
        {
            self.add_yaml(text).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        for (path, text) in
            texts.iter().filter(|(_, text)| yaml::parse(text).ok().is_some_and(|d| decl::is_action_doc(&d)))
        {
            self.add_yaml(text).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(())
    }

    pub fn insert_type(&mut self, decl: TypeDecl) -> Result<(), String> {
        let key = decl.type_ref();
        if self.types.contains_key(&key) {
            return Err(format!("{key} is already registered"));
        }
        self.types.insert(key, decl);
        Ok(())
    }

    pub fn insert_action(&mut self, decl: ActionDecl) -> Result<(), String> {
        for ty in decl.reads.iter().chain(&decl.writes) {
            if !self.types.keys().any(|r| &r.name == ty) {
                return Err(format!("{} uses unregistered type {ty}", decl.qualified()));
            }
        }
        let key = decl.qualified();
        if self.actions.contains_key(&key) {
            return Err(format!("{key} is already registered"));
        }
        self.actions.insert(key, decl);
        Ok(())
    }

    pub fn type_decl(&self, ty: &TypeRef) -> Option<&TypeDecl> {
        self.types.get(ty)
    }

    pub fn types(&self) -> impl Iterator<Item = &TypeDecl> {
        self.types.values()
    }

    pub fn action(&self, qualified: &str) -> Option<&ActionDecl> {
        self.actions.get(qualified)
    }

    pub fn actions(&self) -> impl Iterator<Item = &ActionDecl> {
        self.actions.values()
    }

    /// Actions whose reads or writes mention `ty`.
    pub fn actions_for(&self, ty: &TypeName) -> Vec<&ActionDecl> {
        self.actions.values().filter(|a| a.reads.contains(ty) || a.writes.contains(ty)).collect()
    }

    pub fn check_tx(&self, view: &dyn ReadView, tx: &TxRecord) -> Result<(), String> {
        let Some(name) = &tx.action else { return Ok(()) };
        let Some(action) = self.actions.get(name) else {
            return Err(format!("unknown action {name}"));
        };
        for pre in &action.preconditions {
            let ok = expr::eval_bool(pre, &tx.inputs, |id| load_view(view, id))?;
            if !ok {
                return Err(format!("precondition failed: {pre}"));
            }
        }
        Ok(())
    }
}

fn load_view(view: &dyn ReadView, id: ObjectId) -> Result<Object, String> {
    match view.read(id) {
        Some(obj) if !obj.tombstone => Ok((*obj).clone()),
        Some(_) => Err(format!("{id} is deleted")),
        None => Err(format!("{id} is not visible")),
    }
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            out.push(path);
        }
    }
    Ok(())
}

impl Preconditions for Catalog {
    fn check(&self, view: &dyn ReadView, tx: &TxRecord) -> Result<(), String> {
        self.check_tx(view, tx)
    }
}
