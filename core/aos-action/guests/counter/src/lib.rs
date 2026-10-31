//! `demo.counter.inc`: read the counter and write `value + 1`.
//!
//! The guest has no allocator beyond what `std` provides for wasm, and no
//! imports except the AOS host ABI.

use std::collections::BTreeMap;

use aos_types::{FieldValue, FromCbor, Object, ToCbor};

static mut BUF: [u8; 8192] = [0; 8192];

#[link(wasm_import_module = "aos")]
unsafe extern "C" {
    fn input(ptr: *const u8, len: i32) -> i32;
    fn read(ptr: *const u8, len: i32) -> i32;
    fn write(id: *const u8, id_len: i32, expected: i64, patch: *const u8, patch_len: i32) -> i32;
    fn handle_len(handle: i32) -> i32;
    fn handle_copy(handle: i32, dst: *mut u8, cap: i32) -> i32;
}

fn load(handle: i32) -> Vec<u8> {
    unsafe {
        if handle < 0 {
            return Vec::new();
        }
        let n = handle_len(handle);
        if n < 0 || n as usize > 8192 {
            return Vec::new();
        }
        let copied = handle_copy(handle, std::ptr::addr_of_mut!(BUF).cast(), n);
        if copied < 0 {
            return Vec::new();
        }
        std::slice::from_raw_parts(std::ptr::addr_of!(BUF).cast::<u8>(), copied as usize).to_vec()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn aos_invoke(_ptr: i32, _len: i32) -> i32 {
    let name = b"counter";
    let input_bytes = unsafe { load(input(name.as_ptr(), name.len() as i32)) };
    let Ok(FieldValue::Ref(r)) = FieldValue::from_canonical_bytes(&input_bytes) else {
        return -1;
    };
    let id = r.id.to_string();
    let object_bytes = unsafe { load(read(id.as_ptr(), id.len() as i32)) };
    let Ok(object) = Object::from_canonical_bytes(&object_bytes) else {
        return -1;
    };
    let Some(FieldValue::Int(value)) = object.fields.get("value").cloned() else {
        return -1;
    };
    let patch = FieldValue::Map(BTreeMap::from([("value".into(), FieldValue::Int(value + 1))]));
    let bytes = patch.to_canonical_bytes();
    let version = object.version as i64;
    unsafe { write(id.as_ptr(), id.len() as i32, version, bytes.as_ptr(), bytes.len() as i32) }
}
