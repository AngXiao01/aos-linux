//! Wasm imports. Every byte the guest exchanges is CBOR, except object ids
//! returned by `create`, `intent_create` and `job_submit` (UTF-8) and blob
//! hashes (`sha256:...`).

use wasmtime::{Caller, Memory};

use crate::Host;
use crate::context::{Ctx, Fail, HostValue};

pub fn define<S: aos_log::LogStore>(linker: &mut wasmtime::Linker<Host>) -> Result<(), wasmtime::Error> {
    linker.func_wrap("aos", "input", |mut c: Caller<'_, Host>, p: i32, n: i32| -> Result<i32, wasmtime::Error> {
        let name = read_text(&mut c, p, n)?;
        dispatch::<S>(&mut c, |ctx| ctx.input(&name))
    })?;
    linker.func_wrap("aos", "read", |mut c: Caller<'_, Host>, p: i32, n: i32| -> Result<i32, wasmtime::Error> {
        let id = parse_id(&read_text(&mut c, p, n)?)?;
        dispatch::<S>(&mut c, |ctx| ctx.read(id))
    })?;
    linker.func_wrap(
        "aos",
        "write",
        |mut c: Caller<'_, Host>,
         id_p: i32,
         id_n: i32,
         expected: i64,
         patch_p: i32,
         patch_n: i32|
         -> Result<i32, wasmtime::Error> {
            let id = parse_id(&read_text(&mut c, id_p, id_n)?)?;
            let patch = decode(&read_bytes(&mut c, patch_p, patch_n)?)?;
            let expected = u64::try_from(expected).map_err(|_| bad("version"))?;
            dispatch::<S>(&mut c, |ctx| ctx.write(id, expected, &patch))
        },
    )?;
    linker.func_wrap(
        "aos",
        "create",
        |mut c: Caller<'_, Host>, ty_p: i32, ty_n: i32, f_p: i32, f_n: i32| -> Result<i32, wasmtime::Error> {
            let ty = read_text(&mut c, ty_p, ty_n)?;
            let fields = decode(&read_bytes(&mut c, f_p, f_n)?)?;
            dispatch::<S>(&mut c, |ctx| ctx.create(&ty, &fields))
        },
    )?;
    linker.func_wrap("aos", "query", |mut c: Caller<'_, Host>, p: i32, n: i32| -> Result<i32, wasmtime::Error> {
        let query = decode(&read_bytes(&mut c, p, n)?)?;
        dispatch::<S>(&mut c, |ctx| ctx.query(&query))
    })?;
    linker.func_wrap(
        "aos",
        "blob_write",
        |mut c: Caller<'_, Host>, p: i32, n: i32| -> Result<i32, wasmtime::Error> {
            let bytes = read_bytes(&mut c, p, n)?;
            dispatch::<S>(&mut c, |ctx| ctx.blob_write(&bytes))
        },
    )?;
    linker.func_wrap(
        "aos",
        "blob_read",
        |mut c: Caller<'_, Host>, p: i32, n: i32, offset: i32, len: i32| -> Result<i32, wasmtime::Error> {
            let text = read_text(&mut c, p, n)?;
            let hash: aos_types::Digest = text.parse().map_err(|_| bad("hash"))?;
            let offset = u64::try_from(offset).map_err(|_| bad("offset"))?;
            let len = u64::try_from(len).map_err(|_| bad("len"))?;
            dispatch::<S>(&mut c, |ctx| ctx.blob_read(&hash, offset, len))
        },
    )?;
    linker.func_wrap(
        "aos",
        "intent_create",
        |mut c: Caller<'_, Host>, p: i32, n: i32| -> Result<i32, wasmtime::Error> {
            let body = decode(&read_bytes(&mut c, p, n)?)?;
            dispatch::<S>(&mut c, |ctx| ctx.intent(&body))
        },
    )?;
    linker.func_wrap(
        "aos",
        "job_submit",
        |mut c: Caller<'_, Host>, p: i32, n: i32| -> Result<i32, wasmtime::Error> {
            let body = decode(&read_bytes(&mut c, p, n)?)?;
            dispatch::<S>(&mut c, |ctx| ctx.job(&body))
        },
    )?;
    linker.func_wrap(
        "aos",
        "log",
        |mut c: Caller<'_, Host>, level: i32, p: i32, n: i32| -> Result<i32, wasmtime::Error> {
            let msg = read_text(&mut c, p, n)?;
            dispatch::<S>(&mut c, |ctx| ctx.log(level, msg))
        },
    )?;
    linker.func_wrap("aos", "handle_len", |c: Caller<'_, Host>, handle: i32| -> Result<i32, wasmtime::Error> {
        let len = c.data().handles.get(handle as usize).map(|b| b.len()).ok_or_else(|| bad("handle"))?;
        i32::try_from(len).map_err(|_| bad("handle length"))
    })?;
    linker.func_wrap(
        "aos",
        "handle_copy",
        |mut c: Caller<'_, Host>, handle: i32, dst: i32, cap: i32| -> Result<i32, wasmtime::Error> {
            let bytes = c.data().handles.get(handle as usize).cloned().ok_or_else(|| bad("handle"))?;
            let cap = usize::try_from(cap).map_err(|_| bad("cap"))?;
            let n = bytes.len().min(cap);
            write_mem(&mut c, dst, &bytes[..n])?;
            i32::try_from(n).map_err(|_| bad("copy"))
        },
    )?;
    Ok(())
}

fn dispatch<S: aos_log::LogStore>(
    caller: &mut Caller<'_, Host>,
    op: impl FnOnce(&mut Ctx<'_, S>) -> Result<HostValue, Fail>,
) -> Result<i32, wasmtime::Error> {
    let ptr = caller.data().cx;
    let result = unsafe { op(&mut *ptr.cast::<Ctx<'_, S>>()) };
    match result {
        Ok(HostValue::Status(code)) => Ok(code),
        Ok(HostValue::Bytes(bytes)) => {
            let handle = caller.data().handles.len();
            caller.data_mut().handles.push(bytes);
            i32::try_from(handle).map_err(|_| bad("too many handles"))
        }
        Err(Fail::Code(code)) => Ok(code),
        Err(Fail::Violation(v)) => {
            caller.data_mut().violation = Some(v.clone());
            Err(bad(&v.detail))
        }
    }
}

pub fn read_bytes(caller: &mut Caller<'_, Host>, ptr: i32, len: i32) -> Result<Vec<u8>, wasmtime::Error> {
    let ptr = usize::try_from(ptr).map_err(|_| bad("pointer"))?;
    let len = usize::try_from(len).map_err(|_| bad("length"))?;
    if len > 1_048_576 {
        return Err(bad("argument too large"));
    }
    let mem = memory(caller)?;
    let mut buf = vec![0u8; len];
    mem.read(caller, ptr, &mut buf)?;
    Ok(buf)
}

fn read_text(caller: &mut Caller<'_, Host>, ptr: i32, len: i32) -> Result<String, wasmtime::Error> {
    let bytes = read_bytes(caller, ptr, len)?;
    String::from_utf8(bytes).map_err(|_| bad("utf-8"))
}

fn write_mem(caller: &mut Caller<'_, Host>, ptr: i32, bytes: &[u8]) -> Result<(), wasmtime::Error> {
    let ptr = usize::try_from(ptr).map_err(|_| bad("pointer"))?;
    let mem = memory(caller)?;
    mem.write(caller, ptr, bytes)?;
    Ok(())
}

fn memory(caller: &mut Caller<'_, Host>) -> Result<Memory, wasmtime::Error> {
    caller.get_export("memory").and_then(|e| e.into_memory()).ok_or_else(|| bad("wasm module has no memory"))
}

fn decode(bytes: &[u8]) -> Result<aos_types::cbor::Value, wasmtime::Error> {
    aos_types::cbor::decode(bytes).map_err(|e| bad(&e.to_string()))
}

fn parse_id(text: &str) -> Result<aos_types::ObjectId, wasmtime::Error> {
    text.parse().map_err(|_| bad("object id"))
}

fn bad(msg: &str) -> wasmtime::Error {
    wasmtime::Error::msg(msg.to_owned())
}
