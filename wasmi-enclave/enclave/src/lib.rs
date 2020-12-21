// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "wasmienclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#![allow(unused_variables)]

extern crate sgx_trts;
extern crate sgx_tdh;
extern crate sgx_tcrypto;
extern crate sgx_tkey_exchange;

use sgx_types::*;
use sgx_trts::memeq::ConsttimeMemEq;
use sgx_tcrypto::*;
use sgx_tkey_exchange::*;
use std::slice;
use std::vec::Vec;

//hardcoded public key from challenger: should be sent through.
const G_SP_PUB_KEY : sgx_ec256_public_t = sgx_ec256_public_t {
    gx : [0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38],
    gy : [0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06]
};

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

#[macro_use]
extern crate lazy_static;

use std::prelude::v1::*;
use std::sync::SgxMutex;
use std::ptr;

extern crate wasmi;
extern crate sgxwasm;

use sgxwasm::{SpecDriver, boundary_value_to_runtime_value, result_covert};

use wasmi::{ModuleInstance, ImportsBuilder, RuntimeValue, Error as InterpreterError, Module};

extern crate serde;
extern crate serde_json;

lazy_static!{
    static ref SPECDRIVER: SgxMutex<SpecDriver> = SgxMutex::new(SpecDriver::new());
}

#[no_mangle]
pub extern "C"
fn sgxwasm_init() -> sgx_status_t {
    let mut sd = SPECDRIVER.lock().unwrap();
    *sd = SpecDriver::new();
    sgx_status_t::SGX_SUCCESS
}

fn wasm_invoke(module : Option<String>, field : String, args : Vec<RuntimeValue>)
              -> Result<Option<RuntimeValue>, InterpreterError> {
    let mut program = SPECDRIVER.lock().unwrap();
    let module = program.module_or_last(module.as_ref().map(|x| x.as_ref()))
                        .expect(&format!("Expected program to have loaded module {:?}", module));
    module.invoke_export(&field, &args, program.spec_module())
}

fn wasm_get(module : Option<String>, field : String)
            -> Result<Option<RuntimeValue>, InterpreterError> {
    let program = SPECDRIVER.lock().unwrap();
    let module = match module {
        None => {
                 program
                 .module_or_last(None)
                 .expect(&format!("Expected program to have loaded module {:?}",
                        "None"
                 ))
        },
        Some(str) => {
                 program
                 .module_or_last(Some(&str))
                 .expect(&format!("Expected program to have loaded module {:?}",
                         str
                 ))
        }
    };

    let global = module.export_by_name(&field)
                       .ok_or_else(|| {
                           InterpreterError::Global(format!("Expected to have export with name {}", field))
                       })?
                       .as_global()
                       .cloned()
                       .ok_or_else(|| {
                           InterpreterError::Global(format!("Expected export {} to be a global", field))
                       })?;
     Ok(Some(global.get()))
}

fn try_load_module(wasm: &[u8]) -> Result<Module, InterpreterError> {
    wasmi::Module::from_buffer(wasm).map_err(|e| InterpreterError::Instantiation(format!("Module::from_buffer error {:?}", e)))
}

fn wasm_try_load(wasm: Vec<u8>) -> Result<(), InterpreterError> {
    let ref mut spec_driver = SPECDRIVER.lock().unwrap();
    let module = try_load_module(&wasm[..])?;
    let instance = ModuleInstance::new(&module, &ImportsBuilder::default())?;
    instance
        .run_start(spec_driver.spec_module())
        .map_err(|trap| InterpreterError::Instantiation(format!("ModuleInstance::run_start error on {:?}", trap)))?;
    Ok(())
}

fn wasm_load_module(name: Option<String>, module: Vec<u8>)
                    -> Result<(), InterpreterError> {
    let ref mut spec_driver = SPECDRIVER.lock().unwrap();
    let module = try_load_module(&module[..])?;
    let instance = ModuleInstance::new(&module, &**spec_driver)
        .map_err(|e| InterpreterError::Instantiation(format!("ModuleInstance::new error on {:?}", e)))?
        .run_start(spec_driver.spec_module())
        .map_err(|trap| InterpreterError::Instantiation(format!("ModuleInstance::run_start error on {:?}", trap)))?;

    spec_driver.add_module(name, instance.clone());

    Ok(())
}

fn wasm_register(name: &Option<String>, as_name: String)
                    -> Result<(), InterpreterError> {
    let ref mut spec_driver = SPECDRIVER.lock().unwrap();
    spec_driver.register(name, as_name)
}

#[no_mangle]
pub extern "C"
fn sgxwasm_run_action(context : sgx_ra_context_t,req_bin : *const u8, req_length: usize, gcm_tag : &[u8;16], //authentication tag
                      result_bin : *mut u8, result_max_len: usize) -> sgx_status_t {


    let ret:sgx_status_t;
    let sk_key:sgx_ec_key_128bit_t;

    match rsgx_ra_get_keys(context, sgx_ra_key_type_t::SGX_RA_KEY_SK) {
        Ok(key) => sk_key = key,
        Err(x) => return x
    }

    let secret_slice = unsafe {
        slice::from_raw_parts(req_bin, req_length)
    };

    if secret_slice.len() != req_length {
        ret = sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    let mut decrypted_vec: Vec<u8> = vec![0; req_length];
    let decrypted_slice = &mut decrypted_vec[..];
    let iv = [0;12]; // iv = 00000?
    let aad:[u8;0] = [0;0]; //auth data

    let ret = rsgx_rijndael128GCM_decrypt(&sk_key,
                                          &secret_slice,
                                          &iv,
                                          &aad,
                                          gcm_tag,
                                          decrypted_slice);

    match ret {
        Ok(()) => (),
        Err(_) => {
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }

    let req_slice = decrypted_slice;
    let action_req: sgxwasm::SgxWasmAction = serde_json::from_slice(req_slice).unwrap();

    let response;
    let return_status;

    match action_req {
        sgxwasm::SgxWasmAction::Invoke{module,field,args}=> {
            let args = args.into_iter()
                           .map(|x| boundary_value_to_runtime_value(x))
                           .collect::<Vec<RuntimeValue>>();
            let r = wasm_invoke(module, field, args);
            let r = result_covert(r);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
               }
            }
        },
        sgxwasm::SgxWasmAction::Get{module,field} => {
            let r = wasm_get(module, field);
            let r = result_covert(r);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_v) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
                }
            }
        },
        sgxwasm::SgxWasmAction::LoadModule{name,module} => {
            let r = wasm_load_module(name.clone(), module);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_LOAD_MODULE_ERROR;
                }
            }
        },
        sgxwasm::SgxWasmAction::TryLoad{module} => {
            let r = wasm_try_load(module);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(()) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_TRY_LOAD_ERROR;
                }
            }
        },
        sgxwasm::SgxWasmAction::Register{name, as_name} => {
            let r = wasm_register(&name, as_name.clone());
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(()) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_REGISTER_ERROR;
                }
            }
        }
    }

    //println!("len = {}, Response = {:?}", response.len(), response);

    if response.len() < result_max_len {
        unsafe {
            ptr::copy_nonoverlapping(response.as_ptr(),
                                     result_bin,
                                     response.len());
        }
        return return_status;
    }
    else{
        //println!("Result len = {} > buf size = {}", response.len(), result_max_len);
        return sgx_status_t::SGX_ERROR_WASM_BUFFER_TOO_SHORT;
    }
}

#[no_mangle]
pub extern "C"
fn enclave_init_ra(b_pse : i32,
                   p_context : &mut sgx_ra_context_t)
                   -> sgx_status_t {
    let mut ret: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    match rsgx_ra_init(&G_SP_PUB_KEY, b_pse) {
        Ok(p) => {
            *p_context = p;
            ret = sgx_status_t::SGX_SUCCESS;
        },
        Err(x) => {
            ret = x;
            return ret;
        }
    }
    ret
}

#[no_mangle]
pub extern "C"
fn enclave_ra_close(context : sgx_ra_context_t) -> sgx_status_t {
    match rsgx_ra_close(context) {
        Ok(()) => sgx_status_t::SGX_SUCCESS,
        Err(x) => x
    }
}

#[no_mangle]
pub extern "C"
fn verify_att_result_mac(context : sgx_ra_context_t,
                         message : * const u8,
                         msg_size: size_t,
                         mac     : * const u8,
                         mac_size: size_t) -> sgx_status_t {

    let ret:sgx_status_t;
    let mk_key:sgx_ec_key_128bit_t;
    let mac_slice;
    let message_slice;
    let mac_result:sgx_cmac_128bit_tag_t;

    if mac_size != SGX_MAC_SIZE || msg_size > u32::max_value as usize {
        ret = sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    unsafe {
        mac_slice = slice::from_raw_parts(mac, mac_size as usize);
        message_slice = slice::from_raw_parts(message, msg_size as usize);
    }

    if mac_slice.len() != SGX_MAC_SIZE as usize  ||
        message_slice.len() != msg_size as usize {
        ret = sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    match rsgx_ra_get_keys(context, sgx_ra_key_type_t::SGX_RA_KEY_MK) {
        Ok(k) => mk_key = k,
        Err(x) => return x
    }

    match rsgx_rijndael128_cmac_slice(&mk_key, message_slice) {
        Ok(tag) => mac_result = tag,
        Err(x) => return x
    }

    if mac_slice.consttime_memeq(&mac_result) == false {
        return sgx_status_t::SGX_ERROR_MAC_MISMATCH;
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C"
fn verify_secret_data(context : sgx_ra_context_t,
                      p_secret: * const u8,
                      sec_size: u32,
                      gcm_mac : &[u8;16], //authentication tag
                      max_vlen: u32,
                      p_ret   : & mut [u8;16]) -> sgx_status_t {

    let ret:sgx_status_t;
    let sk_key:sgx_ec_key_128bit_t;

    match rsgx_ra_get_keys(context, sgx_ra_key_type_t::SGX_RA_KEY_SK) {
        Ok(key) => sk_key = key,
        Err(x) => return x
    }

    let secret_slice = unsafe {
        slice::from_raw_parts(p_secret, sec_size as usize)
    };

    if secret_slice.len() != sec_size as usize {
        ret = sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    let mut decrypted_vec: Vec<u8> = vec![0; sec_size as usize];
    let decrypted_slice = &mut decrypted_vec[..];
    let iv = [0;12]; // iv = 00000?
    let aad:[u8;0] = [0;0]; //auth data

    let ret = rsgx_rijndael128GCM_decrypt(&sk_key,
                                          &secret_slice,
                                          &iv,
                                          &aad,
                                          gcm_mac,
                                          decrypted_slice);

    match ret {
        Ok(()) => {
            if decrypted_slice[0] == 0 && decrypted_slice[1] != 1 {
                return sgx_status_t::SGX_ERROR_INVALID_SIGNATURE;
            }
            else {
                return sgx_status_t::SGX_SUCCESS;
            }
        },
        Err(_) => {
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }
}
