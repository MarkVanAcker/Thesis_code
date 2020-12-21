//attestation logic


extern crate sgx_types;
extern crate sgx_urts;

extern crate protobuf;

extern crate dirs;




use sgx_types::*;
use sgx_urts::SgxEnclave;

use std::io::{Read, Write, stdout};
use std::{fs, path, env, char, io, thread, time};
use message_client::RaMsgTypes::*;
use Messages;
use protobuf::Message;
use tcp_client::TCPClient;
use message_client::RaMsg::TYPE_OK;
use enclave::Enclave;
use Messages::{MessageMSG2, MessageMSG3};
use std::ops::IndexMut;


extern {
    fn sgx_ra_proc_msg2_trusted(a: u64,b: *mut sgx_types::sgx_status_t,c: u32,d: *const sgx_types::sgx_ra_msg2_t,e: *const sgx_types::sgx_target_info_t,f: *mut sgx_types::sgx_report_t,g: *mut sgx_types::sgx_quote_nonce_t) -> sgx_types::sgx_status_t;
    fn sgx_ra_get_msg3_trusted(a: u64,
            b: *mut sgx_types::sgx_status_t,
            c: u32,
            d: u32,
            e: *mut sgx_types::sgx_report_t, f: *mut sgx_types::sgx_ra_msg3_t,g: u32) -> sgx_types::sgx_status_t;
}

//found in Network_def.h
pub enum RaMsgTypes {
    RA_MSG0,
    RA_MSG1,
    RA_MSG2,
    RA_MSG3,
    RA_ATT_RESULT,
    RA_VERIFICATION,
    RA_APP_ATT_OK
}


pub fn get_ra_msg_type(tipe: u32) -> RaMsgTypes{
    match tipe{
        0 => RA_MSG0,
        1 => RA_MSG1,
        2 => RA_MSG2,
        3 => RA_MSG3,
        4 => RA_ATT_RESULT,
        5 => RA_VERIFICATION,
        6 => RA_APP_ATT_OK,
        _ => RA_MSG0
    }
}

pub enum RaMsg {
    TYPE_OK,
    TYPE_TERMINATE
}

fn get_epid() -> uint32_t{
    let mut extended_epid_group_id : uint32_t = 0;
    let res = unsafe { sgx_get_extended_epid_group_id(&mut extended_epid_group_id) };

    match res {
        sgx_status_t::SGX_SUCCESS => extended_epid_group_id,
        _ => res as uint32_t
    }
}

pub struct MessageClient {
    tcp_client: TCPClient
}


impl MessageClient {

    pub fn new(addr: String, port: u32) -> MessageClient {
     MessageClient {
         tcp_client: TCPClient::new(addr, port)
     }
    }


    pub fn send_msg0(&mut self) -> (Vec<u8>,RaMsgTypes){
        let mut msg = Messages::MessageMsg0::new();

        msg.set_field_type(RA_MSG0 as u32);
        msg.set_epid(get_epid());

        self.tcp_client.send(msg.write_to_bytes().unwrap().as_slice(),RA_MSG0 as u32);

        let r = self.tcp_client.read();
        r
    }


    pub fn send_msg1(&mut self, enclave :&Enclave) -> (Vec<u8>, RaMsgTypes){
        let mut msg1_keys:sgx_ra_msg1_t = Default::default();

        let mut count : u8 = 0;

        //retry msg1 generation call if busy.
        loop{
            let res = unsafe {
                sgx_ra_get_msg1(enclave.get_context(),
                                enclave.geteid(),
                                sgx_ra_get_ga, &mut msg1_keys)
            };

            match res{
                sgx_status_t::SGX_SUCCESS => break,
                sgx_status_t::SGX_ERROR_BUSY => {
                    if count < 5 {
                        count += 1;
                        thread::sleep(time::Duration::from_secs(3));
                    }else{
                        panic!("Enclave still busy after 5 retries!");
                    }
                }
                _ => panic!("unknow error occured while trying to generate msg1!")
            };

        }

        let mut msg1 = Messages::MessageMSG1::new();


        // build msg1
        msg1.set_field_type(RA_MSG1 as u32);

        let mut gid : Vec<u32> = Vec::new();
        let mut gx : Vec<u32> = Vec::new();
        let mut gy : Vec<u32> = Vec::new();

        for i in msg1_keys.gid.iter(){
            gid.push(*i as u32);
        }
        msg1.set_GID(gid);

        for i in msg1_keys.g_a.gx.iter(){
            gx.push(*i as u32);
        }
        msg1.set_GaX(gx);

        for i in msg1_keys.g_a.gy.iter(){
            gy.push(*i as u32);
        }
        msg1.set_GaY(gy);


        //send msg1
        self.tcp_client.send(msg1.write_to_bytes().unwrap().as_slice(),RA_MSG1 as u32);

        let r = self.tcp_client.read();
        r
    }

    pub fn send_msg3(&mut self, enclave: &Enclave,msg_bytes: &Vec<u8>, tipe: RaMsgTypes) -> (Vec<u8>, RaMsgTypes){
        let mut p_msg2: sgx_ra_msg2_t = Default::default();

        let mut msg2 = MessageMSG2::new();
        msg2.merge_from_bytes(msg_bytes);

        self.assemble_msg2(&msg2,&mut p_msg2);

        let mut p_msg3: sgx_ra_msg3_t = Default::default();
        let mut pp_msg3: *mut sgx_ra_msg3_t = &mut p_msg3;
        let mut msg3_size: u32 = Default::default();

        let mut count : u8 = 0;
        //retry msg3 generation call if busy.
        loop{
            let res = unsafe {
                sgx_ra_proc_msg2(enclave.get_context(),
                                 enclave.geteid(),
                                 sgx_ra_proc_msg2_trusted,
                                 sgx_ra_get_msg3_trusted,
                                 &p_msg2,
                                 msg2.get_size(),
                                 &mut pp_msg3,
                                 &mut msg3_size)
            };

            match res{
                sgx_status_t::SGX_SUCCESS => break,
                sgx_status_t::SGX_ERROR_BUSY => {
                    if count < 5 {
                        count += 1;
                        thread::sleep(time::Duration::from_secs(3));
                    }else{
                        panic!("Enclave still busy after 5 retries!");
                    }
                }
                _ => panic!("unknow error occured while trying to generate msg1!")
            };

        }


        //build message3

        let mut msg3 = MessageMSG3::new();

        msg3.set_field_type(RA_MSG3 as u32);
        msg3.set_size(msg3_size);

        //quote size = msg3size - sizeof(sgx_Ra_msg3_t)

        //TODO: abstract this in a function maybe?
        unsafe {
            let mut mac : Vec<u32> = Vec::new();

            for i in 0..SGX_MAC_SIZE {
                mac.push((*pp_msg3).mac[i] as u32);
            }


            msg3.set_sgx_mac(mac);

            let mut msg3_gax: Vec<u32> = Vec::new();
            let mut msg3_gay: Vec<u32> = Vec::new();

            for i in 0..SGX_ECP256_KEY_SIZE {
                msg3_gax.push((*pp_msg3).g_a.gx[i] as u32);
                msg3_gay.push((*pp_msg3).g_a.gy[i] as u32);
            }

            msg3.set_gax_msg3(msg3_gax);
            msg3.set_gay_msg3(msg3_gay);

            let mut sec_prop : Vec<u32> = Vec::new();

            for i in 0..256 {
                sec_prop.push((*pp_msg3).ps_sec_prop.sgx_ps_sec_prop_desc[i] as u32);
            }

            msg3.set_sec_property(sec_prop);

            let mut quote : Vec<u32> = Vec::new();

            let quote_ptr = &(*pp_msg3).quote as *const u8;

            //println!("{:?}",quote_ptr);
            //println!("{:?}",*(quote_ptr.offset(0)));

            for i in 0..1116 {
                quote.push(*(quote_ptr.offset(i)) as u32);
            }

            msg3.set_quote(quote);
        }


        //send msg3
        self.tcp_client.send(msg3.write_to_bytes().unwrap().as_slice(),RA_MSG3 as u32);

        let r = self.tcp_client.read();
        r


    }

    fn assemble_msg2(&self, msg2: &MessageMSG2, p_msg2: &mut sgx_ra_msg2_t){

        let mut pub_key_gx = [0 as u8;32];
        let mut pub_key_gy  = [0 as u8;32];

        let mut sign_gb_ga : sgx_ec256_signature_t = Default::default();
        let mut spid : sgx_spid_t = Default::default();

        for i in 0..32 {
            pub_key_gx[i] = msg2.get_public_key_gx()[i] as u8;
            pub_key_gy[i] = msg2.get_public_key_gy()[i] as u8;
        }

        for i in 0..16 {
            spid.id[i] = msg2.get_spid()[i] as u8;
        }

        for i in 0..8 {
            sign_gb_ga.x[i] = msg2.get_signature_x()[i];
            sign_gb_ga.y[i] = msg2.get_signature_y()[i];
        }


        p_msg2.sign_gb_ga = sign_gb_ga;
        p_msg2.spid = spid;
        p_msg2.g_b.gx.copy_from_slice(&pub_key_gx);
        p_msg2.g_b.gy.copy_from_slice(&pub_key_gy);


        p_msg2.quote_type = msg2.get_quote_type() as u16;
        p_msg2.kdf_id = msg2.get_cmac_kdf_id() as u16;

        for i in 0..16{
            p_msg2.mac[i] = msg2.get_smac()[i] as u8;
        }

        p_msg2.sig_rl_size = msg2.get_size_sigrl();

        for i in 0..msg2.get_size_sigrl() as usize {
            p_msg2.sig_rl[i] = msg2.get_sigrl()[i] as u8;
        }

    }

}

