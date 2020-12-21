use sgx_urts::SgxEnclave;
use sgx_types::{sgx_enclave_id_t, sgx_ra_context_t,sgx_status_t};

pub struct Enclave{
    instance: SgxEnclave,
    enclave_path: String,
    status:  sgx_status_t,
    context: sgx_ra_context_t
}


impl Enclave{

    pub fn new(enc : SgxEnclave) -> Enclave{
        Enclave{
            instance: enc,
            enclave_path: "enclave.signed.so".to_string(),
            status: sgx_status_t::SGX_SUCCESS,
            context: 0
        }
    }

    pub fn get_enclave(&mut self) -> &mut SgxEnclave{
        &mut self.instance
    }

    pub fn geteid(&self)-> sgx_enclave_id_t{
        self.instance.geteid()
    }

    pub fn get_mut_context(&mut self) -> &mut sgx_ra_context_t {
        &mut self.context
    }

    pub fn get_mut_status(&mut self) ->&mut sgx_status_t{
        &mut self.status
    }

    pub fn get_context(&self) -> sgx_ra_context_t {
        self.context
    }

    pub fn get_status(&self) ->sgx_status_t{
        self.status
    }

    pub fn get_enclave_path(&self) -> &str{
        &self.enclave_path
    }

    pub fn destroy(self){

        // destroy takes ownership over self, so it
        // will be dropped (and the enclave destroyed)
        // before this function returns.

        self.instance.destroy();
    }
}