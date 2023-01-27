use clap::Parser;
use sgx_types::*;
use sgx_urts::SgxEnclave;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

#[derive(Parser)]
struct Cli {
    #[arg(default_value = "../sample.json")]
    path: String,
}

extern "C" {
    fn row_counter(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        some_string: *const u8,
        len: usize,
        count: *mut uint64_t,
    ) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            anyhow::bail!("[-] Init Enclave Failed {x}!");
        }
    };

    let input_string = std::fs::read_to_string(cli.path)?;
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let mut count = 0;
    let result = unsafe {
        row_counter(
            enclave.geteid(),
            &mut retval,
            input_string.as_ptr(),
            input_string.len(),
            &mut count,
        )
    };

    if result == sgx_status_t::SGX_SUCCESS {
        println!("[+] count = {count}");
    } else {
        println!("[-] ECALL Enclave Failed {result}!");
    }

    enclave.destroy();

    Ok(())
}
