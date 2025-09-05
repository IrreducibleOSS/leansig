use host::{prove_xmss_aggregate, create_test_data};

fn main() {
    // Example of using create_test_data from lib.rs
    #[cfg(debug_assertions)]
    {
        use leansig_core::spec::SPEC_1;
        let (_public_inputs, _aggregated) = create_test_data(
            2,        // num_validators
            SPEC_1,   // spec
            8,        // tree_height (small for quick testing)
            1000,     // max_retries
            None,     // default message
            None,     // default epoch
        );
        println!("Successfully created test data from lib.rs");
    }
    
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // Example input
    let input: u32 = 15 * u32::pow(2, 27) + 1;

    // Run the proving and verification
    match prove_xmss_aggregate(input) {
        Ok(result) => {
            println!("Proving successful!");
            println!("Witness generation time: {:?}", result.witness_generation_time);
            println!("Proof generation time: {:?}", result.proof_generation_time);
            println!("Verification time: {:?}", result.verification_time);
            println!("Proof size: {} bytes", result.proof_size_bytes);

            // Decode the output from the receipt
            let _output: u32 = result.receipt.journal.decode().unwrap();
        }
        Err(e) => {
            eprintln!("Proving failed: {}", e);
            std::process::exit(1);
        }
    }
}
