use clap::Parser;
use std::path::PathBuf;

use wraps::preprocessing::WRAPSPreprocessing;

#[derive(Debug, Parser)]
#[command(
    name = "ceremony",
    about = "Run WRAPS Groth16 ceremony preprocessing phases",
    long_about = "Run WRAPS Groth16 ceremony preprocessing phases.\n\
\n\
Required base args:\n\
  --phase <0..5>\n\
  --output-folder <PATH> (used in phases 1, 2, 4, 5)\n\
\n\
Folder mapping by phase:\n\
  phase 0 (extract_circuit_r1cs_config):\n\
    circuit-folder= circuit\n\
\n\
  phase 1 (create_init_srs_phase1):\n\
    circuit-folder= circuit\n\
    output= phase1_init\n\
\n\
  phase 2 (update_srs_phase1):\n\
    circuit-folder= circuit\n\
    input-folder= prev_phase1_srs\n\
    output= next_phase1_srs\n\
\n\
  phase 3 (specialize_srs):\n\
    circuit-folder= circuit\n\
    phase1-input-folder= final_phase1_srs\n\
    phase1-output-folder= phase1_output\n\
    phase2-output-folder= phase2_init\n\
\n\
  phase 4 (update_srs_phase2):\n\
    circuit-folder= circuit\n\
    input-folder= prev_phase2_srs\n\
    output= next_phase2_srs\n\
\n\
  phase 5 (finish_groth_setup):\n\
    phase1-input-folder= final_phase1_srs\n\
    phase1-output-folder= phase1_output\n\
    phase2-input-folder= final_phase2_srs\n\
    output= result_dir\n\
"
)]
struct Args {
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=5))]
    phase: u8,
    #[arg(long)]
    circuit_folder: Option<PathBuf>,
    #[arg(long)]
    input_folder: Option<PathBuf>,
    #[arg(long)]
    output_folder: Option<PathBuf>,
    #[arg(long)]
    phase1_input_folder: Option<PathBuf>,
    #[arg(long)]
    phase1_output_folder: Option<PathBuf>,
    #[arg(long)]
    phase2_input_folder: Option<PathBuf>,
    #[arg(long)]
    phase2_output_folder: Option<PathBuf>,
}

fn require_existing_dir(path: &PathBuf, role: &str) -> Result<(), String> {
    if path.is_dir() {
        Ok(())
    } else {
        Err(format!("{} does not exist or is not a directory: {}", role, path.display()))
    }
}

fn require_arg(value: &Option<PathBuf>, flag: &str) -> Result<PathBuf, String> {
    value
        .clone()
        .ok_or_else(|| format!("missing required argument --{flag} for phase"))
}

fn reject_arg(value: &Option<PathBuf>, flag: &str, phase: u8) -> Result<(), String> {
    if value.is_some() {
        Err(format!("--{flag} is not used in phase {phase}"))
    } else {
        Ok(())
    }
}

fn validate_unused_for_phase_0(args: &Args) -> Result<(), String> {
    reject_arg(&args.input_folder, "input-folder", 0)?;
    reject_arg(&args.output_folder, "output-folder", 0)?;
    reject_arg(&args.phase1_input_folder, "phase1-input-folder", 0)?;
    reject_arg(&args.phase1_output_folder, "phase1-output-folder", 0)?;
    reject_arg(&args.phase2_input_folder, "phase2-input-folder", 0)?;
    reject_arg(&args.phase2_output_folder, "phase2-output-folder", 0)
}

fn validate_unused_for_phase_1(args: &Args) -> Result<(), String> {
    reject_arg(&args.input_folder, "input-folder", 1)?;
    reject_arg(&args.phase1_input_folder, "phase1-input-folder", 1)?;
    reject_arg(&args.phase1_output_folder, "phase1-output-folder", 1)?;
    reject_arg(&args.phase2_input_folder, "phase2-input-folder", 1)?;
    reject_arg(&args.phase2_output_folder, "phase2-output-folder", 1)
}

fn validate_unused_for_phase_2(args: &Args) -> Result<(), String> {
    reject_arg(&args.phase1_input_folder, "phase1-input-folder", 2)?;
    reject_arg(&args.phase1_output_folder, "phase1-output-folder", 2)?;
    reject_arg(&args.phase2_input_folder, "phase2-input-folder", 2)?;
    reject_arg(&args.phase2_output_folder, "phase2-output-folder", 2)
}

fn validate_unused_for_phase_3(args: &Args) -> Result<(), String> {
    reject_arg(&args.input_folder, "input-folder", 3)?;
    reject_arg(&args.output_folder, "output-folder", 3)?;
    reject_arg(&args.phase2_input_folder, "phase2-input-folder", 3)
}

fn validate_unused_for_phase_4(args: &Args) -> Result<(), String> {
    reject_arg(&args.phase1_input_folder, "phase1-input-folder", 4)?;
    reject_arg(&args.phase1_output_folder, "phase1-output-folder", 4)?;
    reject_arg(&args.phase2_input_folder, "phase2-input-folder", 4)?;
    reject_arg(&args.phase2_output_folder, "phase2-output-folder", 4)
}

fn validate_unused_for_phase_5(args: &Args) -> Result<(), String> {
    reject_arg(&args.circuit_folder, "circuit-folder", 5)?;
    reject_arg(&args.input_folder, "input-folder", 5)?;
    reject_arg(&args.phase2_output_folder, "phase2-output-folder", 5)
}

fn ensure_output_dir(path: &PathBuf) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| {
        format!(
            "failed to create output directory {}: {}",
            path.display(),
            e
        )
    })
}

fn run(args: Args) -> Result<(), String> {
    match args.phase {
        0 => {
            validate_unused_for_phase_0(&args)?;
            let circuit_folder = require_arg(&args.circuit_folder, "circuit-folder")?;
            ensure_output_dir(&circuit_folder)?;
            WRAPSPreprocessing::extract_circuit_r1cs_config(&circuit_folder);
            Ok(())
        }
        1 => {
            validate_unused_for_phase_1(&args)?;
            let circuit_folder = require_arg(&args.circuit_folder, "circuit-folder")?;
            let output_folder = require_arg(&args.output_folder, "output-folder")?;
            require_existing_dir(&circuit_folder, "circuit-folder (circuit)")?;
            ensure_output_dir(&output_folder)?;
            WRAPSPreprocessing::create_init_srs_phase1(&circuit_folder, &output_folder);
            Ok(())
        }
        2 => {
            validate_unused_for_phase_2(&args)?;
            let circuit_folder = require_arg(&args.circuit_folder, "circuit-folder")?;
            let input_folder = require_arg(&args.input_folder, "input-folder")?;
            let output_folder = require_arg(&args.output_folder, "output-folder")?;
            require_existing_dir(&circuit_folder, "circuit-folder (circuit)")?;
            require_existing_dir(&input_folder, "input-folder (prev phase1 srs)")?;
            ensure_output_dir(&output_folder)?;
            WRAPSPreprocessing::update_srs_phase1(
                &circuit_folder,
                &input_folder,
                &output_folder,
            );
            Ok(())
        }
        3 => {
            validate_unused_for_phase_3(&args)?;
            let circuit_folder = require_arg(&args.circuit_folder, "circuit-folder")?;
            let phase1_input_folder = require_arg(&args.phase1_input_folder, "phase1-input-folder")?;
            let phase1_output_folder = require_arg(&args.phase1_output_folder, "phase1-output-folder")?;
            let phase2_output_folder = require_arg(&args.phase2_output_folder, "phase2-output-folder")?;
            require_existing_dir(&circuit_folder, "circuit-folder (circuit)")?;
            require_existing_dir(&phase1_input_folder, "phase1-input-folder (final phase1 srs)")?;
            ensure_output_dir(&phase1_output_folder)?;
            ensure_output_dir(&phase2_output_folder)?;
            WRAPSPreprocessing::specialize_srs(
                &circuit_folder,
                &phase1_input_folder,
                &phase1_output_folder,
                &phase2_output_folder,
            );
            Ok(())
        }
        4 => {
            validate_unused_for_phase_4(&args)?;
            let circuit_folder = require_arg(&args.circuit_folder, "circuit-folder")?;
            let input_folder = require_arg(&args.input_folder, "input-folder")?;
            let output_folder = require_arg(&args.output_folder, "output-folder")?;
            require_existing_dir(&circuit_folder, "circuit-folder (circuit)")?;
            require_existing_dir(&input_folder, "input-folder (prev phase2 srs)")?;
            ensure_output_dir(&output_folder)?;
            WRAPSPreprocessing::update_srs_phase2(
                &circuit_folder,
                &input_folder,
                &output_folder,
            );
            Ok(())
        }
        5 => {
            validate_unused_for_phase_5(&args)?;
            let phase1_input_folder = require_arg(&args.phase1_input_folder, "phase1-input-folder")?;
            let phase1_output_folder = require_arg(&args.phase1_output_folder, "phase1-output-folder")?;
            let phase2_input_folder = require_arg(&args.phase2_input_folder, "phase2-input-folder")?;
            let output_folder = require_arg(&args.output_folder, "output-folder")?;
            require_existing_dir(&phase1_input_folder, "phase1-input-folder (final phase1 srs)")?;
            require_existing_dir(&phase1_output_folder, "phase1-output-folder (phase1 output)")?;
            require_existing_dir(&phase2_input_folder, "phase2-input-folder (final phase2 srs)")?;
            ensure_output_dir(&output_folder)?;
            WRAPSPreprocessing::finish_groth_setup(
                &phase1_input_folder,
                &phase1_output_folder,
                &phase2_input_folder,
                &output_folder,
            )
            .map_err(|e| format!("finish_groth_setup failed: {}", e))?;
            Ok(())
        }
        _ => Err(format!("unsupported phase: {}", args.phase)),
    }
}

fn main() {
    let args = Args::parse();
    match run(args) {
        Ok(()) => {}
        Err(message) => {
            eprintln!("Error: {message}");
            std::process::exit(1);
        }
    }
}
