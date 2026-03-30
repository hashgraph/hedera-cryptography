use clap::Parser;
use std::path::PathBuf;

use wraps::preprocessing::WRAPSPreprocessing;

const NUM_COORDINATOR_THREADS: usize = 48;
const NUM_PARTICIPANT_THREADS: usize = 4;

fn setup_rayon_thread_pool(num_threads: usize) {
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .unwrap();
}

#[derive(Debug, Parser)]
#[command(
    name = "ceremony",
    about = "Run WRAPS Groth16 ceremony preprocessing phases",
    long_about = "Run WRAPS Groth16 ceremony preprocessing phases.\n\
\n\
Positional CLI format:\n\
  ceremony <phase> [arg1] [arg2] [arg3] [arg4] [arg5]\n\
\n\
Positional argument meaning by phase:\n\
  phase 0 (extract_circuit_r1cs_config):\n\
    arg1 = circuit-folder\n\
\n\
  phase 1 (create_init_srs_phase1):\n\
    arg1 = circuit-folder\n\
    arg2 = output-folder\n\
\n\
  phase 2 (update_srs_phase1):\n\
    arg1 = circuit-folder\n\
    arg2 = input-folder\n\
    arg3 = output-folder\n\
\n\
  phase 3 (specialize_srs):\n\
    arg1 = circuit-folder\n\
    arg2 = phase1-input-folder\n\
    arg3 = phase1-output-folder\n\
    arg4 = phase2-output-folder\n\
\n\
  phase 4 (update_srs_phase2):\n\
    arg1 = circuit-folder\n\
    arg2 = input-folder\n\
    arg3 = output-folder\n\
\n\
  phase 5 (finish_groth_setup):\n\
    arg1 = circuit-folder\n\
    arg2 = phase1-input-folder\n\
    arg3 = phase1-output-folder\n\
    arg4 = phase2-input-folder\n\
    arg5 = output-folder\n\
\n\
  phase 6 (verify_transcript_phase1):\n\
    arg1 = input-srs-folder\n\
    arg2 = output-srs-folder\n\
\n\
  phase 7 (verify_transcript_phase2):\n\
    arg1 = input-srs-folder\n\
    arg2 = output-srs-folder\n\
"
)]
struct Args {
    #[arg(value_parser = clap::value_parser!(u8).range(0..=7))]
    phase: u8,
    #[arg(value_name = "ARG")]
    args: Vec<PathBuf>,
}

fn require_existing_dir(path: &PathBuf, role: &str) -> Result<(), String> {
    if path.is_dir() {
        Ok(())
    } else {
        Err(format!("{} does not exist or is not a directory: {}", role, path.display()))
    }
}

fn require_arg_count(
    args: &[PathBuf],
    phase: u8,
    expected: usize,
    usage: &str,
) -> Result<(), String> {
    if args.len() == expected {
        Ok(())
    } else {
        Err(format!(
            "phase {phase} expects {expected} positional argument(s): {usage}; got {}",
            args.len()
        ))
    }
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
            require_arg_count(&args.args, 0, 1, "<circuit-folder>")?;
            let circuit_folder = args.args[0].clone();
            ensure_output_dir(&circuit_folder)?;
            WRAPSPreprocessing::extract_circuit_r1cs_config(&circuit_folder);
            Ok(())
        }
        1 => {
            require_arg_count(&args.args, 1, 2, "<circuit-folder> <output-folder>")?;
            let circuit_folder = args.args[0].clone();
            let output_folder = args.args[1].clone();
            require_existing_dir(&circuit_folder, "circuit-folder (circuit)")?;
            ensure_output_dir(&output_folder)?;
            WRAPSPreprocessing::create_init_srs_phase1(&circuit_folder, &output_folder);
            Ok(())
        }
        2 => {
            setup_rayon_thread_pool(NUM_PARTICIPANT_THREADS);
            require_arg_count(
                &args.args,
                2,
                3,
                "<circuit-folder> <input-folder> <output-folder>",
            )?;
            let circuit_folder = args.args[0].clone();
            let input_folder = args.args[1].clone();
            let output_folder = args.args[2].clone();
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
            setup_rayon_thread_pool(NUM_COORDINATOR_THREADS);
            require_arg_count(
                &args.args,
                3,
                4,
                "<circuit-folder> <phase1-input-folder> <phase1-output-folder> <phase2-output-folder>",
            )?;
            let circuit_folder = args.args[0].clone();
            let phase1_input_folder = args.args[1].clone();
            let phase1_output_folder = args.args[2].clone();
            let phase2_output_folder = args.args[3].clone();
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
            setup_rayon_thread_pool(NUM_PARTICIPANT_THREADS);
            require_arg_count(
                &args.args,
                4,
                3,
                "<circuit-folder> <input-folder> <output-folder>",
            )?;
            let circuit_folder = args.args[0].clone();
            let input_folder = args.args[1].clone();
            let output_folder = args.args[2].clone();
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
            setup_rayon_thread_pool(NUM_COORDINATOR_THREADS);
            require_arg_count(
                &args.args,
                5,
                5,
                "<circuit-folder> <phase1-input-folder> <phase1-output-folder> <phase2-input-folder> <output-folder>",
            )?;
            let circuit_folder = args.args[0].clone();
            let phase1_input_folder = args.args[1].clone();
            let phase1_output_folder = args.args[2].clone();
            let phase2_input_folder = args.args[3].clone();
            let output_folder = args.args[4].clone();
            require_existing_dir(&circuit_folder, "circuit-folder (circuit)")?;
            require_existing_dir(&phase1_input_folder, "phase1-input-folder (final phase1 srs)")?;
            require_existing_dir(&phase1_output_folder, "phase1-output-folder (phase1 output)")?;
            require_existing_dir(&phase2_input_folder, "phase2-input-folder (final phase2 srs)")?;
            ensure_output_dir(&output_folder)?;
            WRAPSPreprocessing::finish_groth_setup(
                &circuit_folder,
                &phase1_input_folder,
                &phase1_output_folder,
                &phase2_input_folder,
                &output_folder,
            );
            Ok(())
        }
        6 => {
            setup_rayon_thread_pool(NUM_COORDINATOR_THREADS);
            require_arg_count(
                &args.args,
                6,
                2,
                "<input-srs-folder> <output-srs-folder>",
            )?;
            let input_srs = args.args[0].clone();
            let output_srs = args.args[1].clone();
            require_existing_dir(&input_srs, "input-srs-folder")?;
            require_existing_dir(&output_srs, "output-srs-folder")?;
            WRAPSPreprocessing::verify_transcript_phase1(&input_srs, &output_srs);
            Ok(())
        }
        7 => {
            setup_rayon_thread_pool(NUM_COORDINATOR_THREADS);
            require_arg_count(
                &args.args,
                7,
                2,
                "<input-srs-folder> <output-srs-folder>",
            )?;
            let input_srs = args.args[0].clone();
            let output_srs = args.args[1].clone();
            require_existing_dir(&input_srs, "input-srs-folder")?;
            require_existing_dir(&output_srs, "output-srs-folder")?;
            WRAPSPreprocessing::verify_transcript_phase2(&input_srs, &output_srs);
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
