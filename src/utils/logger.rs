use crate::config::*;
use std::io::Write;

pub struct ProveProgress{
    total_batch_circuits: usize,
    done_batch_circuits: usize,
    total_recursive_proofs: usize,
    done_recursive_proofs: usize,
    total_recursive_circuits: usize,
    created_recursive_circuits: usize,
    total_progress: f64,
    bar_width: usize,
}

const BATCH_PROVE_PROGRESS: f64 = 50.; // 50% of the time is spent in batch proving (estimated)
const RECURSIVE_CIRCUIT_PROGRESS: f64 = 15.; // 15% of the time is spent in recursive circuit building (estimated)
const RECURSIVE_PROVE_PROGRESS: f64 = 35.; // 35% of the time is spent in recursive circuit proving (estimated)


impl ProveProgress{
    pub fn new(total_batch_circuits: usize) -> Self {
        let mut total_recursive_proofs = 1; // 1 to account for the root proof
        let mut total_recursive_circuits = 0;
        let mut remaining = total_batch_circuits;

        while remaining > 1{
            total_recursive_circuits += 1;
            total_recursive_proofs += remaining / RECURSIVE_SIZE;
            remaining /= RECURSIVE_SIZE;
        }

        ProveProgress{
            total_batch_circuits,
            done_batch_circuits: 0,
            total_recursive_proofs,
            created_recursive_circuits: 0,
            total_recursive_circuits,
            done_recursive_proofs: 0,
            total_progress: 0.,
            bar_width: 50,
        }
    }

    pub fn print_progress_bar(&self) {

        let progress = self.total_progress;
        let bar_width = self.bar_width;
        // Ensure progress is within the valid range [0.0, 100.0]
        let clamped_progress = progress.max(0.0).min(100.0);
    
        // Calculate the number of filled characters for the bar
        let progress_chars = (clamped_progress / 100.0 * bar_width as f64).floor() as usize;
    
        // Calculate the number of empty characters
        let empty_chars = bar_width.saturating_sub(progress_chars);
    
        // Create the bar string
        let bar = format!(
            "[{}{}] {:.2}%",
            "=".repeat(progress_chars),
            " ".repeat(empty_chars),
            clamped_progress
        );
    
        // Use carriage return \r to move the cursor to the beginning of the line
        // and print the updated bar.
        print!("\r{bar}");
    
        // Flush the standard output buffer to ensure the output is displayed immediately.
        std::io::stdout().flush().unwrap();
    }

    pub fn clear_bar(&self){
        let clear_line = " ".repeat(self.bar_width + 10); // Add some buffer just in case
        print!("\r{clear_line}\r");
    }

    fn update_total_progress(&mut self){
        self.total_progress = (self.done_batch_circuits as f64 / self.total_batch_circuits as f64) * BATCH_PROVE_PROGRESS;
        self.total_progress += (self.done_recursive_proofs as f64 / self.total_recursive_proofs as f64) * RECURSIVE_PROVE_PROGRESS;
        self.total_progress += (self.created_recursive_circuits as f64 / self.total_recursive_circuits as f64) * RECURSIVE_CIRCUIT_PROGRESS;
    }

    pub fn update_batch_progress(&mut self){
        self.done_batch_circuits += 1;
        self.update_total_progress();

        self.print_progress_bar();
    }

    pub fn update_recursive_progress(&mut self){
        self.done_recursive_proofs += 1;
        self.update_total_progress();

        self.print_progress_bar();
    }

    pub fn update_recursive_circuit_progress(&mut self){
        self.created_recursive_circuits += 1;
        self.update_total_progress();

        self.print_progress_bar();
    }
}

pub struct ProveInclusionProgress{
    total_users: usize,
    done_users: usize,
    bar_width: usize,
}

impl ProveInclusionProgress{
    pub fn new(total_users: usize) -> Self {
        ProveInclusionProgress{
            total_users,
            done_users: 0,
            bar_width: 50,
        }
    }

    pub fn print_progress_bar(&self) {
        let progress = (self.done_users as f64 / self.total_users as f64) * 100.0;
        let bar_width = self.bar_width;
        // Ensure progress is within the valid range [0.0, 100.0]
        let clamped_progress = progress.max(0.0).min(100.0);
    
        // Calculate the number of filled characters for the bar
        let progress_chars = (clamped_progress / 100.0 * bar_width as f64).floor() as usize;
    
        // Calculate the number of empty characters
        let empty_chars = bar_width.saturating_sub(progress_chars);
    
        // Create the bar string
        let bar = format!(
            "[{}{}] {:.2}%",
            "=".repeat(progress_chars),
            " ".repeat(empty_chars),
            clamped_progress
        );
    
        // Use carriage return \r to move the cursor to the beginning of the line
        // and print the updated bar.
        print!("\r{bar}");
    
        // Flush the standard output buffer to ensure the output is displayed immediately.
        std::io::stdout().flush().unwrap();
    }

    pub fn clear_bar(&self){
        let clear_line = " ".repeat(self.bar_width + 10); // Add some buffer just in case
        print!("\r{clear_line}\r");
    }

    pub fn update_progress(&mut self, users: usize){
        self.done_users += users;
        self.print_progress_bar();
    }

}

#[macro_export]
macro_rules! log_success {
    ($($arg:tt)*) => {
        println!("\x1b[32m[+] {}\x1b[0m", format!($($arg)*));
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        eprintln!("\x1b[31m[-] {}\x1b[0m", format!($($arg)*));
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        println!("\x1b[34m[!] {}\x1b[0m", format!($($arg)*));
    };
}

#[macro_export]
macro_rules! log_warning {
    ($($arg:tt)*) => {
        println!("\x1b[33m[!] {}\x1b[0m", format!($($arg)*));
    };
}

// to be used with .expect() or similar
pub fn format_error(message: &str) -> String {
    format!("\x1b[31m[-] {message}\x1b[0m")
}

pub fn print_header(){
    println!("========================================================================");
    println!(r"   ____  _   _            _____             _____      _____       ___  
  / __ \| | | |          / ____|           |  __ \    |  __ \     |__ \ 
 | |  | | |_| |_ ___ _ _| (___   ___  ___  | |__) |__ | |__) |_   __ ) |
 | |  | | __| __/ _ \ '__\___ \ / _ \/ __| |  ___/ _ \|  _  /\ \ / // / 
 | |__| | |_| ||  __/ |  ____) |  __/ (__  | |  | (_) | | \ \ \ V // /_ 
  \____/ \__|\__\___|_| |_____/ \___|\___| |_|   \___/|_|  \_\ \_/|____|");
  println!("\n========================================================================\n");
}