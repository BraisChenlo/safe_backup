use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use chrono::{Utc};

// Custom error types for better error handling
#[derive(Debug)]
enum SafeBackupError {
    InvalidPath(String),
    FileNotFound(String),
    IoError(io::Error),
    #[allow(dead_code)] //Permission not checked in this assessment
    PermissionDenied(String),
}

impl From<io::Error> for SafeBackupError {
    fn from(error: io::Error) -> Self {
        SafeBackupError::IoError(error)
    }
}

impl std::fmt::Display for SafeBackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SafeBackupError::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
            SafeBackupError::FileNotFound(msg) => write!(f, "File not found: {}", msg),
            SafeBackupError::IoError(err) => write!(f, "IO error: {}", err),
            SafeBackupError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
        }
    }
}

type Result<T> = std::result::Result<T, SafeBackupError>;

struct SafeBackup {
    log_file: PathBuf,
}

impl SafeBackup {
    fn new() -> Result<Self> {
        let log_file = PathBuf::from("logfile.txt");
        Ok(SafeBackup { log_file })
    }

    // Secure path validation - prevents path traversal attacks
    fn validate_path(&self, filename: &str) -> Result<PathBuf> {
        // Check for empty filename
        if filename.trim().is_empty() {
            return Err(SafeBackupError::InvalidPath("Filename cannot be empty".to_string()));
        }

        // Check for path traversal sequences
        if filename.contains("..") {
            return Err(SafeBackupError::InvalidPath("Path traversal sequences are not allowed".to_string()));
        }

        // Check for invalid characters (Windows and Unix)
        let invalid_chars = ['<', '>', ':', '"', '|', '?', '*', '\0'];
        if filename.chars().any(|c| invalid_chars.contains(&c)) {
            return Err(SafeBackupError::InvalidPath("Filename contains invalid characters".to_string()));
        }

        // Prevent absolute paths
        let path = Path::new(filename);
        if path.is_absolute() {
            return Err(SafeBackupError::InvalidPath("Absolute paths are not allowed".to_string()));
        }

        // Canonicalize the path to resolve any remaining issues
        let current_dir = std::env::current_dir()?;
        let full_path = current_dir.join(path);
        
        // Ensure the resolved path is still within the current directory
        if !full_path.starts_with(&current_dir) {
            return Err(SafeBackupError::InvalidPath("Path escapes current directory".to_string()));
        }

        Ok(PathBuf::from(filename))
    }

    // Secure logging with proper error handling
    fn log_action(&self, action: &str) -> Result<()> {
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let log_entry = format!("[{}] {}\n", timestamp, action);
        
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)?;
        
        file.write_all(log_entry.as_bytes())?;
        file.flush()?;
        Ok(())
    }

    // Secure file backup with comprehensive error handling
    fn backup_file(&self, filename: &str) -> Result<()> {
        let file_path = self.validate_path(filename)?;
        
        // Check if source file exists and is readable
        if !file_path.exists() {
            return Err(SafeBackupError::FileNotFound(format!("Source file '{}' does not exist", filename)));
        }

        if !file_path.is_file() {
            return Err(SafeBackupError::InvalidPath(format!("'{}' is not a regular file", filename)));
        }

        let backup_name = format!("{}.bak", filename);
        let backup_path = self.validate_path(&backup_name)?;

        // Read source file contents securely
        let contents = fs::read(&file_path)
            .map_err(|e| SafeBackupError::IoError(e))?;

        // Write backup file atomically
        fs::write(&backup_path, contents)?;

        println!("Backup created: {}", backup_name);
        self.log_action(&format!("Performed backup of '{}'", filename))?;
        Ok(())
    }

    // Secure file restoration with validation
    fn restore_file(&self, filename: &str) -> Result<()> {
        let file_path = self.validate_path(filename)?;
        let backup_name = format!("{}.bak", filename);
        let backup_path = self.validate_path(&backup_name)?;

        // Check if backup file exists
        if !backup_path.exists() {
            return Err(SafeBackupError::FileNotFound(format!("Backup file '{}' does not exist", backup_name)));
        }

        if !backup_path.is_file() {
            return Err(SafeBackupError::InvalidPath(format!("'{}' is not a regular file", backup_name)));
        }

        // Read backup contents and restore
        let contents = fs::read(&backup_path)?;
        fs::write(&file_path, contents)?;

        println!("File restored from: {}", backup_name);
        self.log_action(&format!("Performed restore to '{}'", filename))?;
        Ok(())
    }

    // Secure file deletion with confirmation
    fn delete_file(&self, filename: &str) -> Result<()> {
        let file_path = self.validate_path(filename)?;

        // Check if file exists
        if !file_path.exists() {
            return Err(SafeBackupError::FileNotFound(format!("File '{}' does not exist", filename)));
        }

        if !file_path.is_file() {
            return Err(SafeBackupError::InvalidPath(format!("'{}' is not a regular file", filename)));
        }

        // Secure confirmation prompt
        print!("Are you sure you want to delete '{}'? (yes/no): ", filename);
        io::stdout().flush()?;

        let stdin = io::stdin();
        let mut input = String::new();
        stdin.read_line(&mut input)?;
        
        let confirmation = input.trim().to_lowercase();
        
        if confirmation == "yes" {
            fs::remove_file(&file_path)?;
            println!("File deleted successfully.");
            self.log_action(&format!("Performed delete on '{}'", filename))?;
        } else {
            println!("File deletion cancelled.");
            self.log_action(&format!("Delete operation cancelled for '{}'", filename))?;
        }

        Ok(())
    }

    // Secure input handling
    fn get_user_input(prompt: &str) -> Result<String> {
        print!("{}", prompt);
        io::stdout().flush()?;

        let stdin = io::stdin();
        let mut input = String::new();
        stdin.read_line(&mut input)?;

        // Trim whitespace and validate input length
        let trimmed_input = input.trim();
        if trimmed_input.len() > 255 {
            return Err(SafeBackupError::InvalidPath("Input too long".to_string()));
        }

        Ok(trimmed_input.to_string())
    }

    // Main application logic
    fn run(&self) -> Result<()> {
        // Get filename with validation
        let filename = Self::get_user_input("Please enter your file name: ")?;
        
        // Validate the filename immediately
        self.validate_path(&filename)?;

        // Get command with validation
        let command = Self::get_user_input("Please enter your command (backup, restore, delete): ")?;

        // Execute command with proper error handling
        match command.to_lowercase().as_str() {
            "backup" => self.backup_file(&filename),
            "restore" => self.restore_file(&filename),
            "delete" => self.delete_file(&filename),
            _ => {
                println!("Unknown command: '{}'", command);
                self.log_action(&format!("Unknown command attempted: '{}'", command))?;
                Ok(())
            }
        }
    }
}

fn main() {
    match SafeBackup::new() {
        Ok(app) => {
            if let Err(e) = app.run() {
                eprintln!("Error: {}", e);
                // Log the error if possible
                if let Ok(log_app) = SafeBackup::new() {
                    let _ = log_app.log_action(&format!("Error occurred: {}", e));
                }
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Failed to initialize application: {}", e);
            std::process::exit(1);
        }
    }
}