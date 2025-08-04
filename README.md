CYB225 Secure Coding Assignment

Group 12:
- Brais Chenlo Caldelas AIBI20240538
- Jafredd Jaimes AIBI20250043
- Juan Diego Garnica AIBI20250107

This repository contains the redeveloped Rust program to safely backup files, fixing the flaws of the C++ code.

The program should be able to backup, delete, and restore existing files.
Also, it should safely handle the next errors and vulnerabilities:
- Path Traversal
- Invalid characters
- File doesn't exist
- Empty filename
- Absolute paths
- Buffer overflow


To keep a record, a logfile with all the actions would be automatically generated.


Run the program
- Download the program from the given repository
- On a program like VS Code, install plugins able to read and compile Rust
- Access the program folder using "cd" on the terminal
- Run and compile the run using "cargo run"
- Enter any input that you want to test
