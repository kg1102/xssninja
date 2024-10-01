# XSS Ninja

**XSSNinja** is a Rust-based tool for automated detection of Cross-Site Scripting (XSS) vulnerabilities in web applications. It scans provided URLs, testing various payloads to identify potential vulnerabilities.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Command-Line Options](#command-line-options)
- [How It Works](#how-it-works)
- [Contributing](#contributing)
- [License](#license)

## Features

- **High Concurrency**: Scans multiple URLs simultaneously using Rust's asynchronous features.
- **Diverse Payloads**: Uses a variety of well-known payloads for XSS detection.
- **Smart Parameter Extraction**: Extracts parameters from forms and scripts on the page for more comprehensive testing.
- **GET and POST Modes**: Tests both GET and POST requests.
- **Verbose Mode**: Option to display detailed logs during execution.

## Installation

Ensure Rust is installed on your machine. You can install it via [rustup](https://rustup.rs/).

Clone the repository and build the project:

```bash
git clone https://github.com/kg1102/xssninja.git
cd xssninja
cargo build --release
```

The compiled binary will be available at `target/release/xssninja`.

## Usage

You can use **xssninja** by providing a list of URLs through a file or via standard input (stdin).

### Example with a file:

```bash
./xssninja -f urls.txt
```

### Example with standard input:

```bash
cat urls.txt | ./xssninja
```

### Specifying concurrency level:

```bash
./xssninja -f urls.txt -c 100
```

### Enabling verbose mode:

```bash
./xssninja -f urls.txt -v
```

## Command-Line Options

```
USAGE:
    xssninja [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v, --verbose    Activates verbose mode

OPTIONS:
    -c, --concurrency <concurrency>    Sets the level of concurrency [default: 200]
    -f, --file <file>                  Path to the file containing URLs
```

## How It Works

1. **URL Input**: The tool reads URLs to be tested from a file or standard input.
2. **Wordlist Download**: Downloads a wordlist of parameters to increase test coverage.
3. **XSS Scanning**: For each URL:
   - **Initial Analysis**: Makes an initial request to fetch the response body.
   - **Parameter Extraction**: Extracts parameter names from inputs, JavaScript variables, and URLs present in the response.
   - **Payload Testing**:
     - **Existing Parameters**: Tests payloads on the parameters already present in the URL.
     - **Extracted Parameters**: Tests payloads on the parameters extracted from the response body.
     - **Wordlist Parameters**: Tests payloads using parameters from the external wordlist.
   - **XSS Detection**: Checks if injected payloads appear in the response, indicating a potential vulnerability.

4. **Results**: Displays the found vulnerabilities, highlighting confirmed and potential XSS.

## Example Output

```
XSS NINJA - Starting scan...
XSS FOUND (GET): http://example.com/?search=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E
```

- **XSS FOUND**: Confirmed vulnerability.
- **POSSIBLE XSS**: Indicates that the payload might be present in an exploitable context.
- **Sanitized Payload** (Verbose Mode): The payload was filtered by the server.
- **Not Vulnerable** (Verbose Mode): No vulnerabilities detected with the tested payloads.

## Contributing

Contributions are welcome! Feel free to open issues and pull requests.

To set up the development environment:

1. Clone the repository.
2. Create a new branch for your feature or fix.
3. Make your changes and commit.
4. Open a pull request describing your changes.

## License

This project is licensed under the MIT License – see the [LICENSE](https://github.com/kg1102/xssninja/blob/master/LICENSE) file for details.

---

**Disclaimer**: This tool is developed for educational purposes and to assist with authorized security testing. Misuse of this tool may be illegal and is the sole responsibility of the user. Always obtain permission before testing systems that you do not own.

---

For the Portuguese version of this README, see [readme-ptbr.md](readme-ptbr.md).