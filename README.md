# jwt-decode

A simple CLI utility to decode and inspect JWT tokens without verification for debugging authentication issues

## Features

- Decode JWT tokens from command line arguments, stdin, or file input
- Parse and display header claims (algorithm, type, key ID)
- Parse and display payload claims with proper JSON formatting
- Show token expiration time in human-readable format with time-until-expiry calculation
- Display issued-at and not-before times if present
- Validate JWT structure (3 base64url-encoded segments) without signature verification
- Color-coded output: green for valid structure, yellow for warnings, red for errors
- Support for compact and pretty-print JSON output modes
- Detect and warn about expired tokens
- Handle malformed tokens gracefully with helpful error messages
- Display raw base64 segments for manual inspection if needed

## Installation

```bash
# Clone the repository
git clone https://github.com/KurtWeston/jwt-decode.git
cd jwt-decode

# Install dependencies
go build
```

## Usage

```bash
./main
```

## Built With

- go

## Dependencies

- `github.com/fatih/color`
- `github.com/spf13/cobra`

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
