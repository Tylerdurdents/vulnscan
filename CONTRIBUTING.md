# Contributing to VulnScan

Thank you for your interest in contributing to VulnScan! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

Please be respectful and inclusive in all interactions. We expect contributors to:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints
- Accept constructive criticism gracefully
- Focus on what is best for the community

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/vulnscan.git
   cd vulnscan
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Tylerdurdents/vulnscan.git
   ```
4. **Install dependencies**:
   ```bash
   go mod download
   ```

## How to Contribute

### Reporting Bugs

- Use GitHub Issues to report bugs
- Include a clear description of the issue
- Provide steps to reproduce
- Include error messages and logs
- Specify your environment (OS, Go version)

### Suggesting Features

- Use GitHub Issues with the "enhancement" label
- Describe the feature and its use case
- Explain why it would be useful

### Submitting Code

1. Create a new branch for your feature/fix
2. Make your changes
3. Write/update tests
4. Update documentation if needed
5. Submit a pull request

## Development Workflow

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git checkout master
   git merge upstream/master
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make changes and commit**:
   ```bash
   git add .
   git commit -m "Description of your changes"
   ```

4. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request** on GitHub

## Coding Standards

### Go Code Style

- Follow standard Go formatting (`gofmt`)
- Use meaningful variable and function names
- Add comments for exported functions
- Keep functions focused and small
- Handle errors properly

### Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor" not "Moves cursor")
- Limit first line to 72 characters
- Reference issues and pull requests when relevant

Example:
```
Add SQL injection detection module

- Implemented payload injection
- Added error pattern matching
- Updated tests

Fixes #123
```

## Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...

# Run benchmarks
go test -bench=. ./tests/
```

### Writing Tests

- Write unit tests for new functions
- Write integration tests for new features
- Aim for good test coverage
- Use table-driven tests when appropriate

Example:
```go
func TestFunctionName(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
    }{
        {"test case 1", "input1", "expected1"},
        {"test case 2", "input2", "expected2"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := FunctionName(tt.input)
            if result != tt.expected {
                t.Errorf("got %s, want %s", result, tt.expected)
            }
        })
    }
}
```

## Documentation

### Code Documentation

- Add comments for all exported functions
- Use godoc-style comments
- Include examples when helpful

### User Documentation

- Update README.md for new features
- Add usage examples
- Keep documentation up to date

## Pull Request Process

1. **Update your branch** with latest upstream changes
2. **Run tests** to ensure everything passes
3. **Update documentation** if needed
4. **Create a Pull Request** with:
   - Clear title describing the change
   - Detailed description of changes
   - Reference to related issues
   - Screenshots if applicable

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Tests pass locally
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Commit messages are clear and descriptive

## Adding New Vulnerability Modules

1. Create a new directory under `pkg/modules/`
2. Implement the `Module` interface:
   ```go
   type Module interface {
       Name() string
       Description() string
       Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []Vulnerability
   }
   ```
3. Register the module in `pkg/modules/modules.go`
4. Add tests for the module
5. Update documentation

## Questions?

If you have questions, feel free to:
- Open a GitHub Issue
- Start a GitHub Discussion
- Contact the maintainers

Thank you for contributing to VulnScan!
