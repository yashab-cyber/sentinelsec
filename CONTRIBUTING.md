# Contributing to SentinelSec

First off, thank you for considering contributing to SentinelSec! It's people like you that make SentinelSec such a great tool for the cybersecurity community.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps which reproduce the problem** in as many details as possible.
* **Provide specific examples to demonstrate the steps**.
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
* **Explain which behavior you expected to see instead and why.**
* **Include screenshots and animated GIFs** which show you following the described steps and clearly demonstrate the problem.

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* **Use a clear and descriptive title** for the issue to identify the suggestion.
* **Provide a step-by-step description of the suggested enhancement** in as many details as possible.
* **Provide specific examples to demonstrate the steps**.
* **Describe the current behavior** and **explain which behavior you expected to see instead** and why.
* **Explain why this enhancement would be useful** to most SentinelSec users.

### Pull Requests

* Fill in the required template
* Do not include issue numbers in the PR title
* Include screenshots and animated GIFs in your pull request whenever possible.
* Follow the Python style guides.
* Include thoughtfully-worded, well-structured tests.
* Document new code based on the Documentation Styleguide
* End all files with a newline

## Development Process

1. Fork the repo
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for your changes
5. Ensure tests pass
6. Commit your changes (`git commit -m 'Add some amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Style Guides

### Python Style Guide

* Follow PEP 8
* Use 4 spaces for indentation
* Line length should not exceed 88 characters
* Use type hints where appropriate
* Add docstrings to all functions and classes

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

### Documentation Style Guide

* Use Markdown for documentation
* Include code examples where appropriate
* Keep language clear and concise
* Update README.md if needed

## Security Guidelines

### Reporting Security Issues

Please do not report security vulnerabilities through public GitHub issues. Instead, please send an email to yashabalam707@gmail.com with:

* Description of the vulnerability
* Steps to reproduce
* Potential impact
* Suggested fix (if any)

### Security Best Practices

* Never commit API keys, passwords, or other sensitive information
* Sanitize all user inputs
* Follow secure coding practices
* Test security features thoroughly

## Testing

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run tests with coverage
python -m pytest tests/ --cov=core --cov=db --cov=gui

# Run specific test file
python -m pytest tests/test_packet_sniffer.py
```

### Writing Tests

* Write tests for all new features
* Ensure good test coverage
* Use descriptive test names
* Include both positive and negative test cases
* Mock external dependencies

## Additional Notes

### Issue and Pull Request Labels

* `bug` - Something isn't working
* `enhancement` - New feature or request
* `documentation` - Improvements or additions to documentation
* `good first issue` - Good for newcomers
* `help wanted` - Extra attention is needed
* `security` - Security-related issues

Thank you for contributing to SentinelSec! 🛡️
