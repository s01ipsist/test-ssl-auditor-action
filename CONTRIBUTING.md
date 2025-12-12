# Contributing to test-ssl-auditor-action

Thank you for your interest in contributing to this project!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/s01ipsist/test-ssl-auditor-action.git
   cd test-ssl-auditor-action
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Make your changes to the TypeScript source files in the `src/` directory.

4. Run tests:
   ```bash
   npm test
   ```

5. Format your code:
   ```bash
   npm run format
   ```

6. Lint your code:
   ```bash
   npm run lint
   ```

7. Build the action:
   ```bash
   npm run build
   ```

8. Commit the built `dist/` directory along with your source changes.

## Testing Your Changes

You can test the action locally by creating a test workflow in your fork.

## Pull Request Process

1. Ensure all tests pass
2. Update documentation if needed
3. The `dist/` directory must be included in your PR
4. Follow the existing code style

## Code Style

This project uses:
- TypeScript with strict mode
- ESLint for linting
- Prettier for formatting
- Jest for testing

## Questions?

Feel free to open an issue for any questions or concerns.
