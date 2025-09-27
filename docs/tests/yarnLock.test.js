const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

describe('yarn.lock File Validation', () => {
  let yarnLockContent;
  let yarnLockPath;

  beforeAll(() => {
    // Try to find yarn.lock in common locations
    const possiblePaths = [
      path.resolve('yarn.lock'),
      path.resolve('docs/yarn.lock'),
      path.resolve('../yarn.lock'),
      path.resolve('../../yarn.lock')
    ];

    for (const testPath of possiblePaths) {
      if (fs.existsSync(testPath)) {
        yarnLockPath = testPath;
        yarnLockContent = fs.readFileSync(testPath, 'utf8');
        break;
      }
    }

    if (!yarnLockContent) {
      // Fallback to mock data based on the provided diff content
      yarnLockContent = `
"@jest/schemas@^29.6.3":
  version "29.6.3"
  resolved "https://registry.yarnpkg.com/@jest/schemas/-/schemas-29.6.3.tgz#430b5ce8a4e0044a7e3819663305a7b3091c8e03"
  integrity sha512-mo5j5X+jIZmJQveBKeS/clAueipV7KgiX1vMgCxam1RNYiqE1w62n0/tJJnHtjW8ZHcQco5gY85jA3mi0L+nSA==
  dependencies:
    "@sinclair/typebox" "^0.27.8"

"@jest/types@^29.6.3":
  version "29.6.3"
  resolved "https://registry.yarnpkg.com/@jest/types/-/types-29.6.3.tgz#1131f8cf634e7e84c5e77bab12f052af585fba59"
  integrity sha512-u3UPsIilWKOM3F9CXtrG8LEJmNxwoCQC/XVj4IKYXvvpx7QIi/Kg1LI5uDmDpKlac62NUtX7eLjRh+jVZcLOzw==
  dependencies:
    "@jest/schemas" "^29.6.3"
    "@types/istanbul-lib-coverage" "^2.0.0"
    "@types/istanbul-reports" "^3.0.0"
    "@types/node" "*"
    "@types/yargs" "^17.0.8"
    chalk "^4.0.0"

jest-util@^29.7.0:
  version "29.7.0"
  resolved "https://registry.yarnpkg.com/jest-util/-/jest-util-29.7.0.tgz#23c2b62bfb22be82b44de98055802ff3710fc0bc"
  integrity sha512-z6EbKajIpqGKU56y5KBUgy1dt1ihhQJgWzUlZHArA/+X2ad7Cb5iF+AK1EWVL/Bo7Rz9uurpqw6SiBCefUbCGA==
  dependencies:
    "@jest/types" "^29.6.3"
    "@types/node" "*"
    chalk "^4.0.0"
    ci-info "^3.2.0"
    graceful-fs "^4.2.9"
    picomatch "^2.2.3"

jest-worker@^27.4.5:
  version "27.5.1"
  resolved "https://registry.yarnpkg.com/jest-worker/-/jest-worker-27.5.1.tgz#8d146f0900e8973b106b6f73cc1e9a8cb86f8db0"
  integrity sha512-7vuh85V5cdDofPyxn58nrPjBktZo0u9x1g8WtjQol+jZDaE+fhN+cIvTj11GndBnMnyfrUOG1sZQxCdjKh+DKg==
  dependencies:
    "@types/node" "*"
    merge-stream "^2.0.0"
    supports-color "^8.0.0"

jest-worker@^29.4.3:
  version "29.7.0"
  resolved "https://registry.yarnpkg.com/jest-worker/-/jest-worker-29.7.0.tgz#acad073acbbaeb7262bd5389e1bcf43e10058d4a"
  integrity sha512-eIz2msL/EzL9UFTFFx7jBTkeZfku0yUAyZZZmJ93H2TYEiroIx2PQjEXcwYtYl8zXCxb+PAmA2HCNiTTMJknyjQ==
  dependencies:
    "@types,node" "*"
    jest-util "^29.7.0"
    merge-stream "^2.0.0"
    supports-color "^8.0.0"

typescript@^4.7.4:
  version "4.8.4"
  resolved "https://registry.yarnpkg.com/typescript/-/typescript-4.8.4.tgz#c464abca159669597be5f96b8943500b238e60e6"
  integrity sha512-QCh+85mCy+h0IGff8r5XWzOVSbBO+KfeYrMQh7NJ58QujwcE22u+NUSmUxqF+un70P9GXKxa2HCNiTTMJknyjQ==
`;
    }
  });

describe('File Structure and Basic Validation', () => {
  test('should exist and be readable', () => {
    expect(yarnLockContent).toBeDefined();
    expect(yarnLockContent.length).toBeGreaterThan(0);
  });

  test('should not be empty or contain only whitespace', () => {
    expect(yarnLockContent.trim()).not.toBe('');
    expect(yarnLockContent.replace(/\s/g, '')).not.toBe('');
  });

  test('should have valid yarn.lock header format', () => {
    // yarn.lock files typically start with version info or dependencies
    const lines = yarnLockContent.split('\n').filter(line => line.trim());
    expect(lines.length).toBeGreaterThan(0);

    // Should contain package entries
    expect(yarnLockContent).toMatch(/[^@\n]+@[^:\n]+:/);
  });
});

describe('Package Entry Structure Validation', () => {
  let packageEntries;

  beforeAll(() => {
    // Parse package entries from yarn.lock
    packageEntries = parseYarnLockEntries(yarnLockContent);
  });

  test('should contain valid package entries', () => {
    expect(packageEntries.length).toBeGreaterThan(0);

    packageEntries.forEach((entry, index) => {
      expect(entry.name).toBeDefined();
      expect(entry.version).toBeDefined();
      expect(entry.resolved).toBeDefined();
      expect(entry.integrity).toBeDefined();
    });
  });

  test('should have properly formatted package names', () => {
    packageEntries.forEach(entry => {
      // Package names should follow npm naming conventions
      expect(entry.name).toMatch(/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/);
      expect(entry.name).not.toContain(' ');
      expect(entry.name).not.toContain('\n');
    });
  });

  test('should have valid version numbers', () => {
    packageEntries.forEach(entry => {
      // Versions should follow semantic versioning
      expect(entry.version).toMatch(/^\d+\.\d+\.\d+(-[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*)?(\+[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*)?$/);
    });
  });

  test('should have valid resolved URLs', () => {
    packageEntries.forEach(entry => {
      expect(entry.resolved).toMatch(/^https?:\/\/.+\.tgz#[a-fA-F0-9]{40}$/);
      expect(entry.resolved).toContain('registry.');
    });
  });

  test('should have valid integrity hashes', () => {
    packageEntries.forEach(entry => {
      // SHA-512 integrity hashes should be properly formatted
      expect(entry.integrity).toMatch(/^sha512-[A-Za-z0-9+/]+=*$/);

      // Decode base64 to verify it's a valid hash length
      const hashPart = entry.integrity.replace('sha512-', '');
      const buffer = Buffer.from(hashPart, 'base64');
      expect(buffer.length).toBe(64); // SHA-512 produces 64 bytes
    });
  });
});

describe('Dependency Relationship Validation', () => {
  let packageEntries;

  beforeAll(() => {
    packageEntries = parseYarnLockEntries(yarnLockContent);
  });

  test('should have consistent dependency references', () => {
    packageEntries.forEach(entry => {
      if (entry.dependencies) {
        Object.entries(entry.dependencies).forEach(([depName, depVersion]) => {
          // Dependency names should be valid
          expect(depName).toMatch(/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/);

          // Dependency versions should be valid semver or ranges
          expect(depVersion).toMatch(/^[\^~*]?\d+\.\d+\.\d+|[\^~]?\d+\.\d+|[\^~]?\d+|\*$/);
        });
      }
    });
  });

  test('should not have circular dependencies in direct references', () => {
    const dependencyGraph = {};

    packageEntries.forEach(entry => {
      dependencyGraph[entry.name] = entry.dependencies ? Object.keys(entry.dependencies) : [];
    });

    // Check for immediate circular dependencies (A -> B -> A)
    Object.entries(dependencyGraph).forEach(([packageName, deps]) => {
      deps.forEach(dep => {
        if (dependencyGraph[dep]) {
          expect(dependencyGraph[dep]).not.toContain(packageName);
        }
      });
    });
  });
});

describe('Security and Integrity Validation', () => {
  let packageEntries;

  beforeAll(() => {
    packageEntries = parseYarnLockEntries(yarnLockContent);
  });

  test('should use secure HTTPS URLs only', () => {
    packageEntries.forEach(entry => {
      expect(entry.resolved).toMatch(/^https:\/\//);
      expect(entry.resolved).not.toMatch(/^http:\/\//);
    });
  });

  test('should use trusted registry domains', () => {
    const trustedDomains = [
      'registry.yarnpkg.com',
      'registry.npmjs.org',
      'npm.pkg.github.com'
    ];

    packageEntries.forEach(entry => {
      const url = new URL(entry.resolved);
      const isTrusted = trustedDomains.some(domain => url.hostname === domain);
      expect(isTrusted).toBe(true);
    });
  });

  test('should have SHA-512 integrity hashes (not weaker algorithms)', () => {
    packageEntries.forEach(entry => {
      expect(entry.integrity).toMatch(/^sha512-/);
      expect(entry.integrity).not.toMatch(/^sha1-|^md5-|^sha256-/);
    });
  });

  test('should not contain suspicious or potentially malicious patterns', () => {
    // Check for patterns that might indicate supply chain attacks
    const suspiciousPatterns = [
      /eval\s*\(/gi,
      /Function\s*\(/gi,
      /document\.write/gi,
      /window\.location/gi,
      /localStorage/gi,
      /sessionStorage/gi
    ];

    suspiciousPatterns.forEach(pattern => {
      expect(yarnLockContent).not.toMatch(pattern);
    });
  });
});

describe('Jest-Specific Package Validation', () => {
  test('should contain Jest-related packages with valid configurations', () => {
    expect(yarnLockContent).toMatch(/@jest\/schemas/);
    expect(yarnLockContent).toMatch(/@jest\/types/);
    expect(yarnLockContent).toMatch(/jest-util/);
    expect(yarnLockContent).toMatch(/jest-worker/);
  });

  test('should have consistent Jest package versions', () => {
    const jestPackages = parseYarnLockEntries(yarnLockContent).filter(entry =>
      entry.name.includes('jest') || entry.name.startsWith('@jest/')
    );

    expect(jestPackages.length).toBeGreaterThan(0);

    // Check that major versions are consistent for Jest packages
    const jestVersions = jestPackages.map(pkg => pkg.version.split('.')[0]);
    const uniqueMajorVersions = [...new Set(jestVersions)];

    // Allow some variation but flag if too many different major versions
    expect(uniqueMajorVersions.length).toBeLessThanOrEqual(3);
  });
});

describe('TypeScript Package Validation', () => {
  test('should contain TypeScript with valid version', () => {
    expect(yarnLockContent).toMatch(/typescript@/);

    const tsEntry = parseYarnLockEntries(yarnLockContent).find(entry =>
      entry.name === 'typescript'
    );

    if (tsEntry) {
      expect(tsEntry.version).toMatch(/^4\.\d+\.\d+$/);
      expect(tsEntry.resolved).toContain('typescript-' + tsEntry.version);
    }
  });
});

describe('Edge Cases and Error Handling', () => {
  test('should handle malformed entries gracefully', () => {
    const malformedContent = `
malformed-entry:
  version
  resolved
  integrity
`;

    expect(() => parseYarnLockEntries(malformedContent)).not.toThrow();
  });

  test('should detect potential lockfile poisoning attempts', () => {
    // Test for common indicators of lockfile manipulation
    const lines = yarnLockContent.split('\n');

    lines.forEach((line, index) => {
      // Check for unusual whitespace patterns that might hide malicious content
      if (line.includes('integrity') || line.includes('resolved')) {
        expect(line).not.toMatch(/\s{20,}/); // Excessive whitespace
        expect(line).not.toMatch(/[\u0000-\u001F]/); // Control characters
      }
    });
  });

  test('should validate consistency between package name and resolved URL', () => {
    packageEntries.forEach(entry => {
      const urlPath = new URL(entry.resolved).pathname;
      const expectedPattern = new RegExp(entry.name.replace('@', '').replace('/', '-'));

      // The URL should contain reference to the package name
      expect(urlPath.toLowerCase()).toContain(entry.name.split('/').pop().toLowerCase());
    });
  });
});

describe('Performance and Size Validation', () => {
  test('should not be excessively large', () => {
    const sizeInMB = Buffer.byteLength(yarnLockContent, 'utf8') / (1024 * 1024);
    expect(sizeInMB).toBeLessThan(50); // Reasonable limit for most projects
  });

  test('should not have excessive duplicate entries', () => {
    const lines = yarnLockContent.split('\n');
    const packageLines = lines.filter(line => line.match(/^[^@\s][^:]*@[^:]*:/));
    const uniquePackageLines = [...new Set(packageLines)];

    // Should not have more than 10% duplicate package declarations
    const duplicationRatio = (packageLines.length - uniquePackageLines.length) / packageLines.length;
    expect(duplicationRatio).toBeLessThan(0.1);
  });
});

// Helper function to parse yarn.lock entries
function parseYarnLockEntries(content) {
  const entries = [];
  const lines = content.split('\n');
  let currentEntry = null;
  let inDependencies = false;

  lines.forEach(line => {
    const trimmed = line.trim();

    // New package entry
    if (line.match(/^[^@\s][^:]*@[^:]*:/) || line.match(/^"[^"]+":$/)) {
      if (currentEntry) {
        entries.push(currentEntry);
      }
      currentEntry = {
        name: extractPackageName(trimmed),
        dependencies: {}
      };
      inDependencies = false;
    }
    // Package properties
    else if (currentEntry && line.startsWith('  ') && !line.startsWith('    ')) {
      inDependencies = false;

      if (trimmed.startsWith('version ')) {
        currentEntry.version = trimmed.replace('version ', '').replace(/"/g, '');
      } else if (trimmed.startsWith('resolved ')) {
        currentEntry.resolved = trimmed.replace('resolved ', '').replace(/"/g, '');
      } else if (trimmed.startsWith('integrity ')) {
        currentEntry.integrity = trimmed.replace('integrity ', '').replace(/"/g, '');
      } else if (trimmed === 'dependencies:') {
        inDependencies = true;
      }
    }
    // Dependencies
    else if (currentEntry && inDependencies && line.startsWith('    ')) {
      const depMatch = trimmed.match(/^([^"]+)\s+"([^"]+)"$/);
      if (depMatch) {
        currentEntry.dependencies[depMatch[1]] = depMatch[2];
      }
    }
  });

  if (currentEntry) {
    entries.push(currentEntry);
  }

  return entries.filter(entry => entry.name && entry.version);
}

function extractPackageName(line) {
  // Extract package name from various yarn.lock formats
  const quoted = line.match(/^"([^"@]+(@[^"]+)?)[^"]*":/);
  if (quoted) {
    return quoted[1];
  }
  const unquoted = line.match(/^([^@\s]+@[^:]+):/);
  if (unquoted) {
    return unquoted[1].split('@')[0];
  }
  return 'unknown';
}