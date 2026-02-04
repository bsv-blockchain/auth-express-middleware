/** @type {import('ts-jest').JestConfigWithTsJest} */
export default {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testPathIgnorePatterns: ['dist/'],
  modulePathIgnorePatterns: ['<rootDir>/dist/'] // Add this to ignore dist/ for module mapping
}
