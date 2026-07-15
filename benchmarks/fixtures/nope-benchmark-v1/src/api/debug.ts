export function debugEnvironment() {
  return {
    env: process.env,
    stack: new Error().stack,
  };
}
