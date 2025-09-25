const esbuild = require('esbuild');
const path = require('path');

const buildOptions = {
  entryPoints: ['src/handlers/index.ts'],
  bundle: true,
  minify: true,
  sourcemap: true,
  outfile: 'dist/handlers/index.js',
  target: 'node18',
  platform: 'node',
  format: 'cjs',
  external: [
    '@aws-sdk/client-kms',
    '@aws-sdk/client-secrets-manager'
  ]
};

async function build() {
  try {
    console.log('Building Lambda function...');
    await esbuild.build(buildOptions);
    console.log('Build complete!');
  } catch (error) {
    console.error('Build failed:', error);
    process.exit(1);
  }
}

build();