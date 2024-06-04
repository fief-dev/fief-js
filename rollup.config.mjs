import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import terser from '@rollup/plugin-terser';
import typescript from '@rollup/plugin-typescript';

const external = [
  'crypto',
  'jose',
  'next',
  'next/cache',
  'next/headers',
  'next/server',
  'path-to-regexp',
  'react',
  'react/jsx-runtime',
];
const globals = {
  crypto: 'crypto',
};

export default [
  // browser-friendly UMD build
  {
    input: 'src/index.ts',
    output: {
      name: 'fief',
      file: 'build/index.umd.js',
      format: 'umd',
      sourcemap: true,
      globals,
    },
    plugins: [
      nodeResolve({
        jsnext: true,
        preferBuiltins: true,
        browser: true,
      }),
      json(),
      commonjs(),
      typescript(),
      terser(),
    ],
  },
  // CommonJS (for Node)
  {
    input: [
      'src/index.ts',
      'src/react/index.ts',
      'src/express/index.ts',
      'src/nextjs/index.ts',
      'src/nextjs/react/index.ts',
    ],
    plugins: [
      typescript({
        declaration: false,
        rootDir: 'src',
        exclude: ['**/*.test.ts'],
      }),
    ],
    output: [
      {
        dir: 'build/cjs',
        format: 'cjs',
        sourcemap: true,
        preserveModules: true,
        preserveModulesRoot: 'src',
        globals,
      },
    ],
    external,
  },
  // ES module (for bundlers) build.
  {
    input: [
      'src/index.ts',
      'src/react/index.ts',
      'src/express/index.ts',
      'src/nextjs/index.ts',
      'src/nextjs/react/index.ts',
    ],
    plugins: [
      typescript({
        declaration: true,
        declarationDir: 'build/esm',
        rootDir: 'src',
        exclude: ['**/*.test.ts'],
      }),
    ],
    output: [
      {
        dir: 'build/esm',
        format: 'es',
        sourcemap: true,
        preserveModules: true,
        preserveModulesRoot: 'src',
        globals,
      },
    ],
    external,
  },
];
