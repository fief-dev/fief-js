import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';
import copy from 'rollup-plugin-copy';
import { terser } from 'rollup-plugin-terser';

import pkg from './package.json';

export default [
  // browser-friendly UMD build
  {
    input: 'src/index.ts',
    output: {
      name: 'fief',
      file: pkg.browser,
      format: 'umd',
      sourcemap: true,
    },
    plugins: [
      nodeResolve({ jsnext: true, preferBuiltins: true, browser: true }),
      json(),
      commonjs(),
      typescript(),
      terser(),
      copy({
        targets: [
          { src: 'src/index.html', dest: 'build' },
        ],
      }),
    ],
  },
  // CommonJS (for Node)
  {
    input: [
      'src/index.ts',
      'src/react/index.ts',
    ],
    external: ['ms'],
    plugins: [
      typescript({ declaration: false, rootDir: 'src' }),
    ],
    output: [
      {
        dir: 'build/cjs',
        format: 'cjs',
        sourcemap: true,
        preserveModules: true,
        preserveModulesRoot: 'src',
      },
    ],
  },
  // ES module (for bundlers) build.
  {
    input: [
      'src/index.ts',
      'src/react/index.ts',
    ],
    external: ['ms'],
    plugins: [
      typescript({
        declaration: true,
        declarationDir: 'build/esm',
        rootDir: 'src',
      }),
    ],
    output: [
      {
        dir: 'build/esm',
        format: 'es',
        sourcemap: true,
        preserveModules: true,
        preserveModulesRoot: 'src',
      },
    ],
  },
];
