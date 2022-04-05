import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';

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
    ]
  },
  // CommonJS (for Node) and ES module (for bundlers) build.
  {
    input: 'src/index.ts',
    external: ['ms'],
    plugins: [
      typescript(),
    ],
    output: [
      { file: pkg.main, format: 'cjs', sourcemap: true },
      { file: pkg.module, format: 'es', sourcemap: true },
    ]
  }
];
